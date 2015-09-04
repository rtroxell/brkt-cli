# Copyright 2015 Bracket Computing, Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
# https://github.com/brkt/brkt-sdk-java/blob/master/LICENSE
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and
# limitations under the License.

"""
Create a bracket solo metavisor/guest AMI
complete with a encrypted root volume for a given guest AMI

Basic outline:
    create a guest AMI with the right permissions on root vol snapshot
    launch a metavisor AMI with
        *) unencrypted guest root volume as /dev/sda4
        *) (raw) guest root volume (2x size) as /dev/sda5
    wait for the metavisor to launch
        *) dd from /dev/sda4 to /dev/sda5 creating encrypted root for guest
    stop metavisor
    create new AMI from metavisor instance
        *) include ephemeral drives

At that point a new AMI contains the metavisor + encrypted guest root volume.
We should be able to auto-chain load the guest once this AMI is launched

Environment setup:
Either setup environment variables for:
export AWS_ACCESS_KEY_ID=XXXXXXX
export AWS_SECRET_KEY=XXXXXXX

or

export BOTO_CONFIG ~/.ec2/boto_config
------------
boto_config
------------
[Credentials]
aws_access_key_id = XXXXXXXXXXXXX
aws_secret_access_key = XXXXXXXXXXXX
------------
"""
from __future__ import print_function

import argparse
import boto
import boto.ec2
import boto.vpc
import logging
import os
import re
import requests
import string
import sys
import time
import uuid
import warnings

from boto.exception import EC2ResponseError
from boto.ec2.blockdevicemapping import (
    BlockDeviceMapping,
    BlockDeviceType,
    EBSBlockDeviceType
)

from brkt_cli import service
from brkt_cli.util import Deadline, make_nonce

# End user-visible terminology.  These are resource names and descriptions
# that the user will see in his or her EC2 console.

# Snapshotter instance names.
NAME_SNAPSHOT_CREATOR = 'Bracket root snapshot creator'
DESCRIPTION_SNAPSHOT_CREATOR = \
    'Used for creating a snapshot of the root volume from %(image_id)s'

# Security group names
NAME_ENCRYPTOR_SECURITY_GROUP = 'Bracket Encryptor %(nonce)s'
DESCRIPTION_ENCRYPTOR_SECURITY_GROUP = (
    "Allows access to the encryptor's status server.")

# Encryptor instance names.
NAME_ENCRYPTOR = 'Bracket volume encryptor'
DESCRIPTION_ENCRYPTOR = \
    'Copies the root snapshot from %(image_id)s to a new encrypted volume'

# Snapshots names.
NAME_ORIGINAL_SNAPSHOT = 'Bracket encryptor original volume'
DESCRIPTION_ORIGINAL_SNAPSHOT = \
    'Original unencrypted root volume from %(image_id)s'
NAME_ENCRYPTED_ROOT_SNAPSHOT = 'Bracket encrypted root volume'
NAME_METAVISOR_ROOT_SNAPSHOT = 'Bracket system root'
NAME_METAVISOR_GRUB_SNAPSHOT = 'Bracket system GRUB'
NAME_METAVISOR_LOG_SNAPSHOT = 'Bracket system log'
DESCRIPTION_SNAPSHOT = 'Based on %(image_id)s'

# Tag names.
TAG_ENCRYPTOR = 'BrktEncryptor'
TAG_ENCRYPTOR_SESSION_ID = 'BrktEncryptorSessionID'
TAG_ENCRYPTOR_AMI = 'BrktEncryptorAMI'
TAG_DESCRIPTION = 'Description'

NAME_ENCRYPTED_IMAGE = '%(original_image_name)s %(encrypted_suffix)s'
NAME_ENCRYPTED_IMAGE_SUFFIX = '(encrypted %(nonce)s)'
DESCRIPTION_ENCRYPTED_IMAGE = (
    '%(original_image_description)s - based on %(image_id)s, '
    'encrypted by Bracket Computing'
)
DEFAULT_DESCRIPTION_ENCRYPTED_IMAGE = \
    'Based on %(image_id)s, encrypted by Bracket Computing'

SLEEP_ENABLED = True

# Right now this is the STAGE endpoint. We need to make this PROD
# when we have customers running this. This is superceded by the
# API_URL environment variable if it exists
API_URL = \
    "https://stage-api-lb-1316607304.us-west-2.elb.amazonaws.com"

log = None


class SnapshotError(Exception):
    def __init__(self, message):
        super(SnapshotError, self).__init__(message)


def _get_snapshot_progress_text(snapshots):
    elements = [
        '%s: %s' % (str(s.id), str(s.progress))
        for s in snapshots
    ]
    return ', '.join(elements)


def _sleep(seconds):
    if SLEEP_ENABLED:
        time.sleep(seconds)


def _wait_for_instance(
        aws_svc, instance_id, timeout=300, state='running'):
    """ Wait for up to timeout seconds for an instance to be in the
        'running' state.  Sleep for 2 seconds between checks.
    :return: The Instance object, or None if a timeout occurred
    """

    start_timestamp = time.time()

    log.debug(
        'Waiting for %s, timeout=%d, state=%s',
        instance_id, timeout, state)

    # Give the AWS some time to propagate the instance creation.
    # If we create and get immediately, AWS may return 400.  We'll fix
    # this properly for NUC-9311.
    _sleep(10)

    while True:
        if (time.time() - start_timestamp) > timeout:
            return None
        instance = aws_svc.get_instance(instance_id)
        log.debug('Instance %s state=%s', instance.id, instance.state)
        if instance.state == state:
            return instance
        if instance.state == 'error':
            raise Exception(
                'Instance %s is in an error state.  Cannot proceed.'
            )
        _sleep(2)


def _wait_for_encryptor_up(enc_svc, deadline):
    start = time.time()
    while not deadline.is_expired():
        if enc_svc.is_encryptor_up():
            log.debug(
                'Encyption service is up after %.1f seconds',
                time.time() - start
            )
            return
        _sleep(5)
    raise Exception('Unable to contact %s' % enc_svc.hostname)


def _wait_for_encryption(enc_svc):
    err_count = 0
    max_errs = 10
    while err_count < max_errs:
        try:
            status = enc_svc.get_status()
            err_count = 0
        except Exception as e:
            log.warn("Failed getting encryption status: %s", e)
            err_count += 1
            _sleep(10)
            continue

        log.debug('Encryption progress: %d%%', status['percent_complete'])
        state = status['state']
        if state == service.ENCRYPT_SUCCESSFUL:
            sys.stderr.write('\n')
            log.info('Encrypted root drive created.')
            return
        elif state == service.ENCRYPT_FAILED:
            raise Exception('Encryption failed')

        sys.stderr.write('.')
        sys.stderr.flush()
        _sleep(10)
    # We've failed to get encryption status for _max_errs_ consecutive tries.
    # Assume that the server has crashed.
    raise Exception('Encryption service unavailable')


def _get_encrypted_suffix():
    """ Return a suffix that will be appended to the encrypted image name.
    The suffix is in the format "(encrypted 787ace7a)".  The nonce portion of
    the suffix is necessary because Amazon requires image names to be unique.
    """
    nonce = make_nonce()
    return NAME_ENCRYPTED_IMAGE_SUFFIX % {'nonce': nonce}


def _get_encrypted_image_name(original_name, suffix=None):
    suffix = ' ' + (suffix or _get_encrypted_suffix())
    max_length = 128 - len(suffix)
    return original_name[:max_length] + suffix

def _get_encryptor_ami(region):
    api_url = os.environ.get('API_URL', API_URL)
    if not api_url:
        raise Exception('No API URL found')
    # This suppresses warnings about no `subjectAltName` for cert.
    # TODO: remove when the cert has subjectAltName
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        r = requests.get("%s/api/v1/encryptor_ami/%s" %
                         (api_url, region), verify="ca_cert.pem")
    if r.status_code not in (200,201):
        raise Exception('Getting encryptor ami gave response: %s', r.text)
    ami = r.json()['ami_id']
    if not ami:
        raise Exception('No AMI id returned.')
    return ami

def _wait_for_image(amazon_svc, image_id):
    log.debug('Waiting for %s to become available.', image_id)
    for i in range(180):
        _sleep(5)
        try:
            image = amazon_svc.get_image(image_id)
        except EC2ResponseError, e:
            if e.error_code == 'InvalidAMIID.NotFound':
                log.debug('AWS threw a NotFound, ignoring')
                continue
            else:
                log.warn('Unknown AWS error: %s', e)
        # These two attributes are optional in the response and only
        # show up sometimes. So we have to getattr them.
        reason = repr(getattr(image, 'stateReason', None))
        code = repr(getattr(image, 'code', None))
        log.debug("%s: %s reason: %s code: %s",
                  image.id, image.state, reason, code)
        if image.state == 'available':
            break
        if image.state == 'failed':
            raise Exception('Image state became failed')
    else:
        raise Exception(
            'Image failed to become available (%s)' % (image.state,))


def _wait_for_snapshots(svc, *snapshot_ids):
    log.debug('Waiting for status "completed" for %s', str(snapshot_ids))
    last_progress_log = time.time()

    # Give the AWS some time to propagate the snapshot creation.
    # If we create and get immediately, AWS may return 400.  We'll fix
    # this properly for NUC-9311.
    _sleep(20)

    while True:
        snapshots = svc.get_snapshots(*snapshot_ids)
        log.debug('%s', {s.id: s.status for s in snapshots})

        done = True
        error_ids = []
        for snapshot in snapshots:
            if snapshot.status == 'error':
                error_ids.append(snapshot.id)
            if snapshot.status != 'completed':
                done = False

        if error_ids:
            # Get rid of unicode markers in error the message.
            error_ids = [str(id) for id in error_ids]
            raise SnapshotError(
                'Snapshots in error state: %s.  Cannot continue.' %
                str(error_ids)
            )
        if done:
            return

        # Log progress if necessary.
        now = time.time()
        if now - last_progress_log > 60:
            log.info(_get_snapshot_progress_text(snapshots))
            last_progress_log = now

        _sleep(5)


def create_encryptor_security_group(svc):
    sg_name = NAME_ENCRYPTOR_SECURITY_GROUP % {'nonce': make_nonce()}
    sg_desc = DESCRIPTION_ENCRYPTOR_SECURITY_GROUP
    sg_id = svc.create_security_group(sg_name, sg_desc)
    log.info('Created temporary security group with id %s', sg_id)
    try:
        svc.add_security_group_rule(sg_id, ip_protocol='tcp',
                                    from_port=service.ENCRYPTOR_STATUS_PORT,
                                    to_port=service.ENCRYPTOR_STATUS_PORT,
                                    cidr_ip='0.0.0.0/0')
    except Exception as e:
        log.error('Failed adding security group rule to %s: %s', sg_id, e)
        try:
            log.info('Cleaning up temporary security group %s', sg_id)
            svc.delete_security_group(sg_id)
        except Exception as e2:
            log.warn('Failed deleting temporary security group: %s', e2)
        raise e
    try:
        svc.create_tags(sg_id)
    except Exception as e:
        log.error('Failed tagging security group %s: %s', sg_id, e)
    return sg_id


def run_copy_instance(aws_svc, encryptor_image_id, snapshot, root_size,
                      guest_image_id, sg_id):
    log.info('Launching encryptor instance with snapshot %s', snapshot)

    # Use gp2 for fast burst I/O copying root drive
    guest_unencrypted_root = EBSBlockDeviceType(
        volume_type='gp2',
        snapshot_id=snapshot,
        delete_on_termination=True)
    bdm = BlockDeviceMapping()
    bdm['/dev/sda4'] = guest_unencrypted_root

    # Use gp2 for fast burst I/O
    guest_encrypted_root = EBSBlockDeviceType(
        volume_type='gp2',
        delete_on_termination=True)

    guest_encrypted_root.size = 2 * root_size + 1
    bdm['/dev/sda5'] = guest_encrypted_root

    instance = aws_svc.run_instance(encryptor_image_id,
                                    security_group_ids=[sg_id],
                                    block_device_map=bdm)
    aws_svc.create_tags(
        instance.id,
        name=NAME_ENCRYPTOR,
        description=DESCRIPTION_ENCRYPTOR % {'image_id': guest_image_id}
    )
    instance = _wait_for_instance(aws_svc, instance.id)
    log.info('Launched encryptor instance %s', instance.id)
    return instance


def create_root_snapshot(aws_svc, ami):
    """ Launch the snapshotter instance, snapshot the root volume of the given
    AMI, and shut down the instance.

    :except SnapshotError if the snapshot goes into an error state
    """
    instance = aws_svc.run_instance(ami)
    log.info(
        'Launching instance %s to snapshot root disk for %s',
        instance.id, ami)
    aws_svc.create_tags(
        instance.id,
        name=NAME_SNAPSHOT_CREATOR,
        description=DESCRIPTION_SNAPSHOT_CREATOR % {'image_id': ami}
    )
    instance = _wait_for_instance(aws_svc, instance.id)

    log.info(
        'Stopping instance %s in order to create snapshot', instance.id)
    aws_svc.stop_instance(instance.id)
    _wait_for_instance(aws_svc, instance.id, state='stopped')

    # Snapshot root volume.
    root_dev = instance.root_device_name
    bdm = instance.block_device_mapping

    if root_dev not in bdm:
        # try stripping partition id
        root_dev = string.rstrip(root_dev, string.digits)
    root_vol = bdm[root_dev]
    vol = aws_svc.get_volume(root_vol.volume_id)
    snapshot = aws_svc.create_snapshot(
        vol.id,
        name=NAME_ORIGINAL_SNAPSHOT,
        description=DESCRIPTION_ORIGINAL_SNAPSHOT % {'image_id': ami}
    )
    log.info(
        'Creating snapshot %s of root volume for instance %s',
        snapshot.id, instance.id
    )
    _wait_for_snapshots(aws_svc, snapshot.id)

    # Terminate snapshotter instance.
    log.info(
        'Created snapshot %s.  Terminating instance %s',
        snapshot.id, instance.id
    )
    aws_svc.terminate_instance(instance.id)

    ret_values = (
        snapshot.id, root_dev, vol.size, root_vol.volume_type, root_vol.iops)
    log.debug('Returning %s', str(ret_values))
    return ret_values


def run(aws_svc, enc_svc_cls, image_id, encryptor_ami):
    copy_instance = None
    exit_status = 0
    ami = None
    snapshot_id = None
    sg_id = None

    try:
        snapshot_id, root_dev, size, vol_type, iops = create_root_snapshot(
            aws_svc, image_id
        )

        sg_id = create_encryptor_security_group(aws_svc)

        copy_instance = run_copy_instance(
            aws_svc, encryptor_ami, snapshot_id, size, image_id, sg_id
        )

        host_ip = copy_instance.ip_address
        enc_svc = enc_svc_cls(host_ip)
        log.info('Waiting for encryption service on %s at %s',
                 copy_instance.id, host_ip)
        _wait_for_encryptor_up(enc_svc, Deadline(600))
        log.info('Creating encrypted root drive.')
        _wait_for_encryption(enc_svc)
        log.info('Encrypted root drive is ready.')

        bdm = copy_instance.block_device_mapping

        # Create clean snapshots
        log.info('Stopping encryptor instance %s', copy_instance.id)
        aws_svc.stop_instance(copy_instance.id)

        description = DESCRIPTION_SNAPSHOT % {'image_id': image_id}

        # Snapshot volumes.
        snap_guest = aws_svc.create_snapshot(
            bdm['/dev/sda5'].volume_id,
            name=NAME_ENCRYPTED_ROOT_SNAPSHOT,
            description=description
        )
        snap_bsd = aws_svc.create_snapshot(
            bdm['/dev/sda2'].volume_id,
            name=NAME_METAVISOR_ROOT_SNAPSHOT,
            description=description
        )
        snap_grub = aws_svc.create_snapshot(
            bdm['/dev/sda1'].volume_id,
            name=NAME_METAVISOR_GRUB_SNAPSHOT,
            description=description
        )
        snap_log = aws_svc.create_snapshot(
            bdm['/dev/sda3'].volume_id,
            name=NAME_METAVISOR_LOG_SNAPSHOT,
            description=description
        )

        log.info(
            'Creating snapshots for the new encrypted AMI: %s, %s, %s, %s',
            snap_guest.id, snap_bsd.id, snap_grub.id, snap_log.id)

        _wait_for_snapshots(
            aws_svc, snap_guest.id, snap_bsd.id, snap_grub.id, snap_log.id)

        # Set up new Block Device Mappings
        log.debug('Creating block device mapping')
        new_bdm = BlockDeviceMapping()
        dev_grub = EBSBlockDeviceType(volume_type='gp2',
                                      snapshot_id=snap_grub.id,
                                      delete_on_termination=True)
        dev_root = EBSBlockDeviceType(volume_type='gp2',
                                      snapshot_id=snap_bsd.id,
                                      delete_on_termination=True)
        dev_log = EBSBlockDeviceType(volume_type='gp2',
                                     snapshot_id=snap_log.id,
                                     delete_on_termination=True)
        if vol_type == '':
            vol_type = 'standard'
        dev_guest_root = EBSBlockDeviceType(volume_type=vol_type,
                                            snapshot_id=snap_guest.id,
                                            iops=iops,
                                            delete_on_termination=True)
        new_bdm['/dev/sda1'] = dev_grub
        new_bdm['/dev/sda2'] = dev_root
        new_bdm['/dev/sda3'] = dev_log
        new_bdm['/dev/sda5'] = dev_guest_root

        i = 0
        # Just attach 4 ephemeral drives
        # XXX Should get ephemeral drives from guest AMI (e.g. Centos 6.6)
        for drive in ['/dev/sdb', '/dev/sdc', '/dev/sdd', '/dev/sde']:
            t = BlockDeviceType()
            t.ephemeral_name = 'ephemeral%d' % (i,)
            i += 1
            new_bdm[drive] = t

        log.debug('Getting image %s', image_id)
        image = aws_svc.get_image(image_id)
        if image is None:
            raise Exception("Can't find image %s" % image_id)
        avatar_image = aws_svc.get_image(encryptor_ami)
        if avatar_image is None:
            raise Exception("Can't find image %s" % encryptor_ami)

        # Register the new AMI.
        name = _get_encrypted_image_name(image.name)
        if image.description:
            description = DESCRIPTION_ENCRYPTED_IMAGE % {
                'original_image_description': image.description,
                'image_id': image_id
            }
        else:
            description = DEFAULT_DESCRIPTION_ENCRYPTED_IMAGE % {
                'image_id': image_id
            }

        try:
            ami = aws_svc.register_image(
                name=name,
                description=description,
                kernel_id=avatar_image.kernel_id,
                block_device_map=new_bdm
            )
            log.info('Registered AMI %s based on the snapshots.', ami)
            aws_svc.create_tags(ami)
        except EC2ResponseError, e:
            # Sometimes register_image fails with an InvalidAMIID.NotFound
            # error and a message like "The image id '[ami-f9fcf3c9]' does not
            # exist".  In that case, just go ahead with that AMI id. We'll
            # wait for it to be created later (in wait_for_image).
            log.info(
                'Attempting to recover from image registration error: %s', e)
            if e.error_code == 'InvalidAMIID.NotFound':
                # pull the AMI ID out of the exception message if we can
                m = re.search('ami-[a-f0-9]{8}', e.message)
                if m:
                    ami = m.group(0)
                    log.info('Recovered with AMI ID %s', ami)
            if not ami:
                raise

        _wait_for_image(aws_svc, ami)
        log.info('Created encrypted AMI %s based on %s', ami, image_id)
    except Exception:
        # TODO: Better exception handling
        log.exception('Aborting')
        exit_status = 1

    if copy_instance:
        log.info('Terminating encryptor instance %s', copy_instance.id)
        aws_svc.terminate_instance(copy_instance.id)

    if sg_id:
        log.info('Deleting temporary security group %s', sg_id)
        try:
            _wait_for_instance(aws_svc, copy_instance.id, state='terminated')
            aws_svc.delete_security_group(sg_id)
        except Exception as e:
            log.warn('Failed deleting security group %s: %s', sg_id, e)

    if snapshot_id:
        log.info('Deleting snapshot copy of original root volume %s',
                 snapshot_id)
        aws_svc.delete_snapshot(snapshot_id)

    log.info('Done.')
    if ami:
        # Print the AMI ID to stdout, in case the caller wants to process
        # the output.  Log messages go to stderr.
        print(ami)

    return exit_status


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-v',
        '--verbose',
        dest='verbose',
        action='store_true',
        help='Print status information to the console'
    )

    subparsers = parser.add_subparsers()

    encrypt_ami = subparsers.add_parser('encrypt-ami')
    encrypt_ami.add_argument(
        'ami',
        metavar='AMI_ID',
        help='The AMI that will be encrypted'
    )
    # Require the caller to specify the Avatar AMI ID until NUC-9085 is fixed.
    encrypt_ami.add_argument(
        '--encryptor-ami',
        metavar='ID',
        dest='encryptor_ami',
        help='Bracket Encryptor AMI',
        required=False
    )
    encrypt_ami.add_argument(
        '--key',
        metavar='NAME',
        help='EC2 SSH Key Pair name',
        dest='key_name',
        required=True
    )
    encrypt_ami.add_argument(
        '--validate-ami',
        dest='no_validate_ami',
        action='store_true',
        help="Validate AMI properties (default)"
    )
    encrypt_ami.add_argument(
        '--no-validate-ami',
        dest='no_validate_ami',
        action='store_false',
        help="Don't validate AMI properties"
    )
    encrypt_ami.add_argument(
        '--region',
        metavar='NAME',
        help='AWS region (e.g. us-west-2)',
        dest='region',
        required=True
    )

    argv = sys.argv[1:]
    values = parser.parse_args(argv)
    region = values.region

    # Initialize logging.  Log messages are written to stderr and are
    # prefixed with a compact timestamp, so that the user knows how long
    # each operation took.
    if values.verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%H:%M:%S')
    global log
    log = logging.getLogger(__name__)
    log.setLevel(log_level)
    service.log.setLevel(log_level)

    # Validate the region.
    regions = [str(r.name) for r in boto.vpc.regions()]
    if region not in regions:
        print(
            'Invalid region %s.  Must be one of %s.' %
            (region, str(regions)),
            file=sys.stderr
        )
        return 1

    encryptor_ami = values.encryptor_ami
    if not encryptor_ami:
        try:
            encryptor_ami = _get_encryptor_ami(region)
        except:
            log.exception('Failed to get encryptor AMI.')
            return 1

    session_id = uuid.uuid4().hex
    default_tags = {
        TAG_ENCRYPTOR: True,
        TAG_ENCRYPTOR_SESSION_ID: session_id,
        TAG_ENCRYPTOR_AMI: encryptor_ami
    }

    # Connect to AWS.
    aws_svc = service.AWSService(
        session_id, encryptor_ami, default_tags=default_tags)
    aws_svc.connect(values.key_name, region)

    if not values.no_validate_ami:
        error = aws_svc.validate_guest_ami(values.ami)
        if error:
            print(error, file=sys.stderr)
            return 1

        error = aws_svc.validate_encryptor_ami(encryptor_ami)
        if error:
            print(error, file=sys.stderr)
            return 1

    log.info('Starting encryptor session %s', aws_svc.session_id)
    run(
        aws_svc=aws_svc,
        enc_svc_cls=service.EncryptorService,
        image_id=values.ami,
        encryptor_ami=encryptor_ami
    )

if __name__ == '__main__':
    exit_status = main()
    exit(exit_status)
