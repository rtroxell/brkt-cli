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
Create an encrypted AMI based on an existing unencrypted AMI.

Overview of the process:
    * Start an instance based on the unencrypted AMI.
    * Snapshot the root volume of the unencrypted instance.
    * Terminate the instance.
    * Start a Bracket Encryptor instance.
    * Attach the unencrypted root volume to the Encryptor instance.
    * The Bracket Encryptor copies the unencrypted root volume to a new
        encrypted volume that's 2x the size of the original.
    * Snapshot the Bracket Encryptor system volumes and the new encrypted
        root volume.
    * Create a new AMI based on the snapshots.
    * Terminate the Bracket Encryptor instance.
    * Delete the unencrypted snapshot.

Before running brkt encrypt-ami, set the AWS_ACCESS_KEY_ID and
AWS_SECRET_ACCESS_KEY environment variables, like you would when
running the AWS command line utility.
"""
from __future__ import print_function

import argparse
import boto
import boto.ec2
import boto.vpc
import logging
import os
import re
import datetime
import requests
import string
import sys
import tempfile
import time
import uuid
import warnings

from boto.exception import EC2ResponseError, NoAuthHandlerFound
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
    "Allows access to the encryption service.")

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
NAME_ENCRYPTED_IMAGE_SUFFIX = ' (encrypted %(nonce)s)'
SUFFIX_ENCRYPTED_IMAGE = (
    ' - based on %(image_id)s, encrypted by Bracket Computing'
)
DEFAULT_DESCRIPTION_ENCRYPTED_IMAGE = \
    'Based on %(image_id)s, encrypted by Bracket Computing'

SLEEP_ENABLED = True

EVENTUAL_CONSISTENCY_TIMEOUT = 10

# Right now this is the STAGE endpoint. We need to make this PROD
# when we have customers running this. This is superceded by the
# API_URL environment variable if it exists
API_URL = \
    "https://stage-api-lb-1316607304.us-west-2.elb.amazonaws.com"

log = None


class SnapshotError(Exception):
    pass


def _get_snapshot_progress_text(snapshots):
    elements = [
        '%s: %s' % (str(s.id), str(s.progress))
        for s in snapshots
    ]
    return ', '.join(elements)


def _sleep(seconds):
    if SLEEP_ENABLED:
        time.sleep(seconds)


def _safe_get_instance(aws_svc, instance_id):
    """ Get the instance and handle AWS eventual consistency lag.
    """
    deadline = Deadline(EVENTUAL_CONSISTENCY_TIMEOUT)
    instance = None
    while instance is None:
        try:
            instance = aws_svc.get_instance(instance_id)
        except EC2ResponseError as e:
            if e.error_code == 'InvalidInstanceID.NotFound':
                log.debug('Instance was not found.  Sleeping.')
                _sleep(2)
            else:
                raise
        if deadline.is_expired():
            raise Exception('Invalid instance id: ' + instance_id)
    return instance


def _wait_for_instance(
        aws_svc, instance_id, timeout=300, state='running'):
    """ Wait for up to timeout seconds for an instance to be in the
        'running' state.  Sleep for 2 seconds between checks.
    :return: The Instance object, or None if a timeout occurred
    """

    log.debug(
        'Waiting for %s, timeout=%d, state=%s',
        instance_id, timeout, state)

    # Wait for AWS eventual consistency to catch up.
    instance = _safe_get_instance(aws_svc, instance_id)
    deadline = Deadline(timeout)
    while not deadline.is_expired():
        log.debug('Instance %s state=%s', instance.id, instance.state)
        if instance.state == state:
            return instance
        if instance.state == 'error':
            raise Exception(
                'Instance %s is in an error state.  Cannot proceed.'
            )
        _sleep(2)
        instance = aws_svc.get_instance(instance_id)
    raise Exception(
        'Timed out waiting for %s to be in the %s state' %
        (instance_id, state)
    )


def _wait_for_encryptor_up(enc_svc, deadline):
    start = time.time()
    while not deadline.is_expired():
        if enc_svc.is_encryptor_up():
            log.debug(
                'Encryption service is up after %.1f seconds',
                time.time() - start
            )
            return
        _sleep(5)
    raise Exception('Unable to contact %s' % enc_svc.hostname)


def _get_encryption_progress_message(start_time, percent_complete, now=None):
    msg = 'Encryption is %d%% complete' % percent_complete
    if percent_complete > 0:
        remaining = util.estimate_seconds_remaining(
            start_time, percent_complete)
        msg += (
            ', %s remaining' % datetime.timedelta(seconds=int(remaining))
        )
    return msg


class EncryptionError(Exception):
    def __init__(self, message):
        super(EncryptionError, self).__init__(message)
        self.console_output_file = None


def _wait_for_encryption(enc_svc):
    err_count = 0
    max_errs = 10
    start_time = time.time()
    last_progress_log = start_time

    while err_count < max_errs:
        try:
            status = enc_svc.get_status()
            err_count = 0
        except Exception as e:
            log.warn("Failed getting encryption status: %s", e)
            err_count += 1
            _sleep(10)
            continue

        state = status['state']
        percent_complete = status['percent_complete']
        log.debug('state=%s, percent_complete=%d', state, percent_complete)

        # Log progress once a minute.
        now = time.time()
        if now - last_progress_log >= 60:
            msg = _get_encryption_progress_message(
                start_time, percent_complete)
            log.info(msg)
            last_progress_log = now

        if state == service.ENCRYPT_SUCCESSFUL:
            log.info('Encrypted root drive created.')
            return
        elif state == service.ENCRYPT_FAILED:
            raise EncryptionError('Encryption failed')

        _sleep(10)
    # We've failed to get encryption status for _max_errs_ consecutive tries.
    # Assume that the server has crashed.
    raise EncryptionError('Encryption service unavailable')


def _get_encrypted_suffix():
    """ Return a suffix that will be appended to the encrypted image name.
    The suffix is in the format "(encrypted 787ace7a)".  The nonce portion of
    the suffix is necessary because Amazon requires image names to be unique.
    """
    return NAME_ENCRYPTED_IMAGE_SUFFIX % {'nonce': make_nonce()}


def _append_suffix(name, suffix, max_length=None):
    """ Append the suffix to the given name.  If the appended length exceeds
    max_length, truncate the name to make room for the suffix.

    :return: The possibly truncated name with the suffix appended
    """
    if not suffix:
        return name
    if max_length:
        truncated_length = max_length - len(suffix)
        name = name[:truncated_length]
    return name + suffix


def _get_encryptor_ami(region):
    api_url = os.environ.get('API_URL', API_URL)
    if not api_url:
        raise Exception('No API URL found')
    # This suppresses warnings about no `subjectAltName` for cert.
    # TODO: remove when the cert has subjectAltName
    cert = os.path.join(os.path.dirname(__file__), 'assets', 'ca_cert.pem')
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        r = requests.get("%s/api/v1/encryptor_ami/%s" %
                         (api_url, region),
                         verify=cert)
    if r.status_code not in (200, 201):
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

    # Give AWS some time to propagate the snapshot creation.
    # If we create and get immediately, AWS may return 400.
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


def _wait_for_security_group(aws_svc, sg_id):
    log.debug('Waiting for security group %s', sg_id)
    deadline = Deadline(EVENTUAL_CONSISTENCY_TIMEOUT)
    while not deadline.is_expired():
        try:
            return aws_svc.get_security_group(sg_id)
        except EC2ResponseError as e:
            if e.error_code == 'InvalidGroup.NotFound':
                _sleep(2)
            else:
                raise
    raise Exception('Timed out waiting for security group ' + sg_id)


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

    _wait_for_security_group(svc, sg_id)
    svc.create_tags(sg_id)
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
    _safe_get_instance(aws_svc, instance.id)
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
    _safe_get_instance(aws_svc, instance.id)
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


def _write_console_output(aws_svc, instance_id):

    try:
        console_output = aws_svc.get_console_output(instance_id)
        if console_output.output:
            prefix = instance_id + '-'
            with tempfile.NamedTemporaryFile(
                    prefix=prefix, suffix='.log', delete=False) as t:
                t.write(console_output.output)
            return t
    except:
        log.exception('Unable to write console output')

    return None


def run(aws_svc, enc_svc_cls, image_id, encryptor_ami):
    encryptor_instance = None
    ami = None
    snapshot_id = None
    sg_id = None

    try:
        snapshot_id, root_dev, size, vol_type, iops = create_root_snapshot(
            aws_svc, image_id
        )

        sg_id = create_encryptor_security_group(aws_svc)

        encryptor_instance = run_copy_instance(
            aws_svc, encryptor_ami, snapshot_id, size, image_id, sg_id
        )

        host_ip = encryptor_instance.ip_address
        enc_svc = enc_svc_cls(host_ip)
        log.info('Waiting for encryption service on %s at %s',
                 encryptor_instance.id, host_ip)
        _wait_for_encryptor_up(enc_svc, Deadline(600))
        log.info('Creating encrypted root drive.')
        try:
            _wait_for_encryption(enc_svc)
        except EncryptionError as e:
            log.error(
                'Encryption failed.  Check console output of instance %s '
                'for details.',
                encryptor_instance.id
            )

            e.console_output_file = _write_console_output(
                aws_svc, encryptor_instance.id)
            if e.console_output_file:
                log.error(
                    'Wrote console output for instance %s to %s',
                    encryptor_instance.id,
                    e.console_output_file.name
                )
            else:
                log.error(
                    'Console output for instance %s is not available.',
                    encryptor_instance.id
                )
            raise e

        log.info('Encrypted root drive is ready.')

        bdm = encryptor_instance.block_device_mapping

        # Create clean snapshots
        log.info('Stopping encryptor instance %s', encryptor_instance.id)
        aws_svc.stop_instance(encryptor_instance.id)

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
        encryptor_image = aws_svc.get_image(encryptor_ami)
        if encryptor_image is None:
            raise Exception("Can't find image %s" % encryptor_ami)

        # Register the new AMI.
        name = _append_suffix(
            image.name, _get_encrypted_suffix(), max_length=128)
        if image.description:
            suffix = SUFFIX_ENCRYPTED_IMAGE % {'image_id': image_id}
            description = _append_suffix(
                image.description, suffix, max_length=255)
        else:
            description = DEFAULT_DESCRIPTION_ENCRYPTED_IMAGE % {
                'image_id': image_id
            }

        try:
            ami = aws_svc.register_image(
                name=name,
                description=description,
                kernel_id=encryptor_image.kernel_id,
                block_device_map=new_bdm
            )
            log.info('Registered AMI %s based on the snapshots.', ami)
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
        aws_svc.create_tags(ami)
        log.info('Created encrypted AMI %s based on %s', ami, image_id)
    finally:
        if encryptor_instance:
            try:
                log.info(
                    'Terminating encryptor instance %s',
                    encryptor_instance.id
                )
                aws_svc.terminate_instance(encryptor_instance.id)
                pass
            except Exception as e:
                log.warn(
                    'Could not terminate instance %s: %s',
                    encryptor_instance,
                    e
                )
                # Don't wait for instance later if we couldn't terminate it.
                encryptor_instance = None

        if sg_id:
            try:
                if encryptor_instance:
                    log.info(
                        'Waiting for instance %s to terminate.',
                        encryptor_instance.id
                    )
                    _wait_for_instance(
                        aws_svc, encryptor_instance.id, state='terminated')
                log.info('Deleting temporary security group %s', sg_id)
                aws_svc.delete_security_group(sg_id)
            except Exception as e:
                log.warn('Failed deleting security group %s: %s', sg_id, e)

        if snapshot_id:
            try:
                log.info('Deleting snapshot copy of original root volume %s',
                         snapshot_id)
                aws_svc.delete_snapshot(snapshot_id)
            except Exception as e:
                log.warn('Could not delete snapshot %s: %s', snapshot_id, e)

    log.info('Done.')
    return ami


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
        # Boto logs auth errors and 401s at ERROR level by default.
        boto.log.setLevel(logging.FATAL)
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

    try:
        # Connect to AWS.
        aws_svc = service.AWSService(
            session_id, encryptor_ami, default_tags=default_tags)
        aws_svc.connect(values.key_name, region)
    except NoAuthHandlerFound:
        msg = (
            'Unable to connect to AWS.  Are your AWS_ACCESS_KEY_ID and '
            'AWS_SECRET_ACCESS_KEY environment variables set?'
        )
        if values.verbose:
            log.exception(msg)
        else:
            log.error(msg)
        return 1

    try:
        aws_svc.get_key_pair(values.key_name)
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

        encrypted_image_id = run(
            aws_svc=aws_svc,
            enc_svc_cls=service.EncryptorService,
            image_id=values.ami,
            encryptor_ami=encryptor_ami
        )
        # Print the AMI ID to stdout, in case the caller wants to process
        # the output.  Log messages go to stderr.
        print(encrypted_image_id)
        return 0
    except EC2ResponseError as e:
        if e.error_code == 'AuthFailure':
            msg = 'Check your AWS login credentials and permissions'
            if values.verbose:
                log.exception(msg)
            else:
                log.error(msg + ': ' + e.error_message)
        elif e.error_code == 'InvalidKeyPair.NotFound':
            if values.verbose:
                log.exception(e.error_message)
            else:
                log.error(e.error_message)
        elif e.error_code == 'UnauthorizedOperation':
            if values.verbose:
                log.exception(e.error_message)
            else:
                log.error(e.error_message)
            log.error(
                'Unauthorized operation.  Check the IAM policy for your '
                'AWS account.'
            )
        else:
            raise
    return 1

if __name__ == '__main__':
    exit_status = main()
    exit(exit_status)
