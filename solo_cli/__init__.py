#!/usr/bin/env python
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
import sys
import time
import string
import re
import uuid

from boto.exception import EC2ResponseError
from boto.ec2.blockdevicemapping import (BlockDeviceMapping,
        BlockDeviceType, EBSBlockDeviceType)

# End user-visible terminology.  These are resource names and descriptions
# that the user will see in his or her EC2 console.

# Instance names.
from solo_cli.service import Service

NAME_SNAPSHOT_CREATOR = 'Bracket root snapshot creator'
NAME_ENCRYPTOR = 'Bracket image encryptor'

# Snapshot names.
NAME_ORIGINAL_SNAPSHOT = 'Bracket encryptor original volume'
NAME_ENCRYPTED_ROOT_SNAPSHOT = 'Bracket encrypted root volume'
NAME_METAVISOR_ROOT_SNAPSHOT = 'Bracket system root'
NAME_METAVISOR_GRUB_SNAPSHOT = 'Bracket system GRUB'
NAME_METAVISOR_LOG_SNAPSHOT = 'Bracket system log'
NAME_ENCRYPTED_AMI = 'Bracket encrypted AMI'

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


def wait_for_snapshots(svc, *snapshot_ids):
    log.debug('Waiting for status "completed" for %s', str(snapshot_ids))
    last_progress_log = time.time()

    # Give the AWS some time to propagate the snapshot creation.
    # If we create and get immediately, AWS may return 400.  We'll fix
    # this properly for NUC-9311.
    time.sleep(20)

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

        time.sleep(5)


def run_copy_instance(svc, ami, snapshot, root_size):
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

    instance = svc.run_instance(ami, block_device_map=bdm)
    svc.create_tags(instance.id, name='Bracket volume encryptor')
    instance = svc.wait_for_instance(instance.id)
    log.info('Launched encryptor instance %s', instance.id)
    return instance


def create_root_snapshot(svc, ami):
    """ Launch the snapshotter instance, snapshot the root volume of the given
    AMI, and shut down the instance.

    :except SnapshotError if the snapshot goes into an error state
    """
    instance = svc.run_instance(ami)
    log.info(
        'Launching instance %s to snapshot root disk for %s',
        instance.id, ami)
    svc.create_tags(instance.id, NAME_SNAPSHOT_CREATOR)
    instance = svc.wait_for_instance(instance.id)

    log.info(
        'Stopping instance %s in order to create snapshot', instance.id)
    svc.stop_instance(instance.id)

    # Snapshot root volume.
    root_dev = svc.get_instance_attribute(instance.id, 'rootDeviceName')
    bdm = svc.get_instance_attribute(instance.id, 'blockDeviceMapping')
    if root_dev not in bdm:
        # try stripping partition id
        root_dev = string.rstrip(root_dev, string.digits)
    root_vol = bdm[root_dev]
    vol = svc.get_volume(root_vol.volume_id)
    snapshot = svc.create_snapshot(
        vol.id,
        name=NAME_ORIGINAL_SNAPSHOT,
        description='Original unencrypted root volume from ' + ami
    )
    log.info(
        'Creating snapshot %s of root volume for instance %s',
        snapshot.id, instance.id
    )
    wait_for_snapshots(svc, snapshot.id)

    # Terminate snapshotter instance.
    log.info(
        'Created snapshot %s.  Terminating instance %s',
        snapshot.id, instance.id
    )
    svc.terminate_instance(instance.id, wait=False)

    ret_values = (
        snapshot.id, root_dev, vol.size, root_vol.volume_type, root_vol.iops)
    log.debug('Returning %s', str(ret_values))
    return ret_values


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
        dest='avatar_ami',
        help='Bracket Encryptor AMI',
        required=True
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

    session_id = uuid.uuid4().hex
    avatar_ami = values.avatar_ami

    # Validate the region.
    regions = [str(r.name) for r in boto.vpc.regions()]
    if region not in regions:
        print(
            'Invalid region %s.  Must be one of %s.' %
            (region, str(regions)),
            file=sys.stderr
        )
        return 1

    # Connect to AWS.
    svc = Service(session_id, avatar_ami)
    svc.connect(values.key_name, region)

    if not values.no_validate_ami:
        error = svc.validate_guest_ami(values.ami)
        if error:
            print(error, file=sys.stderr)
            return 1

        error = svc.validate_avatar_ami(avatar_ami)
        if error:
            print(error, file=sys.stderr)
            return 1

    log.info('Starting encryptor session %s', session_id)

    copy_instance = None
    exit_status = 0
    ami = None
    snapshot_id = None

    try:
        snapshot_id, root_dev, size, vol_type, iops = create_root_snapshot(
            svc, values.ami
        )

        copy_instance = run_copy_instance(svc, avatar_ami, snapshot_id, size)

        host_ip = copy_instance.ip_address
        log.info('Waiting for ssh to %s at %s', copy_instance.id, host_ip)
        svc.wait_for_encryptor_up(host_ip)

        # Now Wait for the guest root to be created
        # Currently copying at around ~15 MB/sec
        log.info('Creating encrypted root drive.')
        while True:
            try:
                out = svc.get_seed_yaml(host_ip)
                if re.search('avatar_solo_created: true', out):
                    sys.stderr.write('\n')
                    log.info('Encrypted root drive created.')
                    break
                sys.stderr.write('.')
                sys.stderr.flush()
                time.sleep(10)
            except Exception:
                # TODO: Need to handle exception more gracefully
                log.exception('Waiting for guest install')
                time.sleep(10)

        bdm = svc.get_instance_attribute(
            copy_instance.id, 'blockDeviceMapping')

        # Create clean snapshots
        log.info('Stopping encryptor instance %s', copy_instance.id)
        svc.stop_instance(copy_instance.id)

        description = 'Based on ' + values.ami

        # Snapshot volumes.
        snap_guest = svc.create_snapshot(
            bdm['/dev/sda5'].volume_id,
            name=NAME_ENCRYPTED_ROOT_SNAPSHOT,
            description=description
        )
        snap_bsd = svc.create_snapshot(
            bdm['/dev/sda2'].volume_id,
            name=NAME_METAVISOR_ROOT_SNAPSHOT,
            description=description
        )
        snap_grub = svc.create_snapshot(
            bdm['/dev/sda1'].volume_id,
            name=NAME_METAVISOR_GRUB_SNAPSHOT,
            description=description
        )
        snap_log = svc.create_snapshot(
            bdm['/dev/sda3'].volume_id,
            name=NAME_METAVISOR_LOG_SNAPSHOT,
            description=description
        )

        log.info(
            'Creating snapshots for the new encrypted AMI: %s, %s, %s, %s',
            snap_guest.id, snap_bsd.id, snap_grub.id, snap_log.id)

        wait_for_snapshots(
            svc, snap_guest.id, snap_bsd.id, snap_grub.id, snap_log.id)

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

        log.debug('Getting image %s', values.ami)
        image = svc.get_image(values.ami)
        if image is None:
            raise Exception("Can't find image %s" % values.ami)
        avatar_image = svc.get_image(avatar_ami)
        if avatar_image is None:
            raise Exception("Can't find image %s" % avatar_ami)

        name = 'Bracket_%s_%d' % (image.name, time.time())
        if image.description:
            description = 'Bracket: ' + image.description
        else:
            description = name

        try:
            name = '%s based on %s' % (NAME_ENCRYPTED_AMI, values.ami)
            ami = svc.register_image(
                name=name,
                description=description,
                kernel_id=avatar_image.kernel_id,
                block_device_map=new_bdm
            )
            log.info('Registered AMI %s based on the snapshots.', ami)
            svc.create_tags(ami, name)
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

        svc.wait_for_image(ami)
        log.info('Created encrypted AMI %s based on %s', ami, values.ami)
    except Exception:
        # TODO: Better exception handling
        log.exception('Aborting')
        exit_status = 1

    if copy_instance:
        log.info('Terminating encryptor instance %s', copy_instance.id)
        svc.terminate_instance(copy_instance.id, wait=False)

    if snapshot_id:
        log.info('Deleting snapshot copy of original root volume %s',
                 snapshot_id)
        svc.delete_snapshot(snapshot_id)

    log.info('Done.')
    if ami:
        # Print the AMI ID to stdout, in case the caller wants to process
        # the output.  Log messages go to stderr.
        print(ami)

    return exit_status


if __name__ == '__main__':
    exit_status = main()
    sys.exit(exit_status)
