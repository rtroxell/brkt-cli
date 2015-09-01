import logging
import subprocess
import time
import boto
from boto.exception import EC2ResponseError

PLATFORM_WINDOWS = 'windows'

sshflags = " ".join([
    "-o UserKnownHostsFile=/dev/null",
    "-o LogLevel=quiet",
    "-o StrictHostKeyChecking=no",
    "-o ConnectTimeout=5",
])

log = logging.getLogger(__name__)


def _ssh(user, external_ip, sshcommand):
    command = 'ssh %s %s@%s "%s"' % (sshflags, user, external_ip, sshcommand)
    log.debug(command)
    return subprocess.check_output(command, shell=True)


class Service(object):

    def __init__(self, encryptor_session_id, encryptor_ami, default_tags=None):
        self.session_id = encryptor_session_id
        self.encryptor_ami = encryptor_ami
        self.default_tags = default_tags or {}

        # These will be initialized by connect().
        self.key_name = None
        self.region = None
        self.conn = None

    def connect(self, key_name, region):
        self.key_name = key_name
        self.region = region
        self.conn = boto.vpc.connect_to_region(region)

    @staticmethod
    def get_seed_yaml(hostname):
        for _ in range(20):
            try:
                return _ssh('avatar', hostname, 'cat /etc/brkt/seed.yaml')
            except subprocess.CalledProcessError as e:
                time.sleep(1)
        else:
            raise e

    @staticmethod
    def wait_for_encryptor_up(hostname):
        st = time.time()
        time.sleep(60)
        for i in range(60):
            try:
                _ssh('avatar', hostname, 'ls')
                break
            except subprocess.CalledProcessError:
                time.sleep(10)
        else:
            raise Exception('Unable to contact %s' % hostname)
        et = time.time()
        log.debug('Host is ssh-able now after %.1f seconds', (et - st))

    def wait_for_instance(
            self, instance_id, timeout=300, state='running'):
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
        time.sleep(10)

        while True:
            if (time.time() - start_timestamp) > timeout:
                return None
            instance = self.conn.get_only_instances(
                instance_ids=[instance_id])[0]
            log.debug('Instance %s state=%s', instance.id, instance.state)
            if instance.state == state:
                return instance
            if instance.state == 'error':
                raise Exception(
                    'Instance %s is in an error state.  Cannot proceed.'
                )
            time.sleep(2)

    def run_instance(self,
                     image_id,
                     instance_type='m3.medium',
                     block_device_map=None):
        log.debug('Starting a new instance based on %s', image_id)
        try:
            reservation = self.conn.run_instances(
                image_id=image_id,
                key_name=self.key_name,
                instance_type=instance_type,
                block_device_map=block_device_map
            )
            return reservation.instances[0]
        except EC2ResponseError, e:
            # Log the failed operation, so that the user has context.
            log.error('Unable to launch instance for %s', image_id)
            raise

    def create_tags(self, resource_id, name=None, description=None):
        tags = dict(self.default_tags)
        if name:
            tags['Name'] = name
        if description:
            tags['Description'] = description
        log.debug('Tagging %s with %s', resource_id, tags)
        self.conn.create_tags([resource_id], tags)

    def stop_instance(self, instance_id, wait=True):
        log.debug('Stopping instance %s', instance_id)
        instances = self.conn.stop_instances([instance_id])
        if wait:
            return self.wait_for_instance(instance_id, state='stopped')
        else:
            return instances[0]

    def terminate_instance(self, instance_id, wait=True):
        log.debug('Terminating instance %s', instance_id)
        instances = self.conn.terminate_instances([instance_id])
        if wait:
            return self.wait_for_instance(instance_id, state='terminated')
        else:
            return instances[0]

    def get_instance_attribute(self, instance_id, attribute):
        return self.conn.get_instance_attribute(
            instance_id=instance_id,
            attribute=attribute
        )[attribute]

    def get_volume(self, volume_id):
        return self.conn.get_all_volumes(volume_ids=[volume_id])[0]

    def get_snapshots(self, *snapshot_ids):
        return self.conn.get_all_snapshots(snapshot_ids)

    def get_snapshot(self, snapshot_id):
        return self.conn.get_all_snapshots([snapshot_id])[0]

    def create_snapshot(self, volume_id, name=None, description=None):
        snapshot = self.conn.create_snapshot(volume_id, description)
        self.create_tags(snapshot.id, name=name)
        return snapshot

    def copy_snapshot(self, snapshot_id, name=None, description=None):
        new_snapshot_id = self.conn.copy_snapshot(
            self.region, snapshot_id, description=description)
        self.create_tags(new_snapshot_id, name=name)
        return self.get_snapshot(new_snapshot_id)

    def delete_volume(self, volume_id):
        return self.conn.delete_volume(volume_id)

    def validate_guest_ami(self, ami_id):
        try:
            images = self.conn.get_all_images([ami_id])
        except EC2ResponseError, e:
            return e.error_message
        if len(images) == 0:
            return '%s is no longer available' % ami_id
        image = images[0]

        # Amazon's API only returns 'windows' or nothing.  We're not currently
        # able to detect individual Linux distros.
        if image.platform == PLATFORM_WINDOWS:
            return '%s is not a supported platform for %s' % (
                PLATFORM_WINDOWS, ami_id)

        if image.root_device_type != 'ebs':
            return '%s does not use EBS storage.' % ami_id
        if image.hypervisor != 'xen':
            return '%s uses hypervisor %s.  Only xen is supported' % (
                ami_id, image.hypervisor)
        return None

    def validate_encryptor_ami(self, ami_id):
        try:
            images = self.conn.get_all_images([ami_id])
        except EC2ResponseError, e:
            return e.error_message
        if len(images) == 0:
            return 'Bracket encryptor image %s is no longer available' % ami_id
        image = images[0]
        if 'brkt-avatar' not in image.name:
            return '%s (%s) is not a Bracket Encryptor image' % (
                ami_id, image.name)
        return None

    def register_image(self,
                       kernel_id,
                       block_device_map,
                       name=None,
                       description=None):
        log.debug('Registering image.')
        return self.conn.register_image(
            name=name,
            description=description,
            architecture='x86_64',
            kernel_id=kernel_id,
            root_device_name='/dev/sda1',
            block_device_map=block_device_map,
            virtualization_type='paravirtual'
        )

    def wait_for_image(self, image_id):
        log.debug('Waiting for %s to become available.', image_id)
        for i in range(180):
            time.sleep(5)
            try:
                image = self.conn.get_all_images([image_id])[0]
            except EC2ResponseError, e:
                if e.error_code == 'InvalidAMIID.NotFound':
                    log.debug('AWS threw a NotFound, ignoring')
                    continue
                else:
                    log.warn('Unknown AWS error: %s', str(e))
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

    def get_image(self, image_id):
        return self.conn.get_image(image_id)

    def delete_snapshot(self, snapshot_id):
        return self.conn.delete_snapshot(snapshot_id)
