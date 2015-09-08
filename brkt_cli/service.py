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

import abc
import boto
import logging
import json
import urllib2

from boto.exception import EC2ResponseError

ENCRYPT_SUCCESSFUL = 'finished'
ENCRYPT_FAILED = 'failed'
ENCRYPTOR_STATUS_PORT = 8000

PLATFORM_WINDOWS = 'windows'

log = logging.getLogger(__name__)


class BaseAWSService(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def run_instance(self,
                     image_id,
                     security_group_ids=None,
                     instance_type='m3.medium',
                     block_device_map=None):
        pass

    @abc.abstractmethod
    def get_instance(self, instance_id):
        pass

    @abc.abstractmethod
    def create_tags(self, resource_id, name=None, description=None):
        pass

    @abc.abstractmethod
    def stop_instance(self, instance_id):
        pass

    @abc.abstractmethod
    def terminate_instance(self, instance_id):
        pass

    @abc.abstractmethod
    def get_volume(self, volume_id):
        pass

    @abc.abstractmethod
    def get_snapshots(self, *snapshot_ids):
        pass

    @abc.abstractmethod
    def get_snapshot(self, snapshot_id):
        pass

    @abc.abstractmethod
    def create_snapshot(self, volume_id, name=None, description=None):
        pass

    @abc.abstractmethod
    def delete_volume(self, volume_id):
        pass

    @abc.abstractmethod
    def validate_guest_ami(self, ami_id):
        pass

    @abc.abstractmethod
    def validate_encryptor_ami(self, ami_id):
        pass

    @abc.abstractmethod
    def register_image(self,
                       kernel_id,
                       block_device_map,
                       name=None,
                       description=None):
        pass

    @abc.abstractmethod
    def get_image(self, image_id):
        pass

    @abc.abstractmethod
    def delete_snapshot(self, snapshot_id):
        pass

    @abc.abstractmethod
    def create_security_group(self, name, description):
        pass

    @abc.abstractmethod
    def add_security_group_rule(self, sg_id, **kwargs):
        pass

    @abc.abstractmethod
    def delete_security_group(self, sg_id):
        pass


class AWSService(BaseAWSService):

    def __init__(
            self,
            encryptor_session_id,
            encryptor_ami,
            default_tags=None):
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

    def run_instance(self,
                     image_id,
                     security_group_ids=None,
                     instance_type='m3.medium',
                     block_device_map=None):
        if security_group_ids is None:
            security_group_ids = []
        log.debug('Starting a new instance based on %s', image_id)
        try:
            reservation = self.conn.run_instances(
                image_id=image_id,
                key_name=self.key_name,
                instance_type=instance_type,
                block_device_map=block_device_map,
                security_group_ids=security_group_ids
            )
            return reservation.instances[0]
        except EC2ResponseError:
            # Log the failed operation, so that the user has context.
            log.error('Unable to launch instance for %s', image_id)
            raise

    def get_instance(self, instance_id):
        return self.conn.get_only_instances([instance_id])[0]

    def create_tags(self, resource_id, name=None, description=None):
        tags = dict(self.default_tags)
        if name:
            tags['Name'] = name
        if description:
            tags['Description'] = description
        log.debug('Tagging %s with %s', resource_id, tags)
        self.conn.create_tags([resource_id], tags)

    def stop_instance(self, instance_id):
        log.debug('Stopping instance %s', instance_id)
        instances = self.conn.stop_instances([instance_id])
        return instances[0]

    def terminate_instance(self, instance_id):
        log.debug('Terminating instance %s', instance_id)
        self.conn.terminate_instances([instance_id])

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

    def delete_volume(self, volume_id):
        return self.conn.delete_volume(volume_id)

    def validate_guest_ami(self, ami_id):
        try:
            images = self.conn.get_all_images([ami_id])
        except EC2ResponseError, e:
            if e.error_code == 'InvalidAMIID.NotFound':
                return e.error_message
            else:
                raise
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

    def get_image(self, image_id):
        return self.conn.get_image(image_id)

    def delete_snapshot(self, snapshot_id):
        return self.conn.delete_snapshot(snapshot_id)

    def create_security_group(self, name, description):
        sg = self.conn.create_security_group(name, description)
        return sg.id

    def add_security_group_rule(self, sg_id, **kwargs):
        kwargs['group_id'] = sg_id
        ok = self.conn.authorize_security_group(**kwargs)
        if not ok:
            raise Exception('Unknown error while adding security group rule')

    def delete_security_group(self, sg_id):
        ok = self.conn.delete_security_group(group_id=sg_id)
        if not ok:
            raise Exception('Unknown error while deleting security group')


class BaseEncryptorService(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, hostname, port=ENCRYPTOR_STATUS_PORT):
        self.hostname = hostname
        self.port = port

    @abc.abstractmethod
    def is_encryptor_up(self):
        pass

    @abc.abstractmethod
    def get_status(self):
        pass


class EncryptorService(BaseEncryptorService):

    def is_encryptor_up(self):
        try:
            self.get_status()
            return True
        except Exception as e:
            log.debug("Couldn't get encryptor status: %s", e)
            return False

    def get_status(self, timeout_secs=2):
        url = 'http://%s:%d/encryption_status' % (self.hostname, self.port)
        r = urllib2.urlopen(url, timeout=timeout_secs)
        data = r.read()
        info = json.loads(data)
        ratio = 0
        info['percent_complete'] = 0
        if info['state'] == ENCRYPT_SUCCESSFUL:
            info['percent_complete'] = 100
        elif info['bytes_total'] > 0:
            ratio = float(info['bytes_written']) / info['bytes_total']
            info['percent_complete'] = int(100 * ratio)
        return info
