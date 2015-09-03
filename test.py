import logging
import uuid
from boto.ec2.blockdevicemapping import BlockDeviceType, BlockDeviceMapping
from boto.ec2.image import Image
from boto.ec2.instance import Instance
from boto.ec2.snapshot import Snapshot
from boto.ec2.volume import Volume
import brkt_cli
from brkt_cli import service
import re
import unittest


brkt_cli.log = logging.getLogger(__name__)
# logging.basicConfig(level=logging.DEBUG)


def _new_id():
    return uuid.uuid4().hex[:6]


class DummyEncryptorService(service.BaseEncryptorService):

    def __init__(self):
        self.is_up = False
        self.progress = 0

    def is_encryptor_up(self):
        """ The first call returns False.  Subsequent calls return True.
        """
        ret_val = self.is_up
        if not self.is_up:
            self.is_up = True
        return ret_val

    def get_progress(self):
        """ Return progress in increments of 20% for each call.
        """
        ret_val = self.progress
        if self.progress < 100:
            self.progress += 20
        return ret_val


class DummyAWSService(service.BaseAWSService):

    def __init__(self):
        self.instances = {}
        self.volumes = {}
        self.snapshots = {}
        self.transition_to_running = {}
        self.transition_to_completed = {}
        self.images = {}

    def run_instance(self,
                     image_id,
                     instance_type='m3.medium',
                     block_device_map=None):
        instance = Instance()
        instance.id = _new_id()
        instance.root_device_name = '/dev/sda1'
        instance._state.code = 0
        instance._state.name = 'pending'

        # Create volumes based on block device data from the image.
        image = self.get_image(image_id)
        instance_bdm = BlockDeviceMapping()
        for device_name, bdm in image.block_device_mapping.iteritems():
            # Create a new volume and attach it to the instance.
            volume = Volume()
            volume.size = 8
            volume.id = _new_id()
            self.volumes[volume.id] = volume

            bdt = BlockDeviceType(volume_id=volume.id, size=8)
            instance_bdm[device_name] = bdt

        instance.block_device_mapping = instance_bdm
        self.instances[instance.id] = instance

        return instance

    def get_instance(self, instance_id):
        instance = self.instances[instance_id]

        # Transition from pending to running on subsequent calls.
        if instance.state == 'pending':
            if self.transition_to_running.get(instance_id):
                # We returned pending last time.  Transition to running.
                instance._state.code = 16
                instance._state.name = 'running'
                del(self.transition_to_running[instance_id])
            else:
                # Transition to running next time.
                self.transition_to_running[instance_id] = True
        return instance

    def create_tags(self, resource_id, name=None, description=None):
        pass

    def stop_instance(self, instance_id):
        instance = self.instances[instance_id]
        instance._state.code = 80
        instance._state.name = 'stopped'
        return instance

    def terminate_instance(self, instance_id):
        instance = self.instances[instance_id]
        instance._state.code = 48
        instance._state.name = 'terminated'
        return instance

    def get_volume(self, volume_id):
        return self.volumes[volume_id]

    def get_snapshots(self, *snapshot_ids):
        return [self.get_snapshot(id) for id in snapshot_ids]

    def get_snapshot(self, snapshot_id):
        snapshot = self.snapshots[snapshot_id]

        # Transition from pending to completed on subsequent calls.
        if snapshot.status == 'pending':
            if self.transition_to_completed.get(snapshot_id):
                # We returned pending last time.  Transition to completed.
                snapshot.status = 'completed'
                del(self.transition_to_completed[snapshot_id])
            else:
                # Transition to completed next time.
                self.transition_to_completed[snapshot_id] = True
        return snapshot

    def create_snapshot(self, volume_id, name=None, description=None):
        snapshot = Snapshot()
        snapshot.id = _new_id()
        snapshot.status = 'pending'
        self.snapshots[snapshot.id] = snapshot
        return snapshot

    def delete_volume(self, volume_id):
        del(self.volumes[volume_id])

    def validate_guest_ami(self, ami_id):
        pass

    def validate_encryptor_ami(self, ami_id):
        pass

    def register_image(self,
                       kernel_id,
                       block_device_map,
                       name=None,
                       description=None):
        image = Image()
        image.id = _new_id()
        image.block_device_mapping = block_device_map
        image.state = 'available'
        image.name = name
        image.description = description
        self.images[image.id] = image
        return image.id

    def wait_for_image(self, image_id):
        pass

    def get_image(self, image_id):
        return self.images[image_id]

    def delete_snapshot(self, snapshot_id):
        del(self.snapshots[snapshot_id])


class TestSnapshotProgress(unittest.TestCase):

    def test_snapshot_progress_text(self):
        # One snapshot.
        s1 = Snapshot()
        s1.id = '1'
        s1.progress = u'25%'
        self.assertEqual(
            '1: 25%',
            brkt_cli._get_snapshot_progress_text([s1])
        )

        # Two snapshots.
        s2 = Snapshot()
        s2.id = '2'
        s2.progress = u'50%'

        self.assertEqual(
            '1: 25%, 2: 50%',
            brkt_cli._get_snapshot_progress_text([s1, s2])
        )


class TestEncryptedImageName(unittest.TestCase):

    def test_encrypted_image_suffix(self):
        s1 = brkt_cli._get_encrypted_suffix()
        regexp = r'\(encrypted .+\)'
        m = re.match(regexp, s1)
        self.assertIsNotNone(m)

        s2 = brkt_cli._get_encrypted_suffix()
        m = re.match(regexp, s2)
        self.assertIsNotNone(m)
        self.assertNotEqual(s1, s2)

    def test_encrypted_image_name(self):
        name = 'Boogie nights are always the best in town'
        suffix = brkt_cli._get_encrypted_suffix()
        encrypted_name = brkt_cli._get_encrypted_image_name(
            name, suffix=suffix)
        self.assertTrue(encrypted_name.startswith(name))
        self.assertTrue(encrypted_name.endswith(suffix))

        # Make sure we truncate the original name when it's too long.
        name += ('X' * 100)
        encrypted_name = brkt_cli._get_encrypted_image_name(name)
        self.assertEqual(128, len(encrypted_name))
        self.assertTrue(encrypted_name.startswith('Boogie nights'))


class TestSmoke(unittest.TestCase):

    def test_smoke(self):
        aws_svc = DummyAWSService()

        # Encryptor image
        bdm = BlockDeviceMapping()
        for n in (1, 2, 3, 5):
            device_name = '/dev/sda%d' % n
            bdm[device_name] = BlockDeviceType()
        id = aws_svc.register_image(
            kernel_id=None, name='Encryptor image', block_device_map=bdm)
        encryptor_image = aws_svc.get_image(id)

        # Guest image
        bdm = BlockDeviceMapping()
        bdm['/dev/sda1'] = BlockDeviceType()
        id = aws_svc.register_image(
            kernel_id=None, name='Encryptor image', block_device_map=bdm)
        guest_image = aws_svc.get_image(id)

        # Run the smoke test.
        brkt_cli.SLEEP_ENABLED = False
        brkt_cli.run(
            aws_svc=aws_svc,
            enc_svc=DummyEncryptorService(),
            image_id=guest_image.id,
            encryptor_ami=encryptor_image.id
        )
