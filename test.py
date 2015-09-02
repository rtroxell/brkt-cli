from boto.ec2.snapshot import Snapshot
import brkt_cli
import re
import unittest


class TestSoloCli(unittest.TestCase):

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
