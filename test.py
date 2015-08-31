from boto.ec2.snapshot import Snapshot
import solo_cli
import unittest


class TestSoloCli(unittest.TestCase):

    def test_snapshot_progress_text(self):
        # One snapshot.
        s1 = Snapshot()
        s1.id = '1'
        s1.progress = u'25%'
        self.assertEqual(
            '1: 25%',
            solo_cli._get_snapshot_progress_text([s1])
        )

        # Two snapshots.
        s2 = Snapshot()
        s2.id = '2'
        s2.progress = u'50%'

        self.assertEqual(
            '1: 25%, 2: 50%',
            solo_cli._get_snapshot_progress_text([s1, s2])
        )
