"""Snapshot must fail closed when docker cp does not create a regular backup."""
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

AGENT_FILE = Path(__file__).resolve().parents[1] / "scripts" / "nsd-host-agent.py"
spec = importlib.util.spec_from_file_location("nsd_snapshot_regular", AGENT_FILE)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class SnapshotRegularFileTests(unittest.TestCase):
    def _docker(self, behavior):
        docker = Mock(spec=agent.DockerNPM)
        docker.container = "npm"
        docker.exists.return_value = True
        docker.copy_from.side_effect = behavior
        return docker

    def test_missing_backup_after_successful_copy_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            docker = self._docker(lambda remote, local: None)
            with self.assertRaisesRegex(RuntimeError, "non régulière"):
                agent.snapshot(docker, Path(root), 17)
            self.assertEqual(docker.copy_from.call_count, 1)

    def test_symlink_backup_after_copy_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "outside"
            target.write_text("do not trust", encoding="utf-8")
            docker = self._docker(lambda remote, local: Path(local).symlink_to(target))
            with self.assertRaisesRegex(RuntimeError, "non régulière"):
                agent.snapshot(docker, Path(root), 18)
            self.assertEqual(docker.copy_from.call_count, 1)

    def test_regular_backups_are_accepted(self):
        with tempfile.TemporaryDirectory() as root:
            docker = self._docker(lambda remote, local: Path(local).write_text("saved", encoding="utf-8"))
            folder, manifest = agent.snapshot(docker, Path(root), 19)
            self.assertEqual(set(manifest["existed"]), set(agent.SNIPPETS))
            self.assertTrue((folder / "manifest.json").is_file())
            self.assertEqual(docker.copy_from.call_count, len(agent.SNIPPETS))


if __name__ == "__main__":
    unittest.main()
