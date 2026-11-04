"""Snapshot must fail closed when NPM paths change during backup."""
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

spec = importlib.util.spec_from_file_location(
    "nsd_agent_snapshot", Path(__file__).resolve().parents[1] / "scripts" / "nsd-host-agent.py"
)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class SnapshotPathRecheckTests(unittest.TestCase):
    def test_rechecks_before_each_existence_probe_and_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            docker = Mock(spec=agent.DockerNPM)
            docker.container = "npm"
            docker.exists.return_value = True
            def write_backup(_target, destination):
                destination.write_text("saved config", encoding="utf-8")
            docker.copy_from.side_effect = write_backup
            agent.snapshot(docker, Path(directory), 17)
            self.assertEqual(docker.exists.call_count, len(agent.SNIPPETS))
            self.assertEqual(docker.copy_from.call_count, len(agent.SNIPPETS))
            self.assertEqual(docker.assert_safe_paths.call_count, 2 * len(agent.SNIPPETS))

    def test_changed_path_prevents_backup_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            docker = Mock(spec=agent.DockerNPM)
            docker.container = "npm"
            docker.exists.return_value = True
            docker.assert_safe_paths.side_effect = [None, RuntimeError("unsafe path")]
            with self.assertRaisesRegex(RuntimeError, "unsafe path"):
                agent.snapshot(docker, Path(directory), 18)
            docker.copy_from.assert_not_called()

    def test_changed_path_prevents_next_existence_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            docker = Mock(spec=agent.DockerNPM)
            docker.container = "npm"
            docker.exists.return_value = False
            docker.assert_safe_paths.side_effect = [None, RuntimeError("unsafe path")]
            with self.assertRaisesRegex(RuntimeError, "unsafe path"):
                agent.snapshot(docker, Path(directory), 19)
            self.assertEqual(docker.exists.call_count, 1)
            docker.copy_from.assert_not_called()


if __name__ == "__main__":
    unittest.main()
