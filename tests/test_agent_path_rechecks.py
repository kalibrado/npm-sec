"""Regression checks for path revalidation during NSD host-agent rollback."""
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock


AGENT_FILE = Path(__file__).resolve().parents[1] / "scripts" / "nsd-host-agent.py"
spec = importlib.util.spec_from_file_location("nsd_host_agent_path_checks", AGENT_FILE)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class RollbackPathRecheckTests(unittest.TestCase):
    def test_rechecks_before_each_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            for name in agent.SNIPPETS:
                (folder / name).write_text("saved", encoding="utf-8")
            docker = Mock(spec=agent.DockerNPM)
            docker.container = "npm"
            manifest = {
                "container": "npm",
                "existed": {name: True for name in agent.SNIPPETS},
            }
            agent.rollback(docker, folder, manifest)
            self.assertEqual(
                docker.assert_safe_paths.call_count,
                len(agent.SNIPPETS) + 1,
            )
            self.assertEqual(docker.copy_to.call_count, len(agent.SNIPPETS))

    def test_recheck_failure_stops_remaining_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            for name in agent.SNIPPETS:
                (folder / name).write_text("saved", encoding="utf-8")
            docker = Mock(spec=agent.DockerNPM)
            docker.container = "npm"
            # Initial preflight passes; first write passes; next check fails.
            docker.assert_safe_paths.side_effect = [
                None, None, RuntimeError("path changed"),
            ]
            manifest = {
                "container": "npm",
                "existed": {name: True for name in agent.SNIPPETS},
            }
            with self.assertRaisesRegex(RuntimeError, "path changed"):
                agent.rollback(docker, folder, manifest)
            self.assertEqual(docker.copy_to.call_count, 1)
            docker.exec.assert_not_called()


if __name__ == "__main__":
    unittest.main()
