"""Regression tests for host agent path confinement (no real Docker calls)."""
import importlib.util
from pathlib import Path
from unittest.mock import patch
import subprocess
import unittest


SPEC = importlib.util.spec_from_file_location(
    "nsd_host_agent", Path(__file__).resolve().parents[1] / "scripts" / "nsd-host-agent.py"
)
agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent)


class AgentPathSafetyTests(unittest.TestCase):
    def test_all_missing_or_regular_paths_are_allowed(self):
        with patch.object(agent.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)) as run:
            agent.DockerNPM("npm").assert_safe_paths()
        self.assertEqual(run.call_count, 2 + len(agent.SNIPPETS))

    def test_symlink_in_any_target_is_rejected(self):
        for index in range(2 + len(agent.SNIPPETS)):
            with self.subTest(index=index):
                responses = [subprocess.CompletedProcess([], 1) for _ in range(2 + len(agent.SNIPPETS))]
                responses[index] = subprocess.CompletedProcess([], 0)
                with patch.object(agent.subprocess, "run", side_effect=responses):
                    with self.assertRaisesRegex(RuntimeError, "symbolique"):
                        agent.DockerNPM("npm").assert_safe_paths()

    def test_docker_error_is_not_treated_as_absent_symlink(self):
        with patch.object(agent.subprocess, "run", return_value=subprocess.CompletedProcess([], 125)):
            with self.assertRaisesRegex(RuntimeError, "vérifier"):
                agent.DockerNPM("npm").assert_safe_paths()


if __name__ == "__main__":
    unittest.main()
