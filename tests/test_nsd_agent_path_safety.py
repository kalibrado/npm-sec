"""Regression tests for host agent path confinement (no real Docker calls)."""
import importlib.util
from pathlib import Path
from unittest.mock import patch, Mock
import subprocess
import unittest


SPEC = importlib.util.spec_from_file_location(
    "nsd_host_agent", Path(__file__).resolve().parents[1] / "scripts" / "nsd-host-agent.py"
)
agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent)


class AgentPathSafetyTests(unittest.TestCase):
    @staticmethod
    def checked_paths():
        return tuple(dict.fromkeys((
            "/data", "/data/nginx", agent.CUSTOM, agent.TARGET,
            *(str(Path(target).parent) for target in agent.SNIPPETS.values()),
            *agent.SNIPPETS.values(),
            *(target + ".candidate" for target in agent.SNIPPETS.values()),
        )))

    def test_all_missing_or_regular_paths_are_allowed(self):
        with patch.object(agent.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)) as run:
            agent.DockerNPM("npm").assert_safe_paths()
        self.assertEqual(run.call_count, len(self.checked_paths()))
        self.assertEqual(
            [call.args[0][-1] for call in run.call_args_list],
            list(self.checked_paths()),
        )

    def test_symlink_in_any_target_is_rejected(self):
        for index in range(len(self.checked_paths())):
            with self.subTest(index=index):
                responses = [subprocess.CompletedProcess([], 1) for _ in range(len(self.checked_paths()))]
                responses[index] = subprocess.CompletedProcess([], 0)
                with patch.object(agent.subprocess, "run", side_effect=responses):
                    with self.assertRaisesRegex(RuntimeError, "symbolique"):
                        agent.DockerNPM("npm").assert_safe_paths()

    def test_rollback_rechecks_paths_before_restoring_files(self):
        docker = Mock(spec=agent.DockerNPM, container="npm")
        docker.assert_safe_paths.side_effect = RuntimeError("Chemin NPM symbolique interdit")
        from tempfile import TemporaryDirectory
        manifest = {"container": "npm", "existed": {name: True for name in agent.SNIPPETS}}
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            for name in agent.SNIPPETS:
                (folder / name).write_text("original", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "symbolique"):
                agent.rollback(docker, folder, manifest)
        docker.assert_safe_paths.assert_called_once_with()
        docker.copy_to.assert_not_called()
        docker.exec.assert_not_called()

    def test_rollback_preflights_all_backups_before_any_write(self):
        from tempfile import TemporaryDirectory
        docker = Mock(spec=agent.DockerNPM, container="npm")
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            existed = {name: True for name in agent.SNIPPETS}
            # Even if the first backup is valid, a missing later file must
            # abort before any original hook is restored.
            (folder / next(iter(agent.HOOKS))).write_text("original")
            manifest = {"container": "npm", "existed": existed}
            with self.assertRaisesRegex(RuntimeError, "Sauvegarde manquante"):
                agent.rollback(docker, folder, manifest)
        docker.copy_to.assert_not_called()
        docker.exec.assert_not_called()

    def test_rollback_rejects_non_boolean_manifest_values(self):
        docker = Mock(spec=agent.DockerNPM, container="npm")
        manifest = {
            "container": "npm",
            "existed": {name: "false" for name in agent.SNIPPETS},
        }
        with self.assertRaisesRegex(RuntimeError, "non booléenne"):
            agent.rollback(docker, Path("/unused-backup"), manifest)
        docker.copy_to.assert_not_called()
        docker.exec.assert_not_called()

    def test_exists_distinguishes_missing_file_from_docker_failure(self):
        docker = agent.DockerNPM("npm")
        for code, expected in ((0, True), (1, False)):
            with self.subTest(code=code):
                with patch.object(agent.subprocess, "run",
                                  return_value=subprocess.CompletedProcess([], code)) as run:
                    self.assertIs(docker.exists(agent.TARGET + "/http-security.conf"), expected)
                    self.assertEqual(run.call_args.args[0][:4],
                                     ["docker", "exec", "npm", "test"])

        for code in (2, 125, 126, 127, 137):
            with self.subTest(failure_code=code):
                with patch.object(agent.subprocess, "run",
                                  return_value=subprocess.CompletedProcess([], code)):
                    with self.assertRaisesRegex(RuntimeError, "présence"):
                        docker.exists(agent.TARGET + "/http-security.conf")

    def test_snapshot_never_copies_or_records_missing_on_docker_error(self):
        from tempfile import TemporaryDirectory
        docker = Mock(spec=agent.DockerNPM, container="npm")
        docker.exists.side_effect = RuntimeError("Impossible de vérifier la présence du fichier NPM")
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "présence"):
                agent.snapshot(docker, Path(directory), 1)
        docker.copy_from.assert_not_called()

    def test_docker_error_is_not_treated_as_absent_symlink(self):
        with patch.object(agent.subprocess, "run", return_value=subprocess.CompletedProcess([], 125)):
            with self.assertRaisesRegex(RuntimeError, "vérifier"):
                agent.DockerNPM("npm").assert_safe_paths()


if __name__ == "__main__":
    unittest.main()
