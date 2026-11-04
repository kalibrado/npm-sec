"""Regression tests for symlink-safe agent token loading."""
import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

AGENT_FILE = Path(__file__).resolve().parents[1] / "scripts" / "nsd-host-agent.py"
spec = importlib.util.spec_from_file_location("nsd_agent_token_nofollow", AGENT_FILE)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class TokenFileTests(unittest.TestCase):
    def test_reads_private_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            path.write_text("a" * 40 + "\n", encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(agent.token_file(path), "a" * 40)

    def test_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_text("b" * 40, encoding="utf-8")
            target.chmod(0o600)
            link = Path(directory) / "link"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                agent.token_file(link)

    def test_rejects_world_readable_token(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            path.write_text("c" * 40, encoding="utf-8")
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                agent.token_file(path)

    def test_checks_opened_inode_not_path_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            path.write_text("d" * 40, encoding="utf-8")
            path.chmod(0o600)
            with patch.object(agent.os, "fstat", wraps=os.fstat) as check:
                self.assertEqual(agent.token_file(path), "d" * 40)
                check.assert_called_once()


if __name__ == "__main__":
    unittest.main()
