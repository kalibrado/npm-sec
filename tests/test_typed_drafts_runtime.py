"""Exercise the real editor JavaScript with a minimal DOM and controlled HTTP replies."""
from pathlib import Path
import shutil
import subprocess

import pytest


def test_typed_drafts_async_interactions():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the JavaScript interaction test")
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [node, "--test", str(root / "tests" / "typed_drafts_interactions.cjs")],
        cwd=root, capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
