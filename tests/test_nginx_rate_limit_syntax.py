"""Validate generated preview against an isolated Nginx configuration."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from services.nginx_rate_limit_preview import render_rate_limit_preview


@pytest.mark.parametrize("rate,burst", [(1, 0), (12, 25), (100000, 100000)])
def test_rate_limit_preview_passes_real_nginx_syntax(tmp_path: Path, rate: int, burst: int):
    nginx = shutil.which("nginx")
    if nginx is None:
        pytest.skip("nginx executable unavailable; dedicated CI job installs it")
    settings = {
        "auto_ban_enabled": False,
        "country_block_enabled": False,
        "blocked_countries": [],
        "trusted_proxy_cidrs": [],
        "rate_limit_rps": rate,
        "rate_limit_burst": burst,
    }
    preview = render_rate_limit_preview(settings)
    (tmp_path / "http.conf").write_text(preview.http_include, encoding="utf-8")
    (tmp_path / "server.conf").write_text(preview.server_include, encoding="utf-8")
    (tmp_path / "nginx.conf").write_text(
        "worker_processes 1;\n"
        "pid " + str(tmp_path / "nginx.pid") + ";\n"
        "error_log stderr notice;\n"
        "events { worker_connections 16; }\n"
        "http {\n"
        "  access_log off;\n"
        "  include " + str(tmp_path / "http.conf") + ";\n"
        "  server { listen 127.0.0.1:18080;\n"
        "    include " + str(tmp_path / "server.conf") + ";\n"
        "    location / { return 200; }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    # Only syntax check a private fixture. No daemon, NPM, Docker or reload.
    result = subprocess.run(
        [nginx, "-t", "-p", str(tmp_path) + "/", "-c", str(tmp_path / "nginx.conf")],
        capture_output=True, text=True, timeout=15, check=False,
    )
    assert result.returncode == 0, result.stderr
