"""Check invalid placement and unresolved rate-limit zone in disposable Nginx."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from services.nginx_rate_limit_preview import render_rate_limit_preview


@pytest.mark.parametrize("wrong_context", ["http_in_server", "server_without_zone"])
def test_rate_limit_preview_rejects_invalid_placement_or_missing_zone(tmp_path: Path, wrong_context: str):
    nginx = shutil.which("nginx")
    if nginx is None:
        pytest.skip("nginx executable unavailable; dedicated CI job installs it")

    preview = render_rate_limit_preview({
        "auto_ban_enabled": False,
        "country_block_enabled": False,
        "blocked_countries": [],
        "trusted_proxy_cidrs": [],
        "rate_limit_rps": 12,
        "rate_limit_burst": 25,
    })
    if wrong_context == "http_in_server":
        http_directives = ""
        server_directives = preview.http_include
        rejected_directive = "limit_req_zone"
    else:
        http_directives = preview.server_include
        server_directives = ""
        rejected_directive = "nsd_preview_per_ip"

    config = tmp_path / "nginx.conf"
    config.write_text(
        "worker_processes 1;\n"
        "pid " + str(tmp_path / "nginx.pid") + ";\n"
        "error_log stderr notice;\n"
        "events { worker_connections 16; }\n"
        "http {\n"
        "  access_log off;\n"
        + http_directives
        + "  server { listen 127.0.0.1:18080;\n"
        + server_directives
        + "    location / { return 200; }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [nginx, "-t", "-p", str(tmp_path) + "/", "-c", str(config)],
        capture_output=True, text=True, timeout=15, check=False,
    )
    assert result.returncode != 0
    assert rejected_directive in result.stderr
