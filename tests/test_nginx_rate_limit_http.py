"""Exercise rate limiting over HTTP against a disposable Nginx process."""
from __future__ import annotations

import shutil
import socket
import subprocess
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

import pytest

from services.nginx_rate_limit_preview import render_rate_limit_preview


def test_rate_limit_returns_429_under_burst(tmp_path: Path):
    nginx = shutil.which("nginx")
    if nginx is None:
        pytest.skip("nginx unavailable; dedicated CI job installs it")

    preview = render_rate_limit_preview({
        "auto_ban_enabled": False,
        "country_block_enabled": False,
        "blocked_countries": [],
        "trusted_proxy_cidrs": [],
        "rate_limit_rps": 1,
        "rate_limit_burst": 0,
    })
    (tmp_path / "index.html").write_text("ok", encoding="utf-8")
    (tmp_path / "http.conf").write_text(preview.http_include, encoding="utf-8")
    (tmp_path / "server.conf").write_text(preview.server_include, encoding="utf-8")

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]

    config = tmp_path / "nginx.conf"
    config.write_text(
        "worker_processes 1;\n"
        f"pid {tmp_path / 'nginx.pid'};\n"
        f"error_log {tmp_path / 'error.log'} notice;\n"
        "events { worker_connections 64; }\n"
        "http {\n"
        "  access_log off;\n"
        f"  include {tmp_path / 'http.conf'};\n"
        f"  server {{ listen 127.0.0.1:{port};\n"
        f"    include {tmp_path / 'server.conf'};\n"
        f"    location / {{ root {tmp_path}; }}\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    command = [nginx, "-p", str(tmp_path) + "/", "-c", str(config)]
    syntax = subprocess.run(command + ["-t"], capture_output=True, text=True, timeout=15, check=False)
    assert syntax.returncode == 0, syntax.stderr

    process = subprocess.Popen(
        command + ["-g", "daemon off;"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    try:
        url = f"http://127.0.0.1:{port}/index.html"
        deadline = time.monotonic() + 5
        while True:
            if process.poll() is not None:
                raise AssertionError("disposable Nginx exited unexpectedly")
            try:
                with urlopen(url, timeout=1) as response:
                    assert response.status == 200
                break
            except URLError:
                if time.monotonic() >= deadline:
                    raise AssertionError("disposable Nginx did not start")
                time.sleep(0.05)

        statuses = []
        for _ in range(12):
            try:
                with urlopen(url, timeout=2) as response:
                    statuses.append(response.status)
            except HTTPError as exc:
                statuses.append(exc.code)
                exc.close()
        assert 429 in statuses, statuses
        assert set(statuses) <= {200, 429}, statuses
    finally:
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)
