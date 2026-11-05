"""Read-only renderer regression tests."""
import hashlib

import pytest

from services.nginx_rate_limit_preview import (
    UnsupportedProfileError,
    render_rate_limit_preview,
)
from services.nginx_settings_schema import SettingsValidationError


@pytest.fixture
def settings():
    return {
        "auto_ban_enabled": False,
        "country_block_enabled": False,
        "blocked_countries": [],
        "trusted_proxy_cidrs": [],
        "rate_limit_rps": 12,
        "rate_limit_burst": 25,
    }


def test_preview_is_deterministic_and_context_separated(settings):
    first = render_rate_limit_preview(settings)
    second = render_rate_limit_preview(settings)
    assert first == second
    assert "rate=12r/s;" in first.http_include
    assert "limit_req_zone" not in first.server_include
    assert "burst=25 nodelay;" in first.server_include
    assert "limit_req_status 429;" in first.server_include
    assert "limit_req zone=" not in first.http_include
    assert len(first.sha256) == 64
    assert settings["rate_limit_rps"] == 12


@pytest.mark.parametrize("field,value", [
    ("auto_ban_enabled", True),
    ("country_block_enabled", True),
    ("blocked_countries", ["FR"]),
    ("trusted_proxy_cidrs", ["192.168.1.0/24"]),
])
def test_unsupported_security_features_fail_closed(settings, field, value):
    settings[field] = value
    with pytest.raises(UnsupportedProfileError):
        render_rate_limit_preview(settings)


@pytest.mark.parametrize("field,value", [
    ("rate_limit_rps", "12; include /etc/passwd"),
    ("rate_limit_burst", -1),
    ("unknown", "include /tmp/evil;"),
])
def test_invalid_values_never_render(settings, field, value):
    settings[field] = value
    with pytest.raises(SettingsValidationError):
        render_rate_limit_preview(settings)


def test_preview_is_pure_and_does_not_touch_nginx_or_docker(settings, monkeypatch):
    import subprocess
    from pathlib import Path

    def forbidden(*args, **kwargs):
        raise AssertionError("preview attempted a side effect")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)
    assert render_rate_limit_preview(settings).http_include


def test_preview_digest_uses_binary_separator(settings):
    preview = render_rate_limit_preview(settings)
    expected = hashlib.sha256(
        preview.http_include.encode("utf-8")
        + bytes([0])
        + preview.server_include.encode("utf-8")
    ).hexdigest()
    assert preview.sha256 == expected
    assert preview.sha256 != hashlib.sha256(
        (preview.http_include + r"\0" + preview.server_include).encode("utf-8")
    ).hexdigest()
