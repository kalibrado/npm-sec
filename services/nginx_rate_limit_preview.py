"""Deterministic, read-only Nginx rate-limit preview for isolated test fixtures.

Never deploy these snippets automatically. Both HTTP and server includes are
required, and real client IP / GeoIP integration remains outside this scope.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from services.nginx_settings_schema import validate_settings


class UnsupportedProfileError(ValueError):
    """A setting cannot safely be represented by this limited renderer."""


@dataclass(frozen=True)
class RateLimitPreview:
    http_include: str
    server_include: str
    sha256: str


def render_rate_limit_preview(settings: dict) -> RateLimitPreview:
    """Render a strictly bounded rate-limit profile without filesystem access."""
    validated = validate_settings(settings)
    unsupported = (
        validated["auto_ban_enabled"]
        or validated["country_block_enabled"]
        or bool(validated["blocked_countries"])
        or bool(validated["trusted_proxy_cidrs"])
    )
    if unsupported:
        raise UnsupportedProfileError(
            "Preview supports rate limits only; bans, GeoIP and trusted proxies "
            "require separate verified integration"
        )
    rate = validated["rate_limit_rps"]
    burst = validated["rate_limit_burst"]
    http = (
        "# NSD preview only; include in http context after review.\n"
        f"limit_req_zone $binary_remote_addr zone=nsd_preview_per_ip:10m rate={rate}r/s;\n"
    )
    server = (
        "# NSD preview only; include in server context after review.\n"
        f"limit_req zone=nsd_preview_per_ip burst={burst} nodelay;\n"
        "limit_req_status 429;\n"
    )
    digest = hashlib.sha256((http + "\\0" + server).encode("utf-8")).hexdigest()
    return RateLimitPreview(http_include=http, server_include=server, sha256=digest)
