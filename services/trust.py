import ipaddress
import re
import sqlite3
from fastapi import HTTPException

from  config import INTERNAL_NETWORKS
from  database import get_db


def validate_ip_or_cidr(value: str, allow_cidr: bool = False) -> str:
    value = (value or "").strip()
    try:
        if allow_cidr and "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP/CIDR")


def validate_country_code(value: str) -> str:
    value = (value or "").strip().upper()
    if len(value) != 2 or not value.isascii() or not value.isalpha():
        raise HTTPException(status_code=400, detail="Invalid country code")
    return value


def validate_trusted_type(entry_type: str, value: str) -> tuple[str, str]:
    entry_type = (entry_type or "").strip().lower()
    value = (value or "").strip()
    if entry_type == "country":
        return entry_type, validate_country_code(value)
    if entry_type == "cidr":
        return entry_type, validate_ip_or_cidr(value, allow_cidr=True)
    if entry_type == "ip":
        return entry_type, validate_ip_or_cidr(value)
    if entry_type == "ua":
        if not value or len(value) > 160:
            raise HTTPException(status_code=400, detail="Invalid user-agent rule")
        return entry_type, value.lower()
    raise HTTPException(status_code=400, detail="Invalid trusted entry type")


_HOST_LABEL_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def validate_proxy_host(value: str | None) -> str:
    """Canonical exact NPM host, or empty string for a global block.

    Forbid wildcard, URL, port and Nginx special syntax to avoid
    configuration injection. IDNs should be passed in punycode form.
    """
    if value is None or value == "":
        return ""
    if not isinstance(value, str):
        raise HTTPException(status_code=422, detail="Invalid proxy host")
    host = value.strip().lower().rstrip(".")
    if (
        not host or len(host) > 253 or not host.isascii()
        or any(not _HOST_LABEL_PATTERN.fullmatch(x) for x in host.split("."))
    ):
        raise HTTPException(
            status_code=422,
            detail="Invalid proxy host: use an exact DNS name without scheme, port or wildcard",
        )
    return host


def assert_safe_manual_block(
    entry_type: str, value: str, conn: sqlite3.Connection
) -> None:
    """Prevent a rule which would break LAN access or conflict with IP trust.

    GeoIP country bans remain possible; trusted IP/CIDR networks can be used
    as explicit exceptions. For an IP block, explicit trust must be removed
    first, because Nginx trust overrides a block and would silently negate it.
    """
    if entry_type not in {"ip", "cidr"}:
        return

    target = ipaddress.ip_network(value, strict=False)
    for protected in INTERNAL_NETWORKS:
        if target.version == protected.version and target.overlaps(protected):
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Cannot block {value}: overlaps protected internal network "
                    f"{protected}. Update INTERNAL_NETWORKS explicitly if needed."
                ),
            )

    if entry_type == "ip":
        rows = conn.execute(
            "SELECT type, value FROM trusted_entries WHERE type IN ('ip', 'cidr')"
        ).fetchall()
        address = ipaddress.ip_address(value)
        for row in rows:
            try:
                allowed = ipaddress.ip_network(row["value"], strict=False)
            except ValueError:
                continue
            if address in allowed:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"Cannot block {value}: trusted {row['type']} "
                        f"{row['value']} takes precedence. Remove its trust rule first."
                    ),
                )


def is_trusted_event(event: dict, conn: sqlite3.Connection | None = None) -> bool:
    """Returns True for internal/whitelisted events. Keeps auto-ban from eating your own LAN."""
    ip_raw = event.get("ip") or ""
    cc = (event.get("country_code") or "").upper()
    ua = (event.get("ua") or event.get("user_agent") or "").lower()

    if ip_raw and is_internal_ip(ip_raw):
        return True

    try:
        ip_obj = ipaddress.ip_address(ip_raw) if ip_raw else None
    except ValueError:
        ip_obj = None

    close_conn = False
    if conn is None:
        db_cm = get_db()
        conn = db_cm.__enter__()
        close_conn = True

    try:
        rows = conn.execute("SELECT type, value FROM trusted_entries").fetchall()
        for row in rows:
            t, v = row["type"], row["value"]
            try:
                if t == "ip" and ip_obj and ip_obj == ipaddress.ip_address(v):
                    return True
                if t == "cidr" and ip_obj and ip_obj in ipaddress.ip_network(v, strict=False):
                    return True
                if t == "country" and cc and cc == v.upper():
                    return True
                if t == "ua" and v.lower() in ua:
                    return True
            except ValueError:
                continue
        return False
    finally:
        if close_conn:
            db_cm.__exit__(None, None, None)


def is_already_blocked(conn: sqlite3.Connection, ip: str) -> bool:
    if not ip:
        return False
    row = conn.execute(
        "SELECT 1 FROM blocklist WHERE type='ip' AND host='' AND value=? "
        "AND (expires_at IS NULL OR expires_at > datetime('now')) LIMIT 1",
        [ip],
    ).fetchone()
    return row is not None


def is_internal_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in INTERNAL_NETWORKS)
    except (ValueError, ipaddress.AddressValueError):
        return False
