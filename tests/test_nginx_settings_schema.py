import pytest

from services.nginx_settings_schema import SettingsValidationError, import_legacy_defaults, validate_settings


@pytest.fixture
def sample():
    return {
        "auto_ban_enabled": False,
        "country_block_enabled": False,
        "blocked_countries": ["FR", "US"],
        "trusted_proxy_cidrs": ["192.168.1.0/24", "2001:db8::/32"],
        "rate_limit_rps": 10,
        "rate_limit_burst": 20,
    }


def test_valid_settings_preserve_input(sample):
    validated = validate_settings(sample)
    assert validated == sample
    assert validated is not sample
    assert validated["blocked_countries"] is not sample["blocked_countries"]


@pytest.mark.parametrize("field,value", [
    ("auto_ban_enabled", 1),
    ("country_block_enabled", "false"),
    ("rate_limit_rps", True),
    ("rate_limit_rps", 0),
    ("rate_limit_burst", -1),
    ("blocked_countries", ["fr"]),
    ("blocked_countries", ["FR", "FR"]),
    ("blocked_countries", ["FR;deny all"]),
    ("trusted_proxy_cidrs", ["0.0.0.0/0;include /tmp/x"]),
    ("trusted_proxy_cidrs", ["192.168.1.1/24"]),
    ("trusted_proxy_cidrs", ["0.0.0.0/0"]),
    ("trusted_proxy_cidrs", ["::/0"]),
    ("trusted_proxy_cidrs", ["192.168.1.0/24", "192.168.1.0/24"]),
])
def test_reject_invalid_field(sample, field, value):
    sample[field] = value
    with pytest.raises(SettingsValidationError):
        validate_settings(sample)


def test_reject_unknown_and_missing(sample):
    with pytest.raises(SettingsValidationError):
        validate_settings({**sample, "raw_nginx": "deny all;"})
    del sample["auto_ban_enabled"]
    with pytest.raises(SettingsValidationError):
        validate_settings(sample)


def test_import_requires_verified_source_hash(sample):
    with pytest.raises(SettingsValidationError):
        import_legacy_defaults(sample, source_sha256="unknown")
    result = import_legacy_defaults(sample, source_sha256="a" * 64)
    assert result["schema_version"] == 1
    assert result["source_sha256"] == "a" * 64
    assert result["settings"]["auto_ban_enabled"] is False


def test_reject_universal_trusted_proxy_in_legacy_import(sample):
    sample["trusted_proxy_cidrs"] = ["0.0.0.0/0"]
    with pytest.raises(SettingsValidationError, match="trusting all addresses"):
        import_legacy_defaults(sample, source_sha256="a" * 64)
