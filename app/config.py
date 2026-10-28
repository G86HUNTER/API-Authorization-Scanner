"""
Configuration loader and validator for the scanner framework.
Reads YAML configuration and validates required fields.
"""

import re
from pathlib import Path
from typing import Any

import yaml

# Allowed URL schemes for safe scanning
ALLOWED_SCHEMES = {"http", "https"}

# Default allowlist — localhost only by default
DEFAULT_ALLOWED_HOSTS = {"127.0.0.1", "localhost"}

# Maximum retry limit to prevent runaway retries
MAX_RETRIES_LIMIT = 5

# Maximum timeout in seconds
MAX_TIMEOUT_SECONDS = 60

ALLOWED_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


class ConfigError(ValueError):
    """Raised when configuration is invalid."""


def load_config(config_path: str | Path) -> dict[str, Any]:
    """
    Load and validate a YAML scan configuration file.

    Args:
        config_path: Path to the YAML configuration file.

    Returns:
        Validated configuration dictionary.

    Raises:
        ConfigError: If the file is missing, unparseable, or contains invalid values.
    """
    config_path = Path(config_path)

    if not config_path.exists():
        raise ConfigError(f"Configuration file not found: {config_path}")

    try:
        with config_path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Failed to parse YAML configuration: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError("Configuration must be a YAML mapping at the top level.")

    _validate_config(raw)
    return raw


def _validate_config(cfg: dict[str, Any]) -> None:
    """Validate required and optional configuration fields."""
    # Required fields
    _require(cfg, "base_url", str)
    _require(cfg, "identities", list)
    _require(cfg, "endpoints", list)

    base_url: str = cfg["base_url"]
    _validate_url(base_url, cfg.get("allowed_hosts", list(DEFAULT_ALLOWED_HOSTS)))

    # Optional with defaults
    timeout = cfg.get("timeout", 5)
    if not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > MAX_TIMEOUT_SECONDS:
        raise ConfigError(
            f"'timeout' must be a positive number ≤ {MAX_TIMEOUT_SECONDS}. Got: {timeout!r}"
        )

    retries = cfg.get("retries", 1)
    if not isinstance(retries, int) or retries < 0 or retries > MAX_RETRIES_LIMIT:
        raise ConfigError(
            f"'retries' must be an integer 0–{MAX_RETRIES_LIMIT}. Got: {retries!r}"
        )

    # Validate identities
    identities: list = cfg["identities"]
    if not identities:
        raise ConfigError("'identities' list must not be empty.")
    seen_ids = set()
    for idx, identity in enumerate(identities):
        if not isinstance(identity, dict):
            raise ConfigError(f"Identity #{idx} must be a mapping.")
        _require_in(identity, "name", str, context=f"identity #{idx}")
        _require_in(identity, "role", str, context=f"identity #{idx}")
        # id is optional but must be int if present
        if "id" in identity and not isinstance(identity["id"], int):
            raise ConfigError(f"identity #{idx} 'id' must be an integer.")
        name = identity["name"]
        if name in seen_ids:
            raise ConfigError(f"Duplicate identity name: {name!r}")
        seen_ids.add(name)

    # Validate endpoints
    endpoints: list = cfg["endpoints"]
    if not endpoints:
        raise ConfigError("'endpoints' list must not be empty.")
    for idx, ep in enumerate(endpoints):
        if not isinstance(ep, dict):
            raise ConfigError(f"Endpoint #{idx} must be a mapping.")
        _require_in(ep, "path", str, context=f"endpoint #{idx}")
        _require_in(ep, "method", str, context=f"endpoint #{idx}")
        _require_in(ep, "vuln_type", str, context=f"endpoint #{idx}")
        method = ep["method"].upper()
        if method not in ALLOWED_HTTP_METHODS:
            raise ConfigError(
                f"Endpoint #{idx}: unsupported HTTP method {method!r}. "
                f"Allowed: {sorted(ALLOWED_HTTP_METHODS)}"
            )


def _require(cfg: dict, key: str, expected_type: type) -> None:
    if key not in cfg:
        raise ConfigError(f"Missing required configuration field: '{key}'")
    if not isinstance(cfg[key], expected_type):
        raise ConfigError(
            f"Field '{key}' must be a {expected_type.__name__}. Got {type(cfg[key]).__name__}."
        )


def _require_in(mapping: dict, key: str, expected_type: type, context: str = "") -> None:
    prefix = f"[{context}] " if context else ""
    if key not in mapping:
        raise ConfigError(f"{prefix}Missing required field: '{key}'")
    if not isinstance(mapping[key], expected_type):
        raise ConfigError(
            f"{prefix}Field '{key}' must be a {expected_type.__name__}. "
            f"Got {type(mapping[key]).__name__}."
        )


def _validate_url(url: str, allowed_hosts: list[str]) -> None:
    """Validate URL scheme and hostname against the allowlist."""
    # Basic pattern check
    pattern = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/:?#]+)(:\d+)?(/.*)?$")
    match = pattern.match(url)
    if not match:
        raise ConfigError(f"Invalid base_url format: {url!r}")

    scheme = match.group(1).lower()
    host = match.group(2).lower()

    if scheme not in ALLOWED_SCHEMES:
        raise ConfigError(
            f"Unsupported URL scheme {scheme!r}. Allowed: {sorted(ALLOWED_SCHEMES)}"
        )

    normalized_allowed = {h.lower() for h in allowed_hosts}
    if host not in normalized_allowed:
        raise ConfigError(
            f"Host {host!r} is not in the allowed_hosts list: {sorted(normalized_allowed)}. "
            "Add it explicitly to allowed_hosts in your configuration to authorize scanning."
        )


def get_default_config_path() -> Path:
    """Return the default configuration file path relative to the project root."""
    return Path(__file__).resolve().parent.parent / "config" / "scan_config.yaml"
