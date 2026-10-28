"""
Configuration loader tests.
"""

from __future__ import annotations

import io
import textwrap
import pytest
import yaml

from pathlib import Path
from app.config import load_config, ConfigError, _validate_config


VALID_YAML = textwrap.dedent("""\
    base_url: "http://127.0.0.1:5000"
    allowed_hosts:
      - "127.0.0.1"
    timeout: 5
    retries: 1
    identities:
      - name: alice
        id: 1
        role: user
      - name: admin
        id: 2
        role: admin
    endpoints:
      - path: "/api/documents/{object_id}"
        method: GET
        vuln_type: BOLA
        objects:
          - id: 101
        identity_pairs:
          - owner: alice
            attacker: alice
""")


class TestLoadConfig:

    def test_valid_config_loads_successfully(self, tmp_path):
        cfg_file = tmp_path / "scan_config.yaml"
        cfg_file.write_text(VALID_YAML, encoding="utf-8")
        cfg = load_config(cfg_file)
        assert cfg["base_url"] == "http://127.0.0.1:5000"
        assert len(cfg["identities"]) == 2
        assert len(cfg["endpoints"])  == 1

    def test_missing_file_raises_config_error(self, tmp_path):
        with pytest.raises(ConfigError, match="not found"):
            load_config(tmp_path / "nonexistent.yaml")

    def test_invalid_yaml_raises_config_error(self, tmp_path):
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("{\ninvalid yaml: [", encoding="utf-8")
        with pytest.raises(ConfigError, match="Failed to parse"):
            load_config(bad_file)

    def test_non_mapping_yaml_raises_error(self, tmp_path):
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("- item1\n- item2\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="mapping"):
            load_config(bad_file)


class TestValidateConfig:

    def _base(self):
        return yaml.safe_load(VALID_YAML)

    def test_missing_base_url_raises(self):
        cfg = self._base()
        del cfg["base_url"]
        with pytest.raises(ConfigError, match="base_url"):
            _validate_config(cfg)

    def test_missing_identities_raises(self):
        cfg = self._base()
        del cfg["identities"]
        with pytest.raises(ConfigError, match="identities"):
            _validate_config(cfg)

    def test_missing_endpoints_raises(self):
        cfg = self._base()
        del cfg["endpoints"]
        with pytest.raises(ConfigError, match="endpoints"):
            _validate_config(cfg)

    def test_invalid_timeout_raises(self):
        cfg = self._base()
        cfg["timeout"] = -1
        with pytest.raises(ConfigError, match="timeout"):
            _validate_config(cfg)

    def test_too_large_timeout_raises(self):
        cfg = self._base()
        cfg["timeout"] = 999
        with pytest.raises(ConfigError, match="timeout"):
            _validate_config(cfg)

    def test_invalid_retries_raises(self):
        cfg = self._base()
        cfg["retries"] = 99
        with pytest.raises(ConfigError, match="retries"):
            _validate_config(cfg)

    def test_unsupported_http_method_raises(self):
        cfg = self._base()
        cfg["endpoints"][0]["method"] = "TRACE"
        with pytest.raises(ConfigError, match="method"):
            _validate_config(cfg)

    def test_disallowed_host_raises(self):
        cfg = self._base()
        cfg["base_url"] = "http://evil.com/api"
        cfg["allowed_hosts"] = ["127.0.0.1"]
        with pytest.raises(ConfigError, match="allowed_hosts"):
            _validate_config(cfg)

    def test_localhost_alias_allowed(self):
        cfg = self._base()
        cfg["base_url"] = "http://localhost:5000"
        cfg["allowed_hosts"] = ["localhost"]
        # Should not raise
        _validate_config(cfg)

    def test_duplicate_identity_names_raise(self):
        cfg = self._base()
        cfg["identities"].append({"name": "alice", "id": 5, "role": "user"})
        with pytest.raises(ConfigError, match="Duplicate"):
            _validate_config(cfg)

    def test_empty_identities_raises(self):
        cfg = self._base()
        cfg["identities"] = []
        with pytest.raises(ConfigError, match="empty"):
            _validate_config(cfg)

    def test_empty_endpoints_raises(self):
        cfg = self._base()
        cfg["endpoints"] = []
        with pytest.raises(ConfigError, match="empty"):
            _validate_config(cfg)

    def test_unsupported_scheme_raises(self):
        cfg = self._base()
        cfg["base_url"] = "ftp://127.0.0.1:21"
        with pytest.raises(ConfigError, match="scheme"):
            _validate_config(cfg)

    def test_https_scheme_is_allowed(self):
        cfg = self._base()
        cfg["base_url"]      = "https://127.0.0.1:443"
        cfg["allowed_hosts"] = ["127.0.0.1"]
        _validate_config(cfg)  # should not raise
