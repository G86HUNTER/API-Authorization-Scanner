# Ethical Testing Boundaries & Known Limitations

## 1. Ethical Testing Policy
- **Authorized Testing Only**: This scanner is an assessment tool designed exclusively for systems where explicit, written authorization has been obtained.
- **Default Localhost Restriction**: By default, host allowlists only permit `127.0.0.1` and `localhost`. Testing remote hosts requires modifying `config/scan_config.yaml`.
- **Non-Destructive Testing**: Test methods default strictly to safe, non-mutating HTTP methods (`GET`). Dangerous write/delete operations are not simulated.
- **Synthetic Test Identities**: All fixtures operate on synthetic mock users (`alice`, `bob`, `carol`, `admin`).

---

## 2. Technical Limitations
1. **Response Field Dependency**: BOLA detection checks response metadata (`owner_id`, `requested_by`). Opaque bodies with no identity context return `INCONCLUSIVE`.
2. **Token Support**: The current version uses standard simulated test headers (`X-Test-User`). OAuth2 bearer tokens, JWT validation, and session cookies require custom header mapping.
3. **Static Endpoint Specification**: Automatic crawling or endpoint discovery is not supported in v2.0.0; endpoints must be defined in the YAML configuration.
4. **Preliminary Severity**: Severity ratings (High, Medium, Low) are heuristic estimates and do not represent formal CVSS scores.
