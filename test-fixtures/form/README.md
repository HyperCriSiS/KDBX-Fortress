# FormSnapshot fixtures

All fixtures in this directory are synthetic or sanitized representations of public bug classes. They must never contain real credentials, tokens, cookies, private URLs, email addresses, phone numbers, database contents, or user-provided secrets.

Each fixture records only the form structure needed for deterministic field-classification regressions. Public issue references may identify an issue number or repository but must not copy secret-bearing payloads from reports.

`tools/validate_form_fixtures.py` enforces the minimal structure and rejects common secret/PII patterns before fixtures enter CI.
