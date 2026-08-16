#!/usr/bin/env python3
"""Dependency-free validation for sanitized FormSnapshot fixtures."""

from __future__ import annotations

import argparse
import json
import re
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "test-fixtures" / "form" / "fixtures"
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]+$")
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
URL_RE = re.compile(r"https?://", re.I)
TOKEN_RE = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})")
SUSPICIOUS_KEYS = {"password", "secret", "token", "cookie", "credential", "value"}
VALID_ROLES = {"Username", "Email", "AccountId", "CurrentPassword", "NewPassword", "ConfirmPassword", "OTP", "PIN", "Custom", "Unknown"}


class ValidationError(RuntimeError):
    pass


def reject_sensitive(value: object, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in SUSPICIOUS_KEYS:
                raise ValidationError(f"suspicious secret-bearing key at {path}.{key}")
            reject_sensitive(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_sensitive(child, f"{path}[{index}]")
    elif isinstance(value, str):
        if EMAIL_RE.search(value):
            raise ValidationError(f"email-like PII at {path}")
        if URL_RE.search(value):
            raise ValidationError(f"URL not allowed in fixture payload at {path}")
        if TOKEN_RE.search(value):
            raise ValidationError(f"token-like data at {path}")


def validate_file(path: Path) -> None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid JSON: {path}: {exc}") from exc

    if set(data) != {"id", "source", "expected", "fields"}:
        raise ValidationError(f"unexpected top-level keys in {path.name}")
    if not isinstance(data["id"], str) or not ID_RE.fullmatch(data["id"]):
        raise ValidationError(f"invalid fixture id in {path.name}")
    if path.stem != data["id"]:
        raise ValidationError(f"filename/id mismatch in {path.name}")

    source = data["source"]
    if not isinstance(source, dict) or source.get("kind") not in {"synthetic", "public-bug-class"}:
        raise ValidationError(f"invalid source metadata in {path.name}")
    if set(source) - {"kind", "reference"}:
        raise ValidationError(f"unexpected source metadata in {path.name}")

    expected = data["expected"]
    if not isinstance(expected, dict) or not isinstance(expected.get("roles"), dict):
        raise ValidationError(f"invalid expected roles in {path.name}")
    if set(expected) - {"roles", "notes"}:
        raise ValidationError(f"unexpected expected metadata in {path.name}")
    for role in expected["roles"].values():
        if role not in VALID_ROLES:
            raise ValidationError(f"unknown role {role!r} in {path.name}")

    fields = data["fields"]
    if not isinstance(fields, list) or not fields:
        raise ValidationError(f"fixture must contain fields: {path.name}")
    ids = set()
    for field in fields:
        if not isinstance(field, dict):
            raise ValidationError(f"field must be object in {path.name}")
        if set(field) - {"id", "inputType", "autofillHints", "htmlType", "name", "focused"}:
            raise ValidationError(f"unexpected field property in {path.name}")
        if not isinstance(field.get("id"), str) or not isinstance(field.get("inputType"), str):
            raise ValidationError(f"field id/inputType missing in {path.name}")
        if field["id"] in ids:
            raise ValidationError(f"duplicate field id in {path.name}")
        ids.add(field["id"])
        hints = field.get("autofillHints", [])
        if not isinstance(hints, list) or not all(isinstance(x, str) for x in hints):
            raise ValidationError(f"invalid hints in {path.name}")

    if set(expected["roles"]) != ids:
        raise ValidationError(f"expected role map must cover every field in {path.name}")

    reject_sensitive(data)


def validate_all(directory: Path = FIXTURE_DIR) -> int:
    paths = sorted(directory.glob("*.json"))
    if not paths:
        raise ValidationError("no form fixtures found")
    for path in paths:
        validate_file(path)
    return len(paths)


def self_test() -> None:
    count = validate_all()
    with tempfile.TemporaryDirectory(prefix="fixture-validator-") as tmp:
        bad = Path(tmp) / "bad.json"
        bad.write_text(json.dumps({
            "id": "bad", "source": {"kind": "synthetic"},
            "expected": {"roles": {"p": "CurrentPassword"}},
            "fields": [{"id": "p", "inputType": "password", "password": "do-not-store-this"}]
        }), encoding="utf-8")
        try:
            validate_file(bad)
        except ValidationError:
            pass
        else:
            raise AssertionError("validator accepted a secret-bearing fixture")
    print(f"Validator self-test OK ({count} baseline fixtures)")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
        else:
            count = validate_all()
            print(f"Fixture validation OK: {count} sanitized fixtures")
    except (ValidationError, AssertionError) as exc:
        raise SystemExit(f"Fixture validation FAILED: {exc}") from exc


if __name__ == "__main__":
    main()
