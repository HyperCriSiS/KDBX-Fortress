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

    if not isinstance(data, dict):
        raise ValidationError(f"fixture must be an object: {path.name}")
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
    if "reference" in source and not isinstance(source["reference"], str):
        raise ValidationError(f"source reference must be a string in {path.name}")

    expected = data["expected"]
    if not isinstance(expected, dict) or not isinstance(expected.get("roles"), dict):
        raise ValidationError(f"invalid expected roles in {path.name}")
    if set(expected) - {"roles", "notes"}:
        raise ValidationError(f"unexpected expected metadata in {path.name}")
    if "notes" in expected and not isinstance(expected["notes"], str):
        raise ValidationError(f"expected notes must be a string in {path.name}")
    for role in expected["roles"].values():
        if not isinstance(role, str) or role not in VALID_ROLES:
            raise ValidationError(f"invalid role {role!r} in {path.name}")

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

        for property_name in ("htmlType", "name"):
            if (
                property_name in field
                and field[property_name] is not None
                and not isinstance(field[property_name], str)
            ):
                raise ValidationError(
                    f"field {property_name} must be a string or null in {path.name}"
                )
        if "focused" in field and not isinstance(field["focused"], bool):
            raise ValidationError(f"field focused must be boolean in {path.name}")

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


def self_test_fixture() -> dict:
    return {
        "id": "bad",
        "source": {"kind": "synthetic"},
        "expected": {"roles": {"p": "CurrentPassword"}},
        "fields": [
            {
                "id": "p",
                "inputType": "password",
                "autofillHints": ["password"],
                "htmlType": None,
                "name": "password",
                "focused": True,
            }
        ],
    }


def expect_invalid_fixture(
    path: Path,
    payload: object,
    expected_fragment: str,
) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")
    try:
        validate_file(path)
    except ValidationError as error:
        if expected_fragment not in str(error):
            raise AssertionError(
                f"expected failure containing {expected_fragment!r}, got: {error}"
            ) from error
    else:
        raise AssertionError(
            f"validator accepted invalid fixture; expected {expected_fragment!r}"
        )


def self_test() -> None:
    count = validate_all()
    with tempfile.TemporaryDirectory(prefix="fixture-validator-") as tmp:
        bad = Path(tmp) / "bad.json"
        expect_invalid_fixture(bad, [], "fixture must be an object")

        invalid_cases = (
            (("source", "reference"), 42, "source reference must be a string"),
            (("expected", "notes"), [], "expected notes must be a string"),
            (("expected", "roles", "p"), [], "invalid role"),
            (("fields", 0, "autofillHints"), [7], "invalid hints"),
            (("fields", 0, "htmlType"), 7, "field htmlType"),
            (("fields", 0, "name"), {}, "field name"),
            (("fields", 0, "focused"), "yes", "field focused"),
            (
                ("expected", "notes"),
                "ghp_" + ("a" * 20),
                "token-like data",
            ),
            (
                ("fields", 0, "password"),
                "do-not-store-this",
                "unexpected field property",
            ),
        )
        for property_path, invalid_value, expected_fragment in invalid_cases:
            payload = self_test_fixture()
            parent = payload
            for key in property_path[:-1]:
                parent = parent[key]
            parent[property_path[-1]] = invalid_value
            expect_invalid_fixture(bad, payload, expected_fragment)

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
