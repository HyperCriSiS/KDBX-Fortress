#!/usr/bin/env python3
"""Validate KDBX fixture integrity, metadata, provenance, and derivations."""

from __future__ import annotations

import argparse
import base64
import binascii
from collections.abc import Callable
import hashlib
import json
import re
import shutil
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "test-fixtures" / "kdbx"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
GIT_EVIDENCE_RE = re.compile(r"git:[0-9a-f]{40}(?::[^\r\n]+)?")
ALLOWED_ENTRY_KEYS = {
    "file",
    "encoding",
    "sha256",
    "password",
    "format",
    "kdf",
    "outer_cipher",
    "inner_cipher",
    "purpose",
    "expected",
    "expected_failure",
    "keyfile",
    "provenance",
    "derivation",
}
PROVENANCE_KEYS = {
    "status",
    "source_kind",
    "evidence",
    "generator",
    "independent_oracle",
    "gaps",
}


class ValidationError(AssertionError):
    """Raised when fixture bytes or manifest metadata violate corpus policy."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def safe_fixture_name(value: object, label: str) -> str:
    require(isinstance(value, str) and value, f"{label} must be a non-empty string")
    path = Path(value)
    require(
        not path.is_absolute() and path.name == value and value not in {".", ".."},
        f"{label} must be a basename",
    )
    return value


def valid_sha256(value: object, label: str) -> str:
    require(
        isinstance(value, str) and SHA256_RE.fullmatch(value) is not None,
        f"{label} must be a lowercase SHA-256 digest",
    )
    return value


def read_manifest(directory: Path) -> dict:
    manifest_path = directory / "manifest.json"
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValidationError(f"invalid fixture manifest: {error}") from error
    require(isinstance(data, dict), "KDBX fixture manifest must be an object")
    require(set(data) == {"schema", "fixtures"}, "unexpected manifest keys")
    require(data["schema"] == 2, "unsupported KDBX fixture manifest schema")
    require(
        isinstance(data["fixtures"], list) and data["fixtures"],
        "KDBX fixture manifest must not be empty",
    )
    return data


def materialize_fixture(path: Path, encoding: object) -> bytes:
    require(encoding in {"raw", "base64"}, f"unsupported fixture encoding for {path.name}")
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise ValidationError(f"cannot read KDBX fixture {path.name}: {error}") from error
    if encoding == "raw":
        return payload
    try:
        return base64.b64decode(payload.strip(), validate=True)
    except binascii.Error as error:
        raise ValidationError(
            f"invalid base64 fixture encoding for {path.name}: {error}"
        ) from error


def validate_provenance(
    value: object,
    fixture_name: str,
    *,
    is_negative: bool,
) -> None:
    require(isinstance(value, dict), f"invalid provenance for {fixture_name}")
    require(
        set(value) == PROVENANCE_KEYS,
        f"unexpected provenance keys for {fixture_name}",
    )

    status = value["status"]
    require(status in {"complete", "incomplete"}, f"invalid provenance status for {fixture_name}")
    require(
        value["source_kind"]
        in {
            "historical-generator-workflow",
            "repository-introduction",
            "deterministic-derivation",
            "upstream",
        },
        f"invalid provenance source kind for {fixture_name}",
    )

    evidence = value["evidence"]
    require(
        isinstance(evidence, list)
        and evidence
        and all(
            isinstance(item, str) and GIT_EVIDENCE_RE.fullmatch(item) is not None
            for item in evidence
        ),
        f"invalid provenance evidence for {fixture_name}",
    )

    generator = value["generator"]
    if generator is not None:
        require(
            isinstance(generator, dict) and set(generator) == {"name", "version"},
            f"invalid generator metadata for {fixture_name}",
        )
        require(
            isinstance(generator["name"], str) and generator["name"],
            f"missing generator name for {fixture_name}",
        )
        require(
            generator["version"] is None
            or (isinstance(generator["version"], str) and generator["version"]),
            f"invalid generator version for {fixture_name}",
        )

    oracle = value["independent_oracle"]
    if oracle is not None:
        require(
            isinstance(oracle, dict)
            and set(oracle) == {"name", "version", "result"},
            f"invalid independent oracle metadata for {fixture_name}",
        )
        require(
            all(isinstance(oracle[key], str) and oracle[key] for key in oracle),
            f"incomplete independent oracle metadata for {fixture_name}",
        )

    gaps = value["gaps"]
    require(
        isinstance(gaps, list)
        and all(isinstance(gap, str) and gap for gap in gaps),
        f"invalid provenance gaps for {fixture_name}",
    )
    if status == "incomplete":
        require(gaps, f"incomplete provenance must name gaps for {fixture_name}")
    else:
        require(not gaps, f"complete provenance must not name gaps for {fixture_name}")
        if not is_negative:
            require(
                generator is not None and generator["version"] is not None,
                f"complete local provenance requires a pinned generator for {fixture_name}",
            )
            require(
                oracle is not None,
                f"complete positive provenance requires an independent oracle for {fixture_name}",
            )

    if not is_negative and (
        generator is None
        or generator["version"] is None
        or oracle is None
    ):
        require(
            status == "incomplete",
            f"unresolved positive provenance must be incomplete for {fixture_name}",
        )


def validate_keyfile(
    directory: Path,
    value: object,
    fixture_name: str,
    declared_files: set[str],
) -> None:
    require(isinstance(value, dict), f"invalid keyfile metadata for {fixture_name}")
    require(
        set(value) == {"file", "format", "size", "sha256"},
        f"unexpected keyfile metadata for {fixture_name}",
    )
    name = safe_fixture_name(value["file"], f"keyfile name for {fixture_name}")
    require(name not in declared_files, f"duplicate fixture/keyfile name: {name}")
    declared_files.add(name)
    path = directory / name
    require(path.is_file(), f"missing keyfile fixture: {name}")
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise ValidationError(f"cannot read keyfile fixture {name}: {error}") from error

    expected_hash = valid_sha256(value["sha256"], f"keyfile SHA-256 for {name}")
    require(
        hashlib.sha256(payload).hexdigest() == expected_hash,
        f"SHA-256 mismatch for keyfile {name}",
    )
    require(
        isinstance(value["size"], int)
        and not isinstance(value["size"], bool)
        and value["size"] >= 0,
        f"invalid keyfile size for {name}",
    )
    require(len(payload) == value["size"], f"size mismatch for keyfile {name}")
    require(value["format"] == "raw32", f"unsupported keyfile format for {name}")
    require(len(payload) == 32, f"raw32 keyfile must contain exactly 32 bytes: {name}")


def validate_derivation(
    value: object,
    fixture_name: str,
    materialized: dict[str, bytes],
) -> None:
    require(isinstance(value, dict), f"missing derivation metadata for {fixture_name}")
    require(
        set(value) == {"source_file", "operation", "parameters"},
        f"unexpected derivation metadata for {fixture_name}",
    )
    source_name = safe_fixture_name(
        value["source_file"], f"derivation source for {fixture_name}"
    )
    require(source_name in materialized, f"unknown derivation source for {fixture_name}")
    operation = value["operation"]
    parameters = value["parameters"]
    require(isinstance(parameters, dict), f"invalid derivation parameters for {fixture_name}")

    source = materialized[source_name]
    if operation == "prefix":
        require(set(parameters) == {"length"}, f"invalid prefix parameters for {fixture_name}")
        length = parameters["length"]
        require(
            isinstance(length, int) and not isinstance(length, bool) and length >= 0,
            f"invalid prefix length for {fixture_name}",
        )
        expected = source[:length]
    elif operation == "xor-byte":
        require(
            set(parameters) == {"offset", "mask"},
            f"invalid xor-byte parameters for {fixture_name}",
        )
        offset = parameters["offset"]
        mask = parameters["mask"]
        require(
            isinstance(offset, int)
            and not isinstance(offset, bool)
            and 0 <= offset < len(source),
            f"invalid xor-byte offset for {fixture_name}",
        )
        require(
            isinstance(mask, int)
            and not isinstance(mask, bool)
            and 1 <= mask <= 255,
            f"invalid xor-byte mask for {fixture_name}",
        )
        mutated = bytearray(source)
        mutated[offset] ^= mask
        expected = bytes(mutated)
    else:
        raise ValidationError(f"unsupported derivation operation for {fixture_name}")

    require(
        materialized[fixture_name] == expected,
        f"derivation mismatch for {fixture_name}",
    )


def validate_all(directory: Path = FIXTURES) -> int:
    manifest = read_manifest(directory)
    entries = manifest["fixtures"]
    declared_files: set[str] = set()
    materialized: dict[str, bytes] = {}
    negative_entries: list[dict] = []

    for entry in entries:
        require(isinstance(entry, dict), "fixture entry must be an object")
        require(
            set(entry).issubset(ALLOWED_ENTRY_KEYS),
            f"unexpected fixture metadata keys: {sorted(set(entry) - ALLOWED_ENTRY_KEYS)}",
        )
        required = {"file", "sha256", "format", "purpose", "provenance"}
        require(required.issubset(entry), "fixture entry is missing required metadata")

        name = safe_fixture_name(entry["file"], "fixture file")
        require(name not in declared_files, f"duplicate fixture file: {name}")
        declared_files.add(name)
        path = directory / name
        require(path.is_file(), f"missing KDBX fixture: {name}")

        encoding = entry.get("encoding", "raw")
        decoded = materialize_fixture(path, encoding)
        materialized[name] = decoded
        expected_hash = valid_sha256(entry["sha256"], f"fixture SHA-256 for {name}")
        require(
            hashlib.sha256(decoded).hexdigest() == expected_hash,
            f"SHA-256 mismatch for materialized {name}",
        )
        require(entry["format"] in {"KDBX3", "KDBX4"}, f"unsupported format label for {name}")
        require(
            isinstance(entry["purpose"], str) and entry["purpose"],
            f"missing fixture purpose for {name}",
        )
        if "password" in entry:
            require(isinstance(entry["password"], str), f"invalid fixture password for {name}")
        if "kdf" in entry:
            require(
                entry["kdf"] is None or isinstance(entry["kdf"], dict),
                f"invalid KDF metadata for {name}",
            )
        if "outer_cipher" in entry:
            require(
                entry["outer_cipher"] is None
                or (isinstance(entry["outer_cipher"], str) and entry["outer_cipher"]),
                f"invalid outer cipher metadata for {name}",
            )

        is_negative = "expected_failure" in entry
        require(
            is_negative != ("expected" in entry),
            f"fixture must declare exactly one of expected/expected_failure: {name}",
        )
        if is_negative:
            require(
                isinstance(entry["expected_failure"], str) and entry["expected_failure"],
                f"missing expected failure category for {name}",
            )
            require("derivation" in entry, f"negative fixture must declare derivation: {name}")
            negative_entries.append(entry)
        else:
            require(
                isinstance(entry["expected"], dict) and entry["expected"],
                f"missing expected content for {name}",
            )
            require("derivation" not in entry, f"positive fixture must not declare derivation: {name}")

        validate_provenance(entry["provenance"], name, is_negative=is_negative)
        if "keyfile" in entry:
            validate_keyfile(directory, entry["keyfile"], name, declared_files)

    for entry in negative_entries:
        validate_derivation(entry["derivation"], entry["file"], materialized)

    actual_payloads = {
        path.name
        for pattern in ("*.kdbx", "*.kdbx.b64", "*.key")
        for path in directory.glob(pattern)
        if path.is_file()
    }
    require(
        actual_payloads == declared_files,
        "fixture manifest coverage mismatch: "
        f"undeclared={sorted(actual_payloads - declared_files)}, "
        f"missing={sorted(declared_files - actual_payloads)}",
    )
    return len(entries)


def expect_invalid(directory: Path, mutate: Callable[[dict], None], fragment: str) -> None:
    manifest_path = directory / "manifest.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    mutate(data)
    manifest_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    try:
        validate_all(directory)
    except ValidationError as error:
        require(fragment in str(error), f"expected {fragment!r}, got {error!r}")
    else:
        raise AssertionError(f"validator accepted invalid corpus; expected {fragment!r}")


def self_test() -> None:
    count = validate_all()
    cases = (
        (
            lambda data: data["fixtures"].__setitem__(
                1, {**data["fixtures"][1], "file": data["fixtures"][0]["file"]}
            ),
            "duplicate fixture file",
        ),
        (
            lambda data: data["fixtures"][0].__setitem__("file", "../escape.kdbx"),
            "must be a basename",
        ),
        (
            lambda data: data["fixtures"][0]["provenance"].__setitem__("gaps", []),
            "incomplete provenance must name gaps",
        ),
        (
            lambda data: data["fixtures"][0].__setitem__("sha256", "0" * 64),
            "SHA-256 mismatch",
        ),
        (
            lambda data: data["fixtures"][-1]["derivation"]["parameters"].__setitem__(
                "mask", 1
            ),
            "derivation mismatch",
        ),
    )
    for mutate, fragment in cases:
        with tempfile.TemporaryDirectory(prefix="kdbx-fixture-validator-") as temp:
            copied = Path(temp) / "kdbx"
            shutil.copytree(FIXTURES, copied)
            expect_invalid(copied, mutate, fragment)
    print(f"KDBX validator self-test OK ({count} baseline fixtures)")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
        else:
            count = validate_all()
            print(f"validated {count} KDBX fixture(s)")
    except (ValidationError, AssertionError) as error:
        raise SystemExit(f"KDBX fixture validation FAILED: {error}") from error


if __name__ == "__main__":
    main()
