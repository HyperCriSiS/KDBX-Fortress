#!/usr/bin/env python3
"""Fast source-level architecture gate for the Phase-1 Rust Vault Core.

This does not replace Cargo/Clippy/Android target compilation. It catches trust-
boundary regressions before those heavier jobs run.
"""

from __future__ import annotations

import argparse
import shutil
import tempfile
import tomllib
from pathlib import Path

FORBIDDEN_DEP_FRAGMENTS = (
    "android",
    "hyper",
    "jni",
    "ktor",
    "reqwest",
    "socket",
    "tokio",
    "ureq",
)

FORBIDDEN_SOURCE_FRAGMENTS = (
    'extern "C"',
    "jni::",
    "std::net",
    "std :: net",
    "std::{net",
    "tokio::net",
    "reqwest::",
    "ureq::",
)

DEPENDENCY_TABLE_NAMES = {
    "dependencies",
    "dev-dependencies",
    "build-dependencies",
}


class PolicyError(RuntimeError):
    """Raised when the Rust trust-boundary policy is violated."""


def load_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def iter_dependency_names(table: object, path: tuple[str, ...] = ()):
    """Yield dependency names from normal/dev/build and target-specific tables."""
    if not isinstance(table, dict):
        return

    for key, value in table.items():
        next_path = path + (str(key),)
        if key in DEPENDENCY_TABLE_NAMES and isinstance(value, dict):
            for dependency_name in value:
                yield str(dependency_name), ".".join(next_path)
        else:
            yield from iter_dependency_names(value, next_path)


def check(root: Path) -> None:
    workspace = root / "rust" / "Cargo.toml"
    core_manifest = root / "rust" / "vault-core" / "Cargo.toml"
    core_src = root / "rust" / "vault-core" / "src"
    toolchain_path = root / "rust-toolchain.toml"

    for required in (workspace, core_manifest, toolchain_path, core_src / "lib.rs"):
        if not required.exists():
            raise PolicyError(f"missing {required.relative_to(root)}")

    workspace_data = load_toml(workspace)
    core_data = load_toml(core_manifest)
    toolchain = load_toml(toolchain_path)

    package_defaults = workspace_data.get("workspace", {}).get("package", {})
    if package_defaults.get("license") != "AGPL-3.0-or-later":
        raise PolicyError("workspace license must be AGPL-3.0-or-later")
    if package_defaults.get("publish") is not False:
        raise PolicyError("workspace crates must default to publish = false")
    if package_defaults.get("rust-version") != "1.97.1":
        raise PolicyError("unexpected Rust MSRV/toolchain baseline")

    configured_channel = toolchain.get("toolchain", {}).get("channel")
    if configured_channel != "1.97.1":
        raise PolicyError("rust-toolchain.toml must pin Rust 1.97.1")

    targets = set(toolchain.get("toolchain", {}).get("targets", []))
    required_targets = {"aarch64-linux-android", "x86_64-linux-android"}
    if not required_targets.issubset(targets):
        raise PolicyError("Android ARM64 and x86_64 Rust targets must be pinned")

    for name, dependency_table in iter_dependency_names(core_data):
        lower = name.lower()
        if any(fragment in lower for fragment in FORBIDDEN_DEP_FRAGMENTS):
            raise PolicyError(
                f"forbidden vault-core dependency: {name} ({dependency_table})"
            )

    if core_data.get("package", {}).get("build") is not None:
        raise PolicyError("vault-core must not configure a package build script")
    if (root / "rust" / "vault-core" / "build.rs").exists():
        raise PolicyError("vault-core must not contain build.rs")

    if core_data.get("lints", {}).get("workspace") is not True:
        raise PolicyError("vault-core must inherit workspace lints")

    rust_lints = workspace_data.get("workspace", {}).get("lints", {}).get("rust", {})
    if rust_lints.get("unsafe_code") != "forbid":
        raise PolicyError("vault-core workspace must forbid unsafe_code")

    for path in sorted(core_src.rglob("*.rs")):
        text = path.read_text(encoding="utf-8")
        for fragment in FORBIDDEN_SOURCE_FRAGMENTS:
            if fragment in text:
                raise PolicyError(
                    f"forbidden source fragment {fragment!r} in {path.relative_to(root)}"
                )


def expect_failure(root: Path, expected_fragment: str) -> None:
    try:
        check(root)
    except PolicyError as error:
        if expected_fragment not in str(error):
            raise AssertionError(
                f"expected failure containing {expected_fragment!r}, got: {error}"
            ) from error
    else:
        raise AssertionError(f"expected policy failure containing {expected_fragment!r}")


def self_test(real_root: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="rust-core-policy-") as temp:
        temp_root = Path(temp) / "project"
        shutil.copytree(real_root, temp_root)
        check(temp_root)
        manifest = temp_root / "rust" / "vault-core" / "Cargo.toml"
        manifest.write_text(
            manifest.read_text(encoding="utf-8") + '\nreqwest = "0.12"\n',
            encoding="utf-8",
        )
        expect_failure(temp_root, "forbidden vault-core dependency: reqwest")

    with tempfile.TemporaryDirectory(prefix="rust-core-policy-") as temp:
        temp_root = Path(temp) / "project"
        shutil.copytree(real_root, temp_root)
        manifest = temp_root / "rust" / "vault-core" / "Cargo.toml"
        manifest.write_text(
            manifest.read_text(encoding="utf-8")
            + '\n[target.\'cfg(target_os = "android")\'.build-dependencies]\njni = "0.21"\n',
            encoding="utf-8",
        )
        expect_failure(temp_root, "forbidden vault-core dependency: jni")

    with tempfile.TemporaryDirectory(prefix="rust-core-policy-") as temp:
        temp_root = Path(temp) / "project"
        shutil.copytree(real_root, temp_root)
        (temp_root / "rust" / "vault-core" / "build.rs").write_text(
            "fn main() {}\n", encoding="utf-8"
        )
        expect_failure(temp_root, "vault-core must not contain build.rs")

    with tempfile.TemporaryDirectory(prefix="rust-core-policy-") as temp:
        temp_root = Path(temp) / "project"
        shutil.copytree(real_root, temp_root)
        lib = temp_root / "rust" / "vault-core" / "src" / "lib.rs"
        lib.write_text(
            lib.read_text(encoding="utf-8") + '\nfn forbidden() { let _ = std::net::TcpStream::connect("127.0.0.1:1"); }\n',
            encoding="utf-8",
        )
        expect_failure(temp_root, "forbidden source fragment 'std::net'")

    print("Rust core policy self-test OK")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    try:
        if args.self_test:
            self_test(root)
        else:
            check(root)
            print("Rust core policy OK")
    except (PolicyError, AssertionError) as error:
        raise SystemExit(f"Rust core policy FAILED: {error}") from error


if __name__ == "__main__":
    main()
