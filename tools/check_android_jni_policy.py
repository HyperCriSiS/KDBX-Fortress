#!/usr/bin/env python3
"""Fast source-level policy gate for the dedicated Android/JNI adapter crate."""

from __future__ import annotations

import argparse
import shutil
import tempfile
import tomllib
from pathlib import Path

ALLOWED_DEPENDENCIES = {"jni", "vault-core"}
FORBIDDEN_SOURCE_FRAGMENTS = (
    "std::net",
    "std :: net",
    "std::{net",
    "tokio::",
    "reqwest::",
    "ureq::",
    "SecretBytes",
    "get_password",
    "get_raw_otp_value",
    "fields::PASSWORD",
    "fields::OTP",
    "attachment.content",
    "unsafe fn",
    "unsafe extern",
    "unsafe {",
)
EXPECTED_EXPORTS = (
    "Java_world_w3b_kdbxfortress_bridge_NativeBridge_nativeCapabilityProbe",
    "Java_world_w3b_kdbxfortress_bridge_NativeBridge_nativeOpenVault",
    "Java_world_w3b_kdbxfortress_bridge_NativeBridge_nativeLockVault",
    "Java_world_w3b_kdbxfortress_bridge_NativeBridge_nativeLockAllVaults",
    "Java_world_w3b_kdbxfortress_bridge_NativeBridge_nativeIsVaultHandleValid",
    "Java_world_w3b_kdbxfortress_bridge_NativeBridge_nativeReadMetadata",
)
JNI_EXPORT_PREFIX = "Java_world_w3b_kdbxfortress_bridge_NativeBridge_native"
EXPECTED_UNSAFE_ALLOW = "#[allow(unsafe_code)]"
EXPECTED_UNSAFE_EXPORT = "#[unsafe(no_mangle)]"


class PolicyError(RuntimeError):
    """Raised when the Android/JNI lifecycle policy is violated."""


def load_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def check(root: Path) -> None:
    workspace_path = root / "rust" / "Cargo.toml"
    adapter_manifest_path = root / "rust" / "android-jni" / "Cargo.toml"
    adapter_src = root / "rust" / "android-jni" / "src"
    lib_path = adapter_src / "lib.rs"

    for required in (workspace_path, adapter_manifest_path, lib_path):
        if not required.exists():
            raise PolicyError(f"missing {required.relative_to(root)}")

    workspace = load_toml(workspace_path)
    adapter = load_toml(adapter_manifest_path)

    members = set(workspace.get("workspace", {}).get("members", []))
    if not {"vault-core", "android-jni"}.issubset(members):
        raise PolicyError("workspace must contain vault-core and android-jni")

    if adapter.get("package", {}).get("name") != "kdbx-fortress-android-jni":
        raise PolicyError("unexpected Android/JNI adapter package name")

    crate_types = set(adapter.get("lib", {}).get("crate-type", []))
    if crate_types != {"cdylib", "rlib"}:
        raise PolicyError("Android/JNI adapter must build exactly cdylib and rlib")

    dependencies = adapter.get("dependencies", {})
    if set(dependencies) != ALLOWED_DEPENDENCIES:
        raise PolicyError(
            "Android/JNI adapter dependencies must be exactly jni and vault-core"
        )

    jni = dependencies.get("jni")
    if not isinstance(jni, dict):
        raise PolicyError("jni dependency must use an explicit inline table")
    if jni.get("version") != "=0.22.4":
        raise PolicyError("jni dependency must be pinned exactly to 0.22.4")
    if jni.get("default-features") is not False:
        raise PolicyError("jni default features must stay disabled")

    core = dependencies.get("vault-core")
    if not isinstance(core, dict):
        raise PolicyError("vault-core dependency must use an explicit inline table")
    if core.get("package") != "kdbx-fortress-vault-core":
        raise PolicyError("adapter must depend on the Fortress vault-core package")
    if core.get("path") != "../vault-core":
        raise PolicyError("adapter vault-core dependency must stay local and relative")

    if adapter.get("lints", {}).get("rust", {}).get("unsafe_code") != "deny":
        raise PolicyError("adapter must deny unsafe code crate-wide")

    source_files = sorted(adapter_src.rglob("*.rs"))
    source = "\n".join(path.read_text(encoding="utf-8") for path in source_files)

    if source.count(EXPECTED_UNSAFE_ALLOW) != len(EXPECTED_EXPORTS):
        raise PolicyError(
            "adapter must contain one local unsafe lint exception per approved JNI export"
        )
    if source.count(EXPECTED_UNSAFE_EXPORT) != len(EXPECTED_EXPORTS):
        raise PolicyError(
            "adapter must contain one unsafe export attribute per approved JNI export"
        )
    for symbol in EXPECTED_EXPORTS:
        if source.count(symbol) != 1:
            raise PolicyError(
                f"adapter must expose approved JNI symbol exactly once: {symbol}"
            )
    if source.count(JNI_EXPORT_PREFIX) != len(EXPECTED_EXPORTS):
        raise PolicyError("adapter must not expose unapproved NativeBridge JNI symbols")

    for fragment in FORBIDDEN_SOURCE_FRAGMENTS:
        if fragment in source:
            raise PolicyError(f"forbidden Android/JNI source fragment: {fragment}")


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
    with tempfile.TemporaryDirectory(prefix="android-jni-policy-") as temp:
        temp_root = Path(temp) / "project"
        shutil.copytree(real_root, temp_root)
        check(temp_root)
        manifest = temp_root / "rust" / "android-jni" / "Cargo.toml"
        manifest.write_text(
            manifest.read_text(encoding="utf-8") + '\nreqwest = "0.13"\n',
            encoding="utf-8",
        )
        expect_failure(temp_root, "dependencies must be exactly jni and vault-core")

    with tempfile.TemporaryDirectory(prefix="android-jni-policy-") as temp:
        temp_root = Path(temp) / "project"
        shutil.copytree(real_root, temp_root)
        lib = temp_root / "rust" / "android-jni" / "src" / "lib.rs"
        lib.write_text(
            lib.read_text(encoding="utf-8")
            + '\nfn forbidden_network() { let _ = std::net::TcpStream::connect("127.0.0.1:1"); }\n',
            encoding="utf-8",
        )
        expect_failure(temp_root, "forbidden Android/JNI source fragment: std::net")

    with tempfile.TemporaryDirectory(prefix="android-jni-policy-") as temp:
        temp_root = Path(temp) / "project"
        shutil.copytree(real_root, temp_root)
        lib = temp_root / "rust" / "android-jni" / "src" / "lib.rs"
        lib.write_text(
            lib.read_text(encoding="utf-8") + "\nunsafe fn forbidden_unsafe() {}\n",
            encoding="utf-8",
        )
        expect_failure(temp_root, "forbidden Android/JNI source fragment: unsafe fn")

    with tempfile.TemporaryDirectory(prefix="android-jni-policy-") as temp:
        temp_root = Path(temp) / "project"
        shutil.copytree(real_root, temp_root)
        manifest = temp_root / "rust" / "android-jni" / "Cargo.toml"
        text = manifest.read_text(encoding="utf-8").replace(
            'crate-type = ["cdylib", "rlib"]', 'crate-type = ["rlib"]'
        )
        manifest.write_text(text, encoding="utf-8")
        expect_failure(temp_root, "must build exactly cdylib and rlib")

    print("Android/JNI boundary policy self-test OK")


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
            print("Android/JNI boundary policy OK")
    except (PolicyError, AssertionError) as error:
        raise SystemExit(f"Android/JNI policy FAILED: {error}") from error


if __name__ == "__main__":
    main()
