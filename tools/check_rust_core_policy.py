#!/usr/bin/env python3
"""Fast source-level architecture gate for the Phase-0 Rust Vault Core.

This does not replace Cargo/Clippy/Android target compilation. It catches trust-
boundary regressions before those heavier jobs run.
"""

from __future__ import annotations

import argparse
import re
import shlex
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

RUST_GAP = r"(?:\s|//[^\n]*(?:\n|$)|/\*.*?\*/)*"
FORBIDDEN_SOURCE_PATTERNS = (
    ('extern "C"', re.compile(rf'\bextern{RUST_GAP}"C"', re.DOTALL)),
    ("jni::", re.compile(rf"\bjni{RUST_GAP}::{RUST_GAP}", re.DOTALL)),
    (
        "std::net",
        re.compile(
            rf"\bstd{RUST_GAP}::{RUST_GAP}(?:net\b|\{{[^}}]*\bnet\b)",
            re.DOTALL,
        ),
    ),
    (
        "tokio::net",
        re.compile(
            rf"\btokio{RUST_GAP}::{RUST_GAP}(?:net\b|\{{[^}}]*\bnet\b)",
            re.DOTALL,
        ),
    ),
    ("reqwest::", re.compile(rf"\breqwest{RUST_GAP}::{RUST_GAP}", re.DOTALL)),
    ("ureq::", re.compile(rf"\bureq{RUST_GAP}::{RUST_GAP}", re.DOTALL)),
)

DEPENDENCY_TABLE_NAMES = {
    "dependencies",
    "dev-dependencies",
    "build-dependencies",
}

CARGO_COMPILE_COMMANDS = {"build", "check", "clippy", "test"}
REQUIRED_CARGO_COMMANDS = {"check", "clippy", "test"}


class PolicyError(RuntimeError):
    """Raised when the Rust trust-boundary policy is violated."""


def load_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def iter_dependencies(table: object, path: tuple[str, ...] = ()):
    """Yield dependency aliases/specs from normal/dev/build and target tables."""
    if not isinstance(table, dict):
        return

    for key, value in table.items():
        next_path = path + (str(key),)
        if key in DEPENDENCY_TABLE_NAMES and isinstance(value, dict):
            for dependency_alias, dependency_spec in value.items():
                yield str(dependency_alias), dependency_spec, ".".join(next_path)
        else:
            yield from iter_dependencies(value, next_path)


def dependency_package_name(
    alias: str,
    spec: object,
    workspace_dependencies: dict[str, object],
) -> str:
    """Resolve a Cargo dependency alias to the package name it imports."""
    if not isinstance(spec, dict):
        return alias

    package = spec.get("package")
    if isinstance(package, str):
        return package

    if spec.get("workspace") is True:
        inherited = workspace_dependencies.get(alias)
        if isinstance(inherited, dict):
            inherited_package = inherited.get("package")
            if isinstance(inherited_package, str):
                return inherited_package

    return alias


def check_foundation_locked_commands(path: Path) -> None:
    """Require every compiling Cargo command in Foundation CI to use the lockfile."""
    seen_commands: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        command = raw_line.strip()
        if command.startswith("run:"):
            command = command.removeprefix("run:").strip()
        if not command.startswith("cargo "):
            continue
        try:
            tokens = shlex.split(command, comments=True, posix=True)
        except ValueError as error:
            raise PolicyError(f"invalid Cargo command in {path.name}: {error}") from error

        subcommand = next(
            (token for token in tokens[1:] if token in CARGO_COMPILE_COMMANDS),
            None,
        )
        if subcommand is None:
            continue
        seen_commands.add(subcommand)
        if "--locked" not in tokens:
            raise PolicyError(
                f"Foundation cargo {subcommand} command must use --locked"
            )

    missing_commands = REQUIRED_CARGO_COMMANDS - seen_commands
    if missing_commands:
        missing = ", ".join(sorted(missing_commands))
        raise PolicyError(f"Foundation workflow missing Cargo command(s): {missing}")


def check_dependabot_cargo_directory(path: Path) -> None:
    """Require Dependabot to track the Rust workspace lockfile and manifests."""
    in_cargo_update = False
    has_rust_cargo_update = False

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line.startswith("- package-ecosystem:"):
            ecosystem = line.split(":", 1)[1].strip().strip("'\"")
            in_cargo_update = ecosystem == "cargo"
        elif in_cargo_update and line.startswith("directory:"):
            directory = line.split(":", 1)[1].strip().strip("'\"")
            if directory == "/rust":
                has_rust_cargo_update = True

    if not has_rust_cargo_update:
        raise PolicyError("Dependabot cargo updates must target /rust")


SELF_TEST_IGNORE = shutil.ignore_patterns(
    ".git",
    ".gradle",
    ".cxx",
    ".externalNativeBuild",
    "__pycache__",
    "build",
    "target",
    "*.pyc",
)


def copy_self_test_tree(source: Path, destination: Path) -> None:
    """Copy only policy-relevant project content into a mutation sandbox."""
    shutil.copytree(source, destination, ignore=SELF_TEST_IGNORE)


def check(root: Path) -> None:
    workspace = root / "rust" / "Cargo.toml"
    core_manifest = root / "rust" / "vault-core" / "Cargo.toml"
    core_src = root / "rust" / "vault-core" / "src"
    toolchain_path = root / "rust-toolchain.toml"
    lockfile = root / "rust" / "Cargo.lock"
    foundation_workflow = root / ".github" / "workflows" / "foundation.yml"
    dependabot_config = root / ".github" / "dependabot.yml"

    for required in (
        workspace,
        core_manifest,
        lockfile,
        toolchain_path,
        core_src / "lib.rs",
        foundation_workflow,
        dependabot_config,
    ):
        if not required.exists():
            raise PolicyError(f"missing {required.relative_to(root)}")
    check_foundation_locked_commands(foundation_workflow)
    check_dependabot_cargo_directory(dependabot_config)

    workspace_data = load_toml(workspace)
    core_data = load_toml(core_manifest)
    toolchain = load_toml(toolchain_path)
    workspace_dependencies = workspace_data.get("workspace", {}).get(
        "dependencies", {}
    )
    if not isinstance(workspace_dependencies, dict):
        workspace_dependencies = {}

    package_defaults = workspace_data.get("workspace", {}).get("package", {})
    if package_defaults.get("license") != "AGPL-3.0-only":
        raise PolicyError("workspace license must be AGPL-3.0-only")
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

    for alias, spec, dependency_table in iter_dependencies(core_data):
        package_name = dependency_package_name(alias, spec, workspace_dependencies)
        checked_names = {alias.lower(), package_name.lower()}
        if any(
            fragment in checked_name
            for checked_name in checked_names
            for fragment in FORBIDDEN_DEP_FRAGMENTS
        ):
            alias_note = "" if alias == package_name else f" (declared as {alias})"
            raise PolicyError(
                "forbidden vault-core dependency: "
                f"{package_name}{alias_note} ({dependency_table})"
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
        for label, pattern in FORBIDDEN_SOURCE_PATTERNS:
            if pattern.search(text):
                raise PolicyError(
                    f"forbidden source path {label!r} in {path.relative_to(root)}"
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
        copy_self_test_tree(real_root, temp_root)
        check(temp_root)
        manifest = temp_root / "rust" / "vault-core" / "Cargo.toml"
        manifest.write_text(
            manifest.read_text(encoding="utf-8") + '\nreqwest = "0.12"\n',
            encoding="utf-8",
        )
        expect_failure(temp_root, "forbidden vault-core dependency: reqwest")

    with tempfile.TemporaryDirectory(prefix="rust-core-policy-") as temp:
        temp_root = Path(temp) / "project"
        copy_self_test_tree(real_root, temp_root)
        manifest = temp_root / "rust" / "vault-core" / "Cargo.toml"
        manifest.write_text(
            manifest.read_text(encoding="utf-8")
            + '\n[target.\'cfg(target_os = "android")\'.build-dependencies]\njni = "0.21"\n',
            encoding="utf-8",
        )
        expect_failure(temp_root, "forbidden vault-core dependency: jni")


    with tempfile.TemporaryDirectory(prefix="rust-core-policy-") as temp:
        temp_root = Path(temp) / "project"
        copy_self_test_tree(real_root, temp_root)
        manifest = temp_root / "rust" / "vault-core" / "Cargo.toml"
        manifest.write_text(
            manifest.read_text(encoding="utf-8")
            + '\nnetwork_client = { package = "reqwest", version = "0.12" }\n',
            encoding="utf-8",
        )
        expect_failure(temp_root, "forbidden vault-core dependency: reqwest")

    with tempfile.TemporaryDirectory(prefix="rust-core-policy-") as temp:
        temp_root = Path(temp) / "project"
        copy_self_test_tree(real_root, temp_root)
        workspace_manifest = temp_root / "rust" / "Cargo.toml"
        workspace_manifest.write_text(
            workspace_manifest.read_text(encoding="utf-8")
            + '\n[workspace.dependencies]\n'
            + 'network_client = { package = "reqwest", version = "0.12" }\n',
            encoding="utf-8",
        )
        core_manifest = temp_root / "rust" / "vault-core" / "Cargo.toml"
        core_manifest.write_text(
            core_manifest.read_text(encoding="utf-8")
            + "\nnetwork_client.workspace = true\n",
            encoding="utf-8",
        )
        expect_failure(temp_root, "forbidden vault-core dependency: reqwest")

    with tempfile.TemporaryDirectory(prefix="rust-core-policy-") as temp:
        temp_root = Path(temp) / "project"
        copy_self_test_tree(real_root, temp_root)
        (temp_root / "rust" / "vault-core" / "build.rs").write_text(
            "fn main() {}\n", encoding="utf-8"
        )
        expect_failure(temp_root, "vault-core must not contain build.rs")

    with tempfile.TemporaryDirectory(prefix="rust-core-policy-") as temp:
        temp_root = Path(temp) / "project"
        copy_self_test_tree(real_root, temp_root)
        lib = temp_root / "rust" / "vault-core" / "src" / "lib.rs"
        lib.write_text(
            lib.read_text(encoding="utf-8") + '\nfn forbidden() { let _ = std::net::TcpStream::connect("127.0.0.1:1"); }\n',
            encoding="utf-8",
        )
        expect_failure(temp_root, "forbidden source path 'std::net'")


    with tempfile.TemporaryDirectory(prefix="rust-core-policy-") as temp:
        temp_root = Path(temp) / "project"
        copy_self_test_tree(real_root, temp_root)
        lib = temp_root / "rust" / "vault-core" / "src" / "lib.rs"
        lib.write_text(
            lib.read_text(encoding="utf-8")
            + "\nfn forbidden_grouped_import() {\n"
            + "    use std /* policy whitespace */ :: { io,\n"
            + "        net::TcpStream,\n"
            + "    };\n"
            + '    let _ = TcpStream::connect("127.0.0.1:1");\n'
            + "}\n",
            encoding="utf-8",
        )
        expect_failure(temp_root, "forbidden source path 'std::net'")

    with tempfile.TemporaryDirectory(prefix="rust-core-policy-") as temp:
        temp_root = Path(temp) / "project"
        copy_self_test_tree(real_root, temp_root)
        (temp_root / "rust" / "Cargo.lock").unlink()
        expect_failure(temp_root, "Cargo.lock")

    with tempfile.TemporaryDirectory(prefix="rust-core-policy-") as temp:
        temp_root = Path(temp) / "project"
        copy_self_test_tree(real_root, temp_root)
        workflow = temp_root / ".github" / "workflows" / "foundation.yml"
        text = workflow.read_text(encoding="utf-8")
        if " --locked" not in text:
            raise AssertionError("Foundation self-test requires a --locked command")
        workflow.write_text(text.replace(" --locked", "", 1), encoding="utf-8")
        expect_failure(temp_root, "must use --locked")

    with tempfile.TemporaryDirectory(prefix="rust-core-policy-") as temp:
        temp_root = Path(temp) / "project"
        copy_self_test_tree(real_root, temp_root)
        dependabot = temp_root / ".github" / "dependabot.yml"
        text = dependabot.read_text(encoding="utf-8")
        if "directory: /rust" not in text:
            raise AssertionError("Dependabot self-test requires the /rust directory")
        dependabot.write_text(
            text.replace("directory: /rust", "directory: /", 1),
            encoding="utf-8",
        )
        expect_failure(temp_root, "Dependabot cargo updates must target /rust")

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
