#!/usr/bin/env python3
"""Repository structure and hygiene checks that do not require Rust."""

from __future__ import annotations

import re
import stat
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MAX_RUST_LINES = 300
MAX_FACADE_LINES = 120
SECRET_OWNER_TYPES = {
    "src/secret.rs": ["SecretBytes", "SecretString"],
    "src/credentials.rs": ["PreparedPassword", "PreparedCredentials"],
    "src/identity.rs": [
        "ReceivedAuthenticationIdentity",
        "ReceivedAuthorizationIdentity",
    ],
    "src/channel_binding.rs": [
        "ChannelBindingData",
        "ChannelBinding",
        "ChannelBindingMode",
    ],
    "src/outbound.rs": ["OutboundMessage"],
    "src/message/client_final_outbound.rs": ["ClientFinalWithoutProof"],
    "src/client/config.rs": ["ClientConfig", "ClientConfigBuilder"],
    "src/client/begin.rs": ["AwaitingServerFirst"],
    "src/client/derivation.rs": ["PendingDerivation"],
    "src/client/server_final.rs": ["AwaitingServerFinal"],
    "src/salt.rs": ["Salt"],
    "src/server/credential.rs": ["ServerCredential", "PendingServerCredential"],
    "src/server/concealment.rs": ["ConcealmentKey"],
    "src/server/config.rs": ["Server"],
    "src/server/client_first.rs": ["NeedCredential"],
    "src/server/identity_preparation.rs": ["NeedIdentityPreparation"],
}
ZEROIZING_REDACTED_TYPES = {
    "src/identity.rs": [
        "PreparedAuthenticationIdentity",
        "PreparedAuthorizationIdentity",
    ],
}
GENERIC_ORCHESTRATION_TYPES = {
    "src/server/concealment.rs": ["CredentialResponse"],
    "src/server/client_final.rs": ["AwaitingClientFinal", "ProofResult"],
    "src/server/authorization.rs": ["PendingAuthorization", "AuthorizationOutcome"],
}
FORBIDDEN_SECRET_TRAITS = {
    "AsRef",
    "Borrow",
    "Clone",
    "Copy",
    "Deref",
    "Deserialize",
    "Display",
    "Eq",
    "Hash",
    "Ord",
    "PartialEq",
    "PartialOrd",
    "Serialize",
}
TEXT_SUFFIXES = {
    ".lock",
    ".md",
    ".py",
    ".rs",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
TEXT_FILENAMES = {"check", "examples-check", "fuzz-check", "package-check"}


class Checks:
    def __init__(self) -> None:
        self.failures: list[str] = []

    def require(self, condition: bool, message: str) -> None:
        if not condition:
            self.failures.append(message)

    def finish(self) -> int:
        if self.failures:
            print("guardrails failed:", file=sys.stderr)
            for failure in self.failures:
                print(f"  - {failure}", file=sys.stderr)
            return 1
        print("guardrails passed")
        return 0


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as source:
        return tomllib.load(source)


def required_files(checks: Checks) -> None:
    names = [
        ".github/actions/setup-rust/action.yml",
        ".github/workflows/ci.yml",
        ".github/workflows/fuzz.yml",
        ".github/workflows/security.yml",
        "Cargo.lock",
        "Cargo.toml",
        "LICENSE",
        "README.md",
        "deny.toml",
        "examples/continuation_server.rs",
        "examples/scram_sha256_client.rs",
        "examples/scram_sha512_plus.rs",
        "examples/support/error.rs",
        "examples/support/mod.rs",
        "examples/support/nonce.rs",
        "fuzz/Cargo.lock",
        "fuzz/Cargo.toml",
        "fuzz/deny.toml",
        "fuzz/fuzz_targets/client_final.rs",
        "fuzz/fuzz_targets/client_first.rs",
        "fuzz/fuzz_targets/conversation.rs",
        "fuzz/fuzz_targets/server_final.rs",
        "fuzz/fuzz_targets/server_first.rs",
        "rust-toolchain.toml",
        "scripts/examples-check",
        "scripts/fuzz-check",
        "scripts/generate-unicode32-bidi.py",
        "scripts/guardrails.py",
        "scripts/package-check",
        "src/authentication.rs",
        "src/crypto/dispatch.rs",
        "src/crypto/sha512.rs",
        "src/identity.rs",
        "src/lib.rs",
        "src/policy_error.rs",
        "src/saslprep.rs",
        "src/saslprep/unicode32_bidi.rs",
        "src/salt.rs",
        "src/server/identity_preparation.rs",
        "tests/channel_binding.rs",
        "tests/hostile_messages.rs",
        "tests/client_state.rs",
        "tests/identity_properties.rs",
        "tests/kafka_sha512.rs",
        "tests/message_encoding.rs",
        "tests/preparation_profiles.rs",
        "tests/postgres_interop.rs",
        "tests/public_api.rs",
        "tests/rfc7677.rs",
        "tests/secret_safety.rs",
        "tests/server_authorization.rs",
        "tests/server_credential.rs",
        "tests/server_policy.rs",
        "tests/server_state.rs",
        "tests/sha512_state.rs",
        "tests/transcript_preservation.rs",
        "zcheck.toml",
        "zrail.lock",
        "zrail.toml",
    ]
    for name in names:
        checks.require((ROOT / name).is_file(), f"missing required file {name}")


def check_manifest(checks: Checks) -> None:
    manifest = load_toml(ROOT / "Cargo.toml")
    package = manifest.get("package", {})
    workspace = manifest.get("workspace", {})
    metadata = workspace.get("package", {})
    checks.require(workspace.get("resolver") == "3", "workspace resolver must be 3")
    checks.require(package.get("name") == "sasl-scram", "package name drift")
    checks.require(
        package.get("description") == "Strict, sans-I/O SCRAM for Rust.",
        "package description drift",
    )
    checks.require(metadata.get("authors") == ["zsumz <shawn@zsumz.com>"], "author drift")
    checks.require(metadata.get("license") == "Apache-2.0", "license drift")
    checks.require(metadata.get("rust-version") == "1.88", "MSRV drift")
    checks.require(
        metadata.get("repository") == "https://github.com/kafkars/sasl-scram",
        "repository metadata drift",
    )
    features = manifest.get("features", {})
    checks.require(
        features.get("default") == ["std", "sha256", "saslprep"],
        "default feature policy drift",
    )
    checks.require(features.get("std") == ["zeroize/std"], "std feature policy drift")
    checks.require("alloc" not in features, "allocation must not be a decorative crate feature")
    checks.require(
        features.get("sha512")
        == ["dep:ctutils", "dep:hmac", "dep:pbkdf2", "dep:sha2"],
        "sha512 feature policy drift",
    )
    for unavailable in ["legacy-sha1", "system-rng"]:
        checks.require(
            unavailable not in features,
            f"unimplemented feature must not be advertised: {unavailable}",
        )
    for forbidden in ["tokio", "async-std", "rustls", "openssl", "serde", "tracing"]:
        checks.require(forbidden not in features, f"forbidden adapter feature {forbidden}")
    dependency_tables = [
        workspace.get("dependencies", {}),
        manifest.get("dependencies", {}),
        manifest.get("dev-dependencies", {}),
        manifest.get("build-dependencies", {}),
    ]
    serde_dependencies = [
        name
        for dependencies in dependency_tables
        for name, specification in dependencies.items()
        if name == "serde"
        or (isinstance(specification, dict) and specification.get("package") == "serde")
    ]
    checks.require(not serde_dependencies, "serde dependencies are not permitted")
    rust_lints = workspace.get("lints", {}).get("rust", {})
    checks.require(rust_lints.get("unsafe_code") == "forbid", "unsafe code must be forbidden")


def check_repository(checks: Checks) -> None:
    checks.require(not (ROOT / ".gitmodules").exists(), "Git submodules are not permitted")
    checks.require(not (ROOT / "scripts/check").exists(), "zcheck must own qualification orchestration")
    for name in [
        "scripts/examples-check",
        "scripts/fuzz-check",
        "scripts/generate-unicode32-bidi.py",
        "scripts/guardrails.py",
        "scripts/package-check",
    ]:
        path = ROOT / name
        if path.exists():
            checks.require(bool(path.stat().st_mode & stat.S_IXUSR), f"{name} must be executable")
    for name in [".cargo/config", ".cargo/config.toml", ".cargo/audit.toml"]:
        checks.require(not (ROOT / name).exists(), f"repository-local Cargo config: {name}")
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    checks.require("__pycache__/" in gitignore, "Python bytecode directories must be ignored")
    checks.require("*.pyc" in gitignore, "Python bytecode files must be ignored")
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    checks.require(
        "cargo install zcheck --version 0.0.1 --locked" in ci,
        "CI must install the exact zcheck release",
    )
    checks.require(
        "run: zcheck run check --format github" in ci,
        "CI must run the canonical zcheck graph",
    )
    _, msrv_separator, msrv_job = ci.partition("\n  msrv:\n")
    checks.require(bool(msrv_separator), "CI must define an MSRV job")
    checks.require('name: MSRV (Rust 1.88)' in msrv_job, "CI must name the Rust 1.88 MSRV")
    checks.require(
        'toolchain: "1.88.0"' in msrv_job,
        "CI must install the exact MSRV toolchain",
    )
    checks.require(
        "cargo test --workspace --all-features --locked --offline" in msrv_job,
        "CI MSRV job must test the supported crate",
    )
    fuzz = (ROOT / ".github/workflows/fuzz.yml").read_text(encoding="utf-8")
    checks.require('cron: "37 5 * * 1"' in fuzz, "hosted fuzzing must run weekly")
    checks.require(
        "target: [client-first, server-first, client-final, server-final, conversation]" in fuzz,
        "hosted fuzzing must run every target",
    )
    checks.require(
        "cargo install cargo-fuzz --version 0.13.2 --locked" in fuzz,
        "hosted fuzzing must pin cargo-fuzz",
    )
    checks.require("-max_total_time=180" in fuzz, "hosted fuzzing must have a time bound")
    checks.require("-max_len=32768" in fuzz, "hosted fuzzing must cross message limits")


def text_files() -> list[Path]:
    roots = [
        ROOT / "src",
        ROOT / "tests",
        ROOT / "examples",
        ROOT / "scripts",
        ROOT / ".github",
        ROOT / "fuzz",
    ]
    files = [
        ROOT / "Cargo.toml",
        ROOT / "README.md",
        ROOT / "deny.toml",
        ROOT / "rust-toolchain.toml",
        ROOT / "rustfmt.toml",
        ROOT / "clippy.toml",
        ROOT / ".gitignore",
    ]
    for root in roots:
        files.extend(
            path
            for path in root.rglob("*")
            if path.is_file()
            and not {"__pycache__", "artifacts", "corpus", "target"}.intersection(
                path.relative_to(root).parts
            )
            and (path.suffix in TEXT_SUFFIXES or path.name in TEXT_FILENAMES)
        )
    return sorted(set(files))


def check_text(checks: Checks) -> None:
    for path in text_files():
        text = path.read_text(encoding="utf-8")
        name = relative(path)
        checks.require(text.endswith("\n"), f"{name} must end with a newline")
        for number, line in enumerate(text.splitlines(), start=1):
            checks.require("\t" not in line, f"{name}:{number} contains a tab")
            checks.require(line == line.rstrip(), f"{name}:{number} has trailing whitespace")


def check_rust(checks: Checks) -> None:
    rust_files = sorted((ROOT / "src").rglob("*.rs"))
    rust_files.extend(sorted((ROOT / "examples").rglob("*.rs")))
    facades = {ROOT / "src/lib.rs", ROOT / "src/message.rs"}
    forbidden = {
        r"\bunsafe\b": "unsafe code",
        r"\.unwrap\s*\(": "unwrap",
        r"\.expect\s*\(": "expect",
        r"\bpanic!\s*\(": "panic",
        r"\btodo!\s*\(": "todo",
        r"\bunimplemented!\s*\(": "unimplemented",
        r"\bunreachable!\s*\(": "unreachable",
        r"\bdbg!\s*\(": "dbg",
        r"#\s*\[\s*allow\s*\(": "lint suppression",
        r"#\s*\[\s*cfg\s*\(\s*test": "production test module",
        r"^\s*pub\s+use\s+.*::\*": "wildcard public re-export",
    }
    for path in rust_files:
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        name = relative(path)
        limit = MAX_FACADE_LINES if path in facades else MAX_RUST_LINES
        checks.require(len(lines) <= limit, f"{name} has {len(lines)} lines; limit is {limit}")
        checks.require(bool(lines) and lines[0].startswith("//!"), f"{name} needs module docs")
        for pattern, label in forbidden.items():
            checks.require(re.search(pattern, text, re.MULTILINE) is None, f"{name} contains {label}")
    for name in ["src/client/config.rs", "src/server/config.rs"]:
        text = (ROOT / name).read_text(encoding="utf-8")
        checks.require(
            "pub fn builder(algorithm: Algorithm)" in text,
            f"{name} must require explicit algorithm selection",
        )
        checks.require(
            re.search(r"pub(?:\s+const)?\s+fn\s+algorithm\s*\(", text) is None,
            f"{name} must not restore a feature-dependent algorithm setter",
        )


def check_secret_surfaces(checks: Checks) -> None:
    def reject_traits(path: Path, type_name: str, forbidden: set[str]) -> None:
        text = path.read_text(encoding="utf-8")
        checks.require(
            re.search(rf"pub\s+(?:struct|enum)\s+{type_name}\b", text) is not None,
            f"{relative(path)} is missing guarded type {type_name}",
        )
        derive = re.search(
            rf"#\s*\[\s*derive\s*\((?P<traits>[^)]*)\)\s*\]\s*"
            rf"(?:#\s*\[[^]]*\]\s*)*pub\s+(?:struct|enum)\s+{type_name}\b",
            text,
            re.MULTILINE,
        )
        if derive:
            derived = {
                item.strip().split("::")[-1]
                for item in derive.group("traits").split(",")
            }
            checks.require(
                not derived.intersection(forbidden.union({"Debug"})),
                f"{relative(path)} derives a forbidden trait for {type_name}",
            )
        for trait in sorted(forbidden):
            implementation = re.search(
                rf"impl(?:\s*<[^{{}}]*>)?\s+"
                rf"(?:[A-Za-z_][A-Za-z0-9_]*::)*{trait}(?:\s*<[^{{}}]*>)?\s+"
                rf"for\s+{type_name}\b",
                text,
                re.MULTILINE,
            )
            checks.require(
                implementation is None,
                f"{relative(path)} implements forbidden {trait} for {type_name}",
            )

    for name, type_names in SECRET_OWNER_TYPES.items():
        path = ROOT / name
        text = path.read_text(encoding="utf-8")
        for type_name in type_names:
            reject_traits(path, type_name, FORBIDDEN_SECRET_TRAITS)
            checks.require(
                re.search(
                    rf"impl(?:\s*<[^{{}}]*>)?\s+ZeroizeOnDrop\s+for\s+{type_name}\b",
                    text,
                )
                is not None,
                f"{name} does not guarantee zeroize-on-drop for {type_name}",
            )
            checks.require(
                re.search(
                    rf"impl(?:\s*<[^{{}}]*>)?\s+(?:fmt::)?Debug\s+for\s+{type_name}\b",
                    text,
                )
                is not None,
                f"{name} does not manually redact Debug for {type_name}",
            )
    for name, type_names in ZEROIZING_REDACTED_TYPES.items():
        path = ROOT / name
        text = path.read_text(encoding="utf-8")
        for type_name in type_names:
            reject_traits(path, type_name, {"Clone", "Copy", "Deserialize", "Display", "Serialize"})
            checks.require(
                re.search(rf"impl\s+ZeroizeOnDrop\s+for\s+{type_name}\b", text) is not None,
                f"{name} does not guarantee zeroize-on-drop for {type_name}",
            )
            checks.require(
                re.search(rf"impl\s+(?:fmt::)?Debug\s+for\s+{type_name}\b", text) is not None,
                f"{name} does not manually redact Debug for {type_name}",
            )
    for name, type_names in GENERIC_ORCHESTRATION_TYPES.items():
        path = ROOT / name
        text = path.read_text(encoding="utf-8")
        for type_name in type_names:
            reject_traits(path, type_name, FORBIDDEN_SECRET_TRAITS)
            checks.require(
                re.search(
                    rf"impl(?:\s*<[^{{}}]*>)?\s+ZeroizeOnDrop\s+for\s+{type_name}\b",
                    text,
                )
                is None,
                f"{name} overstates zeroize-on-drop for generic {type_name}",
            )
            checks.require(
                re.search(
                    rf"impl(?:\s*<[^{{}}]*>)?\s+(?:fmt::)?Debug\s+for\s+{type_name}\b",
                    text,
                )
                is not None,
                f"{name} does not manually redact Debug for {type_name}",
            )
    reject_traits(
        ROOT / "src/message/server_final.rs",
        "ServerFinalOutcome",
        {"Eq", "Hash", "Ord", "PartialEq", "PartialOrd"},
    )
    reject_traits(
        ROOT / "src/message/server_final.rs",
        "ServerVerifier",
        {"Display", "Eq", "Hash", "Ord", "PartialEq", "PartialOrd"},
    )
    error_text = (ROOT / "src/error.rs").read_text(encoding="utf-8")
    checks.require(
        re.search(r"\b(?:Box|String|Vec)\s*<|&\s*(?:str|\[u8\])", error_text) is None,
        "error vocabulary must not retain owned or borrowed peer text",
    )


def check_tests(checks: Checks) -> None:
    source_tests = sorted((ROOT / "src").rglob("*_test.rs"))
    checks.require(not source_tests, "tests must remain outside production source files")
    for path in sorted((ROOT / "tests").glob("*.rs")):
        text = path.read_text(encoding="utf-8")
        checks.require(text.startswith("//!"), f"{relative(path)} needs module docs")
        checks.require(len(text.splitlines()) <= MAX_RUST_LINES, f"{relative(path)} exceeds 300 lines")

    for path in sorted((ROOT / "fuzz/fuzz_targets").glob("*.rs")):
        text = path.read_text(encoding="utf-8")
        checks.require(text.startswith("//!"), f"{relative(path)} needs module docs")
        checks.require(len(text.splitlines()) <= MAX_RUST_LINES, f"{relative(path)} exceeds 300 lines")


def main() -> int:
    checks = Checks()
    required_files(checks)
    check_manifest(checks)
    check_repository(checks)
    check_text(checks)
    check_rust(checks)
    check_secret_surfaces(checks)
    check_tests(checks)
    return checks.finish()


if __name__ == "__main__":
    sys.exit(main())
