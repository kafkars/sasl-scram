#!/usr/bin/env python3
"""Repository contracts that are not modeled by zrail."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
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
PREPARED_IDENTITY_TYPES = {
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


class Checks:
    def __init__(self) -> None:
        self.failures: list[str] = []

    def require(self, condition: bool, message: str) -> None:
        if not condition:
            self.failures.append(message)

    def finish(self) -> int:
        if self.failures:
            print("repository policy failed:", file=sys.stderr)
            for failure in self.failures:
                print(f"  - {failure}", file=sys.stderr)
            return 1
        print("repository policy passed")
        return 0


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as source:
        return tomllib.load(source)


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
    for adapter in ["tokio", "async-std", "rustls", "openssl", "serde", "tracing"]:
        checks.require(adapter not in features, f"adapter feature is not permitted: {adapter}")


def check_repository_contract(checks: Checks) -> None:
    checks.require(
        not (ROOT / "scripts/check").exists(),
        "zcheck must own qualification orchestration",
    )
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


def check_public_api_contract(checks: Checks) -> None:
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


def reject_traits(
    checks: Checks,
    path: Path,
    type_name: str,
    forbidden: set[str],
) -> None:
    text = path.read_text(encoding="utf-8")
    checks.require(
        re.search(rf"pub\s+(?:struct|enum)\s+{type_name}\b", text) is not None,
        f"{path.relative_to(ROOT).as_posix()} is missing guarded type {type_name}",
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
            f"{path.relative_to(ROOT).as_posix()} derives a forbidden trait for {type_name}",
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
            f"{path.relative_to(ROOT).as_posix()} implements forbidden {trait} for {type_name}",
        )


def check_secret_surfaces(checks: Checks) -> None:
    for name, type_names in SECRET_OWNER_TYPES.items():
        for type_name in type_names:
            reject_traits(checks, ROOT / name, type_name, FORBIDDEN_SECRET_TRAITS)

    prepared_forbidden = {"Clone", "Copy", "Deserialize", "Display", "Serialize"}
    for name, type_names in PREPARED_IDENTITY_TYPES.items():
        for type_name in type_names:
            reject_traits(checks, ROOT / name, type_name, prepared_forbidden)

    generic_forbidden = FORBIDDEN_SECRET_TRAITS.union({"ZeroizeOnDrop"})
    for name, type_names in GENERIC_ORCHESTRATION_TYPES.items():
        for type_name in type_names:
            reject_traits(checks, ROOT / name, type_name, generic_forbidden)

    reject_traits(
        checks,
        ROOT / "src/message/server_final.rs",
        "ServerFinalOutcome",
        {"Eq", "Hash", "Ord", "PartialEq", "PartialOrd"},
    )
    reject_traits(
        checks,
        ROOT / "src/message/server_final.rs",
        "ServerVerifier",
        {"Display", "Eq", "Hash", "Ord", "PartialEq", "PartialOrd"},
    )

    error_text = (ROOT / "src/error.rs").read_text(encoding="utf-8")
    checks.require(
        re.search(r"\b(?:Box|String|Vec)\s*<|&\s*(?:str|\[u8\])", error_text) is None,
        "error vocabulary must not retain owned or borrowed peer text",
    )


def main() -> int:
    checks = Checks()
    check_manifest(checks)
    check_repository_contract(checks)
    check_public_api_contract(checks)
    check_secret_surfaces(checks)
    return checks.finish()


if __name__ == "__main__":
    sys.exit(main())
