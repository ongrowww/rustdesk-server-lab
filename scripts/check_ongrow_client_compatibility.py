#!/usr/bin/env python3
"""Check the pinned OnGROW client/server attestation protocol contract."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

EXPECTED_FIELDS = {
    "RegisterPk": {
        "id": ("string", 1),
        "uuid": ("bytes", 2),
        "pk": ("bytes", 3),
        "old_id": ("string", 4),
        "ongrow_attestation_nonce": ("bytes", 6),
    },
    "OnGrowDeviceAttestation": {
        "id": ("string", 1),
        "device_pk": ("bytes", 2),
        "uuid_sha256": ("bytes", 3),
        "issued_at": ("int64", 4),
        "expires_at": ("int64", 5),
        "nonce": ("bytes", 6),
        "signed_payload": ("bytes", 7),
    },
    "RegisterPkResponse": {
        "ongrow_device_attestation": ("OnGrowDeviceAttestation", 3),
    },
}
CONTEXTS = (
    "ongrow-rustdesk-custom-id-v2",
    "ongrow-rustdesk-device-attestation-v1",
)


def git_revision(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def message_body(proto: str, name: str) -> str:
    match = re.search(rf"message\s+{re.escape(name)}\s*\{{", proto)
    if not match:
        raise ValueError(f"missing protobuf message {name}")
    depth = 1
    position = match.end()
    while position < len(proto) and depth:
        if proto[position] == "{":
            depth += 1
        elif proto[position] == "}":
            depth -= 1
        position += 1
    if depth:
        raise ValueError(f"unclosed protobuf message {name}")
    return proto[match.end() : position - 1]


def fields(proto: str, name: str) -> dict[str, tuple[str, int]]:
    body = message_body(proto, name)
    found: dict[str, tuple[str, int]] = {}
    numbers: dict[int, str] = {}
    for field_type, field_name, raw_number in re.findall(
        r"^\s*(\w+)\s+(\w+)\s*=\s*(\d+)\s*;", body, flags=re.MULTILINE
    ):
        number = int(raw_number)
        if number in numbers:
            raise ValueError(f"protobuf collision in {name}: {numbers[number]} and {field_name} use {number}")
        numbers[number] = field_name
        found[field_name] = (field_type, number)
    return found


def vector(source: str, test_name: str) -> str:
    match = re.search(
        rf"fn\s+{re.escape(test_name)}\(\).*?\"([0-9a-f]{{200,}})\"",
        source,
        flags=re.DOTALL,
    )
    if not match:
        raise ValueError(f"missing canonical vector in {test_name}")
    return match.group(1)


def verify(root: Path, expected: str, label: str) -> None:
    actual = git_revision(root)
    if actual != expected:
        raise ValueError(f"{label} revision mismatch: expected {expected}, got {actual}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--client-root", type=Path, required=True)
    parser.add_argument("--server-root", type=Path, required=True)
    parser.add_argument("--client-revision", required=True)
    parser.add_argument("--server-revision", required=True)
    parser.add_argument("--client-hbb-common-revision", required=True)
    parser.add_argument("--server-hbb-common-revision", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    client_hbb = args.client_root / "libs/hbb_common"
    server_hbb = args.server_root / "libs/hbb_common"
    verify(args.client_root, args.client_revision, "client")
    verify(args.server_root, args.server_revision, "server")
    verify(client_hbb, args.client_hbb_common_revision, "client hbb_common")
    verify(server_hbb, args.server_hbb_common_revision, "server hbb_common")

    client_proto = (client_hbb / "protos/rendezvous.proto").read_text(encoding="utf-8")
    server_proto = (server_hbb / "protos/rendezvous.proto").read_text(encoding="utf-8")
    for message, expected in EXPECTED_FIELDS.items():
        for label, proto in (("client", client_proto), ("server", server_proto)):
            actual = fields(proto, message)
            for field, contract in expected.items():
                if actual.get(field) != contract:
                    raise ValueError(
                        f"{label} {message}.{field} contract mismatch: expected {contract}, got {actual.get(field)}"
                    )

    client_source = (args.client_root / "src/ui_interface.rs").read_text(encoding="utf-8")
    server_source = (args.server_root / "src/common.rs").read_text(encoding="utf-8")
    for context in CONTEXTS:
        if context not in client_source or context not in server_source:
            raise ValueError(f"signature context drift: {context}")
    client_vector = vector(client_source, "attestation_payload_matches_cross_fork_test_vector")
    server_vector = vector(server_source, "attestation_payload_matches_cross_fork_test_vector")
    if client_vector != server_vector:
        raise ValueError("canonical attestation vector differs between client and server")
    for required_test_evidence in ("wrong_server_public_key", "wrong_nonce", "attestation_missing"):
        if required_test_evidence not in client_source:
            raise ValueError(f"client tamper regression is missing: {required_test_evidence}")

    print("OnGROW pinned client/server protobuf and attestation contract is compatible")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        raise SystemExit(f"compatibility gate failed: {exc}") from exc
