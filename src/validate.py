"""Validate all generated certificates, public keys, and trust manifests."""
from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_ZERO_UUID = "00000000-0000-0000-0000-000000000000"
_ALLOWED_ASSURANCE = (
    {"standard"}
    | {f"fips140-{v}-level{l}" for v in (2, 3) for l in (2, 3, 4)}
    | {f"equivalent-level{l}" for l in (2, 3, 4)}
)


def validate_repo(repo_root: Path, *, now: datetime | None = None) -> list[str]:
    """Return list of validation errors; empty list means all artifacts are valid."""
    current_time = now or datetime.now(timezone.utc)
    errors: list[str] = []

    catalog_path = repo_root / "data" / "fips-fido2-devices.json"
    trust_json_path = repo_root / "data" / "shougt-fido-attestation-trust.json"
    trust_yaml_path = repo_root / "data" / "shougt-fido-attestation-trust.yaml"

    for required in (catalog_path, trust_json_path, trust_yaml_path):
        if not required.exists():
            errors.append(f"Missing required artifact: {required}")
            return errors

    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    trust_json = json.loads(trust_json_path.read_text(encoding="utf-8"))
    trust_yaml = yaml.safe_load(trust_yaml_path.read_text(encoding="utf-8"))

    if trust_json != trust_yaml:
        errors.append("JSON and YAML attestation trust bundles are out of sync")

    for device in catalog.get("devices", []):
        aaguid = device.get("aaguid", "")
        if not _UUID_RE.fullmatch(aaguid) or aaguid == _ZERO_UUID:
            errors.append(f"Invalid AAGUID in device catalog: {aaguid}")
        if not any(re.fullmatch(r"FIDO_(?:[2-9]|[1-9]\d+)_\d+(?:_PRE)?", v) for v in device.get("fido", {}).get("versions", [])):
            errors.append(f"Device lacks FIDO2+ version: {aaguid}")
        if not str(device.get("fido", {}).get("status", "")).startswith("FIDO_CERTIFIED"):
            errors.append(f"Non-certified FIDO status present in catalog: {aaguid}")
        if str(device.get("nist", {}).get("status", "")).lower() != "active":
            errors.append(f"Inactive NIST cert in catalog: {aaguid}")

        for root in device.get("attestation_roots", []):
            cert_path = repo_root / root["cert_pem_path"]
            pub_path = repo_root / root["pubkey_pem_path"]
            if not cert_path.exists():
                errors.append(f"Missing certificate PEM: {cert_path}")
                continue
            if not pub_path.exists():
                errors.append(f"Missing public key PEM: {pub_path}")
                continue
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            if cert.fingerprint(hashes.SHA256()).hex() != root["cert_sha256"]:
                errors.append(f"Certificate SHA-256 mismatch: {cert_path}")
            if cert.not_valid_after_utc <= current_time:
                errors.append(f"Expired attestation root certificate exported: {cert_path}")
            pub = serialization.load_pem_public_key(pub_path.read_bytes())
            pub_der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            if hashlib.sha256(pub_der).hexdigest() != root["pubkey_sha256"]:
                errors.append(f"Public key SHA-256 mismatch: {pub_path}")

    seen_ids: set[str] = set()
    for entry in trust_json:
        eid = entry.get("id", "")
        if not eid or eid in seen_ids:
            errors.append(f"Duplicate or empty trust entry id: {eid}")
        seen_ids.add(eid)
        if entry.get("assurance") not in _ALLOWED_ASSURANCE:
            errors.append(f"Disallowed assurance value in {eid}: {entry.get('assurance')}")
        if entry.get("attachment") != "cross-platform":
            errors.append(f"Invalid attachment in {eid}: {entry.get('attachment')}")
        if not entry.get("metadata_reference") or (entry.get("assurance") != "standard" and not entry.get("certification_reference")):
            errors.append(f"Missing reference fields in {eid}")
        cert_file = repo_root / entry.get("root_pem", "")
        if not cert_file.exists():
            errors.append(f"Missing root_pem for {eid}: {cert_file}")
        for aaguid in entry.get("aaguids", []):
            if not _UUID_RE.fullmatch(aaguid) or aaguid == _ZERO_UUID:
                errors.append(f"Invalid AAGUID in {eid}: {aaguid}")
        try:
            expires = datetime.fromisoformat(str(entry.get("valid_until", "")).replace("Z", "+00:00"))
            if not expires.tzinfo or expires <= current_time:
                errors.append(f"Expired valid_until in {eid}: {entry.get('valid_until')}")
        except ValueError:
            errors.append(f"Invalid valid_until ISO timestamp in {eid}")

    return errors


def main(argv: list[str] | None = None) -> int:
    _ = argv
    repo_root = Path(__file__).resolve().parent.parent
    errors = validate_repo(repo_root)
    if errors:
        for err in errors:
            print(f"VALIDATION ERROR: {err}", file=sys.stderr)
        return 1
    print("All certificates, public keys, and trust manifests passed validation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
