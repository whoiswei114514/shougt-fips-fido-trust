"""Download, cryptographically verify, and extract FIDO2+ authenticators from FIDO MDS3."""
from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from .http_client import fetch_bytes

MDS3_URL = "https://mds.fidoalliance.org/"
_MDS_DNS_HOST = "mds.fidoalliance.org"
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_ZERO_UUID = "00000000-0000-0000-0000-000000000000"
_FIDO2_PLUS_VERSION_RE = re.compile(r"^FIDO_(?:[2-9]|[1-9]\d+)_\d+(?:_PRE)?$")

_DISQUALIFYING_STATUSES = frozenset({
    "REVOKED",
    "ATTESTATION_KEY_COMPROMISE",
    "USER_VERIFICATION_BYPASS",
    "USER_KEY_REMOTE_COMPROMISE",
    "USER_KEY_PHYSICAL_COMPROMISE",
})

_CERTIFIED_PRIORITY = {
    "FIDO_CERTIFIED_L3plus": 5,
    "FIDO_CERTIFIED_L3": 4,
    "FIDO_CERTIFIED_L2plus": 3,
    "FIDO_CERTIFIED_L2": 2,
    "FIDO_CERTIFIED_L1plus": 1,
    "FIDO_CERTIFIED_L1": 1,
    "FIDO_CERTIFIED": 0,
}

_JWS_ALGS = {
    "RS256": ("rsa", hashes.SHA256()),
    "RS384": ("rsa", hashes.SHA384()),
    "RS512": ("rsa", hashes.SHA512()),
    "ES256": ("ec", hashes.SHA256()),
    "ES384": ("ec", hashes.SHA384()),
    "ES512": ("ec", hashes.SHA512()),
}


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def load_pinned_roots(roots_dir: Path) -> list[x509.Certificate]:
    """Load all pinned PEM Root CA certificates from roots_dir."""
    roots: list[x509.Certificate] = []
    for path in sorted(roots_dir.glob("*.pem")):
        roots.append(x509.load_pem_x509_certificate(path.read_bytes()))
    if not roots:
        raise ValueError(f"No pinned root CA certificates found in {roots_dir}")
    return roots


def _assert_ca_valid(cert: x509.Certificate, now: datetime) -> None:
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        raise ValueError(f"CA certificate expired or not yet valid: {cert.subject.rfc4514_string()}")
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    if not bc.ca:
        raise ValueError(f"Certificate is missing CA:TRUE constraint: {cert.subject.rfc4514_string()}")
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    if not ku.key_cert_sign:
        raise ValueError(f"Certificate is missing keyCertSign usage: {cert.subject.rfc4514_string()}")


def _assert_mds_leaf_identity(leaf: x509.Certificate) -> None:
    names: list[str] = []
    for attr in leaf.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
        if isinstance(attr.value, str):
            names.append(attr.value.lower())
    try:
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names.extend(str(item).lower() for item in san.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass
    if _MDS_DNS_HOST not in names:
        raise ValueError(f"MDS3 signing leaf certificate does not match {_MDS_DNS_HOST}: {names}")


def _verify_chain_against_roots(
    chain: list[x509.Certificate],
    roots: list[x509.Certificate],
    now: datetime,
) -> None:
    if not chain:
        raise ValueError("Empty x5c certificate chain in MDS3 JWS header")
    leaf = chain[0]
    if not (leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc):
        raise ValueError("MDS3 signing leaf certificate is outside validity window")
    _assert_mds_leaf_identity(leaf)

    root_by_fp = {root.fingerprint(hashes.SHA256()).hex(): root for root in roots}
    anchored = False

    for idx, cert in enumerate(chain):
        if idx > 0:
            _assert_ca_valid(cert, now)
        fp = cert.fingerprint(hashes.SHA256()).hex()
        if idx > 0 and fp in root_by_fp:
            _assert_ca_valid(root_by_fp[fp], now)
            anchored = True
            break
        if idx > 0:
            for root in root_by_fp.values():
                try:
                    _assert_ca_valid(root, now)
                    cert.verify_directly_issued_by(root)
                    anchored = True
                    break
                except (InvalidSignature, ValueError, TypeError, x509.ExtensionNotFound):
                    continue
            if anchored:
                break
        if idx + 1 < len(chain):
            issuer = chain[idx + 1]
            _assert_ca_valid(issuer, now)
            cert.verify_directly_issued_by(issuer)
            continue
        for root in root_by_fp.values():
            try:
                _assert_ca_valid(root, now)
                cert.verify_directly_issued_by(root)
                anchored = True
                break
            except (InvalidSignature, ValueError, TypeError, x509.ExtensionNotFound):
                continue
        if anchored:
            break

    if not anchored:
        raise ValueError("MDS3 certificate chain did not anchor to any pinned root CA")


def _verify_jws_signature(
    signing_input: bytes,
    signature: bytes,
    alg: str,
    public_key,
) -> None:
    spec = _JWS_ALGS.get(alg)
    if spec is None:
        raise ValueError(f"Unsupported MDS3 JWS algorithm: {alg}")
    kind, hash_alg = spec
    if kind == "rsa":
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("MDS3 JWS algorithm requires an RSA leaf certificate")
        public_key.verify(signature, signing_input, padding.PKCS1v15(), hash_alg)
        return

    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("MDS3 JWS algorithm requires an ECDSA leaf certificate")
    coord_bytes = (public_key.curve.key_size + 7) // 8
    if len(signature) != coord_bytes * 2:
        raise ValueError("Invalid ECDSA JWS signature length")
    r = int.from_bytes(signature[:coord_bytes], "big")
    s = int.from_bytes(signature[coord_bytes:], "big")
    der_sig = utils.encode_dss_signature(r, s)
    public_key.verify(der_sig, signing_input, ec.ECDSA(hash_alg))


def verify_and_decode_mds3_blob(
    raw_jwt: bytes,
    roots_dir: Path,
    *,
    now: datetime | None = None,
) -> dict:
    """Verify JWS signature and X.509 chain against pinned roots, then decode MDS3 JSON."""
    current_time = now or datetime.now(timezone.utc)
    token = raw_jwt.decode("ascii").strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("MDS3 blob is not a valid compact JWS")
    header_b64, payload_b64, sig_b64 = parts

    header = json.loads(_b64url_decode(header_b64))
    if not isinstance(header, dict) or not isinstance(header.get("x5c"), list):
        raise ValueError("MDS3 JWS header is missing x5c chain")

    chain = [x509.load_der_x509_certificate(base64.b64decode(item)) for item in header["x5c"]]
    roots = load_pinned_roots(roots_dir)
    _verify_chain_against_roots(chain, roots, current_time)

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    _verify_jws_signature(signing_input, _b64url_decode(sig_b64), str(header.get("alg", "")), chain[0].public_key())

    payload = json.loads(_b64url_decode(payload_b64))
    if not isinstance(payload, dict) or not isinstance(payload.get("entries"), list):
        raise ValueError("MDS3 payload is missing entries list")
    return payload


def fetch_verified_mds3(
    roots_dir: Path,
    *,
    mds_file: Path | None = None,
    now: datetime | None = None,
) -> dict:
    """Fetch FIDO Alliance MDS3 BLOB (or read local snapshot) and verify it."""
    raw = mds_file.read_bytes() if mds_file else fetch_bytes(MDS3_URL, timeout=45)
    return verify_and_decode_mds3_blob(raw, roots_dir, now=now)


def _extract_root_cert_info(b64_der: str) -> dict:
    der = base64.b64decode(re.sub(r"\s+", "", b64_der))
    cert = x509.load_der_x509_certificate(der)
    pub = cert.public_key()
    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    pub_der = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if isinstance(pub, ec.EllipticCurvePublicKey):
        key_type = f"ECDSA {pub.curve.name}"
    elif isinstance(pub, rsa.RSAPublicKey):
        key_type = f"RSA-{pub.key_size}"
    else:
        key_type = type(pub).__name__
    return {
        "cert_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "cert_pem": cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "not_after": cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "pubkey_sha256": hashlib.sha256(pub_der).hexdigest(),
        "pubkey_pem": pub_pem,
        "pubkey_algorithm": key_type,
    }


def _evaluate_status_reports(reports: list[dict]) -> tuple[bool, str, dict]:
    """Return (qualified, reason, summary_dict) for an MDS3 statusReports list."""
    if not reports:
        return False, "missing_status_reports", {}

    ordered = sorted(reports, key=lambda r: str(r.get("effectiveDate", "")))
    for report in ordered:
        st = str(report.get("status", "")).strip()
        if st in _DISQUALIFYING_STATUSES:
            return False, f"disqualified_status:{st}", {"status": st, **report}

    certified_reports = [
        report for report in ordered if str(report.get("status", "")) in _CERTIFIED_PRIORITY
    ]
    if not certified_reports:
        latest = str(ordered[-1].get("status", "UNKNOWN"))
        return False, f"not_fido_certified:{latest}", ordered[-1]

    best = max(certified_reports, key=lambda r: (_CERTIFIED_PRIORITY[r["status"]], str(r.get("effectiveDate", ""))))
    has_explicit_fips = any(
        bool(r.get("fipsRevision") or r.get("fipsPhysicalSecurityLevel")) for r in ordered
    )
    all_descriptors = [
        str(r.get("certificationDescriptor", "")).strip()
        for r in ordered
        if str(r.get("certificationDescriptor", "")).strip()
    ]
    status_urls = [
        str(r.get("url", "")).strip()
        for r in ordered
        if str(r.get("url", "")).strip()
    ]
    return True, "certified", {
        "highest_status": best.get("status", ""),
        "certificate_number": best.get("certificateNumber", ""),
        "certification_descriptor": best.get("certificationDescriptor", ""),
        "all_certification_descriptors": all_descriptors,
        "status_urls": status_urls,
        "effective_date": best.get("effectiveDate", ""),
        "fips_revision": next((r.get("fipsRevision") for r in reversed(ordered) if r.get("fipsRevision") is not None), None),
        "fips_physical_security_level": next((r.get("fipsPhysicalSecurityLevel") for r in reversed(ordered) if r.get("fipsPhysicalSecurityLevel") is not None), None),
        "explicit_fips_report": has_explicit_fips,
        "all_statuses": [str(r.get("status", "")) for r in ordered],
    }


def extract_fido2_authenticators(mds_payload: dict) -> tuple[list[dict], list[dict]]:
    """Extract qualified FIDO2+ external authenticators and FIPS-labeled excluded entries."""
    qualified: list[dict] = []
    excluded_fips: list[dict] = []

    for entry in mds_payload.get("entries", []):
        ms = entry.get("metadataStatement")
        if not isinstance(ms, dict):
            continue
        if ms.get("protocolFamily") != "fido2":
            continue

        raw_aaguid = str(entry.get("aaguid") or ms.get("aaguid") or "").strip().lower()
        if not _UUID_RE.fullmatch(raw_aaguid) or raw_aaguid == _ZERO_UUID:
            continue

        versions = [
            str(v)
            for v in (ms.get("authenticatorGetInfo") or {}).get("versions", [])
            if isinstance(v, str)
        ]
        fido2_versions = [v for v in versions if _FIDO2_PLUS_VERSION_RE.fullmatch(v)]
        if not fido2_versions:
            continue

        hints = [str(h).lower() for h in ms.get("attachmentHint", []) if isinstance(h, str)]
        if not hints or ("external" not in hints and "internal" in hints):
            continue
        if "external" not in hints and not any(h in hints for h in ("wired", "wireless", "nfc", "bluetooth", "network")):
            continue

        raw_roots = [r for r in ms.get("attestationRootCertificates", []) if isinstance(r, str) and r.strip()]
        if not raw_roots:
            continue

        reports = entry.get("statusReports") or []
        ok, reason, status_info = _evaluate_status_reports(reports)
        description = str(ms.get("description") or "").strip()
        cert_descriptor = str(status_info.get("certification_descriptor") or "")
        all_descriptors = " ".join(status_info.get("all_certification_descriptors", []))
        mentions_fips = bool(
            status_info.get("explicit_fips_report")
            or re.search(r"\bfips\b", f"{description} {cert_descriptor} {all_descriptors}", re.I)
        )

        if not ok:
            if mentions_fips:
                excluded_fips.append({
                    "aaguid": raw_aaguid,
                    "description": description,
                    "reason": reason,
                    "status_info": status_info,
                })
            continue

        parsed_roots: list[dict] = []
        root_parse_errors: list[str] = []
        for b64_der in raw_roots:
            try:
                parsed_roots.append(_extract_root_cert_info(b64_der))
            except (ValueError, TypeError) as exc:
                root_parse_errors.append(str(exc))

        if not parsed_roots:
            if mentions_fips:
                excluded_fips.append({
                    "aaguid": raw_aaguid,
                    "description": description,
                    "reason": "invalid_attestation_root_certificate",
                    "status_info": status_info,
                    "errors": root_parse_errors,
                })
            continue

        qualified.append({
            "aaguid": raw_aaguid,
            "description": description,
            "protocol_family": "fido2",
            "versions": fido2_versions,
            "attachment_hints": hints,
            "attestation_types": ms.get("attestationTypes", []),
            "is_fips_claimed": mentions_fips,
            "status_info": status_info,
            "attestation_roots": parsed_roots,
        })

    return qualified, excluded_fips
