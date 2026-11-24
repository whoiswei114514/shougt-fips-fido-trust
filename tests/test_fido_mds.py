import base64
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID

from src.fido_mds import extract_fido2_authenticators, verify_and_decode_mds3_blob


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _gen_root(cn: str = "Test GlobalSign Root"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=10))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _gen_leaf(root_key, root_cert, dns_name: str = "mds.fidoalliance.org", days: int = 30):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns_name)]), critical=False)
        .sign(root_key, hashes.SHA256())
    )
    return key, cert


def _gen_device_root(cn: str = "Device Attestation Root"):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(key, hashes.SHA256())
    )
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")


def _sign_jws(payload: dict, leaf_key, x5c_certs: list[x509.Certificate]) -> bytes:
    header = {
        "alg": "RS256",
        "typ": "JWT",
        "x5c": [base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode("ascii") for c in x5c_certs],
    }
    h_b64 = _b64u(json.dumps(header).encode("utf-8"))
    p_b64 = _b64u(json.dumps(payload).encode("utf-8"))
    sig = leaf_key.sign(f"{h_b64}.{p_b64}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{h_b64}.{p_b64}.{_b64u(sig)}".encode("ascii")


class FidoMdsTests(unittest.TestCase):
    def test_jws_signature_chain_and_tamper_rejection(self):
        root_key, root_cert = _gen_root()
        rogue_key, rogue_cert = _gen_root("Rogue CA")
        leaf_key, leaf_cert = _gen_leaf(root_key, root_cert)
        wrong_host_key, wrong_host_cert = _gen_leaf(root_key, root_cert, dns_name="evil.example.org")

        payload = {"no": 303, "nextUpdate": "2026-12-01", "entries": []}
        with TemporaryDirectory() as tmp:
            roots_dir = Path(tmp) / "roots"
            roots_dir.mkdir()
            (roots_dir / "root.pem").write_bytes(root_cert.public_bytes(serialization.Encoding.PEM))

            good_jws = _sign_jws(payload, leaf_key, [leaf_cert, root_cert])
            decoded = verify_and_decode_mds3_blob(good_jws, roots_dir)
            self.assertEqual(decoded["no"], 303)

            # Tamper payload -> signature invalid
            h, p, s = good_jws.decode("ascii").split(".")
            tampered_p = _b64u(json.dumps({"no": 999, "entries": []}).encode("utf-8"))
            with self.assertRaises(Exception):
                verify_and_decode_mds3_blob(f"{h}.{tampered_p}.{s}".encode("ascii"), roots_dir)

            # Wrong root -> chain does not anchor
            rogue_jws = _sign_jws(payload, *_gen_leaf(rogue_key, rogue_cert)[::-1][:0], x5c_certs=[]) if False else None
            r_leaf_key, r_leaf_cert = _gen_leaf(rogue_key, rogue_cert)
            rogue_jws = _sign_jws(payload, r_leaf_key, [r_leaf_cert, rogue_cert])
            with self.assertRaises(ValueError):
                verify_and_decode_mds3_blob(rogue_jws, roots_dir)

            # Wrong SAN host -> rejected
            bad_host_jws = _sign_jws(payload, wrong_host_key, [wrong_host_cert, root_cert])
            with self.assertRaises(ValueError):
                verify_and_decode_mds3_blob(bad_host_jws, roots_dir)

    def test_extract_filters_non_fido2_internal_revoked_and_preview_entries(self):
        dev_root_b64 = _gen_device_root()
        payload = {
            "entries": [
                {
                    "aaguid": "fcc0118f-cd45-435b-8da1-9782b2da0715",
                    "metadataStatement": {
                        "protocolFamily": "fido2",
                        "description": "YubiKey 5 FIPS Series with NFC",
                        "attachmentHint": ["external", "wired", "nfc"],
                        "authenticatorGetInfo": {"versions": ["FIDO_2_0", "FIDO_2_1"]},
                        "attestationRootCertificates": [dev_root_b64],
                    },
                    "statusReports": [{"status": "FIDO_CERTIFIED_L2", "effectiveDate": "2024-12-21"}],
                },
                {
                    "aaguid": "62e54e98-c209-4df3-b692-de71bb6a8528",
                    "metadataStatement": {
                        "protocolFamily": "fido2",
                        "description": "YubiKey 5 FIPS Series Preview",
                        "attachmentHint": ["external", "wired"],
                        "authenticatorGetInfo": {"versions": ["FIDO_2_0"]},
                        "attestationRootCertificates": [dev_root_b64],
                    },
                    "statusReports": [{"status": "NOT_FIDO_CERTIFIED", "effectiveDate": "2024-04-07"}],
                },
                {
                    "aaguid": "11111111-1111-1111-1111-111111111111",
                    "metadataStatement": {
                        "protocolFamily": "fido2",
                        "description": "Compromised FIPS Key",
                        "attachmentHint": ["external", "wired"],
                        "authenticatorGetInfo": {"versions": ["FIDO_2_0"]},
                        "attestationRootCertificates": [dev_root_b64],
                    },
                    "statusReports": [
                        {"status": "FIDO_CERTIFIED_L2", "effectiveDate": "2024-01-01"},
                        {"status": "REVOKED", "effectiveDate": "2025-01-01"},
                    ],
                },
                {
                    "aaguid": "22222222-2222-2222-2222-222222222222",
                    "metadataStatement": {
                        "protocolFamily": "u2f",
                        "description": "U2F Only FIPS Key",
                        "attachmentHint": ["external", "wired"],
                        "authenticatorGetInfo": {"versions": ["U2F_V2"]},
                        "attestationRootCertificates": [dev_root_b64],
                    },
                    "statusReports": [{"status": "FIDO_CERTIFIED_L1", "effectiveDate": "2021-01-01"}],
                },
                {
                    "aaguid": "33333333-3333-3333-3333-333333333333",
                    "metadataStatement": {
                        "protocolFamily": "fido2",
                        "description": "Internal Platform TPM",
                        "attachmentHint": ["internal"],
                        "authenticatorGetInfo": {"versions": ["FIDO_2_0"]},
                        "attestationRootCertificates": [dev_root_b64],
                    },
                    "statusReports": [{"status": "FIDO_CERTIFIED_L1", "effectiveDate": "2023-01-01"}],
                },
            ]
        }

        qualified, excluded_fips = extract_fido2_authenticators(payload)
        self.assertEqual([item["aaguid"] for item in qualified], ["fcc0118f-cd45-435b-8da1-9782b2da0715"])
        self.assertEqual(len(excluded_fips), 2)
        self.assertTrue(any(e["reason"] == "not_fido_certified:NOT_FIDO_CERTIFIED" for e in excluded_fips))
        self.assertTrue(any(e["reason"] == "disqualified_status:REVOKED" for e in excluded_fips))


if __name__ == "__main__":
    unittest.main()
