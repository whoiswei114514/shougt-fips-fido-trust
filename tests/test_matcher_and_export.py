import base64
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from src.exporter import export_all
from src.fido_mds import extract_fido2_authenticators
from src.matcher import match_devices
from src.validate import validate_repo


def _make_root_b64(cn: str = "Yubico FIPS Root") -> str:
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


class MatcherAndExportTests(unittest.TestCase):
    def setUp(self):
        self.root_b64 = _make_root_b64()
        self.mds_payload = {
            "no": 303,
            "nextUpdate": "2026-12-01",
            "entries": [
                {
                    "aaguid": "fcc0118f-cd45-435b-8da1-9782b2da0715",
                    "metadataStatement": {
                        "protocolFamily": "fido2",
                        "description": "YubiKey 5 FIPS Series with NFC",
                        "attachmentHint": ["external", "wired", "nfc"],
                        "authenticatorGetInfo": {"versions": ["FIDO_2_0", "FIDO_2_1"]},
                        "attestationRootCertificates": [self.root_b64],
                    },
                    "statusReports": [{"status": "FIDO_CERTIFIED_L2", "certificateNumber": "FIDO20020241221002", "effectiveDate": "2024-12-21"}],
                },
                {
                    # Standard non-FIPS consumer YubiKey MUST NOT match NIST #5291
                    "aaguid": "2fc0579f-8113-47ea-b116-bb5a8db9202a",
                    "metadataStatement": {
                        "protocolFamily": "fido2",
                        "description": "YubiKey 5 Series with NFC",
                        "attachmentHint": ["external", "wired", "nfc"],
                        "authenticatorGetInfo": {"versions": ["FIDO_2_0", "FIDO_2_1"]},
                        "attestationRootCertificates": [self.root_b64],
                    },
                    "statusReports": [{"status": "FIDO_CERTIFIED_L1", "effectiveDate": "2024-01-01"}],
                },
            ],
        }
        self.nist_active = [
            {
                "cert_number": "5291",
                "standard": "FIPS 140-3",
                "fips_revision": "3",
                "status": "Active",
                "overall_level": 2,
                "physical_security_level": 3,
                "validation_date": "2026-05-22",
                "sunset_date": "2031-05-21",
                "sunset_iso": "2031-05-21T23:59:59Z",
                "module_type": "Hardware",
                "vendor": "Yubico, Inc.",
                "module_name": "YubiKey 5 Cryptographic Module",
                "description": "YubiKey 5 FIPS",
                "detail_url": "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5291",
                "security_policy_pdf_url": "https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5291.pdf",
            }
        ]

    def test_strict_fips_matching_never_includes_non_fips_consumer_key_and_exports_valid_bundle(self):
        mds_auths, excluded = extract_fido2_authenticators(self.mds_payload)
        self.assertEqual(len(mds_auths), 2)

        matched, review = match_devices(self.nist_active, mds_auths, excluded, overrides=[])
        self.assertEqual([m["aaguid"] for m in matched], ["fcc0118f-cd45-435b-8da1-9782b2da0715"])
        self.assertEqual(matched[0]["assurance"], "fips140-3-level2")
        self.assertEqual(matched[0]["match_method"], "auto_verified")

        with TemporaryDirectory() as tmp:
            root_dir = Path(tmp)
            (root_dir / "README.md").write_text(
                "<!-- DEVICES_TABLE_START -->\nold\n<!-- DEVICES_TABLE_END -->\n",
                encoding="utf-8",
            )
            stats = export_all(
                root_dir,
                matched,
                self.nist_active,
                review,
                mds_meta={"no": 303, "nextUpdate": "2026-12-01"},
            )
            self.assertEqual(stats["device_count"], 1)
            self.assertEqual(stats["trust_entry_count"], 1)
            self.assertEqual(stats["cert_files"], 1)
            self.assertEqual(stats["pubkey_files"], 1)
            self.assertEqual(validate_repo(root_dir), [])
            readme = (root_dir / "README.md").read_text(encoding="utf-8")
            self.assertIn("fcc0118f-cd45-435b-8da1-9782b2da0715", readme)

    def test_curated_mapping_drops_if_nist_cert_is_inactive(self):
        mds_auths, excluded = extract_fido2_authenticators(self.mds_payload)
        overrides = [{"nist_cert": "9999", "aaguid": "fcc0118f-cd45-435b-8da1-9782b2da0715"}]
        matched, review = match_devices([], mds_auths, excluded, overrides=overrides)
        self.assertEqual(matched, [])
        self.assertEqual(review["mds_fips_without_active_nist"][0]["reason"], "curated_nist_cert_not_active")


if __name__ == "__main__":
    unittest.main()
