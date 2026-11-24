import base64
import json
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


def _make_root_b64(cn: str = "FIDO FIPS Root") -> str:
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
                {
                    # FEITIAN ePass K40 (Historical 140-2 #4422) without "FIPS" in MDS description
                    "aaguid": "ee041bce-25e5-4cdb-8f86-897fd6418464",
                    "metadataStatement": {
                        "protocolFamily": "fido2",
                        "description": "Feitian ePass FIDO2-NFC Authenticator",
                        "attachmentHint": ["external", "wired", "nfc"],
                        "authenticatorGetInfo": {"versions": ["FIDO_2_0"]},
                        "attestationRootCertificates": [self.root_b64],
                    },
                    "statusReports": [{"status": "FIDO_CERTIFIED_L2", "certificateNumber": "FIDO20020190101001", "effectiveDate": "2019-01-01"}],
                },
                {
                    # Hirsch / Identiv uTrust FIDO2 Security Key backed by #4679 + IUT
                    "aaguid": "73402251-f2a8-4f03-873e-3cb6db604b03",
                    "metadataStatement": {
                        "protocolFamily": "fido2",
                        "description": "uTrust FIDO2 Security Key",
                        "attachmentHint": ["external", "wired", "nfc"],
                        "authenticatorGetInfo": {"versions": ["FIDO_2_0", "FIDO_2_1"]},
                        "attestationRootCertificates": [self.root_b64],
                    },
                    "statusReports": [{"status": "FIDO_CERTIFIED_L1", "certificateNumber": "FIDO20020220101001", "effectiveDate": "2022-01-01"}],
                },
                {
                    # Level 1 FIPS key: cataloged in fips-fido2-devices.json but excluded from shougt trust bundle
                    "aaguid": "664d9f67-84a2-412a-9ff7-b4f7d8ee6d05",
                    "metadataStatement": {
                        "protocolFamily": "fido2",
                        "description": "OpenSK authenticator",
                        "attachmentHint": ["external", "wired"],
                        "authenticatorGetInfo": {"versions": ["FIDO_2_0"]},
                        "attestationRootCertificates": [self.root_b64],
                    },
                    "statusReports": [{"status": "FIDO_CERTIFIED_L1", "effectiveDate": "2024-01-01"}],
                },
            ],
        }
        self.nist_candidates = [
            {
                "cert_number": "5291",
                "standard": "FIPS 140-3",
                "fips_revision": "3",
                "status": "Active",
                "historical_reason": "",
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
            },
            {
                "cert_number": "4422",
                "standard": "FIPS 140-2",
                "fips_revision": "2",
                "status": "Historical",
                "historical_reason": "Moved to historical list due to sunsetting",
                "overall_level": 2,
                "physical_security_level": 3,
                "validation_date": "2023-01-23",
                "sunset_date": "",
                "sunset_iso": "",
                "module_type": "Hardware",
                "vendor": "FEITIAN Technologies US, Inc.",
                "module_name": "FEITIAN MFA Cryptographic Module",
                "description": "FEITIAN ePass K40 MFA module",
                "detail_url": "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4422",
            },
            {
                "cert_number": "4679",
                "standard": "FIPS 140-3",
                "fips_revision": "3",
                "status": "Active",
                "historical_reason": "",
                "overall_level": 3,
                "physical_security_level": 4,
                "validation_date": "2024-03-11",
                "sunset_date": "2029-03-10",
                "sunset_iso": "2029-03-10T23:59:59Z",
                "module_type": "Hardware",
                "vendor": "NXP Semiconductors",
                "module_name": "JCOP 4.5 on P71D600",
                "description": "JCOP 4.5 secure element",
                "detail_url": "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4679",
            },
            {
                "cert_number": "5087",
                "standard": "FIPS 140-3",
                "fips_revision": "3",
                "status": "Active",
                "historical_reason": "",
                "overall_level": 1,
                "physical_security_level": 3,
                "validation_date": "2025-10-23",
                "sunset_date": "2030-10-22",
                "sunset_iso": "2030-10-22T23:59:59Z",
                "module_type": "Hardware",
                "vendor": "Google, LLC.",
                "module_name": "OpenSK Cryptographic Module",
                "description": "OpenSK U2F",
                "detail_url": "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5087",
            },
            {
                # Revoked FIPS 140-2 cert MUST NEVER match even if configured
                "cert_number": "9998",
                "standard": "FIPS 140-2",
                "fips_revision": "2",
                "status": "Revoked",
                "historical_reason": "Revoked",
                "overall_level": 2,
                "physical_security_level": 3,
                "validation_date": "2020-01-01",
                "sunset_date": "",
                "sunset_iso": "",
                "module_type": "Hardware",
                "vendor": "Revoked Vendor",
                "module_name": "Revoked Key",
                "description": "",
                "detail_url": "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/9998",
            },
        ]
        self.in_process = [
            {
                "list_type": "IUT",
                "module_name": "HIRSCH uTrust FIDO Cryptographic Module",
                "vendor": "Hirsch Inc.",
                "standard": "FIPS 140-3",
                "status_or_date": "12/2/2024",
                "source_url": "https://example.invalid/iut",
            }
        ]

    def test_strict_fips_matching_supports_140_2_and_platform_iut_while_excluding_consumer_keys(self):
        mds_auths, excluded = extract_fido2_authenticators(self.mds_payload)
        self.assertEqual(len(mds_auths), 5)

        overrides = [
            {"nist_cert": "4422", "aaguid": "ee041bce-25e5-4cdb-8f86-897fd6418464", "notes": "K40 140-2"},
            {
                "nist_cert": "4679",
                "aaguid": "73402251-f2a8-4f03-873e-3cb6db604b03",
                "vendor": "Hirsch / Identiv",
                "validation_scope": "platform_plus_in_process",
                "in_process_match": {"vendor": "hirsch", "module_keyword": "utrust"},
                "notes": "Hirsch Gov Series",
            },
            {"nist_cert": "5087", "aaguid": "664d9f67-84a2-412a-9ff7-b4f7d8ee6d05", "notes": "L1"},
        ]

        matched, review = match_devices(
            self.nist_candidates,
            mds_auths,
            excluded,
            overrides=overrides,
            nist_in_process=self.in_process,
        )
        by_aaguid = {m["aaguid"]: m for m in matched}

        # Consumer YubiKey 5 Series MUST NOT match
        self.assertNotIn("2fc0579f-8113-47ea-b116-bb5a8db9202a", by_aaguid)
        self.assertEqual(by_aaguid["fcc0118f-cd45-435b-8da1-9782b2da0715"]["assurance"], "fips140-3-level2")
        self.assertEqual(by_aaguid["ee041bce-25e5-4cdb-8f86-897fd6418464"]["assurance"], "fips140-2-level2")
        self.assertEqual(by_aaguid["ee041bce-25e5-4cdb-8f86-897fd6418464"]["nist"]["status"], "Historical")
        self.assertEqual(by_aaguid["73402251-f2a8-4f03-873e-3cb6db604b03"]["vendor"], "Hirsch / Identiv")
        self.assertEqual(by_aaguid["73402251-f2a8-4f03-873e-3cb6db604b03"]["nist"]["validation_scope"], "platform_plus_in_process")
        self.assertEqual(by_aaguid["73402251-f2a8-4f03-873e-3cb6db604b03"]["nist"]["in_process_entry"]["list_type"], "IUT")
        self.assertFalse(by_aaguid["664d9f67-84a2-412a-9ff7-b4f7d8ee6d05"]["meets_shougt_high_assurance"])

        with TemporaryDirectory() as tmp:
            root_dir = Path(tmp)
            (root_dir / "README.md").write_text(
                "<!-- DEVICES_TABLE_START -->\nold\n<!-- DEVICES_TABLE_END -->\n",
                encoding="utf-8",
            )
            stats = export_all(
                root_dir,
                matched,
                self.nist_candidates,
                review,
                mds_meta={"no": 303, "nextUpdate": "2026-12-01"},
                nist_in_process=self.in_process,
            )
            self.assertEqual(stats["device_count"], 4)
            # Only 3 high-assurance (Level 2+) entries go into shougt trust bundle (OpenSK L1 excluded)
            self.assertEqual(stats["trust_entry_count"], 3)
            self.assertEqual(stats["cert_files"], 4)
            self.assertEqual(stats["pubkey_files"], 4)
            self.assertEqual(validate_repo(root_dir), [])
            self.assertTrue((root_dir / "data" / "nist-in-process.json").exists())
            trust_list = json.loads((root_dir / "data" / "shougt-fido-attestation-trust.json").read_text(encoding="utf-8"))
            self.assertTrue(any("Historical" in item["certification_reference"] for item in trust_list))
            readme = (root_dir / "README.md").read_text(encoding="utf-8")
            self.assertIn("ee041bce-25e5-4cdb-8f86-897fd6418464", readme)
            self.assertIn("Platform + IUT", readme)

    def test_curated_mapping_drops_if_nist_cert_is_inactive_or_revoked(self):
        mds_auths, excluded = extract_fido2_authenticators(self.mds_payload)
        overrides = [{"nist_cert": "9998", "aaguid": "fcc0118f-cd45-435b-8da1-9782b2da0715"}]
        matched, review = match_devices(self.nist_candidates, mds_auths, excluded, overrides=overrides)
        self.assertEqual(review["mds_fips_without_active_nist"][0]["reason"], "curated_nist_cert_not_active")
        self.assertFalse(any(m["aaguid"] == "fcc0118f-cd45-435b-8da1-9782b2da0715" for m in matched))


if __name__ == "__main__":
    unittest.main()
