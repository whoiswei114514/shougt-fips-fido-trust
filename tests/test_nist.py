import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from src.nist import (
    fetch_active_nist_candidates,
    is_hardware_module_type,
    is_potential_fido_module,
    normalize_nist_date,
    parse_active_index,
    parse_certificate_detail,
)

SAMPLE_INDEX_HTML = """
<table>
  <tr><th>Certificate Number</th><th>Vendor Name</th><th>Module Name</th><th>Module Type</th><th>Validation Date</th></tr>
  <tr><td><a href="/projects/cryptographic-module-validation-program/certificate/5291">5291</a></td><td>Yubico, Inc.</td><td>YubiKey 5 Cryptographic Module</td><td>Hardware</td><td>05/22/2026</td></tr>
  <tr><td><a href="/projects/cryptographic-module-validation-program/certificate/5302">5302</a></td><td>Yubico, Inc.</td><td>YubiHSM 2 Cryptographic Module</td><td>Hardware</td><td>06/03/2026</td></tr>
  <tr><td><a href="/projects/cryptographic-module-validation-program/certificate/5601">5601</a></td><td>Ctrl IQ, Inc.</td><td>Rocky Linux 9 NSS Cryptographic Module</td><td>Software</td><td>11/23/2026</td></tr>
</table>
"""

SAMPLE_DETAIL_HTML = """
<h1>YubiKey 5 Cryptographic Module</h1>
<div class="row"><div class="col-md-3">Standard</div><div class="col-md-9">FIPS 140-3</div></div>
<div class="row"><div class="col-md-3">Status</div><div class="col-md-9">Active</div></div>
<div class="row"><div class="col-md-3">Validation Date</div><div class="col-md-9">05/22/2026</div></div>
<div class="row"><div class="col-md-3">Sunset Date</div><div class="col-md-9">5/21/2031</div></div>
<div class="row"><div class="col-md-3">Overall Level</div><div class="col-md-9">2</div></div>
<div class="row"><div class="col-md-3">Security Level Exceptions</div><div class="col-md-9">Physical security: Level 3</div></div>
<div class="row"><div class="col-md-3">Module Type</div><div class="col-md-9">Hardware</div></div>
<div class="row"><div class="col-md-3">Description</div><div class="col-md-9">Secure element token with FIDO2.</div></div>
<a href="/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5291.pdf">Security Policy</a>
"""


class NistTests(unittest.TestCase):
    def test_parse_active_index_and_filter_hardware_non_hsm(self):
        rows = parse_active_index(SAMPLE_INDEX_HTML)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["cert_number"], "5291")
        self.assertEqual(rows[0]["validation_date"], "2026-05-22")

        self.assertTrue(is_hardware_module_type(rows[0]["module_type"]))
        self.assertFalse(is_hardware_module_type(rows[2]["module_type"]))
        self.assertTrue(is_potential_fido_module(rows[0]["vendor"], rows[0]["module_name"]))
        self.assertFalse(is_potential_fido_module(rows[1]["vendor"], rows[1]["module_name"]))

    def test_parse_certificate_detail_extracts_levels_dates_and_pdf(self):
        detail = parse_certificate_detail("5291", SAMPLE_DETAIL_HTML)
        self.assertEqual(detail["standard"], "FIPS 140-3")
        self.assertEqual(detail["fips_revision"], "3")
        self.assertEqual(detail["status"], "Active")
        self.assertEqual(detail["overall_level"], 2)
        self.assertEqual(detail["physical_security_level"], 3)
        self.assertEqual(detail["sunset_date"], "2031-05-21")
        self.assertEqual(detail["sunset_iso"], "2031-05-21T23:59:59Z")
        self.assertTrue(detail["security_policy_pdf_url"].endswith("140sp5291.pdf"))

    def test_date_normalization_and_incremental_cache_reuse(self):
        self.assertEqual(normalize_nist_date("5/21/2031"), "2031-05-21")
        self.assertEqual(normalize_nist_date("N/A"), "")
        with TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "nist-cache.json"
            calls = []

            def fetcher(url):
                calls.append(url)
                return SAMPLE_DETAIL_HTML

            now = datetime(2026, 6, 1, tzinfo=timezone.utc)
            candidates1, stats1 = fetch_active_nist_candidates(
                cache_path,
                curated_certs={"5291"},
                index_html=SAMPLE_INDEX_HTML,
                detail_fetcher=fetcher,
                request_delay=0,
                now=now,
            )
            self.assertEqual(len(candidates1), 1)
            self.assertEqual(stats1["nist_detail_fetched"], 1)

            candidates2, stats2 = fetch_active_nist_candidates(
                cache_path,
                curated_certs={"5291"},
                index_html=SAMPLE_INDEX_HTML,
                detail_fetcher=fetcher,
                request_delay=0,
                now=now,
            )
            self.assertEqual(len(candidates2), 1)
            self.assertEqual(stats2["nist_detail_fetched"], 0)
            self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
