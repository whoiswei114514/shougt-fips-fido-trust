import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from src.nist import (
    fetch_active_nist_candidates,
    is_eligible_nist_certificate,
    is_hardware_module_type,
    is_potential_fido_module,
    normalize_nist_date,
    parse_active_index,
    parse_certificate_detail,
    parse_in_process_list,
)

SAMPLE_INDEX_HTML = """
<table>
  <tr><th>Certificate Number</th><th>Vendor Name</th><th>Module Name</th><th>Module Type</th><th>Validation Date</th></tr>
  <tr><td><a href="/projects/cryptographic-module-validation-program/certificate/5291">5291</a></td><td>Yubico, Inc.</td><td>YubiKey 5 Cryptographic Module</td><td>Hardware</td><td>05/22/2026</td></tr>
  <tr><td><a href="/projects/cryptographic-module-validation-program/certificate/5302">5302</a></td><td>Yubico, Inc.</td><td>YubiHSM 2 Cryptographic Module</td><td>Hardware</td><td>06/03/2026</td></tr>
  <tr><td><a href="/projects/cryptographic-module-validation-program/certificate/5601">5601</a></td><td>Ctrl IQ, Inc.</td><td>Rocky Linux 9 NSS Cryptographic Module</td><td>Software</td><td>11/23/2026</td></tr>
</table>
"""

SAMPLE_HISTORICAL_HTML = """
<table>
  <tr><th>Certificate Number</th><th>Vendor Name</th><th>Module Name</th><th>Module Type</th><th>Validation Date</th></tr>
  <tr><td><a href="/projects/cryptographic-module-validation-program/certificate/4422">4422</a></td><td>FEITIAN Technologies US, Inc.</td><td>FEITIAN MFA Cryptographic Module</td><td>Hardware</td><td>01/23/2023</td></tr>
</table>
"""

SAMPLE_DETAIL_HTML = """
<div class="row">
  <div class="col-md-8">
    <h1>YubiKey 5 Cryptographic Module</h1>
    <div class="row padrow"><div class="col-md-3"><span>Standard</span></div><div class="col-md-9">FIPS 140-3</div></div>
    <div class="row padrow"><div class="col-md-3">Status</div><div class="col-md-9">Active</div></div>
    <div class="row padrow"><div class="col-md-3"><span>Sunset Date</span></div><div class="col-md-9">5/21/2031</div></div>
    <div class="row padrow"><div class="col-md-3"><span>Overall Level</span></div><div class="col-md-9">2</div></div>
    <div class="row padrow"><div class="col-md-3"><span>Security Level Exceptions</span></div><div class="col-md-9"><ul><li>Physical security: Level 3</li></ul></div></div>
    <div class="row padrow"><div class="col-md-3"><span>Module Type</span></div><div class="col-md-9">Hardware</div></div>
    <div class="row padrow"><div class="col-md-3"><span>Description</span></div><div class="col-md-9">Secure element token with FIDO2.</div></div>
    <a href="/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5291.pdf">Security Policy</a>
  </div>
</div>
"""

SAMPLE_HISTORICAL_DETAIL_HTML = """
<div class="row">
  <div class="col-md-8">
    <h1>FEITIAN MFA Cryptographic Module</h1>
    <div class="row padrow"><div class="col-md-3"><span>Standard</span></div><div class="col-md-9">FIPS 140-2</div></div>
    <div class="row padrow"><div class="col-md-3"><span>Status</span></div><div class="col-md-9">Historical</div></div>
    <div class="row padrow"><div class="col-md-3"><span>Historical Reason</span></div><div class="col-md-9">Moved to historical list due to sunsetting</div></div>
    <div class="row padrow"><div class="col-md-3"><span>Overall Level</span></div><div class="col-md-9">2</div></div>
    <div class="row padrow"><div class="col-md-3"><span>Security Level Exceptions</span></div><div class="col-md-9"><ul><li>Physical security: Level 3</li></ul></div></div>
    <div class="row padrow"><div class="col-md-3"><span>Hardware Versions</span></div><div class="col-md-9">SLE78CLUFX5000PH</div></div>
    <div class="row padrow"><div class="col-md-3"><span>Firmware Versions</span></div><div class="col-md-9">7.04</div></div>
    <div class="row padrow"><div class="col-md-3"><span>Module Type</span></div><div class="col-md-9">Hardware</div></div>
    <div class="row padrow"><div class="col-md-3"><span>Description</span></div><div class="col-md-9">Portable MFA authenticator with FIDO2 and U2F.</div></div>
    <a href="/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp4422.pdf">Security Policy</a>
  </div>
  <div class="col-md-4">
    <div class="panel panel-default">
      <div class="panel-heading"><h4 class="panel-title">Vendor</h4></div>
      <div class="panel-body"><a href="#">FEITIAN Technologies US, Inc.</a><br />Santa Clara, CA</div>
    </div>
    <div class="panel panel-default">
      <div class="panel-heading"><h4 class="panel-title">Validation History</h4></div>
      <div class="panel-body"><table><tr><td>1/23/2023</td><td>Initial</td></tr></table></div>
    </div>
  </div>
</div>
"""

SAMPLE_IUT_HTML = """
<table>
  <tr><th>Module Name</th><th>Vendor Name</th><th>Standard</th><th>IUT Date</th></tr>
  <tr><td>HIRSCH uTrust FIDO Cryptographic Module</td><td>Hirsch Inc. View Contacts</td><td>FIPS 140-3</td><td>12/2/2024</td></tr>
  <tr><td>Unrelated TLS Stack</td><td>Some Vendor</td><td>FIPS 140-3</td><td>1/1/2025</td></tr>
</table>
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
        self.assertTrue(is_potential_fido_module("Hirsch Inc.", "HIRSCH uTrust FIDO Cryptographic Module"))

    def test_parse_certificate_detail_extracts_levels_dates_versions_and_panel_vendor(self):
        detail = parse_certificate_detail("5291", SAMPLE_DETAIL_HTML)
        self.assertEqual(detail["standard"], "FIPS 140-3")
        self.assertEqual(detail["fips_revision"], "3")
        self.assertEqual(detail["status"], "Active")
        self.assertEqual(detail["overall_level"], 2)
        self.assertEqual(detail["physical_security_level"], 3)
        self.assertEqual(detail["sunset_date"], "2031-05-21")
        self.assertEqual(detail["sunset_iso"], "2031-05-21T23:59:59Z")
        self.assertTrue(detail["security_policy_pdf_url"].endswith("140sp5291.pdf"))

        hist_detail = parse_certificate_detail("4422", SAMPLE_HISTORICAL_DETAIL_HTML)
        self.assertEqual(hist_detail["standard"], "FIPS 140-2")
        self.assertEqual(hist_detail["fips_revision"], "2")
        self.assertEqual(hist_detail["status"], "Historical")
        self.assertEqual(hist_detail["historical_reason"], "Moved to historical list due to sunsetting")
        self.assertEqual(hist_detail["vendor"], "FEITIAN Technologies US, Inc.")
        self.assertEqual(hist_detail["validation_date"], "2023-01-23")
        self.assertEqual(hist_detail["hardware_versions"], "SLE78CLUFX5000PH")
        self.assertEqual(hist_detail["firmware_versions"], "7.04")

    def test_eligibility_checks_and_in_process_parsing(self):
        self.assertTrue(is_eligible_nist_certificate({"status": "Active", "fips_revision": "3"}))
        self.assertTrue(is_eligible_nist_certificate({
            "status": "Historical",
            "fips_revision": "2",
            "historical_reason": "Moved to historical list due to sunsetting",
        }))
        self.assertFalse(is_eligible_nist_certificate({
            "status": "Historical",
            "fips_revision": "3",
            "historical_reason": "Superseded",
        }))
        self.assertFalse(is_eligible_nist_certificate({
            "status": "Revoked",
            "fips_revision": "2",
            "historical_reason": "Revoked",
        }))

        iut_entries = parse_in_process_list(SAMPLE_IUT_HTML, "IUT", "https://example.invalid/iut")
        self.assertEqual(len(iut_entries), 1)
        self.assertEqual(iut_entries[0]["vendor"], "Hirsch Inc.")
        self.assertEqual(iut_entries[0]["module_name"], "HIRSCH uTrust FIDO Cryptographic Module")

    def test_date_normalization_and_incremental_cache_reuse_with_historical_140_2(self):
        self.assertEqual(normalize_nist_date("5/21/2031"), "2031-05-21")
        self.assertEqual(normalize_nist_date("5/3/2021 8/19/2021"), "2021-08-19")
        self.assertEqual(normalize_nist_date("N/A"), "")
        with TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "nist-cache.json"
            calls = []

            def fetcher(url):
                calls.append(url)
                return SAMPLE_HISTORICAL_DETAIL_HTML if url.endswith("/4422") else SAMPLE_DETAIL_HTML

            now = datetime(2026, 6, 1, tzinfo=timezone.utc)
            candidates1, stats1 = fetch_active_nist_candidates(
                cache_path,
                curated_certs={"5291", "4422"},
                index_html=SAMPLE_INDEX_HTML,
                historical_index_htmls=[SAMPLE_HISTORICAL_HTML],
                detail_fetcher=fetcher,
                request_delay=0,
                now=now,
            )
            self.assertEqual(len(candidates1), 2)
            self.assertEqual(stats1["nist_detail_fetched"], 2)
            self.assertEqual(stats1["nist_historical_140_2_candidates"], 1)

            candidates2, stats2 = fetch_active_nist_candidates(
                cache_path,
                curated_certs={"5291", "4422"},
                index_html=SAMPLE_INDEX_HTML,
                historical_index_htmls=[SAMPLE_HISTORICAL_HTML],
                detail_fetcher=fetcher,
                request_delay=0,
                now=now,
            )
            self.assertEqual(len(candidates2), 2)
            self.assertEqual(stats2["nist_detail_fetched"], 0)
            self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
