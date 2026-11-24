"""Fetch and parse active and non-revoked Historical FIPS 140-2 NIST CMVP modules plus MIP/IUT."""
from __future__ import annotations

import html as html_lib
import json
import re
import time
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path

from .http_client import fetch_text

NIST_ACTIVE_URL = (
    "https://csrc.nist.gov/projects/cryptographic-module-validation-program/"
    "validated-modules/search/all?searchMode=Basic&Vendor=&CertificateStatus=Active&ValidationYear=0"
)
NIST_HISTORICAL_140_2_HW_URL_TEMPLATE = (
    "https://csrc.nist.gov/projects/cryptographic-module-validation-program/"
    "validated-modules/search?SearchMode=Advanced&Standard=140-2&ModuleType=Hardware"
    "&CertificateStatus=Historical&ValidationYear={year}"
)
NIST_HISTORICAL_140_2_HYBRID_URL = (
    "https://csrc.nist.gov/projects/cryptographic-module-validation-program/"
    "validated-modules/search?SearchMode=Advanced&Standard=140-2&ModuleType=Firmware-Hybrid"
    "&CertificateStatus=Historical"
)
NIST_MIP_URL = (
    "https://csrc.nist.gov/projects/cryptographic-module-validation-program/"
    "modules-in-process/modules-in-process-list"
)
NIST_IUT_URL = (
    "https://csrc.nist.gov/projects/cryptographic-module-validation-program/"
    "modules-in-process/iut-list"
)
NIST_CERT_URL_TEMPLATE = (
    "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/{cert_number}"
)

_HARDWARE_MODULE_TYPES = {"hardware", "firmware-hybrid", "hardware-hybrid"}

_EXCLUDED_PATTERNS = re.compile(
    r"\b("
    r"yubihsm|luna|hsm|nvme|ufs|tensor|inline crypto engine|trng|fpga|"
    r"encryptor|router|switch|firewall|self-encrypting|storage engine|safeword|"
    r"trusted platform module|tpm|nshield|cryptovisor|protectserver|"
    r"postal security|infusion pump|look-aside cryptography|"
    r"fortigate|fortimail|fortiproxy|fortisandbox|fireeye|sd-wan|ssd"
    r")\b",
    re.I,
)

_FIDO_INDICATOR_PATTERNS = re.compile(
    r"("
    r"\bfido2?\b|\bctap2?\b|\bwebauthn\b|\bu2f\b|"
    r"\byubikey\b|\bepass\b|\bbiopass\b|\biepass\b|\bdigipass\b|\bcrescendo\b|\bishield\b|"
    r"\betoken\b|\bopensk\b|\btitan\b|\bsecurity key\b|\bpasskey\b|"
    r"\bsmart\s?card\b|\bpiv\b|\bidprime\b|\bidcore\b|\bid-one\b|\bcosmo\b|\bactivid\b|"
    r"\btrustkey\b|\bewbm\b|\bms1201\b|\btoken2\b|\bnitrokey\b|\bauthentrend\b|"
    r"\bhyperpki\b|\bhyp2003\b|\bhypersecu\b|"
    r"\bgotrust\b|\bneowave\b|\bkensington\b|\bhirsch\b|\bidentiv\b|\butrust\b|\bsecurekey\b|"
    r"\bstarsign\b|\btaglio\b|"
    r"\byubico\b|\bfeitian\b|\bswissbit\b|\bonespan\b|\bidemia\b|\bthales\b|\bhid global\b|"
    r"\bgiesecke\b|\bjcop\b|\bp71d600\b"
    r")",
    re.I,
)

_NUMERIC_DATE_RE = re.compile(r"\b(\d{1,2}/\d{1,2}/\d{4}|\d{4}-\d{2}-\d{2})\b")


def _clean_space(text: str) -> str:
    return re.sub(r"\s+", " ", html_lib.unescape(text or "")).strip()


def normalize_nist_date(value: str) -> str:
    """Convert NIST date strings (including multi-date cells) into latest ISO YYYY-MM-DD."""
    raw = _clean_space(value or "")
    if not raw or raw.upper() == "N/A":
        return ""
    parsed: list[str] = []
    for token in _NUMERIC_DATE_RE.findall(raw):
        fmt = "%Y-%m-%d" if "-" in token else "%m/%d/%Y"
        try:
            parsed.append(datetime.strptime(token, fmt).strftime("%Y-%m-%d"))
        except ValueError:
            continue
    if parsed:
        return max(parsed)
    for fmt in ("%B %d, %Y", "%b %d, %Y"):
        try:
            return datetime.strptime(raw, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    return ""


def sunset_to_iso_utc(date_str: str) -> str:
    """Convert YYYY-MM-DD sunset date into ISO-8601 UTC end-of-day timestamp."""
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_str or ""):
        return ""
    return f"{date_str}T23:59:59Z"


class _ActiveTableParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.rows: list[list[str]] = []
        self._in_tr = False
        self._in_cell = False
        self._current_row: list[str] = []
        self._cell_parts: list[str] = []
        self._current_row_href = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "tr":
            self._in_tr = True
            self._current_row = []
            self._current_row_href = ""
        elif self._in_tr and tag in {"td", "th"}:
            self._in_cell = True
            self._cell_parts = []
        elif self._in_cell and tag == "br":
            self._cell_parts.append(" ")
        elif self._in_cell and tag == "a":
            href = dict(attrs).get("href") or ""
            if "/certificate/" in href:
                self._current_row_href = href

    def handle_data(self, data: str) -> None:
        if self._in_cell:
            self._cell_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if self._in_cell and tag in {"td", "th"}:
            self._in_cell = False
            self._current_row.append(_clean_space("".join(self._cell_parts)))
        elif self._in_tr and tag == "tr":
            self._in_tr = False
            if len(self._current_row) >= 5 and re.fullmatch(r"\d+", self._current_row[0]):
                self.rows.append(self._current_row[:5] + [self._current_row_href])


class _InProcessTableParser(HTMLParser):
    """Extract data rows from NIST CMVP MIP and IUT HTML tables."""

    def __init__(self) -> None:
        super().__init__()
        self.rows: list[list[str]] = []
        self._in_tr = False
        self._in_td = False
        self._current_row: list[str] = []
        self._cell_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        _ = attrs
        if tag == "tr":
            self._in_tr = True
            self._current_row = []
        elif self._in_tr and tag == "td":
            self._in_td = True
            self._cell_parts = []
        elif self._in_td and tag in {"br", "p", "div", "li"}:
            self._cell_parts.append(" ")

    def handle_data(self, data: str) -> None:
        if self._in_td:
            self._cell_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if self._in_td and tag == "td":
            self._in_td = False
            self._current_row.append(_clean_space("".join(self._cell_parts)))
        elif self._in_tr and tag == "tr":
            self._in_tr = False
            if len(self._current_row) >= 4:
                self.rows.append(self._current_row)


class _RowDivParser(HTMLParser):
    """Extract label/value div pairs even when Bootstrap `.row` containers are nested."""

    def __init__(self) -> None:
        super().__init__()
        self._depth = 0
        self._row_stack: list[dict] = []
        self.pairs: list[tuple[str, str]] = []
        self.pdf_links: list[str] = []
        self.title = ""
        self._in_h1 = False
        self._h1_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = dict(attrs)
        if tag == "a":
            href = attr_map.get("href") or ""
            if "140sp" in href.lower() and href.lower().endswith(".pdf"):
                self.pdf_links.append(href)
        if tag == "h1":
            self._in_h1 = True
            self._h1_parts = []
        if tag == "div":
            self._depth += 1
            classes = set((attr_map.get("class") or "").split())
            if "row" in classes:
                self._row_stack.append({"depth": self._depth, "cols": [], "col_depth": None, "parts": []})
            elif self._row_stack:
                top = self._row_stack[-1]
                if top["col_depth"] is None and self._depth == top["depth"] + 1:
                    top["col_depth"] = self._depth
                    top["parts"] = []
        elif self._row_stack and self._row_stack[-1]["col_depth"] is not None and tag in {"br", "p", "li"}:
            self._row_stack[-1]["parts"].append(" ")

    def handle_data(self, data: str) -> None:
        if self._in_h1:
            self._h1_parts.append(data)
        for row in self._row_stack:
            if row["col_depth"] is not None:
                row["parts"].append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "h1" and self._in_h1:
            self._in_h1 = False
            self.title = _clean_space("".join(self._h1_parts))
        if tag == "div" and self._depth > 0:
            if self._row_stack:
                top = self._row_stack[-1]
                if top["col_depth"] == self._depth:
                    top["cols"].append(_clean_space("".join(top["parts"])))
                    top["col_depth"] = None
                elif top["depth"] == self._depth:
                    finished = self._row_stack.pop()
                    if len(finished["cols"]) == 2 and finished["cols"][0]:
                        self.pairs.append((finished["cols"][0], finished["cols"][1]))
            self._depth -= 1


def parse_active_index(html: str) -> list[dict]:
    """Parse NIST CMVP search results HTML table into structured records."""
    parser = _ActiveTableParser()
    parser.feed(html)
    records = []
    for cert_no, vendor, module_name, module_type, validation_date, href in parser.rows:
        detail_url = (
            href
            if href.startswith("http")
            else f"https://csrc.nist.gov{href}"
            if href.startswith("/")
            else NIST_CERT_URL_TEMPLATE.format(cert_number=cert_no)
        )
        records.append({
            "cert_number": cert_no,
            "vendor": vendor,
            "module_name": module_name,
            "module_type": module_type,
            "validation_date_raw": validation_date,
            "validation_date": normalize_nist_date(validation_date),
            "detail_url": detail_url,
        })
    return records


def is_hardware_module_type(module_type: str) -> bool:
    """Return True if the NIST module type represents hardware or hardware-hybrid."""
    normalized = _clean_space(module_type).lower().replace(" ", "-")
    return normalized in _HARDWARE_MODULE_TYPES


def is_excluded_non_authenticator(vendor: str, module_name: str, description: str = "") -> bool:
    """Return True for hardware categories that cannot act as external FIDO2 authenticators."""
    combined = f"{vendor} {module_name} {description}"
    return bool(_EXCLUDED_PATTERNS.search(combined))


def is_potential_fido_module(
    vendor: str,
    module_name: str,
    description: str = "",
    caveat: str = "",
) -> bool:
    """Return True when a hardware NIST module could be an external FIDO authenticator."""
    if is_excluded_non_authenticator(vendor, module_name, description):
        return False
    combined = f"{vendor} {module_name} {description} {caveat}"
    return bool(_FIDO_INDICATOR_PATTERNS.search(combined))


def is_revoked_certificate(record: dict) -> bool:
    """Return True if the NIST certificate was revoked."""
    status = str(record.get("status", "")).strip().lower()
    reason = str(record.get("historical_reason", "")).strip().lower()
    return status == "revoked" or "revoked" in reason


def is_eligible_nist_certificate(record: dict) -> bool:
    """Return True for Active certificates and non-revoked Historical FIPS 140-2 certificates."""
    if is_revoked_certificate(record):
        return False
    status = str(record.get("status", "")).strip().lower()
    revision = str(record.get("fips_revision", "")).strip()
    if status == "active":
        return True
    return status == "historical" and revision == "2"


def _extract_vendor_from_panel(html: str) -> str:
    match = re.search(
        r"<h4[^>]*class=[\"'][^\"']*panel-title[^\"']*[\"'][^>]*>\s*Vendor\s*</h4>"
        r".*?<div[^>]*class=[\"'][^\"']*panel-body[^\"']*[\"'][^>]*>(.*?)</div>",
        html,
        re.S | re.I,
    )
    if not match:
        return ""
    body = match.group(1)
    anchor_match = re.search(r"<a[^>]*>(.*?)</a>", body, re.S | re.I)
    if anchor_match:
        vendor_text = _clean_space(re.sub(r"<[^>]+>", " ", anchor_match.group(1)))
        if vendor_text:
            return vendor_text.split("[email")[0].strip()
    first_chunk = re.split(r"<br\b", body, maxsplit=1, flags=re.I)[0]
    vendor_text = _clean_space(re.sub(r"<[^>]+>", " ", first_chunk))
    return vendor_text.split("[email")[0].strip()


def _extract_validation_history_date(html: str) -> str:
    match = re.search(
        r"<h4[^>]*class=[\"'][^\"']*panel-title[^\"']*[\"'][^>]*>\s*Validation History\s*</h4>"
        r".*?<div[^>]*class=[\"'][^\"']*panel-body[^\"']*[\"'][^>]*>(.*?)</div>",
        html,
        re.S | re.I,
    )
    if not match:
        return ""
    panel_text = _clean_space(re.sub(r"<[^>]+>", " ", match.group(1)))
    return normalize_nist_date(panel_text)


def parse_certificate_detail(
    cert_number: str,
    html: str,
    *,
    index_entry: dict | None = None,
) -> dict:
    """Extract validated FIPS level, dates, status, versions, historical reason, and policy URL."""
    parser = _RowDivParser()
    parser.feed(html)
    fields: dict[str, str] = {}
    for label, value in parser.pairs:
        key = label.rstrip(":").strip().lower()
        if key not in fields and value:
            fields[key] = value

    standard_raw = fields.get("standard", "")
    std_match = re.search(r"FIPS\s*140-([23])", standard_raw, re.I)
    if not std_match:
        std_match = re.search(r"FIPS\s*140-([23])", html, re.I)
    fips_version = std_match.group(1) if std_match else ""
    standard = f"FIPS 140-{fips_version}" if fips_version else standard_raw

    overall_raw = fields.get("overall level", "")
    lvl_match = re.search(r"\b([1-4])\b", overall_raw)
    overall_level = int(lvl_match.group(1)) if lvl_match else 0

    exceptions_raw = fields.get("security level exceptions", "")
    phys_match = re.search(r"Physical security\s*:\s*Level\s*([1-4])", exceptions_raw, re.I)
    physical_level = int(phys_match.group(1)) if phys_match else overall_level

    vendor_raw = fields.get("vendor", "")
    vendor = (
        (index_entry or {}).get("vendor")
        or (vendor_raw.split(" [email")[0].strip() if vendor_raw else "")
        or _extract_vendor_from_panel(html)
    )
    module_name = (index_entry or {}).get("module_name") or fields.get("module name", "") or parser.title
    module_type = fields.get("module type", "") or (index_entry or {}).get("module_type", "")

    sunset_date = normalize_nist_date(fields.get("sunset date", ""))
    validation_date = (
        normalize_nist_date(fields.get("validation date", ""))
        or _extract_validation_history_date(html)
        or (index_entry or {}).get("validation_date", "")
    )
    hardware_versions = fields.get("hardware versions") or fields.get("hardware version") or ""
    firmware_versions = fields.get("firmware versions") or fields.get("firmware version") or ""
    historical_reason = fields.get("historical reason", "")

    pdf_url = ""
    for link in parser.pdf_links:
        pdf_url = link if link.startswith("http") else f"https://csrc.nist.gov{link}"
        break

    return {
        "cert_number": str(cert_number),
        "standard": standard,
        "fips_revision": fips_version,
        "status": fields.get("status", ""),
        "historical_reason": historical_reason,
        "overall_level": overall_level,
        "physical_security_level": physical_level,
        "validation_date": validation_date,
        "sunset_date": sunset_date,
        "sunset_iso": sunset_to_iso_utc(sunset_date),
        "module_type": module_type,
        "embodiment": fields.get("embodiment", ""),
        "hardware_versions": hardware_versions,
        "firmware_versions": firmware_versions,
        "vendor": vendor,
        "module_name": module_name,
        "description": fields.get("description", ""),
        "caveat": fields.get("caveat", ""),
        "detail_url": NIST_CERT_URL_TEMPLATE.format(cert_number=cert_number),
        "security_policy_pdf_url": pdf_url,
    }


def parse_in_process_list(html: str, list_type: str, source_url: str) -> list[dict]:
    """Parse NIST CMVP Modules In Process (MIP) or Implementation Under Test (IUT) table rows."""
    parser = _InProcessTableParser()
    parser.feed(html)
    results: list[dict] = []
    for row in parser.rows:
        module_name = row[0]
        vendor = re.sub(r"\s*View Contacts\s*$", "", row[1], flags=re.I).strip()
        standard = row[2]
        status_or_date = row[3]
        if not module_name or module_name.lower() in {"module name", "vendor name"}:
            continue
        if not is_potential_fido_module(vendor, module_name):
            continue
        results.append({
            "list_type": list_type,
            "module_name": module_name,
            "vendor": vendor,
            "standard": standard,
            "status_or_date": status_or_date,
            "source_url": source_url,
        })
    return results


def fetch_nist_in_process(
    *,
    mip_html: str | None = None,
    iut_html: str | None = None,
    request_delay: float = 0.25,
) -> list[dict]:
    """Fetch and parse FIDO/smartcard candidates from official NIST CMVP MIP and IUT lists."""
    entries: list[dict] = []
    mip_raw = mip_html if mip_html is not None else fetch_text(NIST_MIP_URL)
    entries.extend(parse_in_process_list(mip_raw, "MIP", NIST_MIP_URL))
    if iut_html is None and request_delay > 0:
        time.sleep(request_delay)
    iut_raw = iut_html if iut_html is not None else fetch_text(NIST_IUT_URL)
    entries.extend(parse_in_process_list(iut_raw, "IUT", NIST_IUT_URL))
    entries.sort(key=lambda item: (item["list_type"], item["vendor"].lower(), item["module_name"].lower()))
    return entries


def _load_cache(cache_path: Path) -> dict[str, dict]:
    if not cache_path.exists():
        return {}
    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    items = payload.get("certificates") if isinstance(payload, dict) else None
    return dict(items) if isinstance(items, dict) else {}


def _save_cache(cache_path: Path, certs: dict[str, dict]) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    ordered = {k: certs[k] for k in sorted(certs, key=lambda x: int(x) if x.isdigit() else 0)}
    cache_path.write_text(
        json.dumps({"certificates": ordered}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def fetch_active_nist_candidates(
    cache_path: Path,
    *,
    curated_certs: set[str] | None = None,
    force_refresh: bool = False,
    cache_ttl_days: int = 14,
    index_html: str | None = None,
    detail_fetcher=None,
    request_delay: float = 0.35,
    now: datetime | None = None,
    include_historical_140_2: bool = True,
    historical_start_year: int = 2018,
    historical_index_htmls: list[str] | None = None,
    historical_cache_ttl_days: int = 30,
) -> tuple[list[dict], dict]:
    """Fetch Active FIPS 140-3 and non-revoked Historical FIPS 140-2 hardware candidates."""
    current_time = now or datetime.now(timezone.utc)
    curated = {str(c) for c in (curated_certs or set())}

    raw_index = index_html if index_html is not None else fetch_text(NIST_ACTIVE_URL)
    all_active = parse_active_index(raw_index)

    historical_records: list[dict] = []
    if index_html is None:
        if include_historical_140_2:
            for year in range(historical_start_year, current_time.year + 1):
                if request_delay > 0:
                    time.sleep(request_delay)
                yr_html = fetch_text(NIST_HISTORICAL_140_2_HW_URL_TEMPLATE.format(year=year))
                historical_records.extend(parse_active_index(yr_html))
            if request_delay > 0:
                time.sleep(request_delay)
            hyb_html = fetch_text(NIST_HISTORICAL_140_2_HYBRID_URL)
            historical_records.extend(parse_active_index(hyb_html))
    elif include_historical_140_2 and historical_index_htmls:
        for h_html in historical_index_htmls:
            historical_records.extend(parse_active_index(h_html))

    active_hardware = [item for item in all_active if is_hardware_module_type(item["module_type"])]
    hist_hardware = [item for item in historical_records if is_hardware_module_type(item["module_type"])]

    dedup_by_cert: dict[str, dict] = {}
    for item in active_hardware:
        entry = {**item, "_source": "active"}
        dedup_by_cert[item["cert_number"]] = entry
    for item in hist_hardware:
        if item["cert_number"] not in dedup_by_cert:
            dedup_by_cert[item["cert_number"]] = {**item, "_source": "historical"}

    # Ensure every curated cert (Active or Historical FIPS 140-2) is always inspected even if
    # omitted from search pagination or sparse table rows.
    for cert_no in sorted(curated, key=lambda x: int(x) if x.isdigit() else 0):
        if cert_no not in dedup_by_cert:
            dedup_by_cert[cert_no] = {
                "cert_number": cert_no,
                "vendor": "",
                "module_name": "",
                "module_type": "Hardware",
                "validation_date_raw": "",
                "validation_date": "",
                "detail_url": NIST_CERT_URL_TEMPLATE.format(cert_number=cert_no),
                "_source": "curated",
            }

    candidate_index = [
        item
        for item in dedup_by_cert.values()
        if item["cert_number"] in curated
        or is_potential_fido_module(item["vendor"], item["module_name"])
    ]

    cache = _load_cache(cache_path)
    active_cert_numbers = {item["cert_number"] for item in all_active}

    # Invalidate previously Active cache entries that dropped off NIST Active so their current status is refetched.
    for cert_no, cached in list(cache.items()):
        if cert_no not in active_cert_numbers and str(cached.get("status", "")).lower() == "active":
            cached["status"] = "InactiveOrRemoved"

    fetcher = detail_fetcher or fetch_text
    results: list[dict] = []
    fetched_count = 0

    for item in candidate_index:
        cert_no = item["cert_number"]
        cached = cache.get(cert_no)
        fresh_cache = False
        if cached and not force_refresh:
            cached_status = str(cached.get("status", "")).lower()
            source_kind = item.get("_source", "active")
            status_consistent = (
                (source_kind == "active" and cached_status == "active")
                or (source_kind == "historical" and cached_status in {"historical", "revoked"})
                or (source_kind == "curated" and cached_status in {"active", "historical", "revoked"})
            )
            val_matches = (not item["validation_date"]) or (cached.get("validation_date") == item["validation_date"])
            has_complete_fields = bool(cached.get("status") and cached.get("overall_level") and cached.get("vendor"))
            ttl_days = historical_cache_ttl_days if cached_status == "historical" else cache_ttl_days
            if status_consistent and val_matches and has_complete_fields:
                fetched_at_raw = cached.get("cached_at", "")
                try:
                    fetched_at = datetime.fromisoformat(fetched_at_raw.replace("Z", "+00:00"))
                    if current_time - fetched_at < timedelta(days=ttl_days):
                        fresh_cache = True
                except ValueError:
                    fresh_cache = False

        if fresh_cache and cached is not None:
            record = dict(cached)
        else:
            if fetched_count > 0 and request_delay > 0:
                time.sleep(request_delay)
            html = fetcher(item["detail_url"])
            fetched_count += 1
            record = parse_certificate_detail(cert_no, html, index_entry=item)
            cache[cert_no] = {
                **record,
                "cached_at": current_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }

        if not is_eligible_nist_certificate(record):
            continue
        if not (cert_no in curated or is_potential_fido_module(
            record["vendor"], record["module_name"], record.get("description", ""), record.get("caveat", "")
        )):
            continue
        results.append(record)

    _save_cache(cache_path, cache)
    active_cand_count = sum(1 for r in results if str(r.get("status", "")).lower() == "active")
    hist_cand_count = sum(1 for r in results if str(r.get("status", "")).lower() == "historical")
    stats = {
        "nist_total_active": len(all_active),
        "nist_active_hardware": len(active_hardware),
        "nist_historical_140_2_hardware": len(hist_hardware),
        "nist_active_candidates": active_cand_count,
        "nist_historical_140_2_candidates": hist_cand_count,
        "nist_candidate_count": len(results),
        "nist_detail_fetched": fetched_count,
    }
    return results, stats
