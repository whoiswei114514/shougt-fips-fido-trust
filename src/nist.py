"""Fetch and parse active NIST CMVP FIPS 140-2 / 140-3 hardware modules."""
from __future__ import annotations

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
NIST_CERT_URL_TEMPLATE = (
    "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/{cert_number}"
)

_HARDWARE_MODULE_TYPES = {"hardware", "firmware-hybrid", "hardware-hybrid"}

_EXCLUDED_PATTERNS = re.compile(
    r"\b("
    r"yubihsm|luna|hsm|nvme|ufs|tensor|inline crypto engine|trng|fpga|"
    r"encryptor|router|switch|firewall|self-encrypting|storage engine|safeword"
    r")\b",
    re.I,
)

_FIDO_INDICATOR_PATTERNS = re.compile(
    r"("
    r"\bfido2?\b|\bctap2?\b|\bwebauthn\b|\bu2f\b|"
    r"\byubikey\b|\bepass\b|\bdigipass\b|\bcrescendo\b|\bishield\b|"
    r"\betoken\b|\bopensk\b|\btitan\b|\bsecurity key\b|\bpasskey\b|"
    r"\bsmart\s?card\b|\bpiv\b|\bidprime\b|\bid-one\b|\bactivid\b|"
    r"\btrustkey\b|\btoken2\b|\bnitrokey\b|\bauthentrend\b|\bhyperpki\b|"
    r"\bgotrust\b|\bneowave\b|\bkensington\b|"
    r"\byubico\b|\bfeitian\b|\bswissbit\b|\bonespan\b|\bidemia\b|\bthales\b|\bhid global\b"
    r")",
    re.I,
)


def _clean_space(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def normalize_nist_date(value: str) -> str:
    """Convert NIST date strings like 5/21/2031 or 05/22/2026 to ISO YYYY-MM-DD."""
    raw = _clean_space(value or "")
    if not raw or raw.upper() == "N/A":
        return ""
    for fmt in ("%m/%d/%Y", "%Y-%m-%d", "%B %d, %Y", "%b %d, %Y"):
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
        self._links: list[str] = []
        self._current_row_href = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "tr":
            self._in_tr = True
            self._current_row = []
            self._current_row_href = ""
        elif self._in_tr and tag in {"td", "th"}:
            self._in_cell = True
            self._cell_parts = []
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
    """Parse NIST CMVP active validated modules HTML table into structured records."""
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
    return _clean_space(module_type).lower() in _HARDWARE_MODULE_TYPES


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
    """Return True when an active hardware NIST module could be an external FIDO authenticator."""
    if is_excluded_non_authenticator(vendor, module_name, description):
        return False
    combined = f"{vendor} {module_name} {description} {caveat}"
    return bool(_FIDO_INDICATOR_PATTERNS.search(combined))


def parse_certificate_detail(
    cert_number: str,
    html: str,
    *,
    index_entry: dict | None = None,
) -> dict:
    """Extract validated FIPS level, dates, status, description, and policy URL."""
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
    vendor = (index_entry or {}).get("vendor") or vendor_raw.split(" [email")[0].strip()
    module_name = (index_entry or {}).get("module_name") or fields.get("module name", "") or parser.title
    module_type = fields.get("module type", "") or (index_entry or {}).get("module_type", "")

    sunset_date = normalize_nist_date(fields.get("sunset date", ""))
    validation_date = normalize_nist_date(fields.get("validation date", "")) or (index_entry or {}).get("validation_date", "")

    pdf_url = ""
    for link in parser.pdf_links:
        pdf_url = link if link.startswith("http") else f"https://csrc.nist.gov{link}"
        break

    return {
        "cert_number": str(cert_number),
        "standard": standard,
        "fips_revision": fips_version,
        "status": fields.get("status", ""),
        "overall_level": overall_level,
        "physical_security_level": physical_level,
        "validation_date": validation_date,
        "sunset_date": sunset_date,
        "sunset_iso": sunset_to_iso_utc(sunset_date),
        "module_type": module_type,
        "embodiment": fields.get("embodiment", ""),
        "vendor": vendor,
        "module_name": module_name,
        "description": fields.get("description", ""),
        "caveat": fields.get("caveat", ""),
        "detail_url": NIST_CERT_URL_TEMPLATE.format(cert_number=cert_number),
        "security_policy_pdf_url": pdf_url,
    }


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
) -> tuple[list[dict], dict]:
    """Fetch active NIST CMVP hardware modules and enrich candidate certificate details."""
    current_time = now or datetime.now(timezone.utc)
    curated = {str(c) for c in (curated_certs or set())}

    raw_index = index_html if index_html is not None else fetch_text(NIST_ACTIVE_URL)
    all_active = parse_active_index(raw_index)
    hardware_active = [item for item in all_active if is_hardware_module_type(item["module_type"])]
    candidate_index = [
        item
        for item in hardware_active
        if item["cert_number"] in curated
        or is_potential_fido_module(item["vendor"], item["module_name"])
    ]

    cache = _load_cache(cache_path)
    active_cert_numbers = {item["cert_number"] for item in all_active}

    # Mark cached certificates that dropped off NIST Active as non-active cleanly.
    for cert_no, cached in list(cache.items()):
        if cert_no not in active_cert_numbers and cached.get("status") == "Active":
            cached["status"] = "InactiveOrRemoved"

    fetcher = detail_fetcher or fetch_text
    results: list[dict] = []
    fetched_count = 0

    for item in candidate_index:
        cert_no = item["cert_number"]
        cached = cache.get(cert_no)
        fresh_cache = False
        if cached and not force_refresh and cached.get("status") and cached.get("overall_level") and cached.get("validation_date") == item["validation_date"]:
            fetched_at_raw = cached.get("cached_at", "")
            try:
                fetched_at = datetime.fromisoformat(fetched_at_raw.replace("Z", "+00:00"))
                if current_time - fetched_at < timedelta(days=cache_ttl_days):
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

        if record.get("status", "").lower() != "active":
            continue
        if not (cert_no in curated or is_potential_fido_module(
            record["vendor"], record["module_name"], record.get("description", ""), record.get("caveat", "")
        )):
            continue
        results.append(record)

    _save_cache(cache_path, cache)
    stats = {
        "nist_total_active": len(all_active),
        "nist_active_hardware": len(hardware_active),
        "nist_candidate_count": len(results),
        "nist_detail_fetched": fetched_count,
    }
    return results, stats
