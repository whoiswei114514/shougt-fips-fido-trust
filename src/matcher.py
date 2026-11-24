"""Strict cross-matching between active NIST CMVP modules and FIDO MDS3 FIDO2+ authenticators."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

_VENDOR_ALIASES = {
    "yubico": ("yubico", "yubikey"),
    "hid": ("hid global", "crescendo", "activid"),
    "thales": ("thales", "etoken", "safenet", "gemalto", "idprime"),
    "feitian": ("feitian", "epass"),
    "onespan": ("onespan", "digipass"),
    "idemia": ("idemia", "id-one", "cosmo"),
    "swissbit": ("swissbit", "ishield"),
    "google": ("google", "titan", "opensk"),
    "trustkey": ("trustkey", "eWBM"),
    "authentrend": ("authentrend", "atkey"),
    "token2": ("token2",),
    "nitrokey": ("nitrokey",),
    "hypersecu": ("hypersecu", "hyperpki"),
    "gotrust": ("gotrust",),
    "neowave": ("neowave", "winkeo"),
    "kensington": ("kensington", "verimark"),
}

_PRODUCT_FAMILIES = (
    ("yubikey 5", re.compile(r"\byubikey\s*5\b", re.I)),
    ("digipass fx", re.compile(r"\bdigipass\s*fx", re.I)),
    ("crescendo", re.compile(r"\bcrescendo\b", re.I)),
    ("epass", re.compile(r"\bepass\b", re.I)),
    ("ishield", re.compile(r"\bishield\b", re.I)),
    ("etoken", re.compile(r"\betoken\b", re.I)),
    ("idprime", re.compile(r"\bidprime\b", re.I)),
    ("id-one", re.compile(r"\bid-one\b", re.I)),
    ("opensk", re.compile(r"\bopensk\b", re.I)),
    ("titan", re.compile(r"\btitan\b", re.I)),
    ("atkey", re.compile(r"\batkey\b", re.I)),
    ("trustkey", re.compile(r"\btrustkey\b", re.I)),
)


def load_curated_overrides(path: Path) -> list[dict]:
    """Load audited NIST-to-AAGUID mapping overrides."""
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    items = payload.get("mappings") if isinstance(payload, dict) else None
    return [dict(item) for item in (items or []) if isinstance(item, dict)]


def _canonical_vendor(text: str) -> str:
    lowered = text.lower()
    for vendor, aliases in _VENDOR_ALIASES.items():
        if any(alias.lower() in lowered for alias in aliases):
            return vendor
    return ""


def _product_families(text: str) -> set[str]:
    return {name for name, pattern in _PRODUCT_FAMILIES if pattern.search(text)}


def _rank_nist_cert(cert: dict) -> tuple[int, int, str, int]:
    rev = int(cert.get("fips_revision") or 0)
    level = int(cert.get("overall_level") or 0)
    val_date = cert.get("validation_date") or ""
    cert_no = int(cert["cert_number"]) if str(cert.get("cert_number", "")).isdigit() else 0
    return (rev, 1 if level >= 2 else 0, val_date, cert_no)


def _format_assurance(nist_cert: dict) -> str:
    rev = str(nist_cert.get("fips_revision") or "")
    level = int(nist_cert.get("overall_level") or 0)
    if rev in {"2", "3"} and level in {2, 3, 4}:
        return f"fips140-{rev}-level{level}"
    return "standard"


def _compute_valid_until(nist_cert: dict, roots: list[dict]) -> str:
    candidates: list[datetime] = []
    sunset_iso = nist_cert.get("sunset_iso")
    if sunset_iso:
        try:
            candidates.append(datetime.fromisoformat(sunset_iso.replace("Z", "+00:00")))
        except ValueError:
            pass
    for root in roots:
        raw = root.get("not_after")
        if raw:
            try:
                candidates.append(datetime.fromisoformat(raw.replace("Z", "+00:00")))
            except ValueError:
                pass
    if not candidates:
        return ""
    return min(candidates).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def match_devices(
    nist_candidates: list[dict],
    mds_authenticators: list[dict],
    excluded_mds_fips: list[dict],
    overrides: list[dict],
    *,
    now: datetime | None = None,
) -> tuple[list[dict], dict]:
    """Cross-match active NIST FIPS modules with active FIDO2+ MDS3 authenticators."""
    current_time = now or datetime.now(timezone.utc)
    nist_by_cert = {
        str(c["cert_number"]): c
        for c in nist_candidates
        if str(c.get("status", "")).lower() == "active"
        and (not c.get("sunset_iso") or datetime.fromisoformat(c["sunset_iso"].replace("Z", "+00:00")) > current_time)
    }

    overrides_by_aaguid: dict[str, list[dict]] = {}
    for ov in overrides:
        aaguid = str(ov.get("aaguid", "")).strip().lower()
        if aaguid:
            overrides_by_aaguid.setdefault(aaguid, []).append(ov)

    matched: list[dict] = []
    matched_nist_certs: set[str] = set()
    mds_unmatched: list[dict] = []

    for mds in sorted(mds_authenticators, key=lambda item: (item["description"].lower(), item["aaguid"])):
        aaguid = mds["aaguid"]
        mds_text = f"{mds['description']} {mds['status_info'].get('certification_descriptor', '')}"
        mds_vendor = _canonical_vendor(mds_text)
        mds_families = _product_families(mds_text)

        chosen_cert: dict | None = None
        all_matching_certs: list[dict] = []
        match_method = ""
        match_notes = ""

        if aaguid in overrides_by_aaguid:
            ov_list = overrides_by_aaguid[aaguid]
            active_ov_certs = [
                nist_by_cert[str(ov["nist_cert"])]
                for ov in ov_list
                if str(ov.get("nist_cert", "")) in nist_by_cert
            ]
            if active_ov_certs:
                all_matching_certs = sorted(active_ov_certs, key=_rank_nist_cert, reverse=True)
                chosen_cert = all_matching_certs[0]
                match_method = "curated"
                chosen_ov = next(
                    (ov for ov in ov_list if str(ov.get("nist_cert")) == chosen_cert["cert_number"]),
                    ov_list[0],
                )
                match_notes = chosen_ov.get("notes", "")
            elif mds["is_fips_claimed"]:
                mds_unmatched.append({
                    "aaguid": aaguid,
                    "description": mds["description"],
                    "reason": "curated_nist_cert_not_active",
                    "configured_nist_certs": [str(ov.get("nist_cert", "")) for ov in ov_list],
                    "fido_status": mds["status_info"].get("highest_status"),
                })
                continue

        if chosen_cert is None:
            if not mds["is_fips_claimed"]:
                continue
            auto_matches: list[dict] = []
            for cert in nist_by_cert.values():
                cert_text = f"{cert['vendor']} {cert['module_name']} {cert.get('description', '')}"
                cert_vendor = _canonical_vendor(cert_text)
                cert_families = _product_families(cert_text)
                if not mds_vendor or mds_vendor != cert_vendor:
                    continue
                if mds_families and cert_families and (mds_families & cert_families):
                    auto_matches.append(cert)
            if auto_matches:
                all_matching_certs = sorted(auto_matches, key=_rank_nist_cert, reverse=True)
                chosen_cert = all_matching_certs[0]
                match_method = "auto_verified"
                match_notes = "Matched by verified FIPS claim, normalized vendor, and product family."

        if chosen_cert is None:
            mds_unmatched.append({
                "aaguid": aaguid,
                "description": mds["description"],
                "reason": "no_active_nist_match",
                "fido_status": mds["status_info"].get("highest_status"),
                "fido_cert_number": mds["status_info"].get("certificate_number"),
            })
            continue

        matched_nist_certs.update(c["cert_number"] for c in all_matching_certs)
        assurance = _format_assurance(chosen_cert)
        valid_until = _compute_valid_until(chosen_cert, mds["attestation_roots"])

        matched.append({
            "aaguid": aaguid,
            "name": mds["description"],
            "vendor": chosen_cert["vendor"],
            "match_method": match_method,
            "match_notes": match_notes,
            "assurance": assurance,
            "meets_shougt_high_assurance": assurance.startswith("fips140-"),
            "valid_until": valid_until,
            "nist": {
                "cert_number": chosen_cert["cert_number"],
                "all_active_cert_numbers": [c["cert_number"] for c in all_matching_certs],
                "standard": chosen_cert["standard"],
                "fips_revision": chosen_cert["fips_revision"],
                "overall_level": chosen_cert["overall_level"],
                "physical_security_level": chosen_cert["physical_security_level"],
                "status": chosen_cert["status"],
                "validation_date": chosen_cert["validation_date"],
                "sunset_date": chosen_cert["sunset_date"],
                "sunset_iso": chosen_cert["sunset_iso"],
                "module_name": chosen_cert["module_name"],
                "module_type": chosen_cert["module_type"],
                "detail_url": chosen_cert["detail_url"],
                "security_policy_pdf_url": chosen_cert.get("security_policy_pdf_url", ""),
            },
            "fido": {
                "protocol_family": mds["protocol_family"],
                "versions": sorted(mds["versions"]),
                "attachment_hints": mds["attachment_hints"],
                "status": mds["status_info"].get("highest_status", ""),
                "certificate_number": mds["status_info"].get("certificate_number", ""),
                "certification_descriptor": mds["status_info"].get("certification_descriptor", ""),
                "effective_date": mds["status_info"].get("effective_date", ""),
            },
            "attestation_roots": mds["attestation_roots"],
        })

    nist_unmatched = [
        {
            "cert_number": c["cert_number"],
            "vendor": c["vendor"],
            "module_name": c["module_name"],
            "standard": c["standard"],
            "overall_level": c["overall_level"],
            "sunset_date": c["sunset_date"],
            "detail_url": c["detail_url"],
        }
        for c in sorted(nist_by_cert.values(), key=lambda x: int(x["cert_number"]) if x["cert_number"].isdigit() else 0, reverse=True)
        if c["cert_number"] not in matched_nist_certs
        and re.search(r"\b(fido2?|webauthn|ctap2?|u2f|epass|opensk|yubikey|digipass|crescendo)\b", f"{c['module_name']} {c.get('description', '')}", re.I)
    ]

    review_report = {
        "mds_fips_without_active_nist": mds_unmatched,
        "mds_fips_disqualified_or_preview": sorted(excluded_mds_fips, key=lambda x: x["aaguid"]),
        "nist_fido_without_mds_aaguid": nist_unmatched,
    }
    return matched, review_report
