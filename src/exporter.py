"""Export attestation certificates, SPKI public keys, device catalog, and trust bundles."""
from __future__ import annotations

import json
import re
from pathlib import Path

import yaml


def _slugify(value: str, *, max_len: int = 44) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)
    return (slug[:max_len].rstrip("-")) or "device"


def _write_if_changed(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return
    path.write_text(content, encoding="utf-8")


def _prune_stale_files(directory: Path, expected_names: set[str], suffix: str) -> None:
    if not directory.exists():
        return
    for existing in directory.glob(f"*{suffix}"):
        if existing.name not in expected_names:
            existing.unlink()


def export_all(
    repo_root: Path,
    matched_devices: list[dict],
    nist_candidates: list[dict],
    review_report: dict,
    *,
    mds_meta: dict,
    nist_in_process: list[dict] | None = None,
) -> dict:
    """Write deterministic certs, pubkeys, JSON/YAML bundles, and update README table."""
    certs_dir = repo_root / "certs"
    pubkeys_dir = repo_root / "pubkeys"
    data_dir = repo_root / "data"
    certs_dir.mkdir(parents=True, exist_ok=True)
    pubkeys_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    expected_certs: set[str] = set()
    expected_pubkeys: set[str] = set()

    exported_devices: list[dict] = []
    trust_entries: list[dict] = []
    seen_trust_ids: set[str] = set()

    for device in matched_devices:
        dev_slug = _slugify(device["name"])
        root_records: list[dict] = []

        for root in sorted(device["attestation_roots"], key=lambda r: r["cert_sha256"]):
            prefix = root["cert_sha256"][:16]
            cert_filename = f"{prefix}-{dev_slug}.pem"
            pubkey_filename = f"{prefix}-{dev_slug}.pub.pem"
            expected_certs.add(cert_filename)
            expected_pubkeys.add(pubkey_filename)

            _write_if_changed(certs_dir / cert_filename, root["cert_pem"])
            _write_if_changed(pubkeys_dir / pubkey_filename, root["pubkey_pem"])

            cert_rel = f"certs/{cert_filename}"
            pubkey_rel = f"pubkeys/{pubkey_filename}"
            root_records.append({
                "cert_sha256": root["cert_sha256"],
                "cert_pem_path": cert_rel,
                "pubkey_sha256": root["pubkey_sha256"],
                "pubkey_pem_path": pubkey_rel,
                "pubkey_algorithm": root["pubkey_algorithm"],
                "subject": root["subject"],
                "issuer": root["issuer"],
                "not_before": root["not_before"],
                "not_after": root["not_after"],
                "pubkey_pem": root["pubkey_pem"],
            })

            if device["meets_shougt_high_assurance"]:
                nist = device["nist"]
                fido = device["fido"]
                trust_id = f"{dev_slug}-{device['aaguid'][:8]}-{root['cert_sha256'][:8]}"
                if trust_id in seen_trust_ids:
                    trust_id = f"{dev_slug}-{device['aaguid'][:8]}-{root['cert_sha256'][:12]}"
                seen_trust_ids.add(trust_id)

                fido_level = fido["status"]
                cert_num = fido.get("certificate_number") or "MDS3"
                cert_level_short = f"L{nist['overall_level']}"
                nist_status = nist.get("status") or "Unknown"
                if nist.get("validation_scope") == "platform_plus_in_process" and nist.get("in_process_entry"):
                    ip = nist["in_process_entry"]
                    cert_ref = (
                        f"NIST CMVP #{nist['cert_number']} ({nist['standard']} Level {nist['overall_level']}, "
                        f"{nist_status}, Platform + {ip['list_type']} {ip['module_name']}, {nist['detail_url']})"
                    )
                else:
                    cert_ref = (
                        f"NIST CMVP #{nist['cert_number']} ({nist['standard']} Level {nist['overall_level']}, "
                        f"{nist_status}, {nist['detail_url']})"
                    )
                trust_entries.append({
                    "id": trust_id,
                    "root_pem": cert_rel,
                    "aaguids": [device["aaguid"]],
                    "attachment": "cross-platform",
                    "assurance": device["assurance"],
                    "metadata_reference": f"FIDO Alliance MDS3 (AAGUID {device['aaguid']}, {fido_level}, {cert_num})",
                    "certification_reference": cert_ref,
                    "valid_until": device["valid_until"],
                    "revoked_certificates": [],
                    "certifications": [
                        {
                            "standard": nist["standard"],
                            "level": cert_level_short,
                            "reference": f"NIST CMVP #{nist['cert_number']} ({nist['module_name']}, {nist_status})",
                        }
                    ],
                })

        exported_devices.append({
            **{k: v for k, v in device.items() if k != "attestation_roots"},
            "attestation_roots": root_records,
        })

    _prune_stale_files(certs_dir, expected_certs, ".pem")
    _prune_stale_files(pubkeys_dir, expected_pubkeys, ".pub.pem")

    fips_140_3_count = sum(1 for d in exported_devices if str(d.get("nist", {}).get("fips_revision", "")) == "3")
    fips_140_2_count = sum(1 for d in exported_devices if str(d.get("nist", {}).get("fips_revision", "")) == "2")
    catalog_payload = {
        "schema_version": 1,
        "mds_blob_no": mds_meta.get("no"),
        "mds_next_update": mds_meta.get("nextUpdate"),
        "device_count": len(exported_devices),
        "fips_140_3_count": fips_140_3_count,
        "fips_140_2_count": fips_140_2_count,
        "devices": exported_devices,
    }
    _write_if_changed(
        data_dir / "fips-fido2-devices.json",
        json.dumps(catalog_payload, ensure_ascii=False, indent=2) + "\n",
    )

    _write_if_changed(
        data_dir / "shougt-fido-attestation-trust.json",
        json.dumps(trust_entries, ensure_ascii=False, indent=2) + "\n",
    )

    yaml_header = (
        "# Auto-generated FIDO_ATTESTATION_TRUST entries for shougt-v0-backend.\n"
        "# Place downloaded root PEMs under the backend working path and paste under `fido_attestation_trust:`.\n"
    )
    yaml_body = yaml.safe_dump(trust_entries, allow_unicode=True, sort_keys=False, default_flow_style=False)
    _write_if_changed(data_dir / "shougt-fido-attestation-trust.yaml", yaml_header + yaml_body)

    clean_candidates = [
        {k: v for k, v in item.items() if k != "cached_at"}
        for item in sorted(nist_candidates, key=lambda x: int(x["cert_number"]) if str(x["cert_number"]).isdigit() else 0, reverse=True)
    ]
    _write_if_changed(
        data_dir / "nist-fido-candidates.json",
        json.dumps({"count": len(clean_candidates), "candidates": clean_candidates}, ensure_ascii=False, indent=2) + "\n",
    )
    if nist_in_process is not None:
        _write_if_changed(
            data_dir / "nist-in-process.json",
            json.dumps({"count": len(nist_in_process), "entries": nist_in_process}, ensure_ascii=False, indent=2) + "\n",
        )
    _write_if_changed(
        data_dir / "unmatched-review.json",
        json.dumps(review_report, ensure_ascii=False, indent=2) + "\n",
    )

    _update_readme_table(repo_root / "README.md", exported_devices)

    return {
        "device_count": len(exported_devices),
        "fips_140_3_device_count": fips_140_3_count,
        "fips_140_2_device_count": fips_140_2_count,
        "trust_entry_count": len(trust_entries),
        "cert_files": len(expected_certs),
        "pubkey_files": len(expected_pubkeys),
    }


def _update_readme_table(readme_path: Path, devices: list[dict]) -> None:
    if not readme_path.exists():
        return
    content = readme_path.read_text(encoding="utf-8")
    start_marker = "<!-- DEVICES_TABLE_START -->"
    end_marker = "<!-- DEVICES_TABLE_END -->"
    if start_marker not in content or end_marker not in content:
        return

    lines = [
        "| 型号名称 | 厂商 | AAGUID | FIPS 证书 | FIDO2 版本 / 等级 | 有效期至 | 根证书 / 公钥数 |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for dev in devices:
        nist = dev["nist"]
        fido = dev["fido"]
        vers = ", ".join(fido["versions"])
        if nist.get("validation_scope") == "platform_plus_in_process":
            ip = nist.get("in_process_entry")
            scope_tag = f"Platform + {ip['list_type']}" if ip else "Platform + IUT/MIP"
        else:
            scope_tag = nist.get("status") or "Unknown"
        cert_cell = f"[#{nist['cert_number']}]({nist['detail_url']}) ({nist['standard']} L{nist['overall_level']}, {scope_tag})"
        expiry_cell = nist.get("sunset_date") or (dev["valid_until"][:10] if dev.get("valid_until") else "-")
        root_count = len(dev["attestation_roots"])
        lines.append(
            f"| {dev['name']} | {dev['vendor']} | `{dev['aaguid']}` | {cert_cell} | {vers} / `{fido['status']}` | {expiry_cell} | {root_count} 组 |"
        )
    if not devices:
        lines.append("| （暂未匹配到设备） | - | - | - | - | - | - |")

    table = "\n".join(lines)
    before, _, rest = content.partition(start_marker)
    _, _, after = rest.partition(end_marker)
    updated = f"{before}{start_marker}\n{table}\n{end_marker}{after}"
    _write_if_changed(readme_path, updated)
