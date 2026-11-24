"""CLI entrypoint to sync NIST CMVP FIPS certificates and FIDO Alliance MDS3 FIDO2+ authenticators."""
from __future__ import annotations

import argparse
from pathlib import Path

from .exporter import export_all
from .fido_mds import extract_fido2_authenticators, fetch_verified_mds3
from .matcher import load_curated_overrides, match_devices
from .nist import fetch_active_nist_candidates
from .validate import validate_repo


def run_sync(
    repo_root: Path,
    *,
    force_nist_refresh: bool = False,
    mds_file: Path | None = None,
    nist_index_file: Path | None = None,
    dry_run: bool = False,
    summary_file: Path | None = None,
) -> dict:
    """Execute end-to-end NIST CMVP + FIDO MDS3 verification, matching, and export."""
    roots_dir = repo_root / "roots"
    overrides = load_curated_overrides(repo_root / "mappings" / "curated-overrides.json")
    curated_certs = {str(item["nist_cert"]) for item in overrides if item.get("nist_cert")}

    mds_payload = fetch_verified_mds3(roots_dir, mds_file=mds_file)
    mds_authenticators, excluded_mds_fips = extract_fido2_authenticators(mds_payload)

    index_html = nist_index_file.read_text(encoding="utf-8") if nist_index_file else None
    nist_candidates, nist_stats = fetch_active_nist_candidates(
        repo_root / "data" / "nist-cache.json",
        curated_certs=curated_certs,
        force_refresh=force_nist_refresh,
        index_html=index_html,
    )

    matched_devices, review_report = match_devices(
        nist_candidates,
        mds_authenticators,
        excluded_mds_fips,
        overrides,
    )

    export_stats = {
        "device_count": len(matched_devices),
        "trust_entry_count": 0,
        "cert_files": 0,
        "pubkey_files": 0,
    }
    if not dry_run:
        export_stats = export_all(
            repo_root,
            matched_devices,
            nist_candidates,
            review_report,
            mds_meta={"no": mds_payload.get("no"), "nextUpdate": mds_payload.get("nextUpdate")},
        )
        errors = validate_repo(repo_root)
        if errors:
            raise RuntimeError("Post-export validation failed:\n" + "\n".join(errors))

    summary = {
        "mds_blob_no": mds_payload.get("no"),
        "mds_next_update": mds_payload.get("nextUpdate"),
        "mds_fido2_certified_count": len(mds_authenticators),
        "mds_fips_disqualified_count": len(excluded_mds_fips),
        **nist_stats,
        **export_stats,
        "unmatched_mds_fips_count": len(review_report["mds_fips_without_active_nist"]),
        "unmatched_nist_fido_count": len(review_report["nist_fido_without_mds_aaguid"]),
    }

    if summary_file is not None:
        md = (
            "## FIPS + FIDO2+ Trust Sync Summary\n\n"
            f"- MDS3 BLOB No.: `{summary['mds_blob_no']}` (nextUpdate: `{summary['mds_next_update']}`)\n"
            f"- FIDO2+ certified authenticators in MDS3: **{summary['mds_fido2_certified_count']}**\n"
            f"- NIST active hardware modules inspected: **{summary['nist_active_hardware']}** "
            f"(FIDO/curated candidates: **{summary['nist_candidate_count']}**, fresh detail fetches: **{summary['nist_detail_fetched']}**)\n"
            f"- Verified active FIPS + FIDO2+ models matched: **{summary['device_count']}**\n"
            f"- Exported attestation roots / public keys: **{summary['cert_files']}** certs / **{summary['pubkey_files']}** pubkeys\n"
            f"- Ready-to-use `shougt` high-assurance entries: **{summary['trust_entry_count']}**\n"
            f"- Unmatched MDS3 FIPS items for review: **{summary['unmatched_mds_fips_count']}**\n"
            f"- Excluded / preview MDS3 FIPS items: **{summary['mds_fips_disqualified_count']}**\n"
        )
        summary_file.parent.mkdir(parents=True, exist_ok=True)
        summary_file.write_text(md, encoding="utf-8")

    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sync active NIST CMVP FIPS devices with FIDO MDS3 FIDO2+ keys.")
    parser.add_argument("--force-nist-refresh", action="store_true", help="Ignore NIST certificate detail cache TTL.")
    parser.add_argument("--mds-file", type=Path, help="Read FIDO MDS3 JWS BLOB from local file instead of HTTPS.")
    parser.add_argument("--nist-index-file", type=Path, help="Read NIST CMVP active index HTML from local file.")
    parser.add_argument("--dry-run", action="store_true", help="Run verification and matching without writing repo files.")
    parser.add_argument("--summary-file", type=Path, help="Write Markdown run summary to PATH.")
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parent.parent
    summary = run_sync(
        repo_root,
        force_nist_refresh=args.force_nist_refresh,
        mds_file=args.mds_file,
        nist_index_file=args.nist_index_file,
        dry_run=args.dry_run,
        summary_file=args.summary_file,
    )
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
