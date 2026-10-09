#!/usr/bin/env python3
"""Comparative analysis harness for benchmarking against external tools (e.g., MobSF, RiskInDroid).

Enables empirical cross-tool comparison without tight coupling or uploading APKs externally.
Imports standardized external-tool CSV exports and compares them against our tool's findings
indexed by APK SHA-256 hash.

External Tool CSV Format:
  apk_hash,tool,finding_category,finding_name,severity

Outputs:
  - comparison_summary.csv: Tabular cross-tool overlap and uniqueness metrics per APK.
  - comparison_summary.json: Detailed category matrices, finding intersections, and academic disclaimers.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("compare_results")

# Canonical normalized category taxonomy
CANONICAL_CATEGORIES = {
    "PERMISSION": "Permissions",
    "NETWORK_INDICATOR": "Network Security",
    "HARDCODED_SECRET": "Hardcoded Secrets",
    "STORAGE_INSECURITY": "Insecure Storage",
    "CRYPTO_FLAW": "Cryptography Flaws",
    "TRACKING_SDK": "Third-Party & Tracking SDKs",
    "MANIFEST_MISCONFIG": "Manifest Misconfigurations",
    "OTHER": "Other Security Issues",
}

# Heuristic mapping for standardizing third-party tool categories (e.g. MobSF, RiskInDroid)
CATEGORY_MAPPING_PATTERNS = [
    (r"(?i)\bpermission|\bdangerous[_\s-]?permission|\brisk[_\s-]?permission", "PERMISSION"),
    (r"(?i)\bnetwork|\bcleartext|\bhttp|\bssl|\btls|\bcommunication|\btraffic", "NETWORK_INDICATOR"),
    (r"(?i)\bsecret|\bapi[_\s-]?key|\btoken|\bcredential|\bpassword|\bprivate[_\s-]?key", "HARDCODED_SECRET"),
    (r"(?i)\bstorage|\bsharedpref|\bexternal[_\s-]?storage|\bworld[_\s-]?readable|\bsqlite|\bcache", "STORAGE_INSECURITY"),
    (r"(?i)\bcrypto|\bcipher|\bhash\b|\bencryption|\bmd5\b|\bsha1\b|\becb\b|\bprng\b|\binsecure[_\s-]?random", "CRYPTO_FLAW"),
    (r"(?i)\btracker|\btracking|\bsdk|\badware|\banalytics|\btelemetry", "TRACKING_SDK"),
    (r"(?i)\bmanifest|\bmisconfig|\bbackup|\bdebuggable|\bexported", "MANIFEST_MISCONFIG"),
]


def normalize_category(raw_category: str | None) -> str:
    """Normalize raw category strings from heterogeneous tools to canonical taxonomy."""
    if not raw_category or not str(raw_category).strip():
        return "OTHER"

    cat = str(raw_category).strip().upper()
    if cat in CANONICAL_CATEGORIES:
        return cat

    for pattern, canonical in CATEGORY_MAPPING_PATTERNS:
        if re.search(pattern, raw_category):
            return canonical

    return "OTHER"


def normalize_finding_name(name: str | None) -> str:
    """Normalize finding titles for relaxed matching across disparate tools."""
    if not name:
        return ""
    # Lowercase, strip punctuation, remove extra whitespaces
    s = re.sub(r"[^a-zA-Z0-9\s]", " ", str(name).lower())
    return " ".join(s.split())


def load_external_csv(csv_path: Path | str) -> list[dict[str, str]]:
    """Load and validate external comparison tool CSV file.
    
    Expected headers:
      apk_hash,tool,finding_category,finding_name,severity
    """
    path = Path(csv_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"External results CSV file not found: {path}")

    records: list[dict[str, str]] = []
    with open(path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        required_fields = {"apk_hash", "tool", "finding_category", "finding_name", "severity"}
        if not required_fields.issubset({h.strip().lower() for h in (reader.fieldnames or [])}):
            missing = required_fields - {h.strip().lower() for h in (reader.fieldnames or [])}
            raise ValueError(f"External CSV missing required column(s): {missing}. Required: {required_fields}")

        for row_idx, raw_row in enumerate(reader, start=2):
            # Normalize field access case-insensitively
            row = {k.strip().lower(): (v or "").strip() for k, v in raw_row.items() if k}
            apk_hash = row.get("apk_hash", "").lower()
            if not apk_hash:
                logger.warning(f"Row {row_idx} missing apk_hash, skipping.")
                continue

            records.append({
                "apk_hash": apk_hash,
                "tool": row.get("tool", "ExternalTool"),
                "finding_category": normalize_category(row.get("finding_category")),
                "raw_finding_category": row.get("finding_category", ""),
                "finding_name": row.get("finding_name", ""),
                "normalized_name": normalize_finding_name(row.get("finding_name")),
                "severity": row.get("severity", "MEDIUM").upper(),
            })

    logger.info(f"Loaded {len(records)} findings from external CSV: {path.name}")
    return records


def load_our_results(source_path: Path | str) -> list[dict[str, Any]]:
    """Load our tool's findings from evaluation_results.json, CSV, or single JSON report.
    
    Returns:
        List of finding dictionaries containing apk_hash, finding_category, finding_name, severity.
    """
    path = Path(source_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Our results file not found: {path}")

    records: list[dict[str, Any]] = []

    if path.suffix.lower() == ".json":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Handle evaluation_results.json format
        if isinstance(data, dict) and "apks" in data and isinstance(data["apks"], list):
            for apk in data["apks"]:
                apk_hash = str(apk.get("sha256", "")).lower().strip()
                if not apk_hash or apk_hash == "n/a":
                    continue

                # 1. Structured individual findings if present
                if "findings" in apk and isinstance(apk["findings"], list):
                    for f in apk["findings"]:
                        cat = normalize_category(f.get("finding_category") or f.get("category"))
                        name = f.get("finding_name") or f.get("title") or f.get("rule_id", "Finding")
                        sev = str(f.get("severity", "MEDIUM")).upper()
                        records.append({
                            "apk_hash": apk_hash,
                            "tool": "DataLeakDetector",
                            "finding_category": cat,
                            "finding_name": name,
                            "normalized_name": normalize_finding_name(name),
                            "severity": sev,
                            "rule_id": f.get("rule_id"),
                        })
                # 2. Fallback to detected_rules if findings list was empty
                elif "detected_rules" in apk and isinstance(apk["detected_rules"], list):
                    for r_id in apk["detected_rules"]:
                        records.append({
                            "apk_hash": apk_hash,
                            "tool": "DataLeakDetector",
                            "finding_category": normalize_category(r_id),
                            "finding_name": r_id,
                            "normalized_name": normalize_finding_name(r_id),
                            "severity": "HIGH",
                            "rule_id": r_id,
                        })

        # Handle single AnalysisResult JSON format
        elif isinstance(data, dict) and "findings" in data and isinstance(data["findings"], list):
            meta = data.get("application", {})
            apk_hash = str(meta.get("sha256", "")).lower().strip()
            for f in data["findings"]:
                cat = normalize_category(f.get("category"))
                name = f.get("title") or f.get("rule_id", "Finding")
                records.append({
                    "apk_hash": apk_hash,
                    "tool": "DataLeakDetector",
                    "finding_category": cat,
                    "finding_name": name,
                    "normalized_name": normalize_finding_name(name),
                    "severity": str(f.get("severity", "MEDIUM")).upper(),
                    "rule_id": f.get("rule_id"),
                })

    elif path.suffix.lower() == ".csv":
        with open(path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                r = {k.strip().lower(): (v or "").strip() for k, v in row.items() if k}
                apk_hash = (r.get("sha256") or r.get("apk_hash", "")).lower()
                if not apk_hash:
                    continue
                name = r.get("finding_name") or r.get("title") or r.get("rule_id", "Finding")
                cat = normalize_category(r.get("finding_category") or r.get("category"))
                records.append({
                    "apk_hash": apk_hash,
                    "tool": "DataLeakDetector",
                    "finding_category": cat,
                    "finding_name": name,
                    "normalized_name": normalize_finding_name(name),
                    "severity": r.get("severity", "MEDIUM").upper(),
                })

    logger.info(f"Loaded {len(records)} findings for our tool from: {path.name}")
    return records


def calculate_jaccard_similarity(set_a: set[Any], set_b: set[Any]) -> float:
    """Calculate Jaccard similarity index with division-by-zero safeguard."""
    union_len = len(set_a.union(set_b))
    if union_len == 0:
        return 1.0 if len(set_a) == 0 and len(set_b) == 0 else 0.0
    return round(len(set_a.intersection(set_b)) / union_len, 4)


def compare_datasets(
    our_records: list[dict[str, Any]],
    external_records: list[dict[str, Any]],
    output_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Execute cross-tool comparative analysis indexed by APK SHA-256 hash.
    
    Args:
        our_records: Findings produced by our tool.
        external_records: Findings loaded from external comparison tool CSV.
        output_dir: Target directory for summary exports.
        
    Returns:
        Structured dictionary containing comparative metrics.
    """
    out_dir = Path(output_dir).resolve() if output_dir else Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Index by apk_hash
    our_by_hash: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in our_records:
        our_by_hash[r["apk_hash"]].append(r)

    ext_by_hash: dict[str, list[dict[str, Any]]] = defaultdict(list)
    comparison_tools: set[str] = set()
    for r in external_records:
        ext_by_hash[r["apk_hash"]].append(r)
        comparison_tools.add(r.get("tool", "ExternalTool"))

    tool_name_str = ", ".join(sorted(list(comparison_tools))) or "ExternalTool"
    all_hashes = sorted(list(set(our_by_hash.keys()).union(set(ext_by_hash.keys()))))

    per_apk_comparisons: list[dict[str, Any]] = []
    category_overlap_totals: dict[str, dict[str, int]] = {
        cat: {"both": 0, "our_tool_only": 0, "external_tool_only": 0}
        for cat in CANONICAL_CATEGORIES
    }

    total_common_findings = 0
    total_unique_our = 0
    total_unique_ext = 0

    for apk_hash in all_hashes:
        our_findings = our_by_hash.get(apk_hash, [])
        ext_findings = ext_by_hash.get(apk_hash, [])

        our_categories = set(f["finding_category"] for f in our_findings)
        ext_categories = set(f["finding_category"] for f in ext_findings)

        # Build signature sets for finding-level comparison: (normalized_category, normalized_name)
        our_signatures = {
            (f["finding_category"], f["normalized_name"])
            for f in our_findings
            if f["normalized_name"]
        }
        ext_signatures = {
            (f["finding_category"], f["normalized_name"])
            for f in ext_findings
            if f["normalized_name"]
        }

        # Finding intersections
        common_sigs = our_signatures.intersection(ext_signatures)
        unique_our_sigs = our_signatures.difference(ext_signatures)
        unique_ext_sigs = ext_signatures.difference(our_signatures)

        # Fallback to category overlap if naming conventions differ substantially
        common_cats = sorted(list(our_categories.intersection(ext_categories)))
        unique_our_cats = sorted(list(our_categories.difference(ext_categories)))
        unique_ext_cats = sorted(list(ext_categories.difference(our_categories)))

        for cat in CANONICAL_CATEGORIES:
            in_our = cat in our_categories
            in_ext = cat in ext_categories
            if in_our and in_ext:
                category_overlap_totals[cat]["both"] += 1
            elif in_our and not in_ext:
                category_overlap_totals[cat]["our_tool_only"] += 1
            elif not in_our and in_ext:
                category_overlap_totals[cat]["external_tool_only"] += 1

        jaccard = calculate_jaccard_similarity(our_signatures, ext_signatures)
        cat_jaccard = calculate_jaccard_similarity(our_categories, ext_categories)

        total_common_findings += len(common_sigs)
        total_unique_our += len(unique_our_sigs)
        total_unique_ext += len(unique_ext_sigs)

        per_apk_comparisons.append({
            "apk_hash": apk_hash,
            "comparison_tool": tool_name_str,
            "our_findings_count": len(our_findings),
            "external_findings_count": len(ext_findings),
            "common_findings_count": len(common_sigs),
            "unique_our_tool_count": len(unique_our_sigs),
            "unique_external_tool_count": len(unique_ext_sigs),
            "finding_jaccard_similarity": jaccard,
            "category_jaccard_similarity": cat_jaccard,
            "common_categories": "; ".join(common_cats),
            "unique_our_categories": "; ".join(unique_our_cats),
            "unique_external_categories": "; ".join(unique_ext_cats),
            "common_findings_sample": [f"{c}:{n}" for c, n in list(common_sigs)[:5]],
            "unique_our_findings_sample": [f"{c}:{n}" for c, n in list(unique_our_sigs)[:5]],
            "unique_external_findings_sample": [f"{c}:{n}" for c, n in list(unique_ext_sigs)[:5]],
        })

    # Overall dataset statistics
    summary: dict[str, Any] = {
        "metadata": {
            "comparison_tools": list(comparison_tools),
            "total_apks_evaluated": len(all_hashes),
            "our_tool_total_findings": len(our_records),
            "external_tool_total_findings": len(external_records),
            "overall_common_findings": total_common_findings,
            "overall_unique_our_tool": total_unique_our,
            "overall_unique_external_tool": total_unique_ext,
        },
        "methodological_disclaimer": (
            "NOTICE: Divergence in finding counts does not indicate that either tool is erroneous. "
            "Static analysis tools vary widely in their targeted threat models (e.g., general security hygiene "
            "vs. specialized private data leakage paths), rule granularities (aggregated vs. per-occurrence reporting), "
            "and heuristic confidence thresholds. Differences should be interpreted as complementary coverage boundaries "
            "rather than absolute claims of correctness."
        ),
        "category_overlaps": category_overlap_totals,
        "apks": per_apk_comparisons,
    }

    # Write comparison_summary.csv
    csv_path = out_dir / "comparison_summary.csv"
    csv_fields = [
        "apk_hash",
        "comparison_tool",
        "our_findings_count",
        "external_findings_count",
        "common_findings_count",
        "unique_our_tool_count",
        "unique_external_tool_count",
        "finding_jaccard_similarity",
        "category_jaccard_similarity",
        "common_categories",
        "unique_our_categories",
        "unique_external_categories",
    ]

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=csv_fields, extrasaction="ignore")
        writer.writeheader()
        for row in per_apk_comparisons:
            writer.writerow(row)
    logger.info(f"Generated comparison CSV report: {csv_path}")

    # Write comparison_summary.json
    json_path = out_dir / "comparison_summary.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    logger.info(f"Generated comparison JSON report: {json_path}")

    # Print summary to console
    print("\n" + "=" * 75)
    print("CROSS-TOOL COMPARATIVE EVALUATION SUMMARY")
    print(f"Comparison Tool(s):       {tool_name_str}")
    print(f"Total APKs Compared:      {len(all_hashes)}")
    print("=" * 75)
    print(f"Findings in Our Tool:     {len(our_records)}")
    print(f"Findings in Comparison:   {len(external_records)}")
    print(f"Common Findings (Both):   {total_common_findings}")
    print(f"Unique to Our Tool:       {total_unique_our}")
    print(f"Unique to Comparison:     {total_unique_ext}")
    print("-" * 75)
    print("CATEGORY OVERLAPS (NUMBER OF APKS WHERE CATEGORY WAS DETECTED):")
    for cat, counts in sorted(category_overlap_totals.items()):
        name = CANONICAL_CATEGORIES.get(cat, cat)
        print(f"  {name:<30} Both: {counts['both']:<3} | Ours Only: {counts['our_tool_only']:<3} | External Only: {counts['external_tool_only']:<3}")
    print("-" * 75)
    print(summary["methodological_disclaimer"])
    print("=" * 75 + "\n")

    return summary


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Cross-Tool Research Comparison Framework (MobSF / RiskInDroid / etc.)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--our-results",
        "-o",
        type=str,
        required=True,
        help="Path to our evaluation output (evaluation_results.json or evaluation_results.csv).",
    )
    parser.add_argument(
        "--external-results",
        "-e",
        type=str,
        required=True,
        help="Path to external tool CSV (format: apk_hash,tool,finding_category,finding_name,severity).",
    )
    parser.add_argument(
        "--output-dir",
        "-d",
        type=str,
        default=None,
        help="Directory to write comparison_summary.csv and comparison_summary.json.",
    )
    return parser.parse_args()


def main() -> int:
    """CLI entry point."""
    args = parse_args()
    try:
        our_data = load_our_results(args.our_results)
        external_data = load_external_csv(args.external_results)
        compare_datasets(
            our_records=our_data,
            external_records=external_data,
            output_dir=args.output_dir,
        )
        return 0
    except Exception as exc:
        logger.error(f"Comparison framework failed: {exc}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
