#!/usr/bin/env python3
"""Dissertation evaluation harness for static Android data leakage detection.

Executes static analysis across a target directory of authorized APK packages,
aggregates detection metrics, evaluates performance timing statistics, and optionally
computes precision, recall, and F1-score against a ground truth dataset.

Outputs:
  - evaluation_results.csv: Tabular summary of per-APK findings and performance metrics.
  - evaluation_results.json: Structured JSON document with timing benchmarks, detection
    summaries, and confusion matrix accuracy metrics (if ground truth is supplied).
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure project root and src/ are in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from data_leak_detector.analysis.engine import AnalysisEngine
from data_leak_detector.core.models import AnalysisResult, Severity

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("evaluation_harness")


def calculate_timing_statistics(durations: list[float]) -> dict[str, float | None]:
    """Calculate mean, median, min, max, and total analysis durations.
    
    Args:
        durations: List of execution times in seconds.
        
    Returns:
        Dictionary containing timing statistics.
    """
    if not durations:
        return {
            "mean_analysis_time_seconds": None,
            "median_analysis_time_seconds": None,
            "minimum_analysis_time_seconds": None,
            "maximum_analysis_time_seconds": None,
            "total_analysis_time_seconds": 0.0,
        }

    return {
        "mean_analysis_time_seconds": round(statistics.mean(durations), 4),
        "median_analysis_time_seconds": round(statistics.median(durations), 4),
        "minimum_analysis_time_seconds": round(min(durations), 4),
        "maximum_analysis_time_seconds": round(max(durations), 4),
        "total_analysis_time_seconds": round(sum(durations), 4),
    }


def calculate_confusion_metrics(
    true_positives: int,
    false_positives: int,
    false_negatives: int,
) -> dict[str, float | None]:
    """Calculate precision, recall, and F1 score with division-by-zero safeguards.
    
    Mathematical definitions:
      - Precision = TP / (TP + FP)
      - Recall    = TP / (TP + FN)
      - F1 Score  = 2 * (Precision * Recall) / (Precision + Recall)
      
    Args:
        true_positives: Count of correctly flagged expected rules.
        false_positives: Count of flagged rules not expected in ground truth.
        false_negatives: Count of expected ground-truth rules missed by the tool.
        
    Returns:
        Dictionary with precision, recall, and f1_score (rounded to 4 decimal places),
        or None when undefined (e.g. 0/0).
    """
    prec_denom = true_positives + false_positives
    precision = (true_positives / prec_denom) if prec_denom > 0 else (1.0 if true_positives == 0 and false_positives == 0 else 0.0)

    rec_denom = true_positives + false_negatives
    recall = (true_positives / rec_denom) if rec_denom > 0 else (1.0 if true_positives == 0 and false_negatives == 0 else 0.0)

    f1_denom = precision + recall
    f1_score = (2 * precision * recall / f1_denom) if f1_denom > 0 else 0.0

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1_score, 4),
    }


def load_ground_truth(file_path: Path | str) -> dict[str, dict[str, Any]]:
    """Load and normalize ground truth dataset.
    
    Supports both dictionary format keyed by APK identifier (filename, sha256, or package),
    and list of objects with an 'identifier' / 'filename' key.
    
    Returns:
        Mapping of normalized identifier -> ground truth entry dict.
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Ground truth file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    normalized: dict[str, dict[str, Any]] = {}
    if isinstance(data, dict):
        if "apks" in data and isinstance(data["apks"], dict):
            raw_entries = data["apks"]
        else:
            raw_entries = data
        for key, entry in raw_entries.items():
            if isinstance(entry, dict):
                normalized[str(key).lower().strip()] = entry
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                key = item.get("filename") or item.get("sha256") or item.get("package") or item.get("identifier")
                if key:
                    normalized[str(key).lower().strip()] = item

    return normalized


def match_ground_truth_for_apk(
    apk_record: dict[str, Any],
    ground_truth: dict[str, dict[str, Any]] | None,
) -> dict[str, Any] | None:
    """Find matching ground truth record by filename, sha256, or package name."""
    if not ground_truth:
        return None

    filename_key = str(apk_record.get("filename", "")).lower().strip()
    sha256_key = str(apk_record.get("sha256", "")).lower().strip()
    package_key = str(apk_record.get("package", "")).lower().strip()

    if filename_key in ground_truth:
        return ground_truth[filename_key]
    if sha256_key in ground_truth:
        return ground_truth[sha256_key]
    if package_key in ground_truth:
        return ground_truth[package_key]

    return None


def evaluate_apk_record(
    apk_path: Path,
    engine: AnalysisEngine,
) -> tuple[dict[str, Any], AnalysisResult | None, str | None]:
    """Execute static analysis on an individual APK and collect metrics."""
    file_size = apk_path.stat().st_size
    start_time = time.perf_counter()

    try:
        result = engine.analyze_apk(apk_path)
        duration = round(time.perf_counter() - start_time, 4)

        # Count dangerous / sensitive permissions
        dangerous_perms = [
            p.permission
            for p in result.permissions
            if p.risk_level in (Severity.HIGH, Severity.CRITICAL) or p.is_sensitive_user_data
        ]

        # Severity counts
        crit_count = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in result.findings if f.severity == Severity.HIGH)
        med_count = sum(1 for f in result.findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in result.findings if f.severity == Severity.LOW)

        # Collect rule counts and errors
        detected_rule_ids = sorted(list({f.rule_id for f in result.findings}))
        detected_categories = sorted(list({
            f.category.value if hasattr(f.category, "value") else str(f.category)
            for f in result.findings
        }))
        rule_errors = len(result.metrics.warnings) if hasattr(result.metrics, "warnings") else 0

        record: dict[str, Any] = {
            "filename": apk_path.name,
            "sha256": result.application.sha256,
            "package": result.application.package_name,
            "file_size": file_size,
            "analysis_duration": duration,
            "risk_score": result.overall_risk_score,
            "risk_rating": result.risk_rating.value if hasattr(result.risk_rating, "value") else str(result.risk_rating),
            "number_of_permissions": len(result.permissions),
            "dangerous_permissions": len(dangerous_perms),
            "dangerous_permission_names": dangerous_perms,
            "critical_findings": crit_count,
            "high_findings": high_count,
            "medium_findings": med_count,
            "low_findings": low_count,
            "rule_errors": rule_errors,
            "detected_rules": detected_rule_ids,
            "detected_categories": detected_categories,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "finding_name": f.title,
                    "finding_category": f.category.value if hasattr(f.category, "value") else str(f.category),
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                }
                for f in result.findings
            ],
            "status": "SUCCESS",
        }
        return record, result, None

    except Exception as exc:
        duration = round(time.perf_counter() - start_time, 4)
        error_msg = str(exc)
        record = {
            "filename": apk_path.name,
            "sha256": "N/A",
            "package": "N/A",
            "file_size": file_size,
            "analysis_duration": duration,
            "risk_score": 0.0,
            "risk_rating": "FAILED",
            "number_of_permissions": 0,
            "dangerous_permissions": 0,
            "dangerous_permission_names": [],
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "low_findings": 0,
            "rule_errors": 1,
            "detected_rules": [],
            "detected_categories": [],
            "findings": [],
            "status": f"FAILED: {error_msg}",
        }
        return record, None, error_msg


def evaluate_directory(
    apk_dir: Path | str,
    output_dir: Path | str | None = None,
    ground_truth_path: Path | str | None = None,
    limit: int | None = None,
    continue_on_error: bool = True,
) -> dict[str, Any]:
    """Run full evaluation suite over all APKs in target directory.
    
    Args:
        apk_dir: Directory containing target Android APK packages.
        output_dir: Directory to save evaluation_results.csv and evaluation_results.json.
        ground_truth_path: Optional path to ground_truth.json dataset.
        limit: Optional maximum number of APKs to evaluate.
        continue_on_error: If True, log errors and continue; if False, raise on failure.
        
    Returns:
        Structured evaluation output dictionary.
    """
    apk_dir_path = Path(apk_dir).resolve()
    if not apk_dir_path.is_dir():
        raise NotADirectoryError(f"Target APK directory does not exist: {apk_dir_path}")

    out_dir = Path(output_dir).resolve() if output_dir else Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Discover APKs (.apk extension, case-insensitive)
    apk_files = sorted([p for p in apk_dir_path.glob("*") if p.suffix.lower() == ".apk"])
    if not apk_files:
        logger.warning(f"No .apk files found in directory: {apk_dir_path}")

    if limit and limit > 0:
        apk_files = apk_files[:limit]

    ground_truth = None
    if ground_truth_path:
        gt_path = Path(ground_truth_path).resolve()
        logger.info(f"Loading ground truth from: {gt_path}")
        ground_truth = load_ground_truth(gt_path)

    engine = AnalysisEngine()
    records: list[dict[str, Any]] = []
    durations: list[float] = []

    # Evaluation accumulators for ground truth
    total_tp = 0
    total_fp = 0
    total_fn = 0
    rule_confusion: dict[str, dict[str, int]] = {}

    print("\n" + "=" * 70)
    print("MOBILE DATA LEAK DETECTOR - DISSERTATION EVALUATION HARNESS")
    print(f"Target Directory: {apk_dir_path}")
    print(f"Total APKs Found: {len(apk_files)}")
    print(f"Ground Truth:     {'Provided (' + str(len(ground_truth)) + ' entries)' if ground_truth else 'None (Detection Counts & Benchmarks only)'}")
    print("=" * 70 + "\n")

    for idx, apk_path in enumerate(apk_files, 1):
        print(f"[{idx}/{len(apk_files)}] Evaluating: {apk_path.name}...")
        record, _, err = evaluate_apk_record(apk_path, engine)

        if err and not continue_on_error:
            raise RuntimeError(f"Analysis failed for {apk_path.name}: {err}")

        durations.append(record["analysis_duration"])

        # Ground truth evaluation for this APK if available
        gt_entry = match_ground_truth_for_apk(record, ground_truth)
        if gt_entry is not None:
            expected_rules = set(gt_entry.get("expected_rules", []))
            detected_rules = set(record["detected_rules"])

            tp = len(detected_rules.intersection(expected_rules))
            fp = len(detected_rules.difference(expected_rules))
            fn = len(expected_rules.difference(detected_rules))

            metrics = calculate_confusion_metrics(tp, fp, fn)

            record["ground_truth_matched"] = True
            record["expected_rules"] = sorted(list(expected_rules))
            record["true_positives"] = tp
            record["false_positives"] = fp
            record["false_negatives"] = fn
            record["precision"] = metrics["precision"]
            record["recall"] = metrics["recall"]
            record["f1_score"] = metrics["f1_score"]

            total_tp += tp
            total_fp += fp
            total_fn += fn

            # Update per-rule confusion
            for r_id in expected_rules.union(detected_rules):
                stats = rule_confusion.setdefault(r_id, {"tp": 0, "fp": 0, "fn": 0})
                if r_id in detected_rules and r_id in expected_rules:
                    stats["tp"] += 1
                elif r_id in detected_rules and r_id not in expected_rules:
                    stats["fp"] += 1
                elif r_id in expected_rules and r_id not in detected_rules:
                    stats["fn"] += 1
        else:
            record["ground_truth_matched"] = False
            record["expected_rules"] = []
            record["true_positives"] = None
            record["false_positives"] = None
            record["false_negatives"] = None
            record["precision"] = None
            record["recall"] = None
            record["f1_score"] = None

        records.append(record)

    # Calculate overall performance benchmarks
    timing_benchmarks = calculate_timing_statistics(durations)

    # Calculate overall accuracy if ground truth was active
    accuracy_summary: dict[str, Any] | None = None
    if ground_truth is not None and (total_tp + total_fp + total_fn > 0):
        overall_conf = calculate_confusion_metrics(total_tp, total_fp, total_fn)
        per_rule_accuracy: dict[str, Any] = {}
        for r_id, stats in sorted(rule_confusion.items()):
            r_metrics = calculate_confusion_metrics(stats["tp"], stats["fp"], stats["fn"])
            per_rule_accuracy[r_id] = {
                "true_positives": stats["tp"],
                "false_positives": stats["fp"],
                "false_negatives": stats["fn"],
                "precision": r_metrics["precision"],
                "recall": r_metrics["recall"],
                "f1_score": r_metrics["f1_score"],
            }

        accuracy_summary = {
            "total_true_positives": total_tp,
            "total_false_positives": total_fp,
            "total_false_negatives": total_fn,
            "overall_precision": overall_conf["precision"],
            "overall_recall": overall_conf["recall"],
            "overall_f1_score": overall_conf["f1_score"],
            "per_rule_metrics": per_rule_accuracy,
        }
    else:
        accuracy_summary = {
            "status": "No ground truth dataset provided. Accuracy metrics (precision, recall, F1) were omitted to prevent fabricated performance representations.",
            "total_true_positives": None,
            "total_false_positives": None,
            "total_false_negatives": None,
            "overall_precision": None,
            "overall_recall": None,
            "overall_f1_score": None,
        }

    # Aggregate counts
    total_findings = sum(
        r["critical_findings"] + r["high_findings"] + r["medium_findings"] + r["low_findings"]
        for r in records
    )
    total_critical = sum(r["critical_findings"] for r in records)
    total_high = sum(r["high_findings"] for r in records)
    total_medium = sum(r["medium_findings"] for r in records)
    total_low = sum(r["low_findings"] for r in records)

    final_results: dict[str, Any] = {
        "metadata": {
            "evaluation_timestamp": datetime.now(timezone.utc).isoformat(),
            "target_directory": str(apk_dir_path),
            "total_apks_evaluated": len(records),
            "ground_truth_file": str(ground_truth_path) if ground_truth_path else None,
            "ground_truth_enabled": ground_truth is not None,
        },
        "performance_benchmarks": timing_benchmarks,
        "summary_detection_counts": {
            "total_findings": total_findings,
            "critical_findings": total_critical,
            "high_findings": total_high,
            "medium_findings": total_medium,
            "low_findings": total_low,
            "average_risk_score": round(statistics.mean([r["risk_score"] for r in records]), 2) if records else 0.0,
        },
        "accuracy_evaluation": accuracy_summary,
        "apks": records,
    }

    # Write evaluation_results.json
    json_path = out_dir / "evaluation_results.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(final_results, f, indent=2)
    logger.info(f"Exported JSON evaluation report: {json_path}")

    # Write evaluation_results.csv
    csv_path = out_dir / "evaluation_results.csv"
    csv_fields = [
        "filename",
        "sha256",
        "package",
        "file_size",
        "analysis_duration",
        "risk_score",
        "risk_rating",
        "number_of_permissions",
        "dangerous_permissions",
        "critical_findings",
        "high_findings",
        "medium_findings",
        "low_findings",
        "rule_errors",
    ]
    if ground_truth is not None:
        csv_fields.extend([
            "true_positives",
            "false_positives",
            "false_negatives",
            "precision",
            "recall",
            "f1_score",
        ])

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=csv_fields, extrasaction="ignore")
        writer.writeheader()
        for r in records:
            writer.writerow(r)
    logger.info(f"Exported CSV evaluation report: {csv_path}")

    # Print summary table
    print("\n" + "=" * 70)
    print("EVALUATION BENCHMARK SUMMARY")
    print("=" * 70)
    print(f"Total APKs Processed:    {len(records)}")
    print(f"Mean Analysis Time:      {timing_benchmarks['mean_analysis_time_seconds']}s")
    print(f"Median Analysis Time:    {timing_benchmarks['median_analysis_time_seconds']}s")
    print(f"Min Analysis Time:       {timing_benchmarks['minimum_analysis_time_seconds']}s")
    print(f"Max Analysis Time:       {timing_benchmarks['maximum_analysis_time_seconds']}s")
    print(f"Total Analysis Duration: {timing_benchmarks['total_analysis_time_seconds']}s")
    print(f"Total Findings Flagged:  {total_findings} (Crit: {total_critical}, High: {total_high}, Med: {total_medium}, Low: {total_low})")

    if ground_truth is not None and accuracy_summary.get("overall_precision") is not None:
        print("-" * 70)
        print("EMPIRICAL ACCURACY METRICS (AGAINST GROUND TRUTH)")
        print("-" * 70)
        print(f"True Positives (TP):     {accuracy_summary['total_true_positives']}")
        print(f"False Positives (FP):    {accuracy_summary['total_false_positives']}")
        print(f"False Negatives (FN):    {accuracy_summary['total_false_negatives']}")
        print(f"Precision:               {accuracy_summary['overall_precision']}")
        print(f"Recall:                  {accuracy_summary['overall_recall']}")
        print(f"F1 Score:                {accuracy_summary['overall_f1_score']}")
    else:
        print("-" * 70)
        print("ACCURACY STATUS: Ground truth was not provided. Raw detection counts")
        print("are reported as empirical observations without claimed accuracy.")
    print("=" * 70 + "\n")

    return final_results


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Static Android Data Leak Detector - Dissertation Evaluation Harness",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "apk_dir",
        type=str,
        help="Path to directory containing authorized APK files for evaluation.",
    )
    parser.add_argument(
        "--ground-truth",
        "-g",
        type=str,
        default=None,
        help="Optional path to ground_truth.json containing expected findings per APK.",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=str,
        default=None,
        help="Directory where evaluation_results.csv and evaluation_results.json will be saved (defaults to current directory).",
    )
    parser.add_argument(
        "--limit",
        "-l",
        type=int,
        default=None,
        help="Optional limit on number of APKs to evaluate.",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Halt execution immediately if an APK analysis encounters an exception.",
    )
    return parser.parse_args()


def main() -> int:
    """CLI entrypoint."""
    args = parse_args()
    try:
        evaluate_directory(
            apk_dir=args.apk_dir,
            output_dir=args.output_dir,
            ground_truth_path=args.ground_truth,
            limit=args.limit,
            continue_on_error=not args.fail_fast,
        )
        return 0
    except Exception as exc:
        logger.error(f"Evaluation harness failed: {exc}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
