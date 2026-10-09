#!/usr/bin/env python3
"""Profiler for measuring static Android data leakage analysis pipeline performance.

Measures granular stage durations and peak memory:
  - APK validation duration
  - APK parsing duration
  - Decompilation / extraction duration
  - Permission analysis duration
  - Rule execution duration (with category breakdown)
  - Report generation duration (HTML, PDF, Text)
  - Total workflow duration
  - Peak memory allocated (tracemalloc)
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import time
import tracemalloc
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from data_leak_detector.analysis.apk_parser import APKParser
from data_leak_detector.analysis.engine import AnalysisEngine, AnalysisStage
from data_leak_detector.analysis.permission_analyzer import PermissionAnalyzer
from data_leak_detector.analysis.risk_scorer import RiskScorer
from data_leak_detector.core.config import AppConfig
from data_leak_detector.core.models import (
    AnalysisMetrics,
    AnalysisResult,
    ApplicationMetadata,
    ComponentDetail,
    ManifestData,
    ParsedAPKData,
)
from data_leak_detector.reporting.report_generator import ReportGenerator


def create_benchmark_synthetic_apk(target_path: Path, string_count: int = 5000) -> Path:
    """Create a realistic benchmark APK archive with manifest, dex pool, and resources."""
    dex_strings = [
        f"Lcom/benchmark/sample/Class{i};" for i in range(string_count // 5)
    ]
    # Add various URLs, keys, secrets, and tracking tokens to exercise rules
    dex_strings.extend([
        "http://insecure-api.benchmarking.org/telemetry",
        "https://secure-api.benchmarking.org/v1",
        "AIzaSyBenchmarkTestingKey1234567890abcdef",
        "AKIAIOSFODNN7EXAMPLE",
        "DES/ECB/PKCS5Padding",
        "AES/CBC/PKCS5Padding",
        "com.google.android.gms.ads.AdView",
        "com.facebook.ads.AudienceNetworkAds",
        "android.intent.action.MAIN",
    ])
    dex_content = b"dex\n035\x00" + b"\x00".join(s.encode("ascii", errors="ignore") for s in dex_strings)

    manifest_xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.benchmark.leakdetector">\n'
        '    <uses-permission android:name="android.permission.INTERNET" />\n'
        '    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />\n'
        '    <uses-permission android:name="android.permission.READ_CONTACTS" />\n'
        '    <uses-permission android:name="android.permission.CAMERA" />\n'
        '    <application android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true">\n'
        '        <activity android:name=".MainActivity" android:exported="true" />\n'
        '        <service android:name=".DataSyncService" android:exported="false" />\n'
        '    </application>\n'
        '</manifest>'
    )

    with zipfile.ZipFile(target_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_xml.encode("utf-8"))
        zf.writestr("classes.dex", dex_content)
        zf.writestr("res/raw/config.json", b'{"api_endpoint": "http://plain.benchmark.com", "key": "AIzaSyBenchmarkJson1234"}')
        zf.writestr("assets/database_init.sql", b"CREATE TABLE users (id INT, password VARCHAR(255), ssn VARCHAR(32));")

    return target_path


def profile_analysis(
    apk_path: Path,
    output_reports_dir: Path | None = None,
    iterations: int = 1,
) -> dict[str, Any]:
    """Execute end-to-end static analysis and collect stage timings and memory usage."""
    config = AppConfig()
    engine = AnalysisEngine(config=config)
    permission_analyzer = PermissionAnalyzer()
    risk_scorer = RiskScorer()

    out_dir = output_reports_dir or Path(tempfile.mkdtemp(prefix="mld_profile_reports_"))

    print("\n" + "=" * 75)
    print("STATIC ANALYSIS WORKFLOW PROFILER")
    print(f"Target APK:    {apk_path.name} ({apk_path.stat().st_size:,} bytes)")
    print(f"Iterations:    {iterations}")
    print("=" * 75)

    all_runs: list[dict[str, float]] = []
    peak_memory_bytes = 0

    for run_idx in range(1, iterations + 1):
        tracemalloc.start()
        run_timings: dict[str, float] = {}

        # -------------------------------------------------------------
        # 1. APK Validation Duration
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        parser = APKParser(apk_path, config=config)
        parser.validate_file()
        run_timings["apk_validation_seconds"] = time.perf_counter() - t0

        # -------------------------------------------------------------
        # 2. APK Parsing Duration
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        sha256 = parser.calculate_sha256()
        try:
            parsed_apk = parser.parse()
        except Exception:
            # Fallback to synthetic model if AndroGuard cannot decode synthetic XML
            parsed_apk = ParsedAPKData(
                metadata=ApplicationMetadata(
                    filename=apk_path.name,
                    sha256=sha256,
                    file_size=apk_path.stat().st_size,
                    package_name="com.benchmark.leakdetector",
                    file_path=apk_path,
                    analyzed_at=datetime.now(timezone.utc),
                ),
                permissions=[
                    "android.permission.INTERNET",
                    "android.permission.ACCESS_FINE_LOCATION",
                    "android.permission.READ_CONTACTS",
                    "android.permission.CAMERA",
                ],
                manifest_info=ManifestData(
                    package_name="com.benchmark.leakdetector",
                    debuggable=True,
                    allow_backup=True,
                    uses_cleartext_traffic=True,
                    components=[
                        ComponentDetail(
                            component_type="activity",
                            name="com.benchmark.leakdetector.MainActivity",
                            exported=True,
                        )
                    ],
                ),
            )
        run_timings["apk_parsing_seconds"] = time.perf_counter() - t0

        # -------------------------------------------------------------
        # 3. Decompilation / Static Resource Extraction Duration
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        temp_dir = engine._create_temp_dir("profile_scan_")
        extracted_files, extracted_strings, _ = engine._prepare_static_resources(
            apk_path, temp_dir, parsed_apk
        )
        classes = engine._extract_classes_and_packages(extracted_files, parsed_apk)
        context = engine._build_rule_context(parsed_apk, extracted_files, extracted_strings, classes)
        run_timings["decompilation_extraction_seconds"] = time.perf_counter() - t0

        # -------------------------------------------------------------
        # 4. Permission Analysis Duration
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        permission_summary = permission_analyzer.analyze(parsed_apk.permissions)
        permission_findings = permission_summary.findings
        run_timings["permission_analysis_seconds"] = time.perf_counter() - t0

        # -------------------------------------------------------------
        # 5. Rule Execution Duration
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        all_findings = []
        rule_stages = [
            (AnalysisStage.SCANNING_MANIFEST, "manifest"),
            (AnalysisStage.SCANNING_SECRETS, "secrets"),
            (AnalysisStage.SCANNING_NETWORK, "network"),
            (AnalysisStage.SCANNING_STORAGE, "storage"),
            (AnalysisStage.SCANNING_CRYPTO, "crypto"),
            (AnalysisStage.SCANNING_SDKS, "sdks"),
        ]

        stage_timings: dict[str, float] = {}
        for stg, label in rule_stages:
            stg_t0 = time.perf_counter()
            rules = engine._get_rules_for_stage(stg)
            f_list, _, _ = engine._execute_rules(rules, context)
            all_findings.extend(f_list)
            stage_timings[f"rules_{label}_seconds"] = time.perf_counter() - stg_t0

        run_timings["rule_execution_seconds"] = time.perf_counter() - t0
        run_timings.update(stage_timings)

        # Deduplicate & Score
        deduped_findings = engine.deduplicate_findings(all_findings)
        risk_result = risk_scorer.calculate(findings=deduped_findings, permissions=permission_findings)

        analysis_result = AnalysisResult(
            analysis_id=uuid.uuid4().hex,
            application=parsed_apk.metadata,
            overall_risk_score=risk_result.score,
            risk_rating=risk_result.rating,
            metrics=AnalysisMetrics(
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
                duration_seconds=run_timings["decompilation_extraction_seconds"] + run_timings["rule_execution_seconds"],
                files_examined=len(extracted_files),
                rules_executed=len(all_findings),
                warnings=[],
            ),
            permissions=permission_findings,
            findings=deduped_findings,
            analyzer_version="0.1.0",
        )

        # -------------------------------------------------------------
        # 6. Report Generation Duration (HTML, PDF, Text)
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        report_gen = ReportGenerator(analysis_result)
        report_gen.generate_all(out_dir, base_filename="benchmark_report")
        run_timings["report_generation_seconds"] = time.perf_counter() - t0

        # Total duration
        total_pipeline = (
            run_timings["apk_validation_seconds"]
            + run_timings["apk_parsing_seconds"]
            + run_timings["decompilation_extraction_seconds"]
            + run_timings["permission_analysis_seconds"]
            + run_timings["rule_execution_seconds"]
            + run_timings["report_generation_seconds"]
        )
        run_timings["total_analysis_seconds"] = total_pipeline

        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        peak_memory_bytes = max(peak_memory_bytes, peak_mem)
        run_timings["peak_memory_mb"] = round(peak_mem / (1024 * 1024), 2)
        all_runs.append(run_timings)

        # Clean temporary scan dir
        engine._clean_temporary_dirs([temp_dir])

    # Calculate average across iterations
    avg_timings: dict[str, float] = {}
    metric_keys = list(all_runs[0].keys())
    for k in metric_keys:
        avg_timings[k] = round(sum(r[k] for r in all_runs) / len(all_runs), 4)

    peak_mb = round(peak_memory_bytes / (1024 * 1024), 2)

    # Print Profiling Report Table
    print("\n" + "=" * 75)
    print("STAGE-BY-STAGE BENCHMARK RESULTS")
    print("=" * 75)
    print(f"{'Pipeline Stage':<38} {'Time (s)':<12} {'% of Total':<12}")
    print("-" * 75)

    tot = avg_timings["total_analysis_seconds"]
    stages_to_show = [
        ("APK Validation", "apk_validation_seconds"),
        ("APK Parsing & Hashing", "apk_parsing_seconds"),
        ("Decompilation & Resource Extraction", "decompilation_extraction_seconds"),
        ("Permission Analysis", "permission_analysis_seconds"),
        ("Rule Execution", "rule_execution_seconds"),
        ("  - Manifest Rules", "rules_manifest_seconds"),
        ("  - Secret Rules", "rules_secrets_seconds"),
        ("  - Network Rules", "rules_network_seconds"),
        ("  - Storage Rules", "rules_storage_seconds"),
        ("  - Crypto Rules", "rules_crypto_seconds"),
        ("  - SDK & Tracker Rules", "rules_sdks_seconds"),
        ("Report Generation (HTML, PDF, Text)", "report_generation_seconds"),
    ]

    for label, key in stages_to_show:
        dur = avg_timings[key]
        pct = (dur / tot * 100) if tot > 0 else 0.0
        print(f"{label:<38} {dur:<12.4f} {pct:<12.1f}%")

    print("-" * 75)
    print(f"{'TOTAL PIPELINE DURATION':<38} {tot:<12.4f} 100.0%")
    print(f"{'PEAK MEMORY ALLOCATED':<38} {peak_mb:<12.2f} MB")
    print("=" * 75 + "\n")

    return avg_timings


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Static Android Data Leak Detector - Pipeline Profiler",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--apk",
        "-a",
        type=str,
        default=None,
        help="Optional path to real APK file to profile. If omitted, generates a synthetic benchmark APK.",
    )
    parser.add_argument(
        "--iterations",
        "-n",
        type=int,
        default=3,
        help="Number of profiling runs to average.",
    )
    return parser.parse_args()


def main() -> int:
    """CLI entrypoint."""
    args = parse_args()
    temp_dir = None
    try:
        if args.apk:
            apk_path = Path(args.apk).resolve()
            if not apk_path.is_file():
                print(f"Error: APK file not found: {apk_path}")
                return 1
        else:
            temp_dir = tempfile.TemporaryDirectory()
            apk_path = Path(temp_dir.name) / "benchmark_sample.apk"
            print(f"Generating synthetic benchmark APK at: {apk_path}")
            create_benchmark_synthetic_apk(apk_path, string_count=10000)

        profile_analysis(apk_path, iterations=args.iterations)
        return 0
    finally:
        if temp_dir:
            temp_dir.cleanup()


if __name__ == "__main__":
    sys.exit(main())
