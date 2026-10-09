"""Unit tests for the cross-tool research comparison framework (scripts/compare_results.py)."""

from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from scripts.compare_results import (
    calculate_jaccard_similarity,
    compare_datasets,
    load_external_csv,
    load_our_results,
    normalize_category,
    normalize_finding_name,
)


class TestCompareResults(unittest.TestCase):
    """Test suite verifying external tool CSV parsing, category normalization, and overlap metrics."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_category_normalization(self) -> None:
        """Verify normalization of diverse external category labels into canonical taxonomy."""
        self.assertEqual(normalize_category("PERMISSION"), "PERMISSION")
        self.assertEqual(normalize_category("Insecure Communication"), "NETWORK_INDICATOR")
        self.assertEqual(normalize_category("Cleartext HTTP"), "NETWORK_INDICATOR")
        self.assertEqual(normalize_category("Hardcoded API Key"), "HARDCODED_SECRET")
        self.assertEqual(normalize_category("Insecure Data Storage"), "STORAGE_INSECURITY")
        self.assertEqual(normalize_category("Broken Cryptography"), "CRYPTO_FLAW")
        self.assertEqual(normalize_category("Adware / Tracker SDK"), "TRACKING_SDK")
        self.assertEqual(normalize_category("Android Security Misconfiguration"), "MANIFEST_MISCONFIG")
        self.assertEqual(normalize_category("Random Unknown Category"), "OTHER")
        self.assertEqual(normalize_category(None), "OTHER")

    def test_normalize_finding_name(self) -> None:
        """Verify punctuation removal and whitespace collapsing for relaxed matching."""
        self.assertEqual(
            normalize_finding_name("Cleartext HTTP Traffic Allowed!"),
            "cleartext http traffic allowed",
        )
        self.assertEqual(
            normalize_finding_name("Hardcoded_Google_API_Key (v2)"),
            "hardcoded google api key v2",
        )
        self.assertEqual(normalize_finding_name(""), "")

    def test_jaccard_similarity(self) -> None:
        """Verify Jaccard index calculations and boundary conditions."""
        self.assertEqual(calculate_jaccard_similarity(set(), set()), 1.0)
        self.assertEqual(calculate_jaccard_similarity({"a", "b"}, {"a", "b"}), 1.0)
        self.assertEqual(calculate_jaccard_similarity({"a"}, {"b"}), 0.0)
        # Intersection: {"a"} (1), Union: {"a", "b", "c"} (3) -> 1/3 = 0.3333
        self.assertEqual(calculate_jaccard_similarity({"a", "b"}, {"a", "c"}), 0.3333)

    def test_load_external_csv_valid(self) -> None:
        """Verify parsing valid external tool CSV records."""
        csv_path = self.work_dir / "external.csv"
        hash_val = "a" * 64
        csv_content = (
            "apk_hash,tool,finding_category,finding_name,severity\n"
            f"{hash_val},MobSF,Insecure Communication,Cleartext HTTP Allowed,HIGH\n"
            f"{hash_val},MobSF,Hardcoded Secret,Google API Key,HIGH\n"
        )
        csv_path.write_text(csv_content, encoding="utf-8")

        records = load_external_csv(csv_path)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["tool"], "MobSF")
        self.assertEqual(records[0]["finding_category"], "NETWORK_INDICATOR")
        self.assertEqual(records[1]["finding_category"], "HARDCODED_SECRET")

    def test_load_external_csv_missing_columns_raises_error(self) -> None:
        """Verify that invalid CSV lacking required headers raises ValueError."""
        csv_path = self.work_dir / "invalid.csv"
        csv_path.write_text("apk_hash,some_column\n123,val\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            load_external_csv(csv_path)

    def test_load_our_results_json(self) -> None:
        """Verify loading findings from evaluation_results.json schema."""
        json_path = self.work_dir / "evaluation_results.json"
        eval_data = {
            "apks": [
                {
                    "sha256": "b" * 64,
                    "findings": [
                        {
                            "rule_id": "SEC-001",
                            "finding_name": "Google API Key Hardcoded",
                            "finding_category": "HARDCODED_SECRET",
                            "severity": "HIGH",
                        },
                        {
                            "rule_id": "NET-001",
                            "finding_name": "Cleartext HTTP Traffic Allowed",
                            "finding_category": "NETWORK_INDICATOR",
                            "severity": "MEDIUM",
                        },
                    ],
                }
            ]
        }
        json_path.write_text(json.dumps(eval_data), encoding="utf-8")

        records = load_our_results(json_path)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["apk_hash"], "b" * 64)
        self.assertEqual(records[0]["finding_category"], "HARDCODED_SECRET")

    def test_compare_datasets_end_to_end(self) -> None:
        """Verify comparative analysis between our tool and external results."""
        common_hash = "c" * 64

        our_records = [
            {
                "apk_hash": common_hash,
                "tool": "DataLeakDetector",
                "finding_category": "NETWORK_INDICATOR",
                "finding_name": "Cleartext HTTP Traffic Allowed",
                "normalized_name": "cleartext http traffic allowed",
                "severity": "HIGH",
            },
            {
                "apk_hash": common_hash,
                "tool": "DataLeakDetector",
                "finding_category": "STORAGE_INSECURITY",
                "finding_name": "Plaintext SharedPreferences Stored",
                "normalized_name": "plaintext sharedpreferences stored",
                "severity": "MEDIUM",
            },
        ]

        external_records = [
            {
                "apk_hash": common_hash,
                "tool": "MobSF",
                "finding_category": "NETWORK_INDICATOR",
                "finding_name": "Cleartext HTTP Traffic Allowed",
                "normalized_name": "cleartext http traffic allowed",
                "severity": "HIGH",
            },
            {
                "apk_hash": common_hash,
                "tool": "MobSF",
                "finding_category": "CRYPTO_FLAW",
                "finding_name": "Insecure ECB Mode Cipher",
                "normalized_name": "insecure ecb mode cipher",
                "severity": "CRITICAL",
            },
        ]

        out_dir = self.work_dir / "comparison_out"
        summary = compare_datasets(our_records, external_records, output_dir=out_dir)

        self.assertIsNotNone(summary)
        self.assertEqual(summary["metadata"]["total_apks_evaluated"], 1)
        self.assertEqual(summary["metadata"]["overall_common_findings"], 1)
        self.assertEqual(summary["metadata"]["overall_unique_our_tool"], 1)
        self.assertEqual(summary["metadata"]["overall_unique_external_tool"], 1)

        # Check category overlap counts
        overlaps = summary["category_overlaps"]
        self.assertEqual(overlaps["NETWORK_INDICATOR"]["both"], 1)
        self.assertEqual(overlaps["STORAGE_INSECURITY"]["our_tool_only"], 1)
        self.assertEqual(overlaps["CRYPTO_FLAW"]["external_tool_only"], 1)

        # Verify output files exist
        csv_file = out_dir / "comparison_summary.csv"
        json_file = out_dir / "comparison_summary.json"
        self.assertTrue(csv_file.exists())
        self.assertTrue(json_file.exists())

        # Check CSV content
        with open(csv_file, "r", encoding="utf-8") as f:
            reader = list(csv.DictReader(f))
            self.assertEqual(len(reader), 1)
            row = reader[0]
            self.assertEqual(row["apk_hash"], common_hash)
            self.assertEqual(int(row["common_findings_count"]), 1)
            self.assertEqual(int(row["unique_our_tool_count"]), 1)
            self.assertEqual(int(row["unique_external_tool_count"]), 1)


if __name__ == "__main__":
    unittest.main()
