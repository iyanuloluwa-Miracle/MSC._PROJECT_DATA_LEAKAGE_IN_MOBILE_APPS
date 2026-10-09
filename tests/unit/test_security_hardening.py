"""Comprehensive security hardening and threat defense unit tests.

Validates application protections against:
1. Zip Slip / Path Traversal archive entries (CWE-22)
2. Zip Bomb / Decompression bombs and archive entry count limits
3. Oversized and empty APK inputs
4. Untrusted filename and metadata sanitization
5. Windows reserved device filenames (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
6. Subprocess argument injection and timeouts
7. Log sanitization and CRLF log injection neutralization (CWE-117)
8. Output path validation and traversal prevention
9. CSV formula injection neutralization (CWE-123)
10. Malformed Unicode and corrupted archives
11. Temporary directory cleanup resilience
"""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from data_leak_detector.analysis.apk_parser import APKParser
from data_leak_detector.analysis.batch_processor import (
    BatchItem,
    _sanitize_csv_cell,
    export_batch_summary_csv,
)
from data_leak_detector.analysis.engine import AnalysisEngine
from data_leak_detector.analysis.tool_adapters import ToolAdapter
from data_leak_detector.core.config import AppConfig
from data_leak_detector.core.exceptions import (
    ExternalToolError,
    InvalidAPKError,
)
from data_leak_detector.core.logging_config import SensitiveDataFilter
from data_leak_detector.core.models import ApplicationMetadata
from data_leak_detector.core.path_safety import (
    is_safe_zip_path,
    sanitize_for_logging,
    sanitize_untrusted_filename,
    validate_output_path,
)


class DummyToolAdapter(ToolAdapter):
    """Concrete adapter for testing ToolAdapter base functionality."""

    def __init__(self, timeout_seconds: int = 5) -> None:
        super().__init__(executable_name="dummy_tool", timeout_seconds=timeout_seconds)

    def is_available(self) -> bool:
        return True

    def run(self, apk_path: Path, output_dir: Path) -> bool:
        return True


class TestSecurityHardening(unittest.TestCase):
    """Test suite covering the 16 security and privacy vectors."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    # -------------------------------------------------------------------------
    # 1. Zip Slip / Path Traversal Defense
    # -------------------------------------------------------------------------
    def test_is_safe_zip_path(self) -> None:
        """Verify is_safe_zip_path neutralizes directory traversal sequences."""
        # Safe paths
        self.assertTrue(is_safe_zip_path("AndroidManifest.xml"))
        self.assertTrue(is_safe_zip_path("res/layout/main.xml"))
        self.assertTrue(is_safe_zip_path("classes.dex"))
        self.assertTrue(is_safe_zip_path("assets/data/config.json"))

        # Traversal attempts
        self.assertFalse(is_safe_zip_path("../evil.txt"))
        self.assertFalse(is_safe_zip_path("res/../../evil.txt"))
        self.assertFalse(is_safe_zip_path("/etc/passwd"))
        self.assertFalse(is_safe_zip_path("\\Windows\\System32\\calc.exe"))
        self.assertFalse(is_safe_zip_path("C:/evil.bat"))
        self.assertFalse(is_safe_zip_path("D:\\evil.bat"))
        self.assertFalse(is_safe_zip_path("res/\x00evil.txt"))
        self.assertFalse(is_safe_zip_path(""))

    def test_apk_parser_rejects_zip_slip_archive(self) -> None:
        """Verify APKParser.validate_file raises InvalidAPKError on Zip Slip entries."""
        zip_path = self.work_dir / "zip_slip.apk"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest></manifest>")
            zf.writestr("../../etc/cron.d/backdoor", b"* * * * * root reboot\n")

        parser = APKParser(zip_path)
        with self.assertRaises(InvalidAPKError) as ctx:
            parser.validate_file()
        self.assertIn("Zip Slip attempt", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 2. Decompression Bomb & Resource Limits
    # -------------------------------------------------------------------------
    def test_apk_parser_enforces_max_extracted_size(self) -> None:
        """Verify APKParser rejects archives exceeding max_extracted_size_bytes."""
        zip_path = self.work_dir / "large_uncompressed.apk"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest></manifest>")
            zf.writestr("classes.dex", b"0" * 1024)

        config = AppConfig(max_extracted_size_bytes=500)  # Low cap for test
        parser = APKParser(zip_path, config=config)
        with self.assertRaises(InvalidAPKError) as ctx:
            parser.validate_file()
        self.assertIn("exceeds limit", str(ctx.exception))

    def test_apk_parser_enforces_max_extracted_file_count(self) -> None:
        """Verify APKParser rejects archives with excessive file entries."""
        zip_path = self.work_dir / "many_files.apk"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest></manifest>")
            for i in range(15):
                zf.writestr(f"res/raw/file_{i}.txt", b"content")

        config = AppConfig(max_extracted_file_count=10)
        parser = APKParser(zip_path, config=config)
        with self.assertRaises(InvalidAPKError) as ctx:
            parser.validate_file()
        self.assertIn("exceeding maximum allowed count", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 3. Oversized and Empty APK Handling
    # -------------------------------------------------------------------------
    def test_apk_parser_rejects_empty_file(self) -> None:
        """Verify APKParser rejects zero-byte APK files."""
        empty_apk = self.work_dir / "empty.apk"
        empty_apk.write_bytes(b"")

        parser = APKParser(empty_apk)
        with self.assertRaises(InvalidAPKError) as ctx:
            parser.validate_file()
        self.assertIn("empty (0 bytes)", str(ctx.exception))

    def test_apk_parser_rejects_oversized_apk(self) -> None:
        """Verify APKParser rejects files exceeding max_apk_size_bytes."""
        big_apk = self.work_dir / "big.apk"
        big_apk.write_bytes(b"x" * 2048)

        config = AppConfig(max_apk_size_bytes=1024)
        parser = APKParser(big_apk, config=config)
        with self.assertRaises(InvalidAPKError) as ctx:
            parser.validate_file()
        self.assertIn("exceeds configured maximum limit", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 4. Untrusted Filename & Metadata Sanitization
    # -------------------------------------------------------------------------
    def test_sanitize_untrusted_filename(self) -> None:
        """Verify sanitize_untrusted_filename strips traversal, NUL bytes, and reserved names."""
        # Traversal stripping
        self.assertEqual(sanitize_untrusted_filename("../../../etc/shadow"), "shadow")
        self.assertEqual(sanitize_untrusted_filename("..\\..\\malicious.apk"), "malicious.apk")
        
        # NUL byte stripping
        self.assertEqual(sanitize_untrusted_filename("innocent.apk\x00.exe"), "innocent.apk.exe")
        
        # Windows reserved device names
        self.assertEqual(sanitize_untrusted_filename("CON.apk"), "safe_CON.apk")
        self.assertEqual(sanitize_untrusted_filename("prn"), "safe_prn")
        self.assertEqual(sanitize_untrusted_filename("aux.zip"), "safe_aux.zip")
        self.assertEqual(sanitize_untrusted_filename("NUL"), "safe_NUL")
        self.assertEqual(sanitize_untrusted_filename("com1.apk"), "safe_com1.apk")

        # Empty or dots only
        self.assertEqual(sanitize_untrusted_filename("..."), "unnamed.apk")
        self.assertEqual(sanitize_untrusted_filename(None), "unnamed.apk")

    def test_application_metadata_untrusted_inputs(self) -> None:
        """Verify ApplicationMetadata automatically sanitizes filename and metadata."""
        meta = ApplicationMetadata(
            filename="../../CON.apk\x00",
            sha256="a" * 64,
            file_size=100,
            package_name="com.example.app\r\nmalicious",
            app_name="App\x00Title\tSafe",
        )
        self.assertEqual(meta.filename, "safe_CON.apk")
        self.assertNotIn("\r", meta.package_name)
        self.assertNotIn("\n", meta.package_name)
        self.assertNotIn("\x00", meta.app_name)

    # -------------------------------------------------------------------------
    # 5. Output Path Validation
    # -------------------------------------------------------------------------
    def test_validate_output_path(self) -> None:
        """Verify validate_output_path catches NUL bytes and OS reserved devices."""
        # Valid path
        valid = self.work_dir / "reports" / "summary.pdf"
        resolved = validate_output_path(valid)
        self.assertEqual(resolved, valid.resolve())

        # NUL byte injection
        with self.assertRaises(ValueError) as ctx:
            validate_output_path(self.work_dir / "report\x00.pdf")
        self.assertIn("NUL byte", str(ctx.exception))

        # Windows reserved name
        with self.assertRaises(ValueError) as ctx:
            validate_output_path(self.work_dir / "CON.pdf")
        self.assertIn("reserved", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 6. Log Sanitization & CRLF Injection (CWE-117)
    # -------------------------------------------------------------------------
    def test_sanitize_for_logging(self) -> None:
        """Verify sanitize_for_logging neutralizes CRLF injections and control bytes."""
        malicious = "User input\r\n[CRITICAL] Admin logged in!\x00"
        sanitized = sanitize_for_logging(malicious)
        self.assertNotIn("\r", sanitized)
        self.assertNotIn("\n", sanitized)
        self.assertIn("\\r\\n", sanitized)
        self.assertIn("\\x00", sanitized)

    def test_sensitive_data_filter_log_sanitization(self) -> None:
        """Verify SensitiveDataFilter sanitizes CRLF logs while redacting secrets."""
        raw = "User: test\nKey: AKIA1234567890EXAMPLE\r\nStatus: OK"
        filtered = SensitiveDataFilter.redact_and_sanitize(raw)
        self.assertNotIn("\r", filtered)
        self.assertNotIn("\n", filtered)
        self.assertIn("\\r\\n", filtered)
        self.assertIn("[REDACTED_SECRET]", filtered)

    # -------------------------------------------------------------------------
    # 7. Subprocess Safety (Command Injection & Timeouts)
    # -------------------------------------------------------------------------
    def test_tool_adapter_rejects_nul_byte_in_arguments(self) -> None:
        """Verify ToolAdapter rejects command arguments containing NUL bytes."""
        adapter = DummyToolAdapter()
        with self.assertRaises(ExternalToolError) as ctx:
            adapter._execute_subprocess(["dummy", "arg1\x00evil"])
        self.assertIn("illegal NUL byte", str(ctx.exception))

    def test_tool_adapter_enforces_timeout(self) -> None:
        """Verify ToolAdapter enforces execution timeouts safely."""
        adapter = DummyToolAdapter(timeout_seconds=1)
        with patch("subprocess.run", side_effect=__import__("subprocess").TimeoutExpired(cmd=["dummy"], timeout=1)):
            with self.assertRaises(ExternalToolError) as ctx:
                adapter._execute_subprocess(["dummy", "work"])
            self.assertIn("timeout", str(ctx.exception).lower())

    # -------------------------------------------------------------------------
    # 8. CSV Formula Injection Defense (CWE-123)
    # -------------------------------------------------------------------------
    def test_csv_cell_formula_injection_defense(self) -> None:
        """Verify dangerous prefix characters are neutralized in CSV exports."""
        self.assertEqual(_sanitize_csv_cell("=cmd|'/C calc'!A0"), "'=cmd|'/C calc'!A0")
        self.assertEqual(_sanitize_csv_cell("+12345"), "'+12345")
        self.assertEqual(_sanitize_csv_cell("-12345"), "'-12345")
        self.assertEqual(_sanitize_csv_cell("@SUM(1,2)"), "'@SUM(1,2)")
        self.assertEqual(_sanitize_csv_cell("\tTAB_INJECT"), "'\tTAB_INJECT")
        self.assertEqual(_sanitize_csv_cell("safe_name"), "safe_name")

    def test_export_batch_summary_csv_safe(self) -> None:
        """Verify batch CSV export sanitizes malicious APK filenames."""
        csv_path = self.work_dir / "batch_test.csv"
        item = BatchItem(apk_path=Path("=calc.apk"))
        item.filename = "=calc.apk"

        mock_result = MagicMock()
        mock_result.application.package_name = "+com.evil.app"
        mock_result.application.sha256 = "b" * 64
        item.result = mock_result

        export_batch_summary_csv([item], csv_path)
        content = csv_path.read_text(encoding="utf-8")
        self.assertIn("'=calc.apk", content)
        self.assertIn("'+com.evil.app", content)

    # -------------------------------------------------------------------------
    # 9. Temporary Directory Cleanup Resilience
    # -------------------------------------------------------------------------
    def test_engine_clean_temporary_dirs_read_only(self) -> None:
        """Verify _clean_temporary_dirs removes directories containing read-only files."""
        temp_dir = self.work_dir / "ro_temp"
        temp_dir.mkdir()
        ro_file = temp_dir / "locked.txt"
        ro_file.write_text("read-only content")
        
        # Mark file as read-only (removing write permissions)
        os.chmod(ro_file, stat.S_IREAD)

        engine = AnalysisEngine()
        engine._clean_temporary_dirs([temp_dir])
        self.assertFalse(temp_dir.exists())

    # -------------------------------------------------------------------------
    # 10. Malformed Unicode Handling
    # -------------------------------------------------------------------------
    def test_harvest_directory_text_files_handles_malformed_unicode(self) -> None:
        """Verify _harvest_directory_text_files safely reads binary/non-UTF8 files."""
        src_dir = self.work_dir / "src_decompiled"
        src_dir.mkdir()
        bad_file = src_dir / "Invalid.java"
        # Write invalid UTF-8 byte sequence
        bad_file.write_bytes(b"public class Test { \xff\xfe\xfa byte x; }")

        engine = AnalysisEngine()
        extracted: dict[str, str] = {}
        engine._harvest_directory_text_files(src_dir, extracted, valid_extensions=(".java",))
        
        self.assertIn("Invalid.java", extracted)
        # Verify placeholder character replacement occurred without crashing
        self.assertIn("\ufffd", extracted["Invalid.java"])


if __name__ == "__main__":
    unittest.main()
