"""Unit tests for external tool adapters, diagnostics, and subprocess mocking."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from data_leak_detector.analysis.tool_adapters import (
    ApktoolAdapter,
    JadxAdapter,
    get_tool_diagnostics,
    temporary_decompilation_dir,
)
from data_leak_detector.core.exceptions import ExternalToolError, ToolNotFoundError


class TestToolAdapters(unittest.TestCase):
    def setUp(self) -> None:
        self.dummy_apk = Path("/dummy/path/app.apk")
        self.dummy_out = Path("/dummy/out")

    def test_get_tool_diagnostics_structure(self) -> None:
        diagnostics = get_tool_diagnostics()
        self.assertIn("AndroGuard", diagnostics)
        self.assertIn("apktool", diagnostics)
        self.assertIn("jadx", diagnostics)
        self.assertIn(diagnostics["AndroGuard"], ("AVAILABLE", "UNAVAILABLE"))
        self.assertIn(diagnostics["apktool"], ("AVAILABLE", "UNAVAILABLE"))
        self.assertIn(diagnostics["jadx"], ("AVAILABLE", "UNAVAILABLE"))

    @patch("shutil.which")
    def test_tool_is_available_returns_correct_boolean(self, mock_which: MagicMock) -> None:
        adapter = JadxAdapter()

        mock_which.return_value = "C:\\tools\\jadx.bat"
        self.assertTrue(adapter.is_available())

        mock_which.return_value = None
        self.assertFalse(adapter.is_available())

    @patch("shutil.which")
    def test_run_raises_tool_not_found_when_missing(self, mock_which: MagicMock) -> None:
        mock_which.return_value = None
        adapter = JadxAdapter()
        with self.assertRaises(ToolNotFoundError):
            adapter.run(self.dummy_apk, self.dummy_out)

    @patch("subprocess.run")
    @patch("shutil.which")
    def test_jadx_adapter_run_executes_safely(
        self, mock_which: MagicMock, mock_run: MagicMock
    ) -> None:
        mock_which.return_value = "/usr/bin/jadx"
        mock_run.return_value = subprocess.CompletedProcess(
            args=["jadx"], returncode=0, stdout="Success", stderr=""
        )

        adapter = JadxAdapter(timeout_seconds=60)
        with tempfile.TemporaryDirectory() as tmp_out:
            out_path = Path(tmp_out)
            success = adapter.run(self.dummy_apk, out_path)
            self.assertTrue(success)

        # Verify subprocess safety guarantees
        mock_run.assert_called_once()
        _, kwargs = mock_run.call_args
        self.assertFalse(kwargs.get("shell", False), "shell must NOT be True")
        self.assertEqual(kwargs.get("timeout"), 60)

    @patch("subprocess.run")
    @patch("shutil.which")
    def test_apktool_adapter_run_executes_safely(
        self, mock_which: MagicMock, mock_run: MagicMock
    ) -> None:
        mock_which.return_value = "/usr/bin/apktool"
        mock_run.return_value = subprocess.CompletedProcess(
            args=["apktool"], returncode=0, stdout="Success", stderr=""
        )

        adapter = ApktoolAdapter(timeout_seconds=45)
        with tempfile.TemporaryDirectory() as tmp_out:
            out_path = Path(tmp_out)
            success = adapter.run(self.dummy_apk, out_path)
            self.assertTrue(success)

        mock_run.assert_called_once()
        call_args, kwargs = mock_run.call_args
        self.assertEqual(call_args[0][0], "apktool")
        self.assertFalse(kwargs.get("shell", False))
        self.assertEqual(kwargs.get("timeout"), 45)

    @patch("subprocess.run")
    @patch("shutil.which")
    def test_tool_adapter_handles_timeout_gracefully(
        self, mock_which: MagicMock, mock_run: MagicMock
    ) -> None:
        mock_which.return_value = "/usr/bin/jadx"
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["jadx"], timeout=30)

        adapter = JadxAdapter(timeout_seconds=30)
        with tempfile.TemporaryDirectory() as tmp_out:
            with self.assertRaises(ExternalToolError) as ctx:
                adapter.run(self.dummy_apk, Path(tmp_out))
            self.assertIn("exceeded execution timeout", str(ctx.exception))

    @patch("subprocess.run")
    @patch("shutil.which")
    def test_tool_adapter_handles_nonzero_exit_code(
        self, mock_which: MagicMock, mock_run: MagicMock
    ) -> None:
        mock_which.return_value = "/usr/bin/jadx"
        mock_run.return_value = subprocess.CompletedProcess(
            args=["jadx"], returncode=1, stdout="", stderr="Compilation error in class X"
        )

        adapter = JadxAdapter()
        with tempfile.TemporaryDirectory() as tmp_out:
            with self.assertRaises(ExternalToolError) as ctx:
                adapter.run(self.dummy_apk, Path(tmp_out))
            self.assertIn("Compilation error", str(ctx.exception))

    @patch("shutil.which")
    def test_graceful_degradation_when_tools_unavailable(
        self, mock_which: MagicMock
    ) -> None:
        mock_which.return_value = None

        jadx = JadxAdapter()
        apktool = ApktoolAdapter()

        with tempfile.TemporaryDirectory() as tmp_out:
            out_path = Path(tmp_out)
            # decompile_safely and decode_safely must return False, not raise
            self.assertFalse(jadx.decompile_safely(self.dummy_apk, out_path))
            self.assertFalse(apktool.decode_safely(self.dummy_apk, out_path))

    def test_temporary_decompilation_dir_cleanup(self) -> None:
        created_path: Path | None = None
        with temporary_decompilation_dir(prefix="test_clean_") as tmp_dir:
            created_path = tmp_dir
            self.assertTrue(created_path.exists())
            # Create a file inside
            (created_path / "test.txt").write_text("sample decompiled file")

        # After exiting context, the directory should be completely removed
        self.assertIsNotNone(created_path)
        self.assertFalse(created_path.exists())


if __name__ == "__main__":
    unittest.main()
