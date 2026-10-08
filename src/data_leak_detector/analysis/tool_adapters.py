"""Subprocess adapters and diagnostic checkers for external CLI tools (jadx, apktool)."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from abc import ABC, abstractmethod
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Sequence

from data_leak_detector.core.exceptions import ExternalToolError, ToolNotFoundError
from data_leak_detector.core.logging_config import SensitiveDataFilter


logger = logging.getLogger(__name__)


def get_tool_diagnostics() -> dict[str, str]:
    """Diagnostic function returning availability status of core and external tools.
    
    Returns:
        Dictionary mapping tool names to 'AVAILABLE' or 'UNAVAILABLE'.
    """
    androguard_status = "UNAVAILABLE"
    try:
        try:
            from androguard.core.apk import APK  # type: ignore
        except ImportError:
            from androguard.core.bytecodes.apk import APK  # type: ignore
        androguard_status = "AVAILABLE"
    except ImportError:
        androguard_status = "UNAVAILABLE"

    apktool_status = "AVAILABLE" if ApktoolAdapter().is_available() else "UNAVAILABLE"
    jadx_status = "AVAILABLE" if JadxAdapter().is_available() else "UNAVAILABLE"

    diagnostics = {
        "AndroGuard": androguard_status,
        "apktool": apktool_status,
        "jadx": jadx_status,
    }
    logger.info(f"Tool diagnostics: {diagnostics}")
    return diagnostics


@contextmanager
def temporary_decompilation_dir(prefix: str = "mld_tmp_") -> Generator[Path, None, None]:
    """Context manager creating a temporary directory guaranteed to be cleaned up on exit."""
    temp_dir = tempfile.mkdtemp(prefix=prefix)
    target_path = Path(temp_dir)
    try:
        yield target_path
    finally:
        try:
            shutil.rmtree(target_path, ignore_errors=True)
            logger.debug(f"Cleaned up temporary decompilation directory: {target_path}")
        except Exception as e:
            logger.warning(f"Failed to cleanly remove temporary directory {target_path}: {e}")


class ToolAdapter(ABC):
    """Abstract base adapter for safe subprocess execution of external CLI tools."""

    def __init__(self, executable_name: str, timeout_seconds: int = 120) -> None:
        self.executable_name = executable_name
        self.timeout_seconds = timeout_seconds

    def is_available(self) -> bool:
        """Check if the external CLI binary is available on system PATH."""
        return shutil.which(self.executable_name) is not None

    def _execute_subprocess(self, cmd_args: Sequence[str], output_dir: Path | None = None) -> bool:
        """Execute external command with strict safety constraints.
        
        Guarantees:
        - NEVER uses shell=True.
        - Enforces execution timeout.
        - Redacts any sensitive data from log output.
        - Handles failure gracefully with typed exceptions.
        """
        if not self.is_available():
            raise ToolNotFoundError(
                f"External tool '{self.executable_name}' is not found on system PATH."
            )

        cmd_display = " ".join(cmd_args)
        logger.info(SensitiveDataFilter.redact(f"Running safe subprocess: {cmd_display}"))

        try:
            result = subprocess.run(
                list(cmd_args),
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                shell=False,
                check=False,
            )

            if result.returncode != 0:
                stderr_clean = SensitiveDataFilter.redact(result.stderr.strip())
                stdout_clean = SensitiveDataFilter.redact(result.stdout.strip())
                err_msg = stderr_clean or stdout_clean or f"Exit code {result.returncode}"
                logger.error(f"External tool '{self.executable_name}' failed: {err_msg}")
                raise ExternalToolError(
                    f"Tool '{self.executable_name}' exited with error code {result.returncode}: {err_msg}"
                )

            return True

        except subprocess.TimeoutExpired as e:
            logger.error(
                f"External tool '{self.executable_name}' timed out after {self.timeout_seconds}s"
            )
            raise ExternalToolError(
                f"Tool '{self.executable_name}' exceeded execution timeout ({self.timeout_seconds}s)."
            ) from e
        except FileNotFoundError as e:
            raise ToolNotFoundError(
                f"Binary '{self.executable_name}' was not found during execution."
            ) from e
        except (subprocess.SubprocessError, OSError) as e:
            sanitized = SensitiveDataFilter.redact(str(e))
            raise ExternalToolError(
                f"Subprocess execution error for '{self.executable_name}': {sanitized}"
            ) from e

    @abstractmethod
    def run(self, apk_path: Path, output_dir: Path) -> bool:
        """Execute the external tool on target APK."""


class JadxAdapter(ToolAdapter):
    """Subprocess adapter for JADX decompiler with graceful degradation."""

    def __init__(self, timeout_seconds: int = 120) -> None:
        super().__init__("jadx", timeout_seconds=timeout_seconds)

    def run(self, apk_path: Path, output_dir: Path) -> bool:
        """Decompile APK to Java source files via JADX.
        
        Args:
            apk_path: Target APK file.
            output_dir: Destination directory for decompiled Java sources.
            
        Returns:
            True if decompilation succeeded.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            self.executable_name,
            "-d",
            str(output_dir),
            str(apk_path),
            "--no-res",
            "--no-imports",
        ]
        return self._execute_subprocess(cmd, output_dir=output_dir)

    def decompile_safely(self, apk_path: Path, output_dir: Path) -> bool:
        """Attempt JADX decompilation with graceful degradation if unavailable.
        
        Returns:
            True if decompiled, False if jadx is unavailable or degraded.
        """
        if not self.is_available():
            logger.info("JADX is unavailable on system PATH. Degrading gracefully to bytecode analysis.")
            return False
        try:
            return self.run(apk_path, output_dir)
        except ExternalToolError as e:
            logger.warning(f"JADX decompilation failed ({e}). Degrading gracefully.")
            return False


class ApktoolAdapter(ToolAdapter):
    """Subprocess adapter for Apktool resource decoder with graceful degradation."""

    def __init__(self, timeout_seconds: int = 120) -> None:
        super().__init__("apktool", timeout_seconds=timeout_seconds)

    def run(self, apk_path: Path, output_dir: Path) -> bool:
        """Decode APK resources via Apktool.
        
        Args:
            apk_path: Target APK file.
            output_dir: Destination directory for decoded resources.
            
        Returns:
            True if resource decoding succeeded.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            self.executable_name,
            "d",
            "-f",
            "-o",
            str(output_dir),
            "-s",
            str(apk_path),
        ]
        return self._execute_subprocess(cmd, output_dir=output_dir)

    def decode_safely(self, apk_path: Path, output_dir: Path) -> bool:
        """Attempt Apktool resource decoding with graceful degradation if unavailable.
        
        Returns:
            True if decoded, False if apktool is unavailable or degraded.
        """
        if not self.is_available():
            logger.info(
                "Apktool is unavailable on system PATH. Degrading gracefully to AndroGuard resource parsing."
            )
            return False
        try:
            return self.run(apk_path, output_dir)
        except ExternalToolError as e:
            logger.warning(f"Apktool decoding failed ({e}). Degrading gracefully.")
            return False
