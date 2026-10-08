"""Application configuration management with local JSON persistence in user data directory."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def get_default_config_dir() -> Path:
    """Resolve configuration directory in the OS user application data folder."""
    app_folder_name = "MobileDataLeakDetector"
    if os.name == "nt":
        app_data = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        base_dir = Path(app_data) if app_data else Path.home() / "AppData" / "Local"
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        base_dir = Path(xdg) if xdg else Path.home() / ".config"

    target_dir = base_dir / app_folder_name
    target_dir.mkdir(parents=True, exist_ok=True)
    return target_dir


def get_default_config_path() -> Path:
    """Resolve default settings.json file path."""
    return get_default_config_dir() / "settings.json"


@dataclass
class AppConfig:
    """Runtime configuration settings supporting persistent disk serialization."""

    app_name: str = "Mobile Data Leak Detector"
    app_version: str = "0.1.0"
    base_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent.parent.parent)
    resources_dir: Path = field(init=False)
    database_path: Path = field(init=False)
    temp_dir: Path = field(init=False)
    config_file_path: Path = field(init=False)

    # Subprocess timeouts (seconds)
    subprocess_timeout_seconds: int = 120

    # Configurable tool executable paths
    jadx_path: str = ""
    apktool_path: str = ""

    # Output directory for exported reports
    output_dir: str = ""

    # Report Preferences
    report_default_format: str = "PDF"  # PDF, HTML, TXT
    report_include_disclaimer: bool = True
    report_include_owasp: bool = True
    report_include_permissions: bool = True

    # Accessibility & High-Contrast
    high_contrast_mode: bool = False

    # Optional analysis rules toggles
    enable_manifest_rules: bool = True
    enable_secret_rules: bool = True
    enable_network_rules: bool = True
    enable_storage_rules: bool = True
    enable_crypto_rules: bool = True
    enable_sdk_rules: bool = True

    def __post_init__(self) -> None:
        self.resources_dir = self.base_dir / "resources"
        from data_leak_detector.storage.database import get_default_database_path
        self.database_path = get_default_database_path()
        self.temp_dir = self.base_dir / "temp_decompiled"
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.config_file_path = get_default_config_path()

        # If default output dir is empty, use user Documents or project output folder
        if not self.output_dir:
            self.output_dir = str(Path.home() / "Documents" / "DataLeakReports")

    def save_to_disk(self, target_path: Path | None = None) -> Path:
        """Persist settings to user configuration directory as JSON."""
        save_file = target_path or self.config_file_path
        save_file.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "subprocess_timeout_seconds": self.subprocess_timeout_seconds,
            "jadx_path": str(self.jadx_path),
            "apktool_path": str(self.apktool_path),
            "output_dir": str(self.output_dir),
            "report_default_format": self.report_default_format,
            "report_include_disclaimer": self.report_include_disclaimer,
            "report_include_owasp": self.report_include_owasp,
            "report_include_permissions": self.report_include_permissions,
            "high_contrast_mode": self.high_contrast_mode,
            "enable_manifest_rules": self.enable_manifest_rules,
            "enable_secret_rules": self.enable_secret_rules,
            "enable_network_rules": self.enable_network_rules,
            "enable_storage_rules": self.enable_storage_rules,
            "enable_crypto_rules": self.enable_crypto_rules,
            "enable_sdk_rules": self.enable_sdk_rules,
        }

        with open(save_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        logger.info("Saved application settings to: %s", save_file)
        return save_file

    def load_from_disk(self, target_path: Path | None = None) -> bool:
        """Load settings from user configuration directory if present."""
        load_file = target_path or self.config_file_path
        if not load_file.exists():
            return False

        try:
            with open(load_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, dict):
                self.subprocess_timeout_seconds = int(data.get("subprocess_timeout_seconds", 120))
                self.jadx_path = str(data.get("jadx_path", ""))
                self.apktool_path = str(data.get("apktool_path", ""))
                self.output_dir = str(data.get("output_dir", self.output_dir))
                self.report_default_format = str(data.get("report_default_format", "PDF"))
                self.report_include_disclaimer = bool(data.get("report_include_disclaimer", True))
                self.report_include_owasp = bool(data.get("report_include_owasp", True))
                self.report_include_permissions = bool(data.get("report_include_permissions", True))
                self.high_contrast_mode = bool(data.get("high_contrast_mode", False))
                self.enable_manifest_rules = bool(data.get("enable_manifest_rules", True))
                self.enable_secret_rules = bool(data.get("enable_secret_rules", True))
                self.enable_network_rules = bool(data.get("enable_network_rules", True))
                self.enable_storage_rules = bool(data.get("enable_storage_rules", True))
                self.enable_crypto_rules = bool(data.get("enable_crypto_rules", True))
                self.enable_sdk_rules = bool(data.get("enable_sdk_rules", True))
                logger.info("Loaded application settings from: %s", load_file)
                return True
        except Exception as exc:
            logger.warning("Could not read configuration file '%s': %s", load_file, exc)

        return False

    def reset_to_defaults(self, target_path: Path | None = None) -> None:
        """Reset all configurable fields to their initial defaults and update disk."""
        self.subprocess_timeout_seconds = 120
        self.jadx_path = ""
        self.apktool_path = ""
        self.output_dir = str(Path.home() / "Documents" / "DataLeakReports")
        self.report_default_format = "PDF"
        self.report_include_disclaimer = True
        self.report_include_owasp = True
        self.report_include_permissions = True
        self.high_contrast_mode = False
        self.enable_manifest_rules = True
        self.enable_secret_rules = True
        self.enable_network_rules = True
        self.enable_storage_rules = True
        self.enable_crypto_rules = True
        self.enable_sdk_rules = True

        self.save_to_disk(target_path)
