"""Application configuration management."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AppConfig:
    """Runtime configuration settings."""

    app_name: str = "Mobile Data Leak Detector"
    app_version: str = "0.1.0"
    base_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent.parent.parent)
    resources_dir: Path = field(init=False)
    database_path: Path = field(init=False)
    temp_dir: Path = field(init=False)
    
    # External tool timeouts (seconds)
    subprocess_timeout_seconds: int = 120
    
    # Tool availability flags
    jadx_path: Path | None = None
    apktool_path: Path | None = None
    
    def __post_init__(self) -> None:
        self.resources_dir = self.base_dir / "resources"
        from data_leak_detector.storage.database import get_default_database_path
        self.database_path = get_default_database_path()
        self.temp_dir = self.base_dir / "temp_decompiled"
        self.temp_dir.mkdir(parents=True, exist_ok=True)

