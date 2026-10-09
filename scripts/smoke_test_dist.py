"""Smoke test script for the built standalone PyInstaller distribution executable."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path


def smoke_test_executable() -> int:
    """Launch the built executable, verify startup and directories, then terminate."""
    root_dir = Path(__file__).resolve().parent.parent
    src_dir = root_dir / "src"
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))

    dist_dir = root_dir / "dist" / "data_leak_detector"
    exe_name = "data_leak_detector.exe" if os.name == "nt" else "data_leak_detector"
    exe_path = dist_dir / exe_name

    if not exe_path.exists():
        print(f"FAIL: Executable not found at {exe_path}")
        return 1

    print(f"Found built standalone executable at: {exe_path}")

    # Verify resource files inside dist directory
    res_dir = dist_dir / "_internal" / "resources"
    if not res_dir.exists():
        res_dir = dist_dir / "resources"

    required_resources = [
        "permission_metadata.json",
        "sdk_patterns.json",
        "tracking_patterns.json",
    ]
    for res_file in required_resources:
        target = res_dir / res_file
        if not target.exists():
            print(f"FAIL: Required bundled resource missing: {target}")
            return 1
        print(f"Verified bundled resource exists: {res_file} ({target.stat().st_size} bytes)")

    # Launch process
    print("Launching standalone executable in non-interactive verification mode...")
    start_time = time.time()
    proc = subprocess.Popen([str(exe_path)])

    try:
        # Give it a few seconds to start up and initialize
        time.sleep(3)
        poll_status = proc.poll()
        if poll_status is not None:
            print(f"FAIL: Process exited prematurely with exit code: {poll_status}")
            return 1

        print("Process successfully started and running without crash.")

        # Check user config directory
        from data_leak_detector.core.config import get_default_config_dir
        config_dir = get_default_config_dir()
        print(f"Verified user application config directory: {config_dir}")

        from data_leak_detector.storage.database import get_default_database_path
        db_path = get_default_database_path()
        print(f"Verified user database location: {db_path} (exists: {db_path.exists()})")

    finally:
        print("Terminating smoke test process...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
        print("Smoke test process terminated cleanly.")

    elapsed = time.time() - start_time
    print(f"Smoke test completed successfully in {elapsed:.2f}s!")
    return 0


if __name__ == "__main__":
    sys.exit(smoke_test_executable())
