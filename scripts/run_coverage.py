"""Convenience script to run unit and integration tests with code coverage analysis."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def run_coverage() -> int:
    """Execute test suite under coverage and generate terminal and HTML reports."""
    project_root = Path(__file__).resolve().parent.parent

    print("======================================================================")
    print("Running automated test suite with coverage measurement...")
    print("======================================================================")

    # 1. Run unittest discover under coverage
    cmd_run = [
        sys.executable,
        "-m",
        "coverage",
        "run",
        "--source=src",
        str(project_root / "scripts" / "run_tests.py"),
    ]

    res = subprocess.run(cmd_run, cwd=str(project_root))
    if res.returncode != 0:
        print("\n[FAILED] Test execution failed.")
        return res.returncode

    # 2. Print terminal coverage summary
    print("\n======================================================================")
    print("Coverage Report Summary:")
    print("======================================================================")
    cmd_report = [
        sys.executable,
        "-m",
        "coverage",
        "report",
        "--show-missing",
    ]
    subprocess.run(cmd_report, cwd=str(project_root))

    # 3. Generate HTML report
    html_dir = project_root / "docs" / "coverage"
    cmd_html = [
        sys.executable,
        "-m",
        "coverage",
        "html",
        "-d",
        str(html_dir),
    ]
    subprocess.run(cmd_html, cwd=str(project_root))
    print(f"\nHTML coverage report generated in: {html_dir}")

    return 0


if __name__ == "__main__":
    sys.exit(run_coverage())
