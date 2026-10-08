"""Convenience test runner executing unit and integration tests."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


def run_all_tests() -> bool:
    """Discover and run all tests in the tests directory."""
    project_root = Path(__file__).resolve().parent.parent
    src_dir = project_root / "src"
    tests_dir = project_root / "tests"

    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    for sub_dir in ["unit", "integration"]:
        target_dir = tests_dir / sub_dir
        if target_dir.exists():
            discovered = loader.discover(
                start_dir=str(target_dir),
                pattern="test_*.py",
            )
            suite.addTests(discovered)

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
