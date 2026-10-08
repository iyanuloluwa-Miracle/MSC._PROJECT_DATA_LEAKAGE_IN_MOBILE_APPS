"""Rule definitions and execution registry for static detection of data leakage."""

from data_leak_detector.rules.base import BaseRule
from data_leak_detector.rules.registry import RuleExecutionReport, RuleRegistry


__all__ = ["BaseRule", "RuleRegistry", "RuleExecutionReport"]
