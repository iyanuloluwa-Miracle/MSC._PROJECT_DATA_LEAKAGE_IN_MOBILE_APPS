"""RuleRegistry responsible for managing, filtering, and safely executing static detection rules."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Sequence

from data_leak_detector.core.logging_config import SensitiveDataFilter
from data_leak_detector.core.models import BaseModel, SecurityFinding
from data_leak_detector.rules.base import BaseRule


logger = logging.getLogger(__name__)


@dataclass
class RuleExecutionReport(BaseModel):
    """Execution telemetry and aggregated findings from a rule engine pass."""

    rules_executed: int = 0
    rules_skipped: int = 0
    rule_errors: int = 0
    findings: list[SecurityFinding] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)


class RuleRegistry:
    """Manages static rule lifecycle and safe isolated execution.
    
    Guarantees:
    - Fault Isolation: One malfunctioning rule cannot crash analysis.
    - Secret Redaction: Errors and telemetry are sanitized before logging.
    - Execution Tracking: Reports exact counts for executed, skipped, and failed rules.
    """

    def __init__(self, rules: Sequence[BaseRule] | None = None) -> None:
        self._rules: dict[str, BaseRule] = {}
        if rules:
            for rule in rules:
                self.register(rule)

    def register(self, rule: BaseRule) -> None:
        """Register a static analysis rule into the registry."""
        if not isinstance(rule, BaseRule):
            raise TypeError(f"Expected BaseRule instance, got {type(rule).__name__}")
        if not getattr(rule, "rule_id", None):
            raise ValueError("Rule must possess a non-empty 'rule_id' attribute.")
        self._rules[rule.rule_id] = rule
        logger.debug(f"Registered static analysis rule '{rule.rule_id}' ({rule.title})")

    def unregister(self, rule_id: str) -> bool:
        """Remove a rule from the registry by its identifier."""
        if rule_id in self._rules:
            del self._rules[rule_id]
            logger.debug(f"Unregistered rule '{rule_id}'")
            return True
        return False

    def get_rule(self, rule_id: str) -> BaseRule | None:
        """Retrieve a registered rule by its identifier."""
        return self._rules.get(rule_id)

    def list_rules(self) -> list[BaseRule]:
        """Return all registered rules."""
        return list(self._rules.values())

    def get_enabled_rules(self) -> list[BaseRule]:
        """Return all enabled rules."""
        return [r for r in self._rules.values() if getattr(r, "enabled", True)]

    def enable_rule(self, rule_id: str) -> bool:
        """Enable an existing rule."""
        rule = self._rules.get(rule_id)
        if rule:
            rule.enabled = True
            return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disable an existing rule so it will be skipped during execution."""
        rule = self._rules.get(rule_id)
        if rule:
            rule.enabled = False
            return True
        return False

    def execute_all(self, context: Any) -> RuleExecutionReport:
        """Safely execute all enabled rules against the provided analysis context.
        
        Args:
            context: Parsed APK context or artifact dictionary.
            
        Returns:
            RuleExecutionReport containing aggregated findings and execution metrics.
        """
        report = RuleExecutionReport()

        for rule_id, rule in self._rules.items():
            if not getattr(rule, "enabled", True):
                report.rules_skipped += 1
                logger.debug(f"Skipping disabled rule '{rule_id}'")
                continue

            try:
                findings = rule.evaluate(context)
                if findings:
                    report.findings.extend(findings)
                report.rules_executed += 1

            except Exception as e:
                report.rule_errors += 1
                sanitized_error = SensitiveDataFilter.redact(str(e))
                logger.error(
                    f"Rule failure in '{rule_id}' ({rule.title}): {sanitized_error}",
                    exc_info=False,
                )
                report.errors.append({
                    "rule_id": rule_id,
                    "title": rule.title,
                    "error": sanitized_error,
                })

        logger.info(
            f"Rule execution finished: {report.rules_executed} executed, "
            f"{report.rules_skipped} skipped, {report.rule_errors} errors. "
            f"Total findings: {len(report.findings)}"
        )
        return report
