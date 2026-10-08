"""Rules identifying broken or deprecated cryptographic algorithms."""

from __future__ import annotations

from typing import Any

from data_leak_detector.core.models import Finding, FindingCategory, Severity
from data_leak_detector.rules.base import BaseRule


class WeakCryptoRule(BaseRule):
    """Detects usage of weak cryptographic primitives (DES, MD5, SHA1 for signatures, ECB mode)."""

    rule_id = "CRY-001"
    category = FindingCategory.CRYPTO_FLAW
    severity = Severity.HIGH
    title = "Weak / Deprecated Cryptographic Primitive"
    description = (
        "Static bytecode uses broken cryptographic algorithms such as DES, MD5, or AES in ECB mode."
    )

    def evaluate(self, context: dict[str, Any]) -> list[Finding]:
        raise NotImplementedError()
