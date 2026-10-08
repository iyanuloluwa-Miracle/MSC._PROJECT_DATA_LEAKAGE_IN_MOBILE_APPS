"""Permission auditor mapping declared permissions against privacy risk models and sensitive data families."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Sequence, Union

from data_leak_detector.core.config import AppConfig
from data_leak_detector.core.models import (
    Confidence,
    Finding,
    FindingCategory,
    ParsedAPKData,
    PermissionFinding,
    PermissionSummary,
    Severity,
)


logger = logging.getLogger(__name__)


class PermissionAnalyzer:
    """Audits requested Android permissions against transparent privacy and data leakage criteria.
    
    Principles:
    - Does NOT automatically label every dangerous Android permission a vulnerability.
    - Distinguishes:
      1. Sensitive permission
      2. Potentially excessive permission (heuristic)
      3. Permission associated with sensitive user data
      4. Custom/unknown permission
      5. Standard operational permission
    - Provides non-technical, human-readable explanations.
    - Calculates aggregate statistical summaries.
    """

    def __init__(self, metadata_path: Path | None = None) -> None:
        self.config = AppConfig()
        self.metadata_path = (
            Path(metadata_path).resolve()
            if metadata_path
            else self.config.resources_dir / "permission_metadata.json"
        )
        self._metadata: dict[str, Any] = {}
        self._families: dict[str, Any] = {}
        self._load_metadata()

    def _load_metadata(self) -> None:
        """Load external permission metadata JSON database."""
        if not self.metadata_path.exists():
            logger.warning(
                f"Permission metadata file not found at {self.metadata_path}. Using empty database."
            )
            return

        try:
            with open(self.metadata_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self._metadata = data.get("permissions", {})
                self._families = data.get("permission_families", {})
            logger.debug(f"Loaded {len(self._metadata)} permissions from metadata.")
        except Exception as e:
            logger.error(f"Failed to read permission metadata at {self.metadata_path}: {e}")

    def analyze(
        self, apk_input: Union[ParsedAPKData, Sequence[str]]
    ) -> PermissionSummary:
        """Analyze permissions extracted from target APK and return statistical summary.
        
        Args:
            apk_input: ParsedAPKData object or sequence of permission name strings.
            
        Returns:
            PermissionSummary with aggregate counts, findings, and sensitive families.
        """
        permission_names: list[str] = []
        if isinstance(apk_input, ParsedAPKData):
            permission_names = list(apk_input.permissions)
        elif isinstance(apk_input, (list, tuple, set)):
            permission_names = list(apk_input)

        findings: list[PermissionFinding] = []
        dangerous_count = 0
        normal_count = 0
        signature_count = 0
        unknown_custom_count = 0
        sensitive_data_count = 0
        sensitive_families: set[str] = set()

        for raw_perm in permission_names:
            perm_name = raw_perm.strip()
            if not perm_name:
                continue

            finding = self.classify_permission(perm_name)
            findings.append(finding)

            # Categorize protection levels for statistical breakdown
            prot_norm = finding.protection_level.lower()
            if "dangerous" in prot_norm:
                dangerous_count += 1
            elif "signature" in prot_norm:
                signature_count += 1
            elif prot_norm == "normal":
                normal_count += 1
            else:
                unknown_custom_count += 1

            if finding.is_sensitive_user_data:
                sensitive_data_count += 1

            if finding.family:
                sensitive_families.add(finding.family)

        # Sort findings by risk severity descending
        severity_rank = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        findings.sort(key=lambda f: severity_rank.get(f.risk_level, 5))

        return PermissionSummary(
            total_permissions=len(findings),
            dangerous_permissions=dangerous_count,
            normal_permissions=normal_count,
            signature_permissions=signature_count,
            unknown_custom_permissions=unknown_custom_count,
            sensitive_user_data_permissions=sensitive_data_count,
            findings=findings,
            sensitive_families=sorted(sensitive_families),
        )

    def classify_permission(self, perm_name: str) -> PermissionFinding:
        """Classify an individual permission into transparent risk models."""
        meta = self._metadata.get(perm_name)

        if meta:
            prot_level = meta.get("protection_level", "unknown")
            risk_level = Severity(meta.get("risk_level", Severity.LOW.value))
            desc = meta.get("description", "Standard Android permission.")
            user_desc = meta.get(
                "user_friendly_description",
                "Allows the application to access standard device features.",
            )
            family = meta.get("family")
            is_sensitive_data = bool(meta.get("is_sensitive_user_data", False))
            leak_implication = meta.get("leak_implications", "")

            # Determine transparent classification
            if is_sensitive_data:
                classification = "Permission associated with sensitive user data"
            elif "signature" in prot_level.lower():
                classification = "Sensitive permission"
            elif risk_level in (Severity.CRITICAL, Severity.HIGH):
                classification = "Sensitive permission"
            elif prot_level == "normal":
                classification = "Standard operational permission"
            else:
                classification = "Sensitive permission"

            # Check if heuristic warning is justified for high-privilege access
            is_heuristic = False
            reason = leak_implication or desc
            if risk_level in (Severity.CRITICAL, Severity.HIGH):
                is_heuristic = True
                classification = (
                    "Permission associated with sensitive user data"
                    if is_sensitive_data
                    else "Potentially excessive permission"
                )
                reason = (
                    f"Heuristic indicator: Application requests high-privilege capability ({desc}). "
                    "Static audit flags this permission for functional justification review."
                )

            return PermissionFinding(
                permission=perm_name,
                protection_level=prot_level,
                risk_level=risk_level,
                description=desc,
                reason=reason,
                source="manifest",
                confidence=Confidence.HIGH,
                classification=classification,
                user_friendly_description=user_desc,
                family=family,
                is_sensitive_user_data=is_sensitive_data,
                is_heuristic_warning=is_heuristic,
            )

        # Uncatalogued AOSP permission
        if perm_name.startswith("android.permission."):
            short_name = perm_name.replace("android.permission.", "")
            return PermissionFinding(
                permission=perm_name,
                protection_level="normal",
                risk_level=Severity.INFO,
                description=f"Standard Android platform permission ({short_name}).",
                reason="Standard Android operating system capability not catalogued as high-risk.",
                source="manifest",
                confidence=Confidence.MEDIUM,
                classification="Standard operational permission",
                user_friendly_description=f"Standard system feature permission: {short_name}.",
                family=None,
                is_sensitive_user_data=False,
                is_heuristic_warning=False,
            )

        # Custom or Unknown Third-Party Permission
        return PermissionFinding(
            permission=perm_name,
            protection_level="custom/unknown",
            risk_level=Severity.INFO,
            description="Custom or proprietary permission defined outside standard Android specifications.",
            reason="Heuristic assessment: Application defines or requests a proprietary non-standard permission.",
            source="manifest",
            confidence=Confidence.MEDIUM,
            classification="Custom/unknown permission",
            user_friendly_description=(
                f"Custom permission ({perm_name}). Defined by app developers or device manufacturers."
            ),
            family=None,
            is_sensitive_user_data=False,
            is_heuristic_warning=True,
        )

    def analyze_permissions(
        self, declared_permissions: list[str]
    ) -> tuple[list[PermissionFinding], list[Finding]]:
        """Backwards-compatible API returning (permission_findings, security_findings)."""
        summary = self.analyze(declared_permissions)
        security_findings: list[Finding] = []

        # Convert high-risk permissions into security findings where appropriate
        for p in summary.findings:
            if p.risk_level in (Severity.CRITICAL, Severity.HIGH):
                sec_finding = Finding(
                    rule_id=f"PERM-{p.permission.split('.')[-1]}",
                    title=f"Sensitive Permission Declared: {p.permission.split('.')[-1]}",
                    category=FindingCategory.PERMISSION,
                    severity=p.risk_level,
                    confidence=p.confidence,
                    description=p.description,
                    evidence=p.permission,
                    impact=p.reason,
                    remediation=(
                        "Verify whether this permission is strictly necessary for core functionality. "
                        "Follow the principle of least privilege."
                    ),
                    is_static_indicator=True,
                )
                security_findings.append(sec_finding)

        return summary.findings, security_findings


# British spelling alias
PermissionAnalyser = PermissionAnalyzer
