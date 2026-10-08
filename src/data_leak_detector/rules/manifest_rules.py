"""Static analysis security rules evaluating AndroidManifest.xml and component configurations."""

from __future__ import annotations

import logging
from typing import Any

from data_leak_detector.core.models import (
    Confidence,
    FindingCategory,
    ManifestData,
    ParsedAPKData,
    SecurityFinding,
    Severity,
)
from data_leak_detector.rules.base import BaseRule


logger = logging.getLogger(__name__)


def _extract_manifest_and_metadata(
    context: dict[str, Any] | ParsedAPKData | Any,
) -> tuple[ManifestData | None, Any | None, list[str]]:
    """Helper extracting ManifestData, ApplicationMetadata, and permissions from context."""
    if isinstance(context, ParsedAPKData):
        return context.manifest_info, context.metadata, list(context.permissions)

    if isinstance(context, dict):
        manifest = context.get("manifest_info")
        if isinstance(manifest, dict):
            manifest = ManifestData.from_dict(manifest)
        meta = context.get("metadata")
        perms = list(context.get("permissions", []))
        return manifest, meta, perms

    return None, None, []


def _get_target_sdk(metadata: Any, manifest: ManifestData | None) -> int | None:
    """Helper resolving integer targetSdkVersion."""
    for source in [getattr(metadata, "target_sdk", None), getattr(manifest, "target_sdk", None)]:
        if source is not None:
            try:
                return int(str(source).strip())
            except (ValueError, TypeError):
                pass
    return None


class DebuggableRule(BaseRule):
    """Checks if android:debuggable is enabled in production."""

    rule_id = "MAN-001"
    title = "Application Marked Debuggable"
    category = FindingCategory.MANIFEST_MISCONFIG
    default_severity = Severity.HIGH
    description = (
        "Evaluates whether android:debuggable is explicitly enabled in AndroidManifest.xml. "
        "Debuggable builds expose memory and internal state to debugger attach."
    )
    owasp_reference = "OWASP-M1: Improper Platform Usage"

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        manifest, _, _ = _extract_manifest_and_metadata(context)
        if not manifest or manifest.debuggable is not True:
            return []

        return [
            self.create_finding(
                title=self.title,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="The application manifest explicitly declares 'android:debuggable=\"true\"'.",
                evidence="android:debuggable=\"true\" in <application>",
                location="AndroidManifest.xml:<application>",
                impact=(
                    "Enables JDWP process debugging. Any user or attacker with adb access can attach a "
                    "debugger, inspect heap memory, extract stored secrets, and execute arbitrary code."
                ),
                remediation=(
                    "Ensure 'android:debuggable' is omitted or set to 'false' in all release production builds."
                ),
            )
        ]


class AllowBackupRule(BaseRule):
    """Checks if android:allowBackup is enabled, posing local data extraction risk."""

    rule_id = "MAN-002"
    title = "Application Data Backup Enabled"
    category = FindingCategory.MANIFEST_MISCONFIG
    default_severity = Severity.MEDIUM
    description = (
        "Evaluates android:allowBackup configuration. When enabled, application data can be extracted "
        "via adb backup without requiring device root."
    )
    owasp_reference = "OWASP-M2: Insecure Data Storage"

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        manifest, meta, _ = _extract_manifest_and_metadata(context)
        if not manifest:
            return []

        # If allow_backup is explicitly False, it is safe
        if manifest.allow_backup is False:
            return []

        target_sdk = _get_target_sdk(meta, manifest)
        evidence = (
            "android:allowBackup=\"true\""
            if manifest.allow_backup is True
            else "android:allowBackup not specified (defaults to true)"
        )

        return [
            self.create_finding(
                title=self.title,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description=(
                    f"Application allows data backup via ADB ({evidence}). Target SDK: {target_sdk or 'unknown'}."
                ),
                evidence=f"{evidence} in <application>",
                location="AndroidManifest.xml:<application>",
                impact=(
                    "Private databases, shared preferences, and internal files can be copied off the device "
                    "using 'adb backup' without root privileges."
                ),
                remediation=(
                    "Set 'android:allowBackup=\"false\"' in AndroidManifest.xml, or configure restrictive "
                    "'android:dataExtractionRules' (API 31+) / 'android:fullBackupContent' XML rules."
                ),
            )
        ]


class CleartextTrafficPermittedRule(BaseRule):
    """Detects whether unencrypted cleartext HTTP traffic is explicitly permitted or allowed by default."""

    rule_id = "MAN-003"
    title = "Cleartext HTTP Traffic Permitted"
    category = FindingCategory.NETWORK_INDICATOR
    default_severity = Severity.HIGH
    description = (
        "Checks whether android:usesCleartextTraffic is enabled or defaulted to true based on target SDK."
    )
    owasp_reference = "OWASP-M3: Insecure Communication"

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        manifest, meta, _ = _extract_manifest_and_metadata(context)
        if not manifest:
            return []

        target_sdk = _get_target_sdk(meta, manifest)

        if manifest.uses_cleartext_traffic is True:
            return [
                self.create_finding(
                    title="Cleartext Traffic Explicitly Permitted",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description="Manifest explicitly permits cleartext HTTP network traffic.",
                    evidence="android:usesCleartextTraffic=\"true\" in <application>",
                    location="AndroidManifest.xml:<application>",
                    impact=(
                        "Application network requests may transmit plaintext HTTP, allowing on-path network "
                        "eavesdroppers to inspect credentials and sensitive user data."
                    ),
                    remediation=(
                        "Set 'android:usesCleartextTraffic=\"false\"' and enforce HTTPS via Network Security Config."
                    ),
                )
            ]

        # In Android, apps targeting API < 28 allow cleartext by default
        if manifest.uses_cleartext_traffic is None and target_sdk is not None and target_sdk < 28:
            return [
                self.create_finding(
                    title="Cleartext Traffic Allowed by Default (Legacy Target SDK)",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    description=f"App targets legacy SDK {target_sdk} (< 28) where cleartext HTTP is allowed by default.",
                    evidence=f"targetSdkVersion={target_sdk} with unconfigured usesCleartextTraffic",
                    location="AndroidManifest.xml:<application>",
                    impact="Legacy target SDK defaults permit unencrypted HTTP communication.",
                    remediation="Upgrade targetSdkVersion to 28+ and enforce strict HTTPS transport.",
                )
            ]

        return []


class NetworkSecurityConfigRule(BaseRule):
    """Evaluates whether the application defines a custom networkSecurityConfig."""

    rule_id = "MAN-004"
    title = "Missing Custom Network Security Configuration"
    category = FindingCategory.NETWORK_INDICATOR
    default_severity = Severity.MEDIUM
    description = (
        "Checks whether the application specifies an android:networkSecurityConfig attribute to customize TLS policies."
    )
    owasp_reference = "OWASP-M3: Insecure Communication"

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        manifest, meta, _ = _extract_manifest_and_metadata(context)
        if not manifest:
            return []

        target_sdk = _get_target_sdk(meta, manifest)
        # NetworkSecurityConfig is standard starting from API 24
        if target_sdk is not None and target_sdk >= 24 and not manifest.network_security_config:
            return [
                self.create_finding(
                    title=self.title,
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    description="The application does not define an android:networkSecurityConfig resource.",
                    evidence="Missing 'android:networkSecurityConfig' attribute in <application>",
                    location="AndroidManifest.xml:<application>",
                    impact=(
                        "Lacks granular domain-specific TLS rules, certificate pinning, or cleartext restrictions."
                    ),
                    remediation=(
                        "Add an 'android:networkSecurityConfig=\"@xml/network_security_config\"' file to "
                        "enforce strict TLS policies and pinning."
                    ),
                )
            ]

        return []


class ExportedActivityRule(BaseRule):
    """Detects exported activities lacking permission protection that are not the main launcher."""

    rule_id = "MAN-005"
    title = "Exported Activity Without Permission Protection"
    category = FindingCategory.MANIFEST_MISCONFIG
    default_severity = Severity.MEDIUM
    description = (
        "Identifies activities declared as exported without requiring an access permission, excluding the launcher activity."
    )
    owasp_reference = "OWASP-M1: Improper Platform Usage"

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        manifest, _, _ = _extract_manifest_and_metadata(context)
        if not manifest:
            return []

        findings: list[SecurityFinding] = []
        for comp in manifest.components:
            if comp.component_type == "activity" and comp.exported:
                if comp.is_main_launcher:
                    continue  # Main launcher must be exported
                if not comp.permission:
                    findings.append(
                        self.create_finding(
                            title=f"Exported Activity Unprotected: {comp.name.split('.')[-1]}",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            description=f"Activity '{comp.name}' is exported without an access permission.",
                            evidence=f"activity android:name=\"{comp.name}\" android:exported=\"true\" (no permission)",
                            location=f"AndroidManifest.xml:<activity name=\"{comp.name}\">",
                            impact=(
                                "Any external application on the device can launch this activity directly, "
                                "potentially bypassing authentication flows or accessing restricted UI."
                            ),
                            remediation=(
                                "Set 'android:exported=\"false\"' if internal, or declare an 'android:permission' attribute."
                            ),
                        )
                    )
        return findings


class ExportedServiceRule(BaseRule):
    """Detects background services exposed without permission restrictions."""

    rule_id = "MAN-006"
    title = "Exported Service Without Permission Protection"
    category = FindingCategory.MANIFEST_MISCONFIG
    default_severity = Severity.HIGH
    description = (
        "Identifies services exported to third-party applications without permission requirements."
    )
    owasp_reference = "OWASP-M1: Improper Platform Usage"

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        manifest, _, _ = _extract_manifest_and_metadata(context)
        if not manifest:
            return []

        findings: list[SecurityFinding] = []
        for comp in manifest.components:
            if comp.component_type == "service" and comp.exported and not comp.permission:
                findings.append(
                    self.create_finding(
                        title=f"Exported Service Unprotected: {comp.name.split('.')[-1]}",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=f"Service '{comp.name}' is exported without an access permission.",
                        evidence=f"service android:name=\"{comp.name}\" android:exported=\"true\" (no permission)",
                        location=f"AndroidManifest.xml:<service name=\"{comp.name}\">",
                        impact=(
                            "Any external application on the device can start or bind to this service, "
                            "triggering background operations or accessing IPC endpoints."
                        ),
                        remediation=(
                            "Set 'android:exported=\"false\"' or protect the service with a signature-level permission."
                        ),
                    )
                )
        return findings


class ExportedReceiverRule(BaseRule):
    """Detects broadcast receivers exposed to third-party apps without permission restrictions."""

    rule_id = "MAN-007"
    title = "Exported Broadcast Receiver Without Permission Protection"
    category = FindingCategory.MANIFEST_MISCONFIG
    default_severity = Severity.HIGH
    description = (
        "Identifies broadcast receivers declared as exported without requiring an access permission."
    )
    owasp_reference = "OWASP-M1: Improper Platform Usage"

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        manifest, _, _ = _extract_manifest_and_metadata(context)
        if not manifest:
            return []

        findings: list[SecurityFinding] = []
        for comp in manifest.components:
            if comp.component_type == "receiver" and comp.exported and not comp.permission:
                findings.append(
                    self.create_finding(
                        title=f"Exported Receiver Unprotected: {comp.name.split('.')[-1]}",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=f"Broadcast receiver '{comp.name}' is exported without an access permission.",
                        evidence=f"receiver android:name=\"{comp.name}\" android:exported=\"true\" (no permission)",
                        location=f"AndroidManifest.xml:<receiver name=\"{comp.name}\">",
                        impact=(
                            "External applications can broadcast spoofed intents to this receiver, "
                            "potentially inducing unauthorized state changes or data processing."
                        ),
                        remediation=(
                            "Set 'android:exported=\"false\"' or declare an 'android:permission' requirement."
                        ),
                    )
                )
        return findings


class ExportedProviderRule(BaseRule):
    """Detects content providers exposed without read/write permission protections."""

    rule_id = "MAN-008"
    title = "Exported Content Provider Without Permission Protection"
    category = FindingCategory.MANIFEST_MISCONFIG
    default_severity = Severity.CRITICAL
    description = (
        "Identifies content providers exposed to arbitrary applications without read or write permissions."
    )
    owasp_reference = "OWASP-M2: Insecure Data Storage"

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        manifest, _, _ = _extract_manifest_and_metadata(context)
        if not manifest:
            return []

        findings: list[SecurityFinding] = []
        for comp in manifest.components:
            if comp.component_type == "provider" and comp.exported:
                has_protection = bool(comp.permission or comp.read_permission or comp.write_permission)
                if not has_protection:
                    findings.append(
                        self.create_finding(
                            title=f"Exported Content Provider Unprotected: {comp.name.split('.')[-1]}",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            description=f"Content provider '{comp.name}' is exported without read or write permissions.",
                            evidence=f"provider android:name=\"{comp.name}\" android:exported=\"true\" (unprotected)",
                            location=f"AndroidManifest.xml:<provider name=\"{comp.name}\">",
                            impact=(
                                "Any external application on the device can query, insert, update, or delete records "
                                "managed by this content provider, posing direct data leakage and tampering risks."
                            ),
                            remediation=(
                                "Set 'android:exported=\"false\"' or specify 'android:readPermission' and "
                                "'android:writePermission' with signature-level protection."
                            ),
                        )
                    )
        return findings


class SensitiveComponentExposureRule(BaseRule):
    """Detects exported components that register sensitive action keywords without access controls."""

    rule_id = "MAN-009"
    title = "Sensitive Action Exposed on Unprotected Component"
    category = FindingCategory.MANIFEST_MISCONFIG
    default_severity = Severity.HIGH
    description = (
        "Identifies exported components handling sensitive intent actions (auth, payment, backup, sync) without permissions."
    )
    owasp_reference = "OWASP-M1: Improper Platform Usage"

    SENSITIVE_KEYWORDS = (
        "auth", "login", "admin", "payment", "backup", "sync",
        "upload", "export", "token", "credential", "reset"
    )

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        manifest, _, _ = _extract_manifest_and_metadata(context)
        if not manifest:
            return []

        findings: list[SecurityFinding] = []
        for comp in manifest.components:
            if comp.exported and not comp.permission:
                matched_actions = [
                    action for action in comp.actions
                    if any(kw in action.lower() for kw in self.SENSITIVE_KEYWORDS)
                ]
                if matched_actions:
                    actions_summary = ", ".join(matched_actions[:3])
                    findings.append(
                        self.create_finding(
                            title=f"Sensitive Action Exposed: {comp.name.split('.')[-1]}",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            description=(
                                f"Component '{comp.name}' handles sensitive action(s) ({actions_summary}) "
                                "without required permission protection."
                            ),
                            evidence=f"Action(s): {actions_summary} on exported component '{comp.name}'",
                            location=f"AndroidManifest.xml:<{comp.component_type} name=\"{comp.name}\">",
                            impact=(
                                "External callers can invoke sensitive application flows directly without authentication."
                            ),
                            remediation=(
                                "Restrict this component using an explicit signature permission or set android:exported=\"false\"."
                            ),
                        )
                    )
        return findings


class ExcessivePermissionCombinationRule(BaseRule):
    """Detects combinations of sensitive capability permissions combined with network transmission access."""

    rule_id = "MAN-010"
    title = "Sensitive Permission Combination (Exfiltration Vector Indicator)"
    category = FindingCategory.PERMISSION
    default_severity = Severity.HIGH
    description = (
        "Evaluates whether sensitive device capabilities (location, contacts, SMS, phone state) are declared "
        "concurrently with Internet access, representing a static indicator of potential data exfiltration risk."
    )
    owasp_reference = "OWASP-M1: Improper Platform Usage"

    SENSITIVE_PAIRS = [
        (
            {"android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION"},
            "Geolocation Exfiltration Indicator",
            "Combines precise geographic location access with Internet communication.",
        ),
        (
            {"android.permission.READ_PHONE_STATE", "android.permission.READ_PRIVILEGED_PHONE_STATE"},
            "Device Identifier Tracking Indicator",
            "Combines phone hardware/cellular state access with Internet communication.",
        ),
        (
            {"android.permission.READ_CONTACTS", "android.permission.GET_ACCOUNTS"},
            "Contact List / Account Exfiltration Indicator",
            "Combines personal address book access with Internet communication.",
        ),
        (
            {"android.permission.READ_SMS", "android.permission.RECEIVE_SMS"},
            "SMS / 2FA Token Exfiltration Indicator",
            "Combines private SMS/OTP interception with Internet communication.",
        ),
        (
            {"android.permission.RECORD_AUDIO", "android.permission.CAMERA"},
            "Surveillance / Media Exfiltration Indicator",
            "Combines audio/camera recording access with Internet communication.",
        ),
    ]

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        _, _, perms = _extract_manifest_and_metadata(context)
        perm_set = set(perms)

        if "android.permission.INTERNET" not in perm_set:
            return []

        findings: list[SecurityFinding] = []
        for targets, vector_title, vector_desc in self.SENSITIVE_PAIRS:
            matched = perm_set.intersection(targets)
            if matched:
                matched_str = ", ".join(sorted(matched))
                findings.append(
                    self.create_finding(
                        title=f"{vector_title}: {matched_str.split('.')[-1]}",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=(
                            f"Static combination indicator: {vector_desc} Declared permissions: {matched_str} + INTERNET."
                        ),
                        evidence=f"INTERNET + {matched_str}",
                        location="AndroidManifest.xml:<uses-permission>",
                        impact=(
                            "Static risk indicator: The app possesses both the capability to access sensitive user "
                            "data and the capability to transmit data off-device. (Static indicator, not runtime proof)."
                        ),
                        remediation=(
                            "Verify if both capabilities are strictly required by the application's core feature set. "
                            "Follow the principle of least privilege."
                        ),
                    )
                )

        return findings


ALL_MANIFEST_RULES: list[type[BaseRule]] = [
    DebuggableRule,
    AllowBackupRule,
    CleartextTrafficPermittedRule,
    NetworkSecurityConfigRule,
    ExportedActivityRule,
    ExportedServiceRule,
    ExportedReceiverRule,
    ExportedProviderRule,
    SensitiveComponentExposureRule,
    ExcessivePermissionCombinationRule,
]
