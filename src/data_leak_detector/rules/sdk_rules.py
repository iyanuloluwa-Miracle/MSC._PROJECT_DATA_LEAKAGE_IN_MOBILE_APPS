"""Rules identifying embedded third-party SDKs and SDK Permission Exposure.

Analyzes static package names, component declarations, DEX string pools, and decompiled classes
to detect third-party libraries across categories:
- analytics
- advertising
- crash reporting
- social
- payments
- location
- push notifications

Implements the 'SDK Permission Exposure' concept:
Evaluates combinations of detected third-party libraries and sensitive permissions
available to the host process. Findings represent potential exposure indicators
based exclusively on static evidence, never asserting that an SDK actually collected
or transmitted sensitive user data.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Sequence

from data_leak_detector.core.config import AppConfig
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


# ---------------------------------------------------------------------------
# Mapping of sensitive Android permissions to privacy families
# ---------------------------------------------------------------------------

PERMISSION_TO_FAMILY: dict[str, str] = {
    "android.permission.ACCESS_FINE_LOCATION": "location",
    "android.permission.ACCESS_COARSE_LOCATION": "location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "location",
    "android.permission.READ_CONTACTS": "contacts",
    "android.permission.WRITE_CONTACTS": "contacts",
    "android.permission.GET_ACCOUNTS": "contacts",
    "android.permission.CAMERA": "camera",
    "android.permission.RECORD_AUDIO": "microphone",
    "android.permission.READ_PHONE_STATE": "phone",
    "android.permission.READ_PHONE_NUMBERS": "phone",
    "android.permission.CALL_PHONE": "phone",
    "android.permission.READ_CALL_LOG": "call_logs",
    "android.permission.READ_SMS": "sms",
    "android.permission.RECEIVE_SMS": "sms",
    "android.permission.SEND_SMS": "sms",
    "android.permission.READ_CALENDAR": "calendar",
    "android.permission.WRITE_CALENDAR": "calendar",
    "android.permission.READ_EXTERNAL_STORAGE": "storage",
    "android.permission.WRITE_EXTERNAL_STORAGE": "storage",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "storage",
    "android.permission.POST_NOTIFICATIONS": "notifications",
    "android.permission.BLUETOOTH": "bluetooth_nearby",
    "android.permission.BLUETOOTH_SCAN": "bluetooth_nearby",
    "android.permission.BLUETOOTH_CONNECT": "bluetooth_nearby",
    "android.permission.USE_BIOMETRIC": "biometrics",
    "android.permission.USE_FINGERPRINT": "biometrics",
}

CATEGORY_DEFAULT_FAMILIES: dict[str, list[str]] = {
    "analytics": ["location", "phone", "contacts", "storage"],
    "advertising": ["location", "phone", "contacts", "camera", "storage", "microphone"],
    "social": ["contacts", "location", "camera", "microphone", "storage"],
    "location": ["location", "bluetooth_nearby"],
    "push notifications": ["location", "notifications"],
    "crash reporting": ["storage", "phone"],
    "payments": ["camera", "storage"],
}


def _load_sdk_catalog(custom_path: Path | None = None) -> list[dict[str, Any]]:
    """Load configurable SDK patterns from resources/sdk_patterns.json.
    
    Falls back to a curated default catalog if the file is unavailable.
    """
    config = AppConfig()
    patterns_file = custom_path if custom_path else config.resources_dir / "sdk_patterns.json"

    if patterns_file.exists():
        try:
            with open(patterns_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    if "sdk_definitions" in data and isinstance(data["sdk_definitions"], list):
                        return list(data["sdk_definitions"])
                    if "ad_and_analytics_sdks" in data and isinstance(data["ad_and_analytics_sdks"], list):
                        return list(data["ad_and_analytics_sdks"])
        except Exception as exc:
            logger.warning(
                f"Failed to read SDK patterns from {patterns_file}: {exc}. Using built-in catalog."
            )

    # Built-in fallback catalog
    return [
        {
            "id": "google_admob",
            "name": "Google AdMob",
            "category": "advertising",
            "package_pattern": r"com\.(?:google\.android\.gms\.ads|google\.ads)",
            "description": "Mobile advertising network and monetization platform.",
            "sensitive_families": ["location", "phone", "storage"],
        },
        {
            "id": "firebase_analytics",
            "name": "Firebase Analytics / Google Measurement",
            "category": "analytics",
            "package_pattern": r"com\.google\.android\.gms\.measurement",
            "description": "App usage telemetry, event tracking, and attribution platform.",
            "sensitive_families": ["location", "phone"],
        },
        {
            "id": "facebook_sdk",
            "name": "Meta / Facebook SDK & Audience Network",
            "category": "social",
            "package_pattern": r"com\.facebook\.(?:ads|appevents|login|share|bolts)",
            "description": "Social graph integration, single sign-on, and ad measurement.",
            "sensitive_families": ["location", "contacts", "camera", "storage"],
        },
        {
            "id": "crashlytics",
            "name": "Firebase Crashlytics",
            "category": "crash reporting",
            "package_pattern": r"com\.(?:google\.firebase\.crashlytics|crashlytics)",
            "description": "Real-time crash analysis and diagnostic telemetry reporting.",
            "sensitive_families": ["storage", "phone"],
        },
        {
            "id": "sentry",
            "name": "Sentry SDK",
            "category": "crash reporting",
            "package_pattern": r"io\.sentry",
            "description": "Application monitoring and crash error logging.",
            "sensitive_families": ["storage"],
        },
        {
            "id": "appsflyer",
            "name": "AppsFlyer",
            "category": "analytics",
            "package_pattern": r"com\.appsflyer",
            "description": "Mobile attribution, deep linking, and marketing measurement.",
            "sensitive_families": ["location", "phone"],
        },
        {
            "id": "adjust",
            "name": "Adjust SDK",
            "category": "analytics",
            "package_pattern": r"com\.adjust\.sdk",
            "description": "Mobile attribution and app measurement telemetry.",
            "sensitive_families": ["location", "phone"],
        },
        {
            "id": "unity_ads",
            "name": "Unity Ads",
            "category": "advertising",
            "package_pattern": r"com\.unity3d\.(?:services\.ads|ads)",
            "description": "In-game video and interstitial advertising network.",
            "sensitive_families": ["storage", "location"],
        },
        {
            "id": "stripe",
            "name": "Stripe Android SDK",
            "category": "payments",
            "package_pattern": r"com\.stripe\.android",
            "description": "Credit card tokenization and checkout handling.",
            "sensitive_families": ["camera", "storage"],
        },
        {
            "id": "onesignal",
            "name": "OneSignal",
            "category": "push notifications",
            "package_pattern": r"com\.onesignal",
            "description": "Push notification delivery and engagement tracking.",
            "sensitive_families": ["location", "notifications"],
        },
        {
            "id": "mapbox",
            "name": "Mapbox Maps & Location SDK",
            "category": "location",
            "package_pattern": r"com\.mapbox",
            "description": "Vector maps rendering, navigation, and location telemetry.",
            "sensitive_families": ["location", "storage"],
        },
    ]


def _extract_declared_permissions(context: Any) -> list[str]:
    """Helper extracting all declared permissions from analysis context."""
    if isinstance(context, ParsedAPKData):
        return list(context.permissions)
    if isinstance(context, dict):
        if "permissions" in context and isinstance(context["permissions"], (list, tuple, set)):
            return list(context["permissions"])
        if "parsed_apk" in context and isinstance(context["parsed_apk"], ParsedAPKData):
            return list(context["parsed_apk"].permissions)
        if "manifest_info" in context:
            m = context["manifest_info"]
            if isinstance(m, ManifestData):
                return []
    return []


def _extract_sdk_candidates(context: Any) -> list[tuple[str, str]]:
    """Extract candidate strings, package names, component names, and file paths."""
    candidates: list[tuple[str, str]] = []

    if isinstance(context, ParsedAPKData):
        for comp in context.activities:
            candidates.append(("Activity", comp))
        for comp in context.services:
            candidates.append(("Service", comp))
        for comp in context.receivers:
            candidates.append(("Receiver", comp))
        for comp in context.providers:
            candidates.append(("Provider", comp))
        for lib in context.libraries:
            candidates.append(("Library", lib))
        if context.manifest_info and context.manifest_info.raw_xml:
            candidates.append(("AndroidManifest.xml", context.manifest_info.raw_xml))

    elif isinstance(context, dict):
        if "classes" in context and isinstance(context["classes"], (list, tuple, set)):
            for cls_name in context["classes"]:
                candidates.append(("Class", str(cls_name)))

        if "packages" in context and isinstance(context["packages"], (list, tuple, set)):
            for pkg in context["packages"]:
                candidates.append(("Package", str(pkg)))

        for comp_key in ("activities", "services", "receivers", "providers", "libraries"):
            if comp_key in context and isinstance(context[comp_key], (list, tuple, set)):
                for comp in context[comp_key]:
                    candidates.append((comp_key.capitalize(), str(comp)))

        if "strings" in context:
            str_data = context["strings"]
            if isinstance(str_data, (list, tuple, set)):
                candidates.append(("DEX:StringPool", "\n".join(str(s) for s in str_data)))
            elif isinstance(str_data, str):
                candidates.append(("DEX:StringPool", str_data))

        if "files" in context and isinstance(context["files"], dict):
            for filename, content in context["files"].items():
                candidates.append(("FilePath", str(filename)))
                if isinstance(content, str):
                    candidates.append((str(filename), content))

        if "parsed_apk" in context and isinstance(context["parsed_apk"], ParsedAPKData):
            candidates.extend(_extract_sdk_candidates(context["parsed_apk"]))

    elif isinstance(context, str):
        candidates.append(("TextContent", context))

    return candidates


# ---------------------------------------------------------------------------
# SDK Rules Implementation
# ---------------------------------------------------------------------------

class ThirdPartySdkIdentificationRule(BaseRule):
    """Identifies embedded third-party SDKs and classifies them into functional categories.
    
    Generates informational findings rather than malicious labels.
    """

    rule_id = "SDK-001"
    title = "Third-Party SDK Identified"
    category = FindingCategory.TRACKING_SDK
    default_severity = Severity.INFO
    description = (
        "Static inspection identified the presence of a third-party SDK. "
        "Third-party libraries execute within the host application's address space "
        "and share its runtime permissions and sandbox environment."
    )
    owasp_reference = "OWASP-M3: Insecure Communication"

    def __init__(self, sdk_catalog: list[dict[str, Any]] | None = None) -> None:
        super().__init__()
        self._catalog = sdk_catalog if sdk_catalog is not None else _load_sdk_catalog()

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen_sdks: set[str] = set()
        candidates = _extract_sdk_candidates(context)

        for sdk in self._catalog:
            sdk_id = sdk.get("id") or sdk.get("name", "unknown_sdk")
            sdk_name = sdk.get("name", "Unknown SDK")
            category = sdk.get("category", "general")
            pattern_str = sdk.get("package_pattern")

            if not pattern_str or sdk_id in seen_sdks:
                continue

            try:
                pattern = re.compile(pattern_str, re.IGNORECASE)
            except Exception as e:
                logger.warning(f"Invalid regex for SDK {sdk_name}: {e}")
                continue

            for location_type, candidate_text in candidates:
                match = pattern.search(candidate_text)
                if match:
                    seen_sdks.add(sdk_id)
                    matched_snippet = match.group(0)
                    findings.append(
                        self.create_finding(
                            title=f"Third-Party SDK Detected: {sdk_name} ({category})",
                            severity=Severity.INFO,
                            confidence=Confidence.HIGH,
                            description=(
                                f"Static analysis identified the presence of third-party SDK '{sdk_name}' "
                                f"belonging to category '{category}'. Detected via static package/class pattern "
                                f"'{matched_snippet}' in {location_type}. Third-party libraries run in the host process "
                                "and inherit all permissions granted to the host application."
                            ),
                            evidence=f"SDK: {sdk_name} (Category: {category}, Matched: {matched_snippet} in {location_type})",
                            location=location_type,
                            impact=(
                                "Third-party SDK code executes with the host application's identity and privileges. "
                                "Its data handling practices should be reviewed for privacy policy compliance."
                            ),
                            remediation=(
                                "Audit third-party SDK integration against the application's published privacy policy. "
                                "Ensure data collection parameters are appropriately configured and user consent is respected."
                            ),
                        )
                    )
                    break

        return findings


# Backwards compatibility alias
ThirdPartyTrackerRule = ThirdPartySdkIdentificationRule


class SdkPermissionExposureRule(BaseRule):
    """Detects SDK Permission Exposure where an SDK has access to sensitive host permissions.
    
    Produces potential exposure indicators without asserting that runtime collection occurred.
    """

    rule_id = "SDK-002"
    title = "SDK Permission Exposure Indicator"
    category = FindingCategory.TRACKING_SDK
    default_severity = Severity.MEDIUM
    description = (
        "Static analysis identified a combination of an embedded third-party SDK and declared sensitive host permissions. "
        "Because third-party libraries inherit all permissions granted to the host process, this represents a potential "
        "SDK Permission Exposure. Static analysis alone cannot determine whether the SDK actually accesses or transmits "
        "sensitive data at runtime."
    )
    owasp_reference = "OWASP-M3: Insecure Communication"

    def __init__(self, sdk_catalog: list[dict[str, Any]] | None = None) -> None:
        super().__init__()
        self._catalog = sdk_catalog if sdk_catalog is not None else _load_sdk_catalog()

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        candidates = _extract_sdk_candidates(context)
        declared_permissions = _extract_declared_permissions(context)

        if not declared_permissions:
            return []

        # Map declared permissions to sensitive families
        active_families: dict[str, list[str]] = {}
        for perm in declared_permissions:
            perm_clean = perm.strip()
            family = PERMISSION_TO_FAMILY.get(perm_clean)
            if family:
                active_families.setdefault(family, []).append(perm_clean)

        if not active_families:
            return []

        seen_exposures: set[tuple[str, str]] = set()

        for sdk in self._catalog:
            sdk_id = sdk.get("id") or sdk.get("name", "unknown_sdk")
            sdk_name = sdk.get("name", "Unknown SDK")
            category = sdk.get("category", "general")
            pattern_str = sdk.get("package_pattern")

            if not pattern_str:
                continue

            try:
                pattern = re.compile(pattern_str, re.IGNORECASE)
            except Exception:
                continue

            # Verify if SDK is present
            sdk_matched = False
            matched_location = "Host Application"
            for location_type, candidate_text in candidates:
                if pattern.search(candidate_text):
                    sdk_matched = True
                    matched_location = location_type
                    break

            if not sdk_matched:
                continue

            # Determine relevant sensitive families for this SDK
            target_families = sdk.get("sensitive_families")
            if not target_families:
                target_families = CATEGORY_DEFAULT_FAMILIES.get(category, [])

            # Check overlap with host application's active sensitive families
            for family in target_families:
                if family in active_families:
                    exposure_key = (sdk_id, family)
                    if exposure_key in seen_exposures:
                        continue
                    seen_exposures.add(exposure_key)

                    matching_perms = active_families[family]
                    perm_str = ", ".join(sorted(matching_perms))
                    family_display = family.replace("_", " ").title()

                    findings.append(
                        self.create_finding(
                            title=f"SDK Permission Exposure: {sdk_name} with {family_display} Access",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            description=(
                                f"The host application requests sensitive permission(s) ({perm_str}) while integrating "
                                f"the third-party '{sdk_name}' ({category}) SDK. Because embedded third-party libraries "
                                "inherit all permissions granted to the host process, this represents an SDK Permission Exposure. "
                                "Static analysis alone cannot determine whether the SDK actually accesses, collects, or "
                                "transmits this sensitive data at runtime."
                            ),
                            evidence=(
                                f"SDK '{sdk_name}' ({category}) detected in {matched_location} + "
                                f"Host permissions: [{perm_str}]"
                            ),
                            location=f"{matched_location}:<uses-permission>",
                            impact=(
                                f"Third-party '{category}' SDK possesses the capability to query sensitive {family_display} "
                                "data via host privileges without requiring separate runtime prompts."
                            ),
                            remediation=(
                                f"Review SDK configuration documentation to restrict access to {family_display} APIs "
                                "(e.g., disabling automatic location forwarding or device identifier logging). "
                                "Remove sensitive permissions from the host manifest if they are not required for core features."
                            ),
                        )
                    )

        return findings


ALL_SDK_RULES: list[type[BaseRule]] = [
    ThirdPartySdkIdentificationRule,
    SdkPermissionExposureRule,
]
