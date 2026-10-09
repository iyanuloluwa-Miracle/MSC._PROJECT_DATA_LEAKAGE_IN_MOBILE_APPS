"""Static analysis rules identifying network communication indicators and unencrypted endpoints.

Analyzes static source code, manifest configurations, resource XMLs, and string pools.
This module strictly performs static inspection; it does not perform runtime packet
inspection or active network monitoring.

Every finding clearly indicates that it is derived exclusively from static evidence.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urlparse

from data_leak_detector.core.config import AppConfig
from data_leak_detector.core.models import (
    ApplicationMetadata,
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
# Suppression Lists & Constants
# ---------------------------------------------------------------------------

# Standard XML schema and namespace domains that are identifiers rather than actual network targets
SCHEMA_DOMAINS: set[str] = {
    "schemas.android.com",
    "www.w3.org",
    "w3.org",
    "apache.org",
    "www.apache.org",
    "xml.org",
    "json-schema.org",
    "schemas.xmlsoap.org",
    "java.sun.com",
    "xmlns.jcp.org",
    "oasis-open.org",
}

SCHEMA_PATH_SUBSTRINGS: tuple[str, ...] = (
    "/apk/res/android",
    "/apk/res-auto",
    "/apk/res/",
    "/apk/distribution",
    "/tools",
    "/xmlns",
)

# Loopback, internal, and test domain hostnames/IPs to suppress from external finding alerts
LOCALHOST_AND_TEST_HOSTS: set[str] = {
    "localhost",
    "127.0.0.1",
    "10.0.2.2",  # Android emulator default host loopback
    "0.0.0.0",
    "::1",
    "example.com",
    "example.org",
    "example.net",
    "sample.com",
    "test.com",
    "placeholder.com",
}

TEST_DOMAIN_SUFFIXES: tuple[str, ...] = (
    ".localhost",
    ".test",
    ".example",
    ".invalid",
    ".local",
)

# Standard Android platform / Google OS domains excluded from generic third-party finding noise
PLATFORM_DOMAINS: set[str] = {
    "android.com",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "play.google.com",
    "android.googlesource.com",
}

# Regex matching candidate HTTP/HTTPS URLs
URL_PATTERN = re.compile(
    r"\bhttps?://[a-zA-Z0-9.-]+(?::[0-9]+)?(?:/[^\s\"'<>`\[\]{}|\\^]*)?",
    re.IGNORECASE,
)


def _clean_url(raw: str) -> str:
    """Trim trailing punctuation and delimiter characters from static URL strings."""
    return raw.rstrip(".,;:)\"'>`];{}")


def _is_schema_or_namespace(url: str, hostname: str) -> bool:
    """Determine whether a URL is a static XML schema or namespace definition."""
    host = hostname.lower()
    if host in SCHEMA_DOMAINS or any(host.endswith("." + d) for d in SCHEMA_DOMAINS):
        return True
    url_lower = url.lower()
    return any(sub in url_lower for sub in SCHEMA_PATH_SUBSTRINGS)


def _is_localhost_or_test_host(hostname: str) -> bool:
    """Determine whether a hostname is loopback, local emulator, or reserved test domain."""
    host = hostname.lower()
    if host in LOCALHOST_AND_TEST_HOSTS:
        return True
    return any(host.endswith(suffix) for suffix in TEST_DOMAIN_SUFFIXES)


def _extract_text_targets(context: Any) -> list[tuple[str, str]]:
    """Helper extracting (source_location, text_content) pairs from analysis context."""
    targets: list[tuple[str, str]] = []

    if isinstance(context, ParsedAPKData):
        if context.manifest_info and context.manifest_info.raw_xml:
            targets.append(("AndroidManifest.xml", context.manifest_info.raw_xml))

    elif isinstance(context, dict):
        # Strings pool
        if "strings" in context:
            str_data = context["strings"]
            if isinstance(str_data, (list, set, tuple)):
                targets.append(("DEX:StringPool", "\n".join(str(s) for s in str_data)))
            elif isinstance(str_data, str):
                targets.append(("DEX:StringPool", str_data))

        # Files or decompiled content
        if "files" in context and isinstance(context["files"], dict):
            for filename, content in context["files"].items():
                if isinstance(content, str):
                    targets.append((str(filename), content))

        # Manifest info
        manifest = context.get("manifest_info")
        if isinstance(manifest, dict) and manifest.get("raw_xml"):
            targets.append(("AndroidManifest.xml", str(manifest["raw_xml"])))
        elif isinstance(manifest, ManifestData) and manifest.raw_xml:
            targets.append(("AndroidManifest.xml", manifest.raw_xml))

        # Network security config or resource XMLs
        if "network_security_config_xml" in context and isinstance(
            context["network_security_config_xml"], str
        ):
            targets.append(
                ("res/xml/network_security_config.xml", context["network_security_config_xml"])
            )

        # Generic raw content
        if "text_content" in context and isinstance(context["text_content"], str):
            targets.append(("TextContent", context["text_content"]))

    elif isinstance(context, str):
        targets.append(("TextContent", context))

    return targets


def _load_tracking_catalog() -> list[dict[str, str]]:
    """Load known tracking/advertising domains from resources/tracking_patterns.json.
    
    Falls back to a curated catalog if the resource file cannot be read.
    """
    config = AppConfig()
    patterns_file = config.resources_dir / "tracking_patterns.json"

    if patterns_file.exists():
        try:
            with open(patterns_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict) and "tracking_domains" in data:
                    return list(data["tracking_domains"])
        except Exception as exc:
            logger.warning(
                f"Failed to read tracking catalog from {patterns_file}: {exc}. Using built-in catalog."
            )

    # Built-in curated catalog fallback
    return [
        {"domain": "google-analytics.com", "name": "Google Analytics", "category": "Analytics"},
        {"domain": "googletagmanager.com", "name": "Google Tag Manager", "category": "Analytics"},
        {"domain": "app-measurement.com", "name": "Firebase App Measurement", "category": "Analytics"},
        {"domain": "crashlytics.com", "name": "Crashlytics", "category": "Crash Reporting"},
        {"domain": "flurry.com", "name": "Yahoo Flurry Analytics", "category": "Analytics"},
        {"domain": "appsflyer.com", "name": "AppsFlyer", "category": "Attribution"},
        {"domain": "adjust.com", "name": "Adjust", "category": "Attribution"},
        {"domain": "branch.io", "name": "Branch Metrics", "category": "Attribution"},
        {"domain": "amplitude.com", "name": "Amplitude", "category": "Product Analytics"},
        {"domain": "mixpanel.com", "name": "Mixpanel", "category": "Product Analytics"},
        {"domain": "doubleclick.net", "name": "Google DoubleClick", "category": "Advertising"},
        {"domain": "admob.com", "name": "Google AdMob", "category": "Advertising"},
        {"domain": "scorecardresearch.com", "name": "ScorecardResearch", "category": "Tracking"},
        {"domain": "kochava.com", "name": "Kochava", "category": "Attribution"},
        {"domain": "onesignal.com", "name": "OneSignal", "category": "Push Telemetry"},
        {"domain": "facebook.com/tr", "name": "Meta Pixel Tracking", "category": "Advertising Tracking"},
        {"domain": "graph.facebook.com", "name": "Facebook Graph API Events", "category": "Social & Ad Telemetry"},
        {"domain": "mparticle.com", "name": "mParticle", "category": "CDP"},
        {"domain": "braze.com", "name": "Braze", "category": "Customer Analytics"},
        {"domain": "singular.net", "name": "Singular", "category": "Attribution"},
        {"domain": "applovin.com", "name": "AppLovin", "category": "Ad Network"},
        {"domain": "vungle.com", "name": "Vungle", "category": "Video Ads"},
        {"domain": "chartboost.com", "name": "Chartboost", "category": "Game Ads"},
        {"domain": "tapjoy.com", "name": "Tapjoy", "category": "Ad Offerwall"},
        {"domain": "ironsrc.com", "name": "ironSource", "category": "Mediation"},
        {"domain": "criteo.com", "name": "Criteo", "category": "Retargeting"},
        {"domain": "segment.io", "name": "Segment", "category": "Customer Tracking"},
        {"domain": "smartlook.com", "name": "Smartlook", "category": "Session Recording"},
        {"domain": "hotjar.com", "name": "Hotjar", "category": "Behavior Analytics"},
        {"domain": "moatads.com", "name": "Moat", "category": "Ad Verification"},
        {"domain": "quantserve.com", "name": "Quantcast", "category": "Measurement"},
        {"domain": "comscore.com", "name": "Comscore", "category": "Measurement"},
    ]


# ---------------------------------------------------------------------------
# Rule Implementations
# ---------------------------------------------------------------------------

class CleartextHttpUrlRule(BaseRule):
    """Detects hardcoded cleartext HTTP URLs in static strings and bytecode.
    
    Suppresses XML namespaces, schemas, and localhost/test endpoints to avoid false positives.
    """

    rule_id = "NET-001"
    title = "Hardcoded Cleartext HTTP URL"
    category = FindingCategory.NETWORK_INDICATOR
    default_severity = Severity.MEDIUM
    description = (
        "Static code and string inspection detected an unencrypted cleartext HTTP URL. "
        "Static analysis alone cannot determine whether sensitive information is transmitted to this endpoint."
    )
    owasp_reference = "OWASP-M3: Insecure Communication"

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen_urls: set[str] = set()

        for location, text in _extract_text_targets(context):
            for match in URL_PATTERN.finditer(text):
                raw_url = match.group(0)
                url = _clean_url(raw_url)

                # Strictly evaluate unencrypted HTTP scheme
                if not url.lower().startswith("http://"):
                    continue

                if url in seen_urls:
                    continue

                try:
                    parsed = urlparse(url)
                    hostname = parsed.hostname or ""
                except Exception:
                    continue

                # Suppress false positives: schemas and XML namespaces
                if _is_schema_or_namespace(url, hostname):
                    continue

                # Suppress false positives: localhost and internal test domains
                if _is_localhost_or_test_host(hostname):
                    continue

                seen_urls.add(url)
                findings.append(
                    self.create_finding(
                        title=self.title,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description=(
                            f"Static analysis detected a hardcoded unencrypted HTTP URL: '{url}'. "
                            "Static analysis alone cannot determine whether this endpoint is actively "
                            "invoked at runtime or whether sensitive information is transmitted to it."
                        ),
                        evidence=f"Static URL: {url}",
                        location=location,
                        impact=(
                            "Unencrypted HTTP communication is vulnerable to eavesdropping and manipulation "
                            "by on-path network adversaries (Man-in-the-Middle)."
                        ),
                        remediation=(
                            "Update the endpoint to secure HTTPS (TLS 1.2+) and configure Network Security "
                            "Configuration to disallow cleartext traffic."
                        ),
                    )
                )

        return findings


# Backwards compatibility alias
CleartextTrafficRule = CleartextHttpUrlRule


class CleartextTrafficConfigRule(BaseRule):
    """Detects cleartext-traffic permission configurations in AndroidManifest and Network Security Config."""

    rule_id = "NET-002"
    title = "Cleartext Network Traffic Permitted"
    category = FindingCategory.NETWORK_INDICATOR
    default_severity = Severity.HIGH
    description = (
        "Checks whether unencrypted cleartext HTTP traffic is explicitly permitted in application configuration."
    )
    owasp_reference = "OWASP-M3: Insecure Communication"

    CLEARTEXT_CONFIG_PATTERN = re.compile(
        r'cleartextTrafficPermitted\s*=\s*["\']true["\']',
        re.IGNORECASE,
    )

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []

        # Check ParsedAPKData manifest info
        if isinstance(context, ParsedAPKData) and context.manifest_info:
            if context.manifest_info.uses_cleartext_traffic is True:
                findings.append(
                    self.create_finding(
                        title="Cleartext Traffic Permitted in Manifest",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=(
                            "Static manifest analysis indicates that cleartext HTTP network traffic is "
                            "explicitly permitted (android:usesCleartextTraffic='true'). Static analysis "
                            "alone cannot determine whether unencrypted transmission occurs at runtime."
                        ),
                        evidence='android:usesCleartextTraffic="true" in <application>',
                        location="AndroidManifest.xml:<application>",
                        impact="Allows the application to make unencrypted cleartext HTTP requests across all domains.",
                        remediation="Set 'android:usesCleartextTraffic=\"false\"' and enforce HTTPS communication.",
                    )
                )

        # Check dictionary context or raw XML sources
        if isinstance(context, dict):
            manifest_info = context.get("manifest_info")
            if isinstance(manifest_info, ManifestData) and manifest_info.uses_cleartext_traffic is True:
                findings.append(
                    self.create_finding(
                        title="Cleartext Traffic Permitted in Manifest",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=(
                            "Static manifest analysis indicates that cleartext HTTP network traffic is "
                            "explicitly permitted (android:usesCleartextTraffic='true'). Static analysis "
                            "alone cannot determine whether unencrypted transmission occurs at runtime."
                        ),
                        evidence='android:usesCleartextTraffic="true" in <application>',
                        location="AndroidManifest.xml:<application>",
                        impact="Allows the application to make unencrypted cleartext HTTP requests across all domains.",
                        remediation="Set 'android:usesCleartextTraffic=\"false\"' and enforce HTTPS communication.",
                    )
                )

        # Scan text targets for cleartextTrafficPermitted="true" in network security configuration XMLs
        for location, text in _extract_text_targets(context):
            if "network_security_config" in location.lower() or "res/xml" in location.lower():
                if self.CLEARTEXT_CONFIG_PATTERN.search(text):
                    findings.append(
                        self.create_finding(
                            title="Cleartext Traffic Permitted in Network Security Config",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=(
                                "Static configuration analysis revealed that Network Security Configuration "
                                "explicitly enables cleartextTrafficPermitted='true'. Static analysis alone "
                                "cannot determine whether sensitive information is transmitted over cleartext."
                            ),
                            evidence='cleartextTrafficPermitted="true"',
                            location=location,
                            impact="Explicitly whitelists unencrypted HTTP traffic in Network Security Config.",
                            remediation="Set cleartextTrafficPermitted=\"false\" in base-config and domain-config.",
                        )
                    )

        return findings


class TrustAllCertificatesRule(BaseRule):
    """Detects suspicious trust-all X.509 certificate implementations."""

    rule_id = "NET-003"
    title = "Trust-All X.509 Certificate Validation Pattern"
    category = FindingCategory.NETWORK_INDICATOR
    default_severity = Severity.HIGH
    description = (
        "Static code inspection identified an X.509 TrustManager implementation configured to accept all "
        "certificates without validation. Static analysis alone cannot determine whether this TrustManager "
        "is invoked during runtime communication."
    )
    owasp_reference = "OWASP-M3: Insecure Communication"

    # Matches checkServerTrusted with empty body or immediate return without throwing exceptions
    EMPTY_CHECK_SERVER_TRUSTED = re.compile(
        r"void\s+checkServerTrusted\s*\([^)]*\)\s*\{\s*(?://[^\n]*\s*|/\*.*?\*/\s*)*\}",
        re.MULTILINE,
    )
    EMPTY_CHECK_CLIENT_TRUSTED = re.compile(
        r"void\s+checkClientTrusted\s*\([^)]*\)\s*\{\s*(?://[^\n]*\s*|/\*.*?\*/\s*)*\}",
        re.MULTILINE,
    )
    # Matches classes named TrustAllManager, TrustAllCertificates, etc.
    TRUST_ALL_CLASS_NAME = re.compile(
        r"\b(?:TrustAll(?:Trust)?Manager|TrustAllCertificates|TrustAllSSLSocketFactory|NaiveTrustManager|InsecureTrustManager)\b"
    )
    # Smali empty checkServerTrusted implementation
    SMALI_EMPTY_CHECK_TRUSTED = re.compile(
        r"\.method\s+[^\n]*checkServerTrusted[^\n]*\n(?:\s*\.[a-zA-Z0-9_-]+[^\n]*\n)*\s*return-void\s*\n\s*\.end\s+method",
        re.MULTILINE,
    )

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen_matches: set[str] = set()

        for location, text in _extract_text_targets(context):
            # Check for empty checkServerTrusted
            for server_match in self.EMPTY_CHECK_SERVER_TRUSTED.finditer(text):
                match_snippet = server_match.group(0).strip()
                key = f"{location}:{match_snippet}"
                if key not in seen_matches:
                    seen_matches.add(key)
                    findings.append(
                        self.create_finding(
                            title=self.title,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=(
                                "Static code analysis identified an empty checkServerTrusted() implementation "
                                "that performs no certificate validation. Static analysis alone cannot verify "
                                "whether this TrustManager is executed during runtime operations."
                            ),
                            evidence=match_snippet,
                            location=location,
                            impact=(
                                "Disables TLS certificate verification, leaving network connections completely "
                                "vulnerable to Man-in-the-Middle (MITM) attacks and credential theft."
                            ),
                            remediation=(
                                "Remove custom TrustManagers that bypass validation. Rely on the standard Android "
                                "trust store and Network Security Configuration."
                            ),
                        )
                    )

            # Check for smali empty checkServerTrusted
            for smali_match in self.SMALI_EMPTY_CHECK_TRUSTED.finditer(text):
                match_snippet = smali_match.group(0).strip()
                key = f"{location}:{match_snippet}"
                if key not in seen_matches:
                    seen_matches.add(key)
                    findings.append(
                        self.create_finding(
                            title=self.title,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=(
                                "Static bytecode analysis identified an empty Smali checkServerTrusted implementation "
                                "returning immediately without validation. Static analysis alone cannot verify "
                                "whether this method is invoked at runtime."
                            ),
                            evidence="Smali return-void in checkServerTrusted",
                            location=location,
                            impact="Permits any TLS certificate, enabling active on-path eavesdropping.",
                            remediation="Delete the custom trust-all TrustManager and use system TLS verification.",
                        )
                    )

            # Check for trust-all class names
            for class_match in self.TRUST_ALL_CLASS_NAME.finditer(text):
                class_name = class_match.group(0)
                key = f"{location}:{class_name}"
                if key not in seen_matches:
                    seen_matches.add(key)
                    findings.append(
                        self.create_finding(
                            title="Trust-All Certificate Manager Reference",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=(
                                f"Static analysis identified a class name indicating trust-all TLS behavior: '{class_name}'. "
                                "Static analysis alone cannot determine whether this component is initialized at runtime."
                            ),
                            evidence=f"Class reference: {class_name}",
                            location=location,
                            impact="Indicates presence of custom TLS bypass logic that accepts invalid certificates.",
                            remediation="Remove custom trust-all classes and adhere to Android default TLS trust chain.",
                        )
                    )

        return findings


class PermissiveHostnameVerifierRule(BaseRule):
    """Detects permissive HostnameVerifier patterns that accept arbitrary server hostnames."""

    rule_id = "NET-004"
    title = "Permissive HostnameVerifier Pattern"
    category = FindingCategory.NETWORK_INDICATOR
    default_severity = Severity.HIGH
    description = (
        "Static analysis identified a permissive HostnameVerifier pattern that accepts all server hostnames. "
        "Static analysis alone cannot determine whether this verifier is utilized during runtime operations."
    )
    owasp_reference = "OWASP-M3: Insecure Communication"

    ALLOW_ALL_CONST = re.compile(
        r"\b(?:ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier|NullHostnameVerifier)\b"
    )
    VERIFY_RETURN_TRUE = re.compile(
        r"boolean\s+verify\s*\([^)]*\)\s*\{\s*return\s+true\s*;?\s*\}",
        re.MULTILINE,
    )
    LAMBDA_VERIFY_TRUE = re.compile(
        r"\(\s*[a-zA-Z0-9_]+\s*,\s*[a-zA-Z0-9_]+\s*\)\s*->\s*true"
    )

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen: set[str] = set()

        for location, text in _extract_text_targets(context):
            # Check constant pattern
            for match in self.ALLOW_ALL_CONST.finditer(text):
                matched_token = match.group(0)
                key = f"{location}:{matched_token}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        self.create_finding(
                            title=self.title,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=(
                                f"Static analysis detected reference to permissive hostname verifier: '{matched_token}'. "
                                "Static analysis alone cannot determine whether this verifier is utilized during runtime operations."
                            ),
                            evidence=f"Verifier identifier: {matched_token}",
                            location=location,
                            impact=(
                                "Accepts server certificates with mismatched hostnames, allowing attackers with "
                                "valid certificates for any domain to impersonate target servers."
                            ),
                            remediation=(
                                "Use default platform hostname verification (e.g., HttpsURLConnection.getDefaultHostnameVerifier())."
                            ),
                        )
                    )

            # Check method returning true
            method_match = self.VERIFY_RETURN_TRUE.search(text)
            if method_match:
                snippet = method_match.group(0).strip()
                key = f"{location}:{snippet}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        self.create_finding(
                            title=self.title,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=(
                                "Static inspection identified a HostnameVerifier method implementation returning "
                                "'true' unconditionally. Static analysis alone cannot confirm whether this verifier "
                                "is actively invoked during network transactions."
                            ),
                            evidence=snippet,
                            location=location,
                            impact="Allows connections to any host regardless of whether the certificate matches.",
                            remediation="Remove custom HostnameVerifier implementations that return true unconditionally.",
                        )
                    )

            # Check lambda returning true
            lambda_match = self.LAMBDA_VERIFY_TRUE.search(text)
            if lambda_match:
                snippet = lambda_match.group(0).strip()
                key = f"{location}:{snippet}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        self.create_finding(
                            title=self.title,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=(
                                "Static inspection identified a HostnameVerifier lambda expression returning 'true'. "
                                "Static analysis alone cannot confirm whether this verifier is actively invoked."
                            ),
                            evidence=snippet,
                            location=location,
                            impact="Disables hostname verification for TLS sessions.",
                            remediation="Use default platform hostname verification instead of a permissive lambda.",
                        )
                    )

        return findings


class SslValidationBypassRule(BaseRule):
    """Detects SSL/TLS certificate validation bypass patterns."""

    rule_id = "NET-005"
    title = "SSL/TLS Certificate Validation Bypass Pattern"
    category = FindingCategory.NETWORK_INDICATOR
    default_severity = Severity.HIGH
    description = (
        "Static analysis detected an SSL/TLS certificate validation bypass pattern in application code. "
        "Static analysis alone cannot verify whether this bypass executes under production operational conditions."
    )
    owasp_reference = "OWASP-M3: Insecure Communication"

    # WebView onReceivedSslError proceeding despite errors
    SSL_ERROR_PROCEED = re.compile(
        r"onReceivedSslError\s*\([^)]*\)\s*\{[^}]*\bhandler\.proceed\(\)",
        re.DOTALL,
    )
    # SSLContext initialized with TrustManager bypass (chained or local variable)
    SSL_CONTEXT_BYPASS = re.compile(
        r"(?:SSLContext\b[^\n;]*|\b[a-zA-Z0-9_]+)\.init\s*\(\s*null\s*,\s*new\s+TrustManager\[\]",
        re.MULTILINE,
    )

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen: set[str] = set()

        for location, text in _extract_text_targets(context):
            # Check WebView SSL error proceed
            proceed_match = self.SSL_ERROR_PROCEED.search(text)
            if proceed_match:
                snippet = proceed_match.group(0).strip()
                key = f"{location}:{snippet}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        self.create_finding(
                            title="WebView SSL Error Bypass (handler.proceed)",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=(
                                "Static code analysis identified a WebViewClient.onReceivedSslError() implementation "
                                "calling handler.proceed(). Static analysis alone cannot verify whether this callback "
                                "executes under production operational conditions."
                            ),
                            evidence=snippet,
                            location=location,
                            impact=(
                                "Instructs WebView to ignore all SSL/TLS validation failures, allowing malicious "
                                "interceptors to forge certificates without user notification."
                            ),
                            remediation=(
                                "Call handler.cancel() on SSL errors and notify users of certificate validation failures."
                            ),
                        )
                    )

            # Check SSLContext initialized with custom trust manager
            ctx_match = self.SSL_CONTEXT_BYPASS.search(text)
            if ctx_match:
                snippet = ctx_match.group(0).strip()
                key = f"{location}:{snippet}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        self.create_finding(
                            title="SSLContext Custom TrustManager Initialization",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=(
                                "Static analysis detected custom TrustManager array initialization on SSLContext. "
                                "Static analysis alone cannot determine whether this context is used for production requests."
                            ),
                            evidence=snippet,
                            location=location,
                            impact="Indicates manual TLS context configuration which frequently bypasses certificate verification.",
                            remediation="Use system default SSLContext or Android Network Security Configuration.",
                        )
                    )

        return findings


class InsecureWebViewNetworkRule(BaseRule):
    """Detects potentially insecure WebView network and origin access configurations."""

    rule_id = "NET-006"
    title = "Insecure WebView Network Configuration"
    category = FindingCategory.NETWORK_INDICATOR
    default_severity = Severity.MEDIUM
    description = (
        "Static inspection identified a potentially insecure WebView configuration setting. "
        "Static analysis alone cannot determine whether untrusted web content is loaded into this WebView "
        "or if sensitive data is accessed at runtime."
    )
    owasp_reference = "OWASP-M1: Improper Platform Usage"

    PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
        (
            "WebView Universal File Access Enabled",
            re.compile(r"setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)"),
            "Allows scripts running from file:// URLs to access content from any origin (cross-origin bypass).",
        ),
        (
            "WebView File Access from File URLs Enabled",
            re.compile(r"setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)"),
            "Allows scripts in file:// contexts to access other local files on the device filesystem.",
        ),
        (
            "WebView Mixed Content Allowed",
            re.compile(r"setMixedContentMode\s*\(\s*(?:WebSettings\.MIXED_CONTENT_ALWAYS_ALLOW|0)\s*\)"),
            "Allows an HTTPS page in WebView to load unencrypted HTTP sub-resources (scripts, images).",
        ),
    ]

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen: set[str] = set()

        for location, text in _extract_text_targets(context):
            for title_suffix, pattern, impact_desc in self.PATTERNS:
                match = pattern.search(text)
                if match:
                    snippet = match.group(0).strip()
                    key = f"{location}:{snippet}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(
                            self.create_finding(
                                title=f"Insecure WebView Setting: {title_suffix}",
                                severity=Severity.MEDIUM,
                                confidence=Confidence.HIGH,
                                description=(
                                    f"Static inspection detected '{snippet}'. Static analysis alone cannot determine "
                                    "whether untrusted web content is loaded into this WebView or if sensitive data "
                                    "is exposed at runtime."
                                ),
                                evidence=snippet,
                                location=location,
                                impact=impact_desc,
                                remediation=(
                                    "Explicitly disable cross-origin file URL access on WebSettings and use "
                                    "MIXED_CONTENT_NEVER_ALLOW (API 21+)."
                                ),
                            )
                        )

        return findings


class TrackingAndAdEndpointRule(BaseRule):
    """Detects known tracking, analytics, and advertising domains in static application strings and resources."""

    rule_id = "NET-007"
    title = "Embedded Tracking or Advertising Endpoint"
    category = FindingCategory.NETWORK_INDICATOR
    default_severity = Severity.MEDIUM
    description = (
        "The application's static resources contain an endpoint associated with tracking. "
        "Static analysis alone cannot determine whether sensitive information is transmitted to this endpoint."
    )
    owasp_reference = "OWASP-M3: Insecure Communication"

    def __init__(self, tracking_catalog: list[dict[str, str]] | None = None) -> None:
        super().__init__()
        self._catalog = tracking_catalog if tracking_catalog is not None else _load_tracking_catalog()

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen_domains: set[str] = set()

        for location, text in _extract_text_targets(context):
            # First extract all URLs found in the text
            urls_in_target: list[str] = []
            for match in URL_PATTERN.finditer(text):
                cleaned = _clean_url(match.group(0))
                urls_in_target.append(cleaned)

            for entry in self._catalog:
                pattern_domain = entry.get("domain", "").lower()
                provider_name = entry.get("name", "Tracking/Ad Provider")
                if not pattern_domain:
                    continue

                if pattern_domain in seen_domains:
                    continue

                matched = False
                matched_evidence = ""

                # Check URL host matches
                for u in urls_in_target:
                    try:
                        p = urlparse(u)
                        host = (p.hostname or "").lower()
                        path = p.path or ""
                        full_spec = host + path
                    except Exception:
                        continue

                    # Exact host or subdomain or path prefix match (e.g. facebook.com/tr)
                    if host == pattern_domain or host.endswith("." + pattern_domain) or pattern_domain in full_spec:
                        matched = True
                        matched_evidence = f"URL: {u} (matches {pattern_domain})"
                        break

                # If not matched via URL, check for direct string domain appearance
                if not matched:
                    # Look for domain boundary pattern in text
                    domain_regex = re.compile(r"\b" + re.escape(pattern_domain) + r"\b", re.IGNORECASE)
                    if domain_regex.search(text):
                        matched = True
                        matched_evidence = f"Domain string: {pattern_domain}"

                if matched:
                    seen_domains.add(pattern_domain)
                    findings.append(
                        self.create_finding(
                            title=self.title,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            description=(
                                f"The application's static resources contain an endpoint associated with tracking "
                                f"({pattern_domain} - {provider_name}). Static analysis alone cannot determine "
                                "whether sensitive information is transmitted to this endpoint."
                            ),
                            evidence=f"Static evidence: {matched_evidence}",
                            location=location,
                            impact=(
                                "Endpoints associated with analytics, advertising, or attribution services may "
                                "receive telemetry, persistent device identifiers, or app usage metrics if contacted at runtime."
                            ),
                            remediation=(
                                "Review third-party analytics and tracking SDK usage against privacy policies and "
                                "obtain explicit user consent prior to telemetry transmission."
                            ),
                        )
                    )

        return findings


class ThirdPartyEndpointRule(BaseRule):
    """Detects embedded third-party external endpoints in application strings/resources."""

    rule_id = "NET-008"
    title = "Embedded Third-Party Endpoint"
    category = FindingCategory.NETWORK_INDICATOR
    default_severity = Severity.LOW
    description = (
        "The application's static resources contain an embedded third-party endpoint. "
        "Static analysis alone cannot determine whether communication occurs with this endpoint "
        "or if sensitive information is transmitted."
    )
    owasp_reference = "OWASP-M3: Insecure Communication"

    def __init__(self, tracking_catalog: list[dict[str, str]] | None = None) -> None:
        super().__init__()
        tracking = tracking_catalog if tracking_catalog is not None else _load_tracking_catalog()
        self._tracking_domains: set[str] = {t.get("domain", "").lower() for t in tracking if t.get("domain")}

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen_hosts: set[str] = set()

        # Extract app package name if available to avoid flagging first-party domains
        package_name = ""
        if isinstance(context, ParsedAPKData) and context.metadata and context.metadata.package_name:
            package_name = context.metadata.package_name
        elif isinstance(context, dict):
            if "parsed_apk" in context and isinstance(context["parsed_apk"], ParsedAPKData):
                if context["parsed_apk"].metadata and context["parsed_apk"].metadata.package_name:
                    package_name = context["parsed_apk"].metadata.package_name
            elif "metadata" in context and isinstance(context["metadata"], ApplicationMetadata):
                package_name = context["metadata"].package_name
            elif "package_name" in context and isinstance(context["package_name"], str):
                package_name = context["package_name"]
            elif "manifest_info" in context:
                m = context["manifest_info"]
                if isinstance(m, ManifestData) and m.package_name:
                    package_name = m.package_name
                elif isinstance(m, dict) and m.get("package_name"):
                    package_name = str(m["package_name"])

        first_party_tokens: set[str] = set()
        if package_name:
            parts = [p.lower() for p in package_name.split(".") if p]
            generic_tlds = {"com", "org", "net", "io", "app", "dev", "co", "uk", "de", "fr", "android"}
            for part in parts:
                if len(part) >= 4 and part not in generic_tlds:
                    first_party_tokens.add(part)

        for location, text in _extract_text_targets(context):
            for match in URL_PATTERN.finditer(text):
                url = _clean_url(match.group(0))
                try:
                    parsed = urlparse(url)
                    hostname = (parsed.hostname or "").lower()
                except Exception:
                    continue

                if not hostname or hostname in seen_hosts:
                    continue

                # Filter out standard schemas and XML namespaces
                if _is_schema_or_namespace(url, hostname):
                    continue

                # Filter out localhost and test hosts
                if _is_localhost_or_test_host(hostname):
                    continue

                # Filter out standard platform domains (Google, Android OS)
                if hostname in PLATFORM_DOMAINS or any(hostname.endswith("." + d) for d in PLATFORM_DOMAINS):
                    continue

                # Filter out tracking domains (handled by TrackingAndAdEndpointRule)
                if hostname in self._tracking_domains or any(
                    hostname.endswith("." + d) for d in self._tracking_domains
                ):
                    continue

                # Filter out first party domain tokens
                if any(tok in hostname for tok in first_party_tokens):
                    continue

                seen_hosts.add(hostname)
                findings.append(
                    self.create_finding(
                        title=self.title,
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        description=(
                            f"The application's static resources contain an embedded third-party endpoint: '{hostname}'. "
                            "Static analysis alone cannot determine whether communication occurs with this endpoint "
                            "or if sensitive information is transmitted."
                        ),
                        evidence=f"Static endpoint reference: {url}",
                        location=location,
                        impact=(
                            "Third-party endpoints represent external network dependencies and integrations that "
                            "should be inventoried and assessed for data handling compliance."
                        ),
                        remediation=(
                            "Inventory external endpoints, verify encryption (TLS), and ensure compliance with "
                            "the application's external dependency and privacy requirements."
                        ),
                    )
                )

        return findings


ALL_NETWORK_RULES: list[type[BaseRule]] = [
    CleartextHttpUrlRule,
    CleartextTrafficConfigRule,
    TrustAllCertificatesRule,
    PermissiveHostnameVerifierRule,
    SslValidationBypassRule,
    InsecureWebViewNetworkRule,
    TrackingAndAdEndpointRule,
    ThirdPartyEndpointRule,
]
