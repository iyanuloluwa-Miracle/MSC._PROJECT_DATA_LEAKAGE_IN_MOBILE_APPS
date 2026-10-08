"""Static analysis rules identifying insecure local storage patterns.

Analyzes static source code, bytecode, and resources for:
- World-readable or world-writable legacy file modes
- Storing sensitive data on external/public storage
- Plaintext SharedPreferences operations involving sensitive keys
- Plaintext SQLite/database schemas involving sensitive fields
- Sensitive data written to system logs (logcat)
- Potentially sensitive cache or temporary storage usage

All findings strictly state that conclusions are based on static evidence and
include concrete remediation guidance.
"""

from __future__ import annotations

import logging
import re
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


# ---------------------------------------------------------------------------
# Sensitive keywords and suppression patterns
# ---------------------------------------------------------------------------

SENSITIVE_STORAGE_KEYWORDS: set[str] = {
    "password",
    "passwd",
    "secret",
    "token",
    "auth_token",
    "authtoken",
    "access_token",
    "refresh_token",
    "credential",
    "private_key",
    "privkey",
    "pin",
    "ssn",
    "credit_card",
    "cvv",
    "bank_account",
    "auth",
}

# Regex matching sensitive words or identifier substrings (handles camelCase and snake_case)
SENSITIVE_WORD_REGEX = re.compile(
    r"(?i)(?:password|passwd|secret|token|auth_token|authtoken|credential|cred|pin|ssn|credit_card|cvv|private_key|privkey|bank_account|auth\b)"
)


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

        # Generic raw content
        if "text_content" in context and isinstance(context["text_content"], str):
            targets.append(("TextContent", context["text_content"]))

    elif isinstance(context, str):
        targets.append(("TextContent", context))

    return targets


# ---------------------------------------------------------------------------
# Storage Rule Implementations
# ---------------------------------------------------------------------------

class WorldReadableWritableStorageRule(BaseRule):
    """Detects usage of deprecated MODE_WORLD_READABLE and MODE_WORLD_WRITEABLE modes."""

    rule_id = "STO-001"
    title = "World-Readable or World-Writable Storage Mode"
    category = FindingCategory.STORAGE_INSECURITY
    default_severity = Severity.HIGH
    description = (
        "Static code inspection detected the use of legacy MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE file modes. "
        "Static analysis alone cannot verify runtime execution on specific Android OS versions."
    )
    owasp_reference = "OWASP-M2: Insecure Data Storage"

    PATTERN_CONSTANT = re.compile(
        r"\b(?:Context\.)?MODE_WORLD_(?:READABLE|WRITEABLE)\b"
    )
    PATTERN_NUMERIC = re.compile(
        r"\b(?:openFileOutput|getSharedPreferences|openOrCreateDatabase)\s*\([^,]+,\s*([12])\s*\)"
    )

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen: set[str] = set()

        for location, text in _extract_text_targets(context):
            # Check symbolic constant
            for match in self.PATTERN_CONSTANT.finditer(text):
                matched = match.group(0)
                key = f"{location}:{matched}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        self.create_finding(
                            title=self.title,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=(
                                f"Static inspection detected usage of '{matched}'. Files created with world-readable "
                                "or world-writable permissions can be accessed or modified by any other application "
                                "on the device."
                            ),
                            evidence=matched,
                            location=location,
                            impact="Permits arbitrary third-party applications on the device to read or overwrite private application data.",
                            remediation=(
                                "Use Context.MODE_PRIVATE (0) for local file and preference storage. For cross-app "
                                "sharing, implement an explicit ContentProvider protected by signature permissions."
                            ),
                        )
                    )

            # Check numeric flag (1 = MODE_WORLD_READABLE, 2 = MODE_WORLD_WRITEABLE)
            for match in self.PATTERN_NUMERIC.finditer(text):
                full_snippet = match.group(0).strip()
                flag_val = match.group(1)
                flag_name = "MODE_WORLD_READABLE (1)" if flag_val == "1" else "MODE_WORLD_WRITEABLE (2)"
                key = f"{location}:{full_snippet}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        self.create_finding(
                            title=self.title,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=(
                                f"Static analysis identified file/preference creation with numeric mode {flag_name}. "
                                "Static analysis alone cannot verify runtime execution."
                            ),
                            evidence=full_snippet,
                            location=location,
                            impact="Allows unauthorized access or tampering with application files by other apps.",
                            remediation="Replace numeric mode flag with Context.MODE_PRIVATE (0).",
                        )
                    )

        return findings


# Backwards compatibility alias
InsecureStorageRule = WorldReadableWritableStorageRule


class ExternalStorageSensitiveDataRule(BaseRule):
    """Detects operations targeting external/public storage combined with sensitive data indicators."""

    rule_id = "STO-002"
    title = "Sensitive Data Stored on External/Public Storage"
    category = FindingCategory.STORAGE_INSECURITY
    default_severity = Severity.HIGH
    description = (
        "Static code analysis identified references to external/public storage combined with sensitive data indicators. "
        "Static analysis alone cannot determine whether sensitive user data is actively written to public storage at runtime."
    )
    owasp_reference = "OWASP-M2: Insecure Data Storage"

    EXTERNAL_STORAGE_APIS = re.compile(
        r"(?:Environment\.getExternalStorageDirectory\(\)|"
        r"Environment\.getExternalStoragePublicDirectory\([^)]*\)|"
        r"(?:Context\.)?getExternalFilesDir\([^)]*\)|"
        r"(?:Context\.)?getExternalCacheDir\(\)|"
        r"[\"']/sdcard/)"
    )

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen: set[str] = set()

        for location, text in _extract_text_targets(context):
            lines = text.splitlines()
            for idx, line in enumerate(lines):
                if self.EXTERNAL_STORAGE_APIS.search(line):
                    # Check surrounding window (3 lines before and after) for sensitive keywords
                    start_idx = max(0, idx - 3)
                    end_idx = min(len(lines), idx + 4)
                    window_text = " ".join(lines[start_idx:end_idx])

                    sensitive_match = SENSITIVE_WORD_REGEX.search(window_text)
                    if sensitive_match:
                        matched_kw = sensitive_match.group(0)
                        evidence = line.strip()
                        key = f"{location}:{evidence}:{matched_kw}"
                        if key not in seen:
                            seen.add(key)
                            findings.append(
                                self.create_finding(
                                    title=self.title,
                                    severity=Severity.HIGH,
                                    confidence=Confidence.HIGH,
                                    description=(
                                        f"Static analysis detected external storage access in proximity to sensitive keyword "
                                        f"'{matched_kw}'. Static analysis alone cannot verify whether sensitive data is "
                                        "written to external storage at runtime."
                                    ),
                                    evidence=f"{evidence} (keyword: {matched_kw})",
                                    location=f"{location}:line {idx + 1}",
                                    impact=(
                                        "External storage is world-readable by any app with READ_EXTERNAL_STORAGE permission "
                                        "and accessible via USB file transfer without device root."
                                    ),
                                    remediation=(
                                        "Store sensitive data exclusively in internal app storage (Context.getFilesDir()) "
                                        "or use AndroidX EncryptedFile with hardware-backed keys."
                                    ),
                                )
                            )

        return findings


class PlaintextSharedPreferencesRule(BaseRule):
    """Detects unencrypted SharedPreferences operations referencing sensitive credential/key names."""

    rule_id = "STO-003"
    title = "Plaintext SharedPreferences Storing Sensitive Data"
    category = FindingCategory.STORAGE_INSECURITY
    default_severity = Severity.MEDIUM
    description = (
        "Static code inspection identified unencrypted SharedPreferences operations referencing sensitive credential/key names. "
        "Static analysis alone cannot determine whether encryption is applied before storage or if this path is triggered at runtime."
    )
    owasp_reference = "OWASP-M2: Insecure Data Storage"

    PUT_SENSITIVE_PREF = re.compile(
        r"\b(?:editor|sp|pref|preferences)\.put(?:String|Int|Long|Float|Boolean)\s*\(\s*[\"']([^\"']*)[\"']",
        re.IGNORECASE,
    )
    GET_SENSITIVE_PREF_FILE = re.compile(
        r"getSharedPreferences\s*\(\s*[\"']([^\"']*(?:password|token|auth|cred|secret|account|session)[^\"']*)[\"']",
        re.IGNORECASE,
    )

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen: set[str] = set()

        for location, text in _extract_text_targets(context):
            # Suppress if EncryptedSharedPreferences is explicitly used in the file
            if "EncryptedSharedPreferences" in text or "MasterKey" in text:
                continue

            # Check putString calls with sensitive keys
            for match in self.PUT_SENSITIVE_PREF.finditer(text):
                pref_key = match.group(1)
                if SENSITIVE_WORD_REGEX.search(pref_key):
                    snippet = match.group(0).strip()
                    k = f"{location}:{snippet}"
                    if k not in seen:
                        seen.add(k)
                        findings.append(
                            self.create_finding(
                                title=self.title,
                                severity=Severity.MEDIUM,
                                confidence=Confidence.HIGH,
                                description=(
                                    f"Static analysis detected unencrypted SharedPreferences write with sensitive key name: '{pref_key}'. "
                                    "Static analysis alone cannot verify whether application logic encrypts the value prior to storage."
                                ),
                                evidence=snippet,
                                location=location,
                                impact=(
                                    "Plaintext SharedPreferences XML files stored under /data/data/<package>/shared_prefs "
                                    "can be inspected on rooted devices or extracted via ADB backup."
                                ),
                                remediation=(
                                    "Use androidx.security.crypto.EncryptedSharedPreferences to store sensitive values "
                                    "using AES-256-SIV key encryption and AES-256-GCM value encryption."
                                ),
                            )
                        )

            # Check getSharedPreferences called with sensitive file name
            for match in self.GET_SENSITIVE_PREF_FILE.finditer(text):
                pref_file = match.group(1)
                snippet = match.group(0).strip()
                k = f"{location}:{snippet}"
                if k not in seen:
                    seen.add(k)
                    findings.append(
                        self.create_finding(
                            title=self.title,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            description=(
                                f"Static analysis detected unencrypted SharedPreferences file name referencing credentials: '{pref_file}'. "
                                "Static analysis alone cannot verify whether contents are encrypted."
                            ),
                            evidence=snippet,
                            location=location,
                            impact="Preference files with sensitive names often contain unencrypted auth tokens or credentials.",
                            remediation="Migrate the preference file to EncryptedSharedPreferences.",
                        )
                    )

        return findings


class PlaintextDatabaseSensitiveDataRule(BaseRule):
    """Detects SQLite database schemas defining sensitive fields without database-level encryption."""

    rule_id = "STO-004"
    title = "Plaintext SQLite Database Schema with Sensitive Fields"
    category = FindingCategory.STORAGE_INSECURITY
    default_severity = Severity.HIGH
    description = (
        "Static analysis identified SQLite database schema definitions with sensitive data fields without database-level encryption. "
        "Static analysis alone cannot determine whether field-level encryption is applied before insertion."
    )
    owasp_reference = "OWASP-M2: Insecure Data Storage"

    CREATE_TABLE_PATTERN = re.compile(
        r"CREATE\s+TABLE\s+[^(]+\(([^)]+)\)",
        re.IGNORECASE,
    )

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen: set[str] = set()

        for location, text in _extract_text_targets(context):
            # Suppress if SQLCipher is imported or used in the context
            if "net.sqlcipher" in text or "SQLCipher" in text or "SQLiteDatabaseHook" in text:
                continue

            for match in self.CREATE_TABLE_PATTERN.finditer(text):
                columns_def = match.group(1)
                sensitive_match = SENSITIVE_WORD_REGEX.search(columns_def)
                if sensitive_match:
                    matched_field = sensitive_match.group(0)
                    snippet = match.group(0).strip()
                    key = f"{location}:{matched_field}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(
                            self.create_finding(
                                title=self.title,
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                description=(
                                    f"Static analysis detected SQLite table definition containing sensitive column '{matched_field}' "
                                    "without detectable database-level encryption (e.g. SQLCipher). Static analysis alone cannot "
                                    "verify whether field-level encryption is applied prior to writing."
                                ),
                                evidence=f"Schema with '{matched_field}': {snippet}",
                                location=location,
                                impact=(
                                    "Unencrypted SQLite databases stored on device storage can be inspected directly with "
                                    "sqlite3 CLI if extracted via backup or device access."
                                ),
                                remediation=(
                                    "Use SQLCipher for Android (net.sqlcipher.database.SQLiteDatabase) with a KeyStore-backed "
                                    "passphrase to encrypt the entire database file on flash storage."
                                ),
                            )
                        )

        return findings


class SensitiveInformationLoggingRule(BaseRule):
    """Detects system logging calls (Log.* or System.out) referencing sensitive credential/auth variables."""

    rule_id = "STO-005"
    title = "Sensitive Data Logged to System Logs"
    category = FindingCategory.STORAGE_INSECURITY
    default_severity = Severity.MEDIUM
    description = (
        "Static analysis identified logging calls (Log.* or System.out) referencing potentially sensitive variables or data. "
        "Static analysis alone cannot determine whether sensitive values are populated or logged in release builds."
    )
    owasp_reference = "OWASP-M2: Insecure Data Storage"

    LOGGING_PATTERN = re.compile(
        r"\b(?:Log\.[dview]|System\.(?:out|err)\.println)\s*\(\s*(?:[^,]+,\s*)?([^)]+)\)",
        re.IGNORECASE,
    )

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen: set[str] = set()

        for location, text in _extract_text_targets(context):
            for match in self.LOGGING_PATTERN.finditer(text):
                logged_arg = match.group(1)
                sensitive_match = SENSITIVE_WORD_REGEX.search(logged_arg)
                if sensitive_match:
                    matched_kw = sensitive_match.group(0)
                    snippet = match.group(0).strip()
                    key = f"{location}:{snippet}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(
                            self.create_finding(
                                title=self.title,
                                severity=Severity.MEDIUM,
                                confidence=Confidence.HIGH,
                                description=(
                                    f"Static inspection detected logging call referencing sensitive keyword '{matched_kw}'. "
                                    "Static analysis alone cannot confirm whether sensitive data is output in production builds."
                                ),
                                evidence=snippet,
                                location=location,
                                impact=(
                                    "Logcat messages can be inspected by tools with READ_LOGS or via USB ADB debugging, "
                                    "potentially leaking authentication credentials and secrets."
                                ),
                                remediation=(
                                    "Strip sensitive debug logs using ProGuard/R8 rules or ensure sensitive variables are never "
                                    "passed to Log.* or System.out methods."
                                ),
                            )
                        )

        return findings


class SensitiveCacheStorageRule(BaseRule):
    """Detects sensitive data operations referencing application cache or temporary storage directories."""

    rule_id = "STO-006"
    title = "Sensitive Data Stored in Temporary/Cache Directory"
    category = FindingCategory.STORAGE_INSECURITY
    default_severity = Severity.MEDIUM
    description = (
        "Static code inspection identified sensitive data operations referencing application cache or temporary storage directories. "
        "Static analysis alone cannot confirm whether files are written to cache at runtime."
    )
    owasp_reference = "OWASP-M2: Insecure Data Storage"

    CACHE_STORAGE_PATTERN = re.compile(
        r"(?:getCacheDir\(\)|getExternalCacheDir\(\)|File\.createTempFile\([^)]*\))"
    )

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen: set[str] = set()

        for location, text in _extract_text_targets(context):
            lines = text.splitlines()
            for idx, line in enumerate(lines):
                if self.CACHE_STORAGE_PATTERN.search(line):
                    # Check window of 3 lines before and after for sensitive keyword
                    start_idx = max(0, idx - 3)
                    end_idx = min(len(lines), idx + 4)
                    window_text = " ".join(lines[start_idx:end_idx])

                    sensitive_match = SENSITIVE_WORD_REGEX.search(window_text)
                    if sensitive_match:
                        matched_kw = sensitive_match.group(0)
                        snippet = line.strip()
                        key = f"{location}:{snippet}:{matched_kw}"
                        if key not in seen:
                            seen.add(key)
                            findings.append(
                                self.create_finding(
                                    title=self.title,
                                    severity=Severity.MEDIUM,
                                    confidence=Confidence.HIGH,
                                    description=(
                                        f"Static analysis detected cache/temp file operation in proximity to sensitive keyword '{matched_kw}'. "
                                        "Static analysis alone cannot confirm whether sensitive data is cached at runtime."
                                    ),
                                    evidence=f"{snippet} (keyword: {matched_kw})",
                                    location=f"{location}:line {idx + 1}",
                                    impact=(
                                        "Temporary and cache directories are subject to unpredictable system cleanup, "
                                        "and external cache files can be accessed by other applications."
                                    ),
                                    remediation=(
                                        "Do not cache sensitive credentials or tokens in cache directories. Use encrypted "
                                        "internal storage or retain sensitive data strictly in transient memory."
                                    ),
                                )
                            )

        return findings


ALL_STORAGE_RULES: list[type[BaseRule]] = [
    WorldReadableWritableStorageRule,
    ExternalStorageSensitiveDataRule,
    PlaintextSharedPreferencesRule,
    PlaintextDatabaseSensitiveDataRule,
    SensitiveInformationLoggingRule,
    SensitiveCacheStorageRule,
]
