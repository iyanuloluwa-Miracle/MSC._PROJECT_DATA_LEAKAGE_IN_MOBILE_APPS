"""Static analysis rules identifying broken or insecure cryptographic practices.

Analyzes static source code, bytecode, and string literals for:
- Deprecated or broken ciphers (DES, 3DES, RC4, Blowfish)
- Insecure Electronic Codebook (ECB) mode
- Hardcoded, static, or zero-initialized Initialization Vectors (IVs)
- Hardcoded cryptographic secret keys
- Obsolete hash functions (MD5, SHA-1) in security-sensitive contexts (conservative detection)
- Insecure random number generators and static seeds

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
from data_leak_detector.core.redactor import redact_secret
from data_leak_detector.rules.base import BaseRule


logger = logging.getLogger(__name__)


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
# Cryptography Rule Implementations
# ---------------------------------------------------------------------------

class BrokenCipherRule(BaseRule):
    """Detects usage of broken or deprecated symmetric ciphers (DES, 3DES, RC4, Blowfish)."""

    rule_id = "CRY-001"
    title = "Broken / Deprecated Cryptographic Algorithm"
    category = FindingCategory.CRYPTO_FLAW
    default_severity = Severity.HIGH
    description = (
        "Static code inspection detected the use of a broken or deprecated cryptographic algorithm. "
        "Static analysis alone cannot determine whether this cipher is actively used in production communication."
    )
    owasp_reference = "OWASP-M5: Insufficient Cryptography"

    BROKEN_CIPHERS: list[tuple[str, re.Pattern[str], str]] = [
        (
            "DES",
            re.compile(r'Cipher\.getInstance\s*\(\s*["\']DES(?:/[^"\']*)?["\']\)', re.IGNORECASE),
            "DES has an inadequate 56-bit key length and can be brute-forced in hours with modern hardware.",
        ),
        (
            "3DES / TripleDES",
            re.compile(r'Cipher\.getInstance\s*\(\s*["\'](?:DESede|TripleDES)(?:/[^"\']*)?["\']\)', re.IGNORECASE),
            "3DES uses 64-bit blocks vulnerable to Sweet32 collision attacks and is deprecated by NIST.",
        ),
        (
            "RC4 / ARCFOUR",
            re.compile(r'Cipher\.getInstance\s*\(\s*["\'](?:RC4|ARC4|ARCFOUR)(?:/[^"\']*)?["\']\)', re.IGNORECASE),
            "RC4 is a stream cipher with severe statistical biases in its keystream and is prohibited by RFC 7465.",
        ),
        (
            "Blowfish",
            re.compile(r'Cipher\.getInstance\s*\(\s*["\']Blowfish(?:/[^"\']*)?["\']\)', re.IGNORECASE),
            "Blowfish has a 64-bit block size vulnerable to birthday paradox collision attacks.",
        ),
    ]

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen: set[str] = set()

        for location, text in _extract_text_targets(context):
            for cipher_name, pattern, impact_desc in self.BROKEN_CIPHERS:
                for match in pattern.finditer(text):
                    snippet = match.group(0).strip()
                    key = f"{location}:{snippet}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(
                            self.create_finding(
                                title=f"Broken / Deprecated Cipher: {cipher_name}",
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                description=(
                                    f"Static inspection detected instantiation of deprecated cipher '{cipher_name}'. "
                                    "Static analysis alone cannot verify whether sensitive data is encrypted using this algorithm."
                                ),
                                evidence=snippet,
                                location=location,
                                impact=impact_desc,
                                remediation=(
                                    "Replace legacy ciphers with AES-256 in GCM mode (AES/GCM/NoPadding) or ChaCha20-Poly1305."
                                ),
                            )
                        )

        return findings


# Backwards compatibility alias
WeakCryptoRule = BrokenCipherRule


class EcbModeCipherRule(BaseRule):
    """Detects usage of insecure Electronic Codebook (ECB) cipher mode."""

    rule_id = "CRY-002"
    title = "Insecure ECB Cipher Mode"
    category = FindingCategory.CRYPTO_FLAW
    default_severity = Severity.HIGH
    description = (
        "Static code analysis identified symmetric encryption initialized in Electronic Codebook (ECB) mode. "
        "Static analysis alone cannot verify whether sensitive data is encrypted with this cipher at runtime."
    )
    owasp_reference = "OWASP-M5: Insufficient Cryptography"

    # Explicit ECB mode in transformation string
    EXPLICIT_ECB = re.compile(
        r'Cipher\.getInstance\s*\(\s*["\'][^"\']*/ECB/[^"\']*["\']\)',
        re.IGNORECASE,
    )
    # Bare AES transformation string defaults to ECB mode on Android / SunJCE
    BARE_AES = re.compile(
        r'Cipher\.getInstance\s*\(\s*["\']AES["\']\)',
    )

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen: set[str] = set()

        for location, text in _extract_text_targets(context):
            # Check explicit ECB
            for match in self.EXPLICIT_ECB.finditer(text):
                snippet = match.group(0).strip()
                key = f"{location}:{snippet}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        self.create_finding(
                            title=self.title,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=(
                                f"Static inspection detected explicit ECB mode: '{snippet}'. ECB mode does not use "
                                "an Initialization Vector (IV) and encrypts identical plaintext blocks into identical "
                                "ciphertext blocks, preserving data patterns."
                            ),
                            evidence=snippet,
                            location=location,
                            impact="Preserves structural data patterns and enables replay or block-swapping attacks.",
                            remediation="Use authenticated encryption mode AES/GCM/NoPadding with a unique random IV.",
                        )
                    )

            # Check bare "AES" which defaults to ECB
            for match in self.BARE_AES.finditer(text):
                snippet = match.group(0).strip()
                key = f"{location}:{snippet}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        self.create_finding(
                            title="Insecure Cipher Mode: Unspecified Mode Defaults to ECB",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=(
                                "Static inspection detected 'Cipher.getInstance(\"AES\")'. Omitting the mode and padding "
                                "defaults to AES/ECB/PKCS5Padding on standard Android cryptographic providers."
                            ),
                            evidence=snippet,
                            location=location,
                            impact="Unspecified mode defaults to ECB, leaking structural patterns of encrypted plaintext.",
                            remediation="Explicitly specify an authenticated mode: Cipher.getInstance(\"AES/GCM/NoPadding\").",
                        )
                    )

        return findings


class StaticOrWeakIvRule(BaseRule):
    """Detects usage of hardcoded, static, or zero-initialized Initialization Vectors (IVs)."""

    rule_id = "CRY-003"
    title = "Static or Weak Initialization Vector (IV)"
    category = FindingCategory.CRYPTO_FLAW
    default_severity = Severity.HIGH
    description = (
        "Static analysis identified the use of a hardcoded, static, or zero-initialized Initialization Vector (IV). "
        "Static analysis alone cannot determine whether this IV is reused across multiple encryption operations at runtime."
    )
    owasp_reference = "OWASP-M5: Insufficient Cryptography"

    # Matches hardcoded string or byte array in IvParameterSpec
    HARDCODED_IV_INLINE = re.compile(
        r'new\s+IvParameterSpec\s*\(\s*(?:["\'][^"\']+["\']\.getBytes\(\)|new\s+byte\[\]\s*\{[^}]+\}|new\s+byte\[\s*(?:8|12|16)\s*\])\s*\)'
    )
    # Matches zero-initialized array assigned to IvParameterSpec across lines
    ZERO_ARRAY_PATTERN = re.compile(
        r'byte\[\]\s+([a-zA-Z0-9_]+)\s*=\s*new\s+byte\[\s*(?:8|12|16)\s*\];[\s\S]{0,150}?\bnew\s+IvParameterSpec\s*\(\s*\1\s*\)'
    )

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen: set[str] = set()

        for location, text in _extract_text_targets(context):
            # Check inline hardcoded/zero IV
            for match in self.HARDCODED_IV_INLINE.finditer(text):
                snippet = match.group(0).strip()
                key = f"{location}:{snippet}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        self.create_finding(
                            title=self.title,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=(
                                f"Static analysis identified hardcoded or zero-initialized IV: '{snippet}'. "
                                "Using a static or zero IV negates cipher randomness and allows attackers to detect "
                                "whether two plaintexts share common prefixes."
                            ),
                            evidence=snippet,
                            location=location,
                            impact="IV reuse under the same key completely compromises confidentiality in CBC and GCM modes.",
                            remediation=(
                                "Generate a fresh, cryptographically secure random IV for every encryption using "
                                "SecureRandom and store or transmit the IV alongside the ciphertext."
                            ),
                        )
                    )

            # Check zero-initialized byte array passed to IvParameterSpec
            for match in self.ZERO_ARRAY_PATTERN.finditer(text):
                snippet = match.group(0).strip()
                key = f"{location}:{snippet}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        self.create_finding(
                            title="Zero-Initialized Static IV Pattern",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=(
                                "Static inspection detected an all-zero byte array passed to IvParameterSpec. "
                                "Static analysis alone cannot verify whether non-zero data is populated at runtime."
                            ),
                            evidence=snippet,
                            location=location,
                            impact="A static all-zero IV destroys the uniqueness guarantee required by modern cipher modes.",
                            remediation="Initialize the IV using SecureRandom.nextBytes(ivBytes).",
                        )
                    )

        return findings


class HardcodedCryptoKeyRule(BaseRule):
    """Detects hardcoded cryptographic keys directly instantiated in bytecode or strings."""

    rule_id = "CRY-004"
    title = "Hardcoded Cryptographic Key in Code"
    category = FindingCategory.CRYPTO_FLAW
    default_severity = Severity.HIGH
    description = (
        "Static inspection detected a hardcoded secret key instantiated directly into SecretKeySpec. "
        "Static analysis alone cannot determine whether this key is used for test or production data."
    )
    owasp_reference = "OWASP-M5: Insufficient Cryptography"

    HARDCODED_SECRET_KEY_SPEC = re.compile(
        r'new\s+SecretKeySpec\s*\(\s*(?:["\']([^"\']{8,})["\']\.getBytes\(\)|new\s+byte\[\]\s*\{([^}]{16,})\})\s*,\s*["\']([^"\']+)["\']\s*\)'
    )

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen: set[str] = set()

        for location, text in _extract_text_targets(context):
            for match in self.HARDCODED_SECRET_KEY_SPEC.finditer(text):
                raw_str_key = match.group(1)
                raw_byte_key = match.group(2)
                algorithm = match.group(3)

                if raw_str_key:
                    redacted = redact_secret(raw_str_key, prefix_len=2, suffix_len=2)
                    evidence_repr = f'new SecretKeySpec("{redacted}".getBytes(), "{algorithm}")'
                else:
                    redacted = "[STATIC_BYTE_ARRAY]"
                    evidence_repr = f'new SecretKeySpec(new byte[] {{ {redacted} }}, "{algorithm}")'

                key = f"{location}:{algorithm}:{redacted}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        self.create_finding(
                            title=self.title,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=(
                                f"Static inspection detected hardcoded cryptographic key for algorithm '{algorithm}'. "
                                "Static analysis alone cannot determine whether this key is used for production encryption."
                            ),
                            evidence=evidence_repr,
                            location=location,
                            impact=(
                                "Any adversary with access to the APK can extract the embedded key via reverse engineering "
                                "and decrypt stored or transmitted application data."
                            ),
                            remediation=(
                                "Store keys in the hardware-backed Android KeyStore (KeyStore.getInstance(\"AndroidKeyStore\")) "
                                "or derive keys dynamically using PBKDF2/Argon2 from user credentials."
                            ),
                        )
                    )

        return findings


class InsecureContextHashRule(BaseRule):
    """Detects obsolete hash algorithms (MD5, SHA-1) in security-sensitive contexts.
    
    Adheres strictly to conservative detection: ignores normal file checksums,
    cache keys, and non-sensitive hashing.
    """

    rule_id = "CRY-005"
    title = "Obsolete Hash Function in Security Context"
    category = FindingCategory.CRYPTO_FLAW
    default_severity = Severity.MEDIUM
    description = (
        "Static inspection detected the use of an obsolete hash algorithm in a security-sensitive context. "
        "Static analysis alone cannot determine whether this hash is utilized for credential validation at runtime."
    )
    owasp_reference = "OWASP-M5: Insufficient Cryptography"

    HASH_PATTERN = re.compile(
        r'MessageDigest\.getInstance\s*\(\s*["\'](MD5|SHA-1|SHA1)["\']\s*\)',
        re.IGNORECASE,
    )

    SENSITIVE_CONTEXT_KEYWORDS: set[str] = {
        "password",
        "passwd",
        "token",
        "credential",
        "cred",
        "secret",
        "auth",
        "login",
        "pin",
        "signature",
        "sign",
        "private",
    }

    NON_SENSITIVE_KEYWORDS: set[str] = {
        "checksum",
        "etag",
        "cache",
        "cachekey",
        "cache_key",
        "download",
        "filehash",
        "hashfile",
        "fingerprint",
        "asset",
        "url_hash",
        "filename",
        "content_hash",
        "crc",
        "avatar",
        "gravatar",
    }

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen: set[str] = set()

        for location, text in _extract_text_targets(context):
            lines = text.splitlines()
            for idx, line in enumerate(lines):
                match = self.HASH_PATTERN.search(line)
                if match:
                    algo = match.group(1).upper()
                    # Inspect surrounding window of 5 lines before and after
                    start_idx = max(0, idx - 5)
                    end_idx = min(len(lines), idx + 6)
                    window_text = " ".join(lines[start_idx:end_idx]).lower()

                    # Conservative heuristic:
                    # If non-sensitive keywords are present AND sensitive keywords are absent, suppress!
                    has_non_sensitive = any(kw in window_text for kw in self.NON_SENSITIVE_KEYWORDS)
                    matched_sensitive = [kw for kw in self.SENSITIVE_CONTEXT_KEYWORDS if kw in window_text]

                    if has_non_sensitive and not matched_sensitive:
                        # Suppress: standard checksum, cache key, or etag
                        continue

                    # Only flag if there is positive contextual evidence of security/credential use
                    if matched_sensitive:
                        sensitive_kw = matched_sensitive[0]
                        evidence = line.strip()
                        key = f"{location}:{algo}:{sensitive_kw}"
                        if key not in seen:
                            seen.add(key)
                            findings.append(
                                self.create_finding(
                                    title=f"Obsolete Hash Algorithm in Security Context: {algo}",
                                    severity=Severity.MEDIUM,
                                    confidence=Confidence.HIGH,
                                    description=(
                                        f"Static inspection detected '{algo}' hash computation in proximity to security keyword "
                                        f"'{sensitive_kw}'. Static analysis alone cannot verify whether this hash is utilized "
                                        "for credential authentication or integrity validation."
                                    ),
                                    evidence=f"{evidence} (context: '{sensitive_kw}')",
                                    location=f"{location}:line {idx + 1}",
                                    impact=(
                                        f"{algo} is cryptographically broken and vulnerable to collision and pre-image attacks. "
                                        "It is unsuitable for passwords, authentication tokens, or cryptographic signatures."
                                    ),
                                    remediation=(
                                        "Use SHA-256 or SHA-3 for digital signatures and data integrity. Use dedicated "
                                        "salted password hashing functions (Argon2id, PBKDF2WithHmacSHA256, or bcrypt) for credentials."
                                    ),
                                )
                            )

        return findings


class InsecureRandomSeedRule(BaseRule):
    """Detects predictable random number generation patterns and static seeds."""

    rule_id = "CRY-006"
    title = "Insecure Random Number Generator or Static Seed"
    category = FindingCategory.CRYPTO_FLAW
    default_severity = Severity.HIGH
    description = (
        "Static code inspection identified an insecure random number generator pattern. "
        "Static analysis alone cannot determine whether generated values are used for security-critical operations at runtime."
    )
    owasp_reference = "OWASP-M5: Insufficient Cryptography"

    SET_SEED_PATTERN = re.compile(
        r'\b[a-zA-Z0-9_]+\.setSeed\s*\([^)]+\)'
    )
    UTIL_RANDOM_CRYPTO = re.compile(
        r'new\s+Random\s*\(\s*\)[^;]*(?:nextBytes|nextInt)[^;]*(?:key|token|iv|secret|password)',
        re.IGNORECASE,
    )

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen: set[str] = set()

        for location, text in _extract_text_targets(context):
            # Check static seed on SecureRandom
            if "SecureRandom" in text:
                for match in self.SET_SEED_PATTERN.finditer(text):
                    snippet = match.group(0).strip()
                    key = f"{location}:{snippet}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(
                            self.create_finding(
                                title="Static Seed Configured on SecureRandom",
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                description=(
                                    f"Static inspection detected static seed initialization: '{snippet}'. "
                                    "Calling setSeed() on SecureRandom with static data reduces entropy and makes "
                                    "pseudorandom sequences completely predictable."
                                ),
                                evidence=snippet,
                                location=location,
                                impact="Allows attackers to predict cryptographic keys, session IDs, and initialization vectors.",
                                remediation="Do not call setSeed() with static data; rely on default OS entropy for SecureRandom.",
                            )
                        )

            # Check java.util.Random used in security context
            for match in self.UTIL_RANDOM_CRYPTO.finditer(text):
                snippet = match.group(0).strip()
                key = f"{location}:{snippet}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        self.create_finding(
                            title="Insecure java.util.Random Used in Security Context",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=(
                                "Static inspection identified java.util.Random used in proximity to cryptographic keys or tokens. "
                                "Static analysis alone cannot verify runtime execution."
                            ),
                            evidence=snippet,
                            location=location,
                            impact="java.util.Random is a linear congruential generator and is cryptographically insecure.",
                            remediation="Use java.security.SecureRandom for all security-relevant tokens and keys.",
                        )
                    )

        return findings


ALL_CRYPTO_RULES: list[type[BaseRule]] = [
    BrokenCipherRule,
    EcbModeCipherRule,
    StaticOrWeakIvRule,
    HardcodedCryptoKeyRule,
    InsecureContextHashRule,
    InsecureRandomSeedRule,
]
