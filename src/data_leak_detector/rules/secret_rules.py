"""Static analysis security rules detecting embedded credentials, API keys, and secrets."""

from __future__ import annotations

import logging
import re
from typing import Any, Iterable, Sequence

from data_leak_detector.core.models import (
    Confidence,
    FindingCategory,
    ParsedAPKData,
    SecurityFinding,
    Severity,
)
from data_leak_detector.core.redactor import (
    calculate_shannon_entropy,
    is_placeholder_or_sample,
    redact_secret,
)
from data_leak_detector.rules.base import BaseRule


logger = logging.getLogger(__name__)


def _extract_text_targets(context: Any) -> list[tuple[str, str]]:
    """Helper extracting (source_location, text_content) pairs from analysis context.
    
    Searches:
    - String literals list/set
    - Raw manifest XML
    - Decompiled files or source dictionary
    """
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

        # Generic raw content
        if "text_content" in context and isinstance(context["text_content"], str):
            targets.append(("TextContent", context["text_content"]))

    return targets


class GoogleApiKeyRule(BaseRule):
    """Detects embedded Google Cloud / Firebase API keys."""

    rule_id = "SEC-001"
    title = "Hardcoded Google API Key"
    category = FindingCategory.HARDCODED_SECRET
    default_severity = Severity.HIGH
    description = "Statically embedded Google / Firebase API key detected in resources or bytecode."
    owasp_reference = "OWASP-M9: Reverse Engineering"

    PATTERN = re.compile(r"\b(AIza[0-9A-Za-z\-_]{30,45})\b")

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen: set[str] = set()

        for location, text in _extract_text_targets(context):
            for match in self.PATTERN.finditer(text):
                raw_key = match.group(1)
                if raw_key in seen:
                    continue
                seen.add(raw_key)

                # Filter false positives: placeholders or low entropy
                if is_placeholder_or_sample(raw_key):
                    continue
                if calculate_shannon_entropy(raw_key) < 3.0:
                    continue

                redacted = redact_secret(raw_key, prefix_len=8, suffix_len=3)
                findings.append(
                    self.create_finding(
                        title=self.title,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=(
                            "A statically embedded Google API key was discovered. Depending on API "
                            "restrictions, this key may allow unauthorized access to billable cloud services."
                        ),
                        evidence=f"API Key: {redacted}",
                        location=location,
                        impact="Potential quota exhaustion, billable service abuse, or data access.",
                        remediation=(
                            "Apply strict package-name and SHA-1 certificate restrictions in Google Cloud Console. "
                            "Never embed unrestricted cloud keys in mobile client binaries."
                        ),
                    )
                )
        return findings


class AwsCredentialRule(BaseRule):
    """Detects embedded AWS Access Key IDs and secret credentials."""

    rule_id = "SEC-002"
    title = "Hardcoded AWS Cloud Credential"
    category = FindingCategory.HARDCODED_SECRET
    default_severity = Severity.CRITICAL
    description = "Statically embedded AWS access key or secret credential detected."
    owasp_reference = "OWASP-M9: Reverse Engineering"

    KEY_ID_PATTERN = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
    SECRET_PATTERN = re.compile(
        r"(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"
    )

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen: set[str] = set()

        for location, text in _extract_text_targets(context):
            # AWS Access Key ID
            for match in self.KEY_ID_PATTERN.finditer(text):
                raw_val = match.group(1)
                if raw_val in seen:
                    continue
                seen.add(raw_val)

                if is_placeholder_or_sample(raw_val) or calculate_shannon_entropy(raw_val) < 2.5:
                    continue

                redacted = redact_secret(raw_val, prefix_len=6, suffix_len=2)
                findings.append(
                    self.create_finding(
                        title="Hardcoded AWS Access Key ID",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description="Statically embedded AWS Access Key ID detected.",
                        evidence=f"AWS Key ID: {redacted}",
                        location=location,
                        impact="Allows programmatic interaction with AWS cloud APIs if paired with secret.",
                        remediation=(
                            "Revoke this access key immediately in AWS IAM. Use Amazon Cognito identity pools "
                            "for temporary, role-based mobile credentials."
                        ),
                    )
                )

            # AWS Secret Access Key
            for match in self.SECRET_PATTERN.finditer(text):
                raw_secret = match.group(1)
                if raw_secret in seen:
                    continue
                seen.add(raw_secret)

                if is_placeholder_or_sample(raw_secret) or calculate_shannon_entropy(raw_secret) < 3.2:
                    continue

                redacted = redact_secret(raw_secret, prefix_len=6, suffix_len=3)
                findings.append(
                    self.create_finding(
                        title="Hardcoded AWS Secret Access Key",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        description="Statically embedded AWS Secret Access Key detected.",
                        evidence=f"AWS Secret Key: {redacted}",
                        location=location,
                        impact="Complete administrative compromise of AWS account resources.",
                        remediation="Immediately revoke key in AWS IAM and inspect CloudTrail audit logs.",
                    )
                )
        return findings


class PrivateKeyMaterialRule(BaseRule):
    """Detects embedded PEM private keys (RSA, EC, DSA, OpenSSH)."""

    rule_id = "SEC-003"
    title = "Hardcoded Cryptographic Private Key Material"
    category = FindingCategory.HARDCODED_SECRET
    default_severity = Severity.CRITICAL
    description = "Statically embedded cryptographic private key block detected in binary or resources."
    owasp_reference = "OWASP-M9: Reverse Engineering"

    PATTERN = re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]{20,250}-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    )

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen: set[str] = set()

        for location, text in _extract_text_targets(context):
            for match in self.PATTERN.finditer(text):
                block = match.group(0)
                if block in seen:
                    continue
                seen.add(block)

                if "test" in block.lower() and "placeholder" in block.lower():
                    continue

                # Redact inner key block
                header = block.split("\n")[0] if "\n" in block else "-----BEGIN PRIVATE KEY-----"
                evidence = f"{header} [REDACTED_PRIVATE_KEY_BYTES]"

                findings.append(
                    self.create_finding(
                        title=self.title,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        description="Statically embedded cryptographic private key block was found in the package.",
                        evidence=evidence,
                        location=location,
                        impact=(
                            "Allows adversaries to decrypt confidential communications, forge digital signatures, "
                            "or impersonate trusted backend infrastructure."
                        ),
                        remediation=(
                            "Never distribute private keys inside client applications. Store private keys exclusively "
                            "in Hardware Security Modules (HSM) or secure server infrastructure."
                        ),
                    )
                )
        return findings


class OAuthClientSecretRule(BaseRule):
    """Detects embedded OAuth client secrets and credentials."""

    rule_id = "SEC-004"
    title = "Hardcoded OAuth Client Secret"
    category = FindingCategory.HARDCODED_SECRET
    default_severity = Severity.HIGH
    description = "Statically embedded OAuth client secret or client credential assignment."
    owasp_reference = "OWASP-M9: Reverse Engineering"

    PATTERN = re.compile(
        r"(?i)(?:client_secret|clientsecret|oauth_secret)\s*[:=]\s*[\"']([A-Za-z0-9_\-\.]{16,80})[\"']"
    )

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen: set[str] = set()

        for location, text in _extract_text_targets(context):
            for match in self.PATTERN.finditer(text):
                raw_secret = match.group(1)
                if raw_secret in seen:
                    continue
                seen.add(raw_secret)

                if is_placeholder_or_sample(raw_secret) or calculate_shannon_entropy(raw_secret) < 2.8:
                    continue

                redacted = redact_secret(raw_secret, prefix_len=4, suffix_len=3)
                findings.append(
                    self.create_finding(
                        title=self.title,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description="Statically embedded OAuth client secret was discovered.",
                        evidence=f"client_secret = \"{redacted}\"",
                        location=location,
                        impact=(
                            "Allows rogue applications to impersonate the client application in OAuth flows, "
                            "enabling authorization code interception and token issuance."
                        ),
                        remediation=(
                            "Use PKCE (Proof Key for Code Exchange) with public clients instead of client secrets. "
                            "Client secrets cannot be kept confidential in decompilable mobile binaries."
                        ),
                    )
                )
        return findings


class DatabaseCredentialRule(BaseRule):
    """Detects embedded database connection strings containing credentials."""

    rule_id = "SEC-005"
    title = "Hardcoded Database Connection URI"
    category = FindingCategory.HARDCODED_SECRET
    default_severity = Severity.CRITICAL
    description = "Statically embedded database connection string with plaintext credentials."
    owasp_reference = "OWASP-M2: Insecure Data Storage"

    PATTERN = re.compile(
        r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|oracle)://([^:\s/]+):([^@\s/]+)@([^/\s:]+)(?::[0-9]+)?/[^\s\"']+)\b",
        re.IGNORECASE,
    )

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen: set[str] = set()

        for location, text in _extract_text_targets(context):
            for match in self.PATTERN.finditer(text):
                full_uri = match.group(1)
                scheme = full_uri.split("://")[0]
                user = match.group(2)
                password = match.group(3)
                host = match.group(4)

                if full_uri in seen or is_placeholder_or_sample(password):
                    continue
                seen.add(full_uri)

                redacted_pass = redact_secret(password, prefix_len=2, suffix_len=1)
                redacted_uri = f"{scheme}://{user}:{redacted_pass}@{host}/..."

                findings.append(
                    self.create_finding(
                        title=self.title,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        description="Direct database connection URI with embedded credentials detected.",
                        evidence=f"Database URI: {redacted_uri}",
                        location=location,
                        impact="Direct external access to backend production database with user credentials.",
                        remediation=(
                            "Never connect mobile clients directly to SQL/NoSQL databases. Route all data requests "
                            "through an authenticated REST or GraphQL backend API."
                        ),
                    )
                )
        return findings


class HardcodedPasswordRule(BaseRule):
    """Detects hardcoded password variable assignments."""

    rule_id = "SEC-006"
    title = "Hardcoded Password / Static Credential"
    category = FindingCategory.HARDCODED_SECRET
    default_severity = Severity.HIGH
    description = "Statically embedded password assignment discovered in strings or source code."
    owasp_reference = "OWASP-M9: Reverse Engineering"

    PATTERN = re.compile(
        r"(?i)\b(password|passwd|master_key|admin_pass)\s*[:=]\s*[\"']([^\"'\s]{8,64})[\"']"
    )

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen: set[str] = set()

        for location, text in _extract_text_targets(context):
            for match in self.PATTERN.finditer(text):
                var_name = match.group(1)
                raw_pwd = match.group(2)
                if raw_pwd in seen:
                    continue
                seen.add(raw_pwd)

                if is_placeholder_or_sample(raw_pwd) or calculate_shannon_entropy(raw_pwd) < 2.5:
                    continue

                redacted = redact_secret(raw_pwd, prefix_len=2, suffix_len=2)
                findings.append(
                    self.create_finding(
                        title=self.title,
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        description=f"Static credential assignment for '{var_name}' identified.",
                        evidence=f"{var_name} = \"{redacted}\"",
                        location=location,
                        impact="Static credentials can be retrieved by decompiling the APK.",
                        remediation="Do not hardcode credentials. Prompt the user or use Android KeyStore.",
                    )
                )
        return findings


class GenericApiTokenRule(BaseRule):
    """Detects generic high-entropy API tokens, JWTs, and bearer tokens."""

    rule_id = "SEC-007"
    title = "Hardcoded API Token / Bearer Token"
    category = FindingCategory.HARDCODED_SECRET
    default_severity = Severity.HIGH
    description = "High-entropy API token or authorization credential assignment detected."
    owasp_reference = "OWASP-M9: Reverse Engineering"

    PATTERN = re.compile(
        r"(?i)\b(api_key|apikey|auth_token|bearer_token|access_token|secret_key)\s*[:=]\s*[\"']([A-Za-z0-9_\-\.]{20,256})[\"']"
    )

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        seen: set[str] = set()

        for location, text in _extract_text_targets(context):
            for match in self.PATTERN.finditer(text):
                var_name = match.group(1)
                raw_token = match.group(2)
                if raw_token in seen:
                    continue
                seen.add(raw_token)

                if is_placeholder_or_sample(raw_token):
                    continue
                if calculate_shannon_entropy(raw_token) < 3.0:
                    continue

                redacted = redact_secret(raw_token, prefix_len=4, suffix_len=3)
                findings.append(
                    self.create_finding(
                        title=self.title,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=f"Static token assignment for '{var_name}' identified with high entropy.",
                        evidence=f"{var_name} = \"{redacted}\"",
                        location=location,
                        impact="Permits unauthorized access to remote backend APIs with service privileges.",
                        remediation="Obtain tokens dynamically via secure user authentication; never hardcode tokens.",
                    )
                )
        return findings


class HardcodedSecretRule(BaseRule):
    """Composite rule coordinating all embedded secret and credential detection rules."""

    rule_id = "SEC-000"
    title = "Embedded Secret & Credential Scanner"
    category = FindingCategory.HARDCODED_SECRET
    default_severity = Severity.HIGH
    description = "Comprehensive scanner detecting hardcoded API keys, cloud tokens, and passwords."
    owasp_reference = "OWASP-M9: Reverse Engineering"

    def __init__(self) -> None:
        self.sub_rules: list[BaseRule] = [
            GoogleApiKeyRule(),
            AwsCredentialRule(),
            PrivateKeyMaterialRule(),
            OAuthClientSecretRule(),
            DatabaseCredentialRule(),
            HardcodedPasswordRule(),
            GenericApiTokenRule(),
        ]

    def evaluate(self, context: Any) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        for rule in self.sub_rules:
            findings.extend(rule.evaluate(context))
        return findings


ALL_SECRET_RULES: list[type[BaseRule]] = [
    GoogleApiKeyRule,
    AwsCredentialRule,
    PrivateKeyMaterialRule,
    OAuthClientSecretRule,
    DatabaseCredentialRule,
    HardcodedPasswordRule,
    GenericApiTokenRule,
]

