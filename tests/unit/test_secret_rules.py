"""Unit tests for secret detection rules, entropy verification, and strict redaction privacy guarantees."""

from __future__ import annotations

import io
import logging
import unittest

from data_leak_detector.core.logging_config import SensitiveDataFilter
from data_leak_detector.core.models import Severity
from data_leak_detector.core.redactor import (
    calculate_shannon_entropy,
    is_placeholder_or_sample,
    redact_secret,
)
from data_leak_detector.rules.secret_rules import (
    AwsCredentialRule,
    DatabaseCredentialRule,
    GenericApiTokenRule,
    GoogleApiKeyRule,
    HardcodedPasswordRule,
    HardcodedSecretRule,
    OAuthClientSecretRule,
    PrivateKeyMaterialRule,
)


class TestSecretRules(unittest.TestCase):
    def test_redact_secret_exact_format(self) -> None:
        # User specified example:
        # Original: AIzaSyABC123456789XYZ
        # Displayed: AIzaSyAB********XYZ
        original = "AIzaSyABC123456789XYZ"
        redacted = redact_secret(original, prefix_len=8, suffix_len=3)
        self.assertEqual(redacted, "AIzaSyAB********XYZ")
        self.assertNotIn("123456789", redacted)

    def test_redact_secret_short_values(self) -> None:
        short = "secret"
        redacted = redact_secret(short)
        self.assertEqual(redacted, "********")
        self.assertNotIn("secret", redacted)

    def test_entropy_and_placeholder_filtering(self) -> None:
        # Low entropy / repeated
        low_ent = "AAAAAAAAAAAAAAAAAAAA"
        self.assertLess(calculate_shannon_entropy(low_ent), 1.0)
        self.assertTrue(is_placeholder_or_sample(low_ent))

        # Obvious placeholders
        self.assertTrue(is_placeholder_or_sample("your_api_key_here"))
        self.assertTrue(is_placeholder_or_sample("INSERT_YOUR_SECRET_KEY"))
        self.assertTrue(is_placeholder_or_sample("test_dummy_key_12345"))
        self.assertTrue(is_placeholder_or_sample("dummy_placeholder_token"))
        self.assertTrue(is_placeholder_or_sample("change_me"))

        # Real high-entropy string
        high_ent = "AIzaSyBwK910xVzP9L2mNtQ4rUx-78YZaBcDeF"
        self.assertGreater(calculate_shannon_entropy(high_ent), 3.5)
        self.assertFalse(is_placeholder_or_sample(high_ent))

    def test_google_api_key_rule_detection_and_redaction(self) -> None:
        rule = GoogleApiKeyRule()
        # High entropy non-placeholder key
        raw_key = "AIzaSyBwK910xVzP9L2mNtQ4rUx-78YZaBcDeF"
        context = {
            "strings": [
                f"apiKey = '{raw_key}';",
                "normal_string_value",
            ]
        }

        findings = rule.evaluate(context)
        self.assertEqual(len(findings), 1)
        finding = findings[0]

        # Privacy guarantee: Raw key must NEVER appear in any finding attribute
        self.assertNotIn(raw_key, finding.evidence)
        self.assertNotIn(raw_key, finding.description)
        self.assertNotIn(raw_key, finding.title)
        self.assertIn("AIzaSyBw********DeF", finding.evidence)
        self.assertEqual(finding.severity, Severity.HIGH)

    def test_google_api_key_placeholder_ignored(self) -> None:
        rule = GoogleApiKeyRule()
        context = {
            "strings": [
                "AIzaSyExamplePlaceholderKey1234567890",
                "AIzaSyTestKeyHere00000000000000000000",
            ]
        }
        self.assertEqual(len(rule.evaluate(context)), 0)

    def test_aws_credential_rule_detection_and_redaction(self) -> None:
        rule = AwsCredentialRule()
        # Constructed dynamically to prevent push protection scanner false positives on mock test data
        raw_key_id = "AKIA" + "IOSFODNN7" + "9876543"
        raw_secret = "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCY" + "9876543210"
        context = {
            "files": {
                "AwsConfig.java": f'aws_access_key_id = "{raw_key_id}";\naws_secret_access_key = "{raw_secret}";'
            }
        }

        findings = rule.evaluate(context)
        self.assertEqual(len(findings), 2)

        for f in findings:
            self.assertNotIn(raw_key_id, f.evidence)
            self.assertNotIn(raw_secret, f.evidence)
            self.assertIn("********", f.evidence)

    def test_private_key_material_rule(self) -> None:
        rule = PrivateKeyMaterialRule()
        raw_pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Y7Z5Xz9rQ8K...\n"
            "MIIEowIBAAKCAQEA0Y7Z5Xz9rQ8K...\n"
            "-----END RSA PRIVATE KEY-----"
        )
        context = {"strings": [raw_pem]}

        findings = rule.evaluate(context)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, Severity.CRITICAL)
        self.assertNotIn("MIIEowIBAAKCAQEA0Y7Z5Xz9rQ8K", f.evidence)
        self.assertIn("[REDACTED_PRIVATE_KEY_BYTES]", f.evidence)

    def test_oauth_client_secret_rule(self) -> None:
        rule = OAuthClientSecretRule()
        raw_secret = "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d"
        context = {"strings": [f'client_secret = "{raw_secret}"']}

        findings = rule.evaluate(context)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertNotIn(raw_secret, f.evidence)
        self.assertIn("client_secret = \"9a8b********c4d\"", f.evidence)

    def test_database_credential_rule(self) -> None:
        rule = DatabaseCredentialRule()
        raw_uri = "postgresql://prod_user:SuperSecretPassword99!@db.internal:5432/customer_db"
        context = {"strings": [raw_uri]}

        findings = rule.evaluate(context)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, Severity.CRITICAL)
        self.assertNotIn("SuperSecretPassword99!", f.evidence)
        self.assertIn("postgresql://prod_user:Su********!@db.internal/...", f.evidence)

    def test_hardcoded_password_rule(self) -> None:
        rule = HardcodedPasswordRule()
        context = {"strings": ['password = "MyComplexP@ssw0rd99!"']}

        findings = rule.evaluate(context)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertNotIn("MyComplexP@ssw0rd99!", f.evidence)
        self.assertIn("password = \"My********9!\"", f.evidence)

    def test_generic_api_token_rule(self) -> None:
        rule = GenericApiTokenRule()
        raw_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMC6Y53Oi3MTVwpMLUyDDnSiQ"
        context = {"strings": [f'auth_token = "{raw_token}"']}

        findings = rule.evaluate(context)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertNotIn(raw_token, f.evidence)
        self.assertIn("auth_token = \"eyJh********SiQ\"", f.evidence)

    def test_composite_hardcoded_secret_rule(self) -> None:
        rule = HardcodedSecretRule()
        raw_gkey = "AIzaSyBwK910xVzP9L2mNtQ4rUx-78YZaBcDeF"
        raw_db = "mysql://root:ComplexPasswd992@db.host.com/db"
        context = {
            "strings": [
                f"google_key = '{raw_gkey}'",
                f"db_url = '{raw_db}'",
            ]
        }
        findings = rule.evaluate(context)
        self.assertEqual(len(findings), 2)
        for f in findings:
            self.assertNotIn(raw_gkey, f.evidence)
            self.assertNotIn("ComplexPasswd992", f.evidence)

    def test_application_logs_redaction(self) -> None:
        log_stream = io.StringIO()
        handler = logging.StreamHandler(log_stream)
        handler.addFilter(SensitiveDataFilter())

        test_logger = logging.getLogger("test_redact_logger")
        test_logger.setLevel(logging.INFO)
        test_logger.addHandler(handler)

        raw_secret = "AIzaSyD3x9ExampleKey1234567890abcdef"
        test_logger.info(f"Scanning target, matched token: {raw_secret} and password=SecretPass123")

        output = log_stream.getvalue()
        self.assertNotIn(raw_secret, output)
        self.assertIn("[REDACTED_SECRET]", output)


if __name__ == "__main__":
    unittest.main()
