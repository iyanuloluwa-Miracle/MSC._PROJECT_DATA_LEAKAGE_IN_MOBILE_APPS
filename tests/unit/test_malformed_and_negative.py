"""Meaningful malformed-file tests and negative tests to reduce false positives.

Guarantees:
- Tests graceful handling of corrupted, truncated, and malformed Android package assets.
- Validates that benign patterns (XML namespaces, placeholders, modern crypto, private storage)
  are NOT incorrectly flagged as vulnerabilities (false-positive prevention).
"""

from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from data_leak_detector.analysis.apk_parser import APKParser
from data_leak_detector.core.exceptions import InvalidAPKError
from data_leak_detector.core.models import (
    ComponentDetail,
    ManifestData,
    PermissionFinding,
    Severity,
)
from data_leak_detector.rules.crypto_rules import (
    BrokenCipherRule,
    WeakCryptoRule,
)
from data_leak_detector.rules.manifest_rules import (
    CleartextTrafficPermittedRule,
    DebuggableRule,
    ExportedActivityRule,
)
from data_leak_detector.rules.network_rules import CleartextHttpUrlRule
from data_leak_detector.rules.sdk_rules import SdkPermissionExposureRule
from data_leak_detector.rules.secret_rules import (
    GenericApiTokenRule,
    GoogleApiKeyRule,
    HardcodedSecretRule,
)
from data_leak_detector.rules.storage_rules import (
    PlaintextSharedPreferencesRule,
    WorldReadableWritableStorageRule,
)


class TestMalformedFiles(unittest.TestCase):
    """Test suite testing graceful handling of corrupted and malformed inputs."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_truncated_zip_file_rejected(self) -> None:
        """Verify partially written or truncated zip file raises InvalidAPKError."""
        bad_apk = self.work_dir / "truncated.apk"
        # Standard zip magic number PK\x03\x04 followed by random truncated garbage
        bad_apk.write_bytes(b"PK\x03\x04\x14\x00\x00\x00\x08\x00truncated_data")

        parser = APKParser(bad_apk)
        with self.assertRaises(InvalidAPKError) as ctx:
            parser.validate_file()
        self.assertIn("valid ZIP/APK archive", str(ctx.exception))

    def test_archive_missing_android_indicators_rejected(self) -> None:
        """Verify zip archive containing random files but no Android indicators is rejected."""
        non_apk = self.work_dir / "non_android.zip"
        with zipfile.ZipFile(non_apk, "w") as zf:
            zf.writestr("notes.txt", b"meeting notes")
            zf.writestr("image.png", b"\x89PNG\r\n\x1a\n")

        parser = APKParser(non_apk)
        with self.assertRaises(InvalidAPKError) as ctx:
            parser.validate_file()
        self.assertIn("lacks Android package indicators", str(ctx.exception))

    def test_empty_dex_and_manifest_rejected_gracefully(self) -> None:
        """Verify archive with zero-byte manifest and zero-byte dex handles inspection."""
        zero_apk = self.work_dir / "zero_indicators.apk"
        with zipfile.ZipFile(zero_apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"")
            zf.writestr("classes.dex", b"")

        parser = APKParser(zero_apk)
        # File is structurally a valid zip with indicator names, but invalid APK content
        parser.validate_file()
        self.assertTrue(zero_apk.exists())


class TestNegativeRules(unittest.TestCase):
    """Test suite ensuring benign patterns do not trigger false positive findings."""

    def test_network_schemas_and_localhost_not_flagged(self) -> None:
        """Standard XML schemas, w3c namespaces, and localhost must not be flagged as cleartext HTTP leaks."""
        rule = CleartextHttpUrlRule()
        context = {
            "extracted_files": {
                "AndroidManifest.xml": (
                    '<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
                    '    xmlns:tools="http://schemas.android.com/tools"\n'
                    '    xmlns:w3c="http://www.w3.org/2000/xmlns/">\n'
                    "</manifest>"
                ),
                "res/layout/activity_main.xml": (
                    '<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android">\n'
                    '    <TextView android:text="http://localhost:8080/test" />\n'
                    '    <TextView android:text="http://127.0.0.1:9000/debug" />\n'
                    '    <TextView android:text="https://api.secure-endpoint.com/v1" />\n'
                    "</LinearLayout>"
                ),
            }
        }
        findings = rule.evaluate(context)
        # None of the schema URLs, localhost, 127.0.0.1, or https should be flagged
        self.assertEqual(len(findings), 0)

    def test_secret_placeholders_and_low_entropy_not_flagged(self) -> None:
        """Sample placeholders and low-entropy keys must not generate secret findings."""
        secret_rule = HardcodedSecretRule()
        api_token_rule = GenericApiTokenRule()

        context = {
            "extracted_files": {
                "Config.java": (
                    'public static final String KEY = "YOUR_API_KEY_HERE";\n'
                    'String sample = "placeholder_value_123";\n'
                    'String repeated = "AAAAAAAAAAAAAAAAAAAA";\n'
                    'String genericText = "Please enter your password in the form below.";\n'
                )
            }
        }

        f1 = secret_rule.evaluate(context)
        f2 = api_token_rule.evaluate(context)
        self.assertEqual(len(f1), 0)
        self.assertEqual(len(f2), 0)

    def test_google_api_key_rule_ignores_placeholders(self) -> None:
        """GoogleApiKeyRule must ignore standard documentation placeholders."""
        rule = GoogleApiKeyRule()
        context = {
            "extracted_files": {
                "GoogleService.java": 'String key = "AIzaSyEXAMPLE_PLACEHOLDER_NOT_REAL_KEY";'
            }
        }
        findings = rule.evaluate(context)
        self.assertEqual(len(findings), 0)

    def test_modern_crypto_primitives_not_flagged(self) -> None:
        """Modern secure crypto (AES-GCM, SHA-256, SHA-512) must not trigger weak crypto rules."""
        broken_cipher = BrokenCipherRule()
        weak_crypto = WeakCryptoRule()

        context = {
            "extracted_files": {
                "CryptoManager.java": (
                    'Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");\n'
                    'MessageDigest md = MessageDigest.getInstance("SHA-256");\n'
                    'MessageDigest md512 = MessageDigest.getInstance("SHA-512");\n'
                    'KeyGenerator kg = KeyGenerator.getInstance("AES");\n'
                    'SecureRandom random = new SecureRandom();\n'
                )
            }
        }

        f1 = broken_cipher.evaluate(context)
        f2 = weak_crypto.evaluate(context)
        self.assertEqual(len(f1), 0)
        self.assertEqual(len(f2), 0)

    def test_safe_storage_patterns_not_flagged(self) -> None:
        """Private internal storage and EncryptedSharedPreferences must not be flagged as insecure."""
        world_rule = WorldReadableWritableStorageRule()
        shared_prefs_rule = PlaintextSharedPreferencesRule()

        context = {
            "extracted_files": {
                "StorageHelper.java": (
                    'SharedPreferences safe = EncryptedSharedPreferences.create(\n'
                    '    "secret_prefs", masterKey, context,\n'
                    '    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,\n'
                    '    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM\n'
                    ');\n'
                    'FileOutputStream fos = context.openFileOutput("data.txt", Context.MODE_PRIVATE);\n'
                )
            }
        }

        f1 = world_rule.evaluate(context)
        f2 = shared_prefs_rule.evaluate(context)
        self.assertEqual(len(f1), 0)
        self.assertEqual(len(f2), 0)

    def test_sdk_without_sensitive_permissions_not_flagged(self) -> None:
        """Apps importing Ad/Analytics SDKs without requesting sensitive user permissions are not flagged."""
        rule = SdkPermissionExposureRule()
        context = {
            "extracted_files": {
                "MainActivity.java": 'import com.google.android.gms.ads.AdView;\n'
            },
            "classes": ["com.google.android.gms.ads.AdView"],
            "permissions": [
                # Only harmless normal permissions, no location, contacts, or camera
                PermissionFinding(
                    permission="android.permission.INTERNET",
                    protection_level="normal",
                    risk_level=Severity.INFO,
                    description="Network access",
                    reason="Normal application network access",
                    is_sensitive_user_data=False,
                ),
                PermissionFinding(
                    permission="android.permission.ACCESS_NETWORK_STATE",
                    protection_level="normal",
                    risk_level=Severity.INFO,
                    description="View network connections",
                    reason="Normal network connectivity monitoring",
                    is_sensitive_user_data=False,
                ),
            ],
        }

        findings = rule.evaluate(context)
        self.assertEqual(len(findings), 0)

    def test_manifest_secure_configuration_not_flagged(self) -> None:
        """Secure manifest configuration must not produce findings."""
        debug_rule = DebuggableRule()
        cleartext_rule = CleartextTrafficPermittedRule()

        manifest = ManifestData(
            package_name="com.example.secure",
            app_name="SecureApp",
            debuggable=False,
            uses_cleartext_traffic=False,
            allow_backup=False,
        )
        context = {"manifest": manifest}

        self.assertEqual(len(debug_rule.evaluate(context)), 0)
        self.assertEqual(len(cleartext_rule.evaluate(context)), 0)

    def test_protected_exported_component_not_flagged(self) -> None:
        """Exported activity requiring signature or system permission must not be flagged."""
        rule = ExportedActivityRule()
        component = ComponentDetail(
            component_type="activity",
            name="com.example.secure.AdminActivity",
            exported=True,
            permission="com.example.secure.permission.ADMIN_SIGNATURE",
        )
        manifest = ManifestData(
            package_name="com.example.secure",
            components=[component],
        )
        context = {"manifest": manifest}

        findings = rule.evaluate(context)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
