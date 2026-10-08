"""Unit tests for static storage security rules.

Tests positive detection and negative/suppression cases for:
- World-readable / world-writable legacy file modes
- Sensitive data stored on external storage
- Plaintext SharedPreferences with sensitive keys vs EncryptedSharedPreferences
- Plaintext SQLite schemas with sensitive columns vs SQLCipher
- Sensitive information logged to logcat vs non-sensitive logging
- Sensitive cache storage vs non-sensitive cache
"""

from __future__ import annotations

import unittest

from data_leak_detector.core.models import FindingCategory, Severity
from data_leak_detector.rules.storage_rules import (
    ALL_STORAGE_RULES,
    ExternalStorageSensitiveDataRule,
    InsecureStorageRule,
    PlaintextDatabaseSensitiveDataRule,
    PlaintextSharedPreferencesRule,
    SensitiveCacheStorageRule,
    SensitiveInformationLoggingRule,
    WorldReadableWritableStorageRule,
)


class TestStorageRules(unittest.TestCase):
    # -----------------------------------------------------------------------
    # World-Readable / World-Writable Mode Tests
    # -----------------------------------------------------------------------

    def test_world_readable_constant_positive(self) -> None:
        rule = WorldReadableWritableStorageRule()
        code = """
        FileOutputStream fos = openFileOutput("shared_data.xml", Context.MODE_WORLD_READABLE);
        SharedPreferences sp = getSharedPreferences("prefs", MODE_WORLD_WRITEABLE);
        """
        findings = rule.evaluate({"files": {"StorageHelper.java": code}})
        self.assertEqual(len(findings), 2)
        for f in findings:
            self.assertEqual(f.category, FindingCategory.STORAGE_INSECURITY)
            self.assertEqual(f.severity, Severity.HIGH)
            self.assertIn("Static", f.description)
            self.assertTrue(len(f.remediation) > 0)

    def test_world_readable_numeric_flag_positive(self) -> None:
        rule = WorldReadableWritableStorageRule()
        code = 'FileOutputStream fos = openFileOutput("config.txt", 1);'
        findings = rule.evaluate({"files": {"App.java": code}})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("MODE_WORLD_READABLE (1)", findings[0].description)

    def test_private_mode_negative(self) -> None:
        rule = WorldReadableWritableStorageRule()
        code = """
        FileOutputStream fos = openFileOutput("secure.dat", Context.MODE_PRIVATE);
        SharedPreferences sp = getSharedPreferences("app_prefs", 0);
        """
        findings = rule.evaluate({"files": {"SecureStorage.java": code}})
        self.assertEqual(findings, [])

    # -----------------------------------------------------------------------
    # External Storage Sensitive Data Tests
    # -----------------------------------------------------------------------

    def test_external_storage_sensitive_data_positive(self) -> None:
        rule = ExternalStorageSensitiveDataRule()
        code = """
        File externalDir = Environment.getExternalStorageDirectory();
        File tokenFile = new File(externalDir, "user_token.json");
        saveAuthToken(tokenFile, token);
        """
        findings = rule.evaluate({"files": {"AuthManager.java": code}})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("Static analysis detected external storage access", findings[0].description)
        self.assertIn("token", findings[0].evidence)

    def test_external_storage_non_sensitive_negative(self) -> None:
        rule = ExternalStorageSensitiveDataRule()
        code = """
        File publicDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES);
        File photo = new File(publicDir, "camera_capture_001.jpg");
        """
        findings = rule.evaluate({"files": {"CameraActivity.java": code}})
        self.assertEqual(findings, [])

    # -----------------------------------------------------------------------
    # Plaintext SharedPreferences Tests
    # -----------------------------------------------------------------------

    def test_plaintext_shared_preferences_positive(self) -> None:
        rule = PlaintextSharedPreferencesRule()
        code = """
        SharedPreferences.Editor editor = preferences.edit();
        editor.putString("password", userPassword);
        editor.putString("auth_token", sessionToken);
        editor.apply();
        """
        findings = rule.evaluate({"files": {"LoginManager.java": code}})
        self.assertEqual(len(findings), 2)
        for f in findings:
            self.assertEqual(f.severity, Severity.MEDIUM)
            self.assertIn("Static analysis detected unencrypted SharedPreferences", f.description)
            self.assertTrue(len(f.remediation) > 0)

    def test_encrypted_shared_preferences_negative(self) -> None:
        rule = PlaintextSharedPreferencesRule()
        code = """
        SharedPreferences sp = EncryptedSharedPreferences.create(
            "secret_shared_prefs",
            masterKeyAlias,
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );
        sp.edit().putString("password", userPassword).apply();
        """
        findings = rule.evaluate({"files": {"SecurePrefs.java": code}})
        self.assertEqual(findings, [])

    # -----------------------------------------------------------------------
    # Plaintext SQLite Database Tests
    # -----------------------------------------------------------------------

    def test_plaintext_database_sensitive_column_positive(self) -> None:
        rule = PlaintextDatabaseSensitiveDataRule()
        code = """
        String sql = "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, ssn TEXT)";
        db.execSQL(sql);
        """
        findings = rule.evaluate({"files": {"DatabaseHelper.java": code}})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("password", findings[0].evidence)
        self.assertTrue(len(findings[0].remediation) > 0)

    def test_sqlcipher_database_negative(self) -> None:
        rule = PlaintextDatabaseSensitiveDataRule()
        code = """
        import net.sqlcipher.database.SQLiteDatabase;
        String sql = "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)";
        db.execSQL(sql);
        """
        findings = rule.evaluate({"files": {"EncryptedDbHelper.java": code}})
        self.assertEqual(findings, [])

    def test_database_non_sensitive_schema_negative(self) -> None:
        rule = PlaintextDatabaseSensitiveDataRule()
        code = 'String sql = "CREATE TABLE article_cache (id INTEGER PRIMARY KEY, title TEXT, body TEXT)";'
        findings = rule.evaluate({"files": {"NewsDb.java": code}})
        self.assertEqual(findings, [])

    # -----------------------------------------------------------------------
    # Sensitive Information Logging Tests
    # -----------------------------------------------------------------------

    def test_sensitive_logging_positive(self) -> None:
        rule = SensitiveInformationLoggingRule()
        code = """
        Log.d("Auth", "User authentication token: " + token);
        System.out.println("DEBUG: user password is " + password);
        """
        findings = rule.evaluate({"files": {"Authenticator.java": code}})
        self.assertEqual(len(findings), 2)
        for f in findings:
            self.assertEqual(f.severity, Severity.MEDIUM)
            self.assertIn("Static inspection detected logging call", f.description)
            self.assertTrue(len(f.remediation) > 0)

    def test_non_sensitive_logging_negative(self) -> None:
        rule = SensitiveInformationLoggingRule()
        code = """
        Log.d("MainActivity", "Activity onResume called");
        Log.i("Network", "HTTP request completed with status 200");
        System.out.println("Processing finished successfully.");
        """
        findings = rule.evaluate({"files": {"MainActivity.java": code}})
        self.assertEqual(findings, [])

    # -----------------------------------------------------------------------
    # Sensitive Cache Storage Tests
    # -----------------------------------------------------------------------

    def test_sensitive_cache_storage_positive(self) -> None:
        rule = SensitiveCacheStorageRule()
        code = """
        File cache = context.getCacheDir();
        File tokenCache = new File(cache, "auth_token_cache.dat");
        writeBytes(tokenCache, tokenData);
        """
        findings = rule.evaluate({"files": {"CacheManager.java": code}})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.MEDIUM)
        self.assertIn("token", findings[0].evidence)

    def test_non_sensitive_cache_negative(self) -> None:
        rule = SensitiveCacheStorageRule()
        code = """
        File cache = context.getCacheDir();
        File imageCache = new File(cache, "thumbnails");
        imageCache.mkdirs();
        """
        findings = rule.evaluate({"files": {"ImageLoader.java": code}})
        self.assertEqual(findings, [])

    # -----------------------------------------------------------------------
    # Rule Metadata & Alias Verification
    # -----------------------------------------------------------------------

    def test_all_storage_rules_instantiation(self) -> None:
        for rule_cls in ALL_STORAGE_RULES:
            rule = rule_cls()
            self.assertTrue(rule.rule_id.startswith("STO-"))
            self.assertTrue(len(rule.title) > 0)
            self.assertEqual(rule.category, FindingCategory.STORAGE_INSECURITY)
            self.assertTrue(callable(rule.evaluate))

    def test_backwards_compatible_alias(self) -> None:
        self.assertIs(InsecureStorageRule, WorldReadableWritableStorageRule)


if __name__ == "__main__":
    unittest.main()
