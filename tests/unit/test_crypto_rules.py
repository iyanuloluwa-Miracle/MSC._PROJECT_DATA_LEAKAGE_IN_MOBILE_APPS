"""Unit tests for static cryptography security rules.

Tests positive detection and negative/suppression cases for:
- Broken/deprecated ciphers (DES, 3DES, RC4, Blowfish) vs modern ciphers (AES-GCM)
- ECB cipher mode (explicit and bare AES) vs authenticated GCM mode
- Static / zero IV usage vs dynamic SecureRandom IVs
- Hardcoded cryptographic secret keys (and verifies key redaction)
- Obsolete hashing (MD5/SHA-1) in security-sensitive contexts vs non-sensitive file checksums/cache keys
- Static seeds on SecureRandom vs standard entropy sources
"""

from __future__ import annotations

import unittest

from data_leak_detector.core.models import FindingCategory, Severity
from data_leak_detector.rules.crypto_rules import (
    ALL_CRYPTO_RULES,
    BrokenCipherRule,
    EcbModeCipherRule,
    HardcodedCryptoKeyRule,
    InsecureContextHashRule,
    InsecureRandomSeedRule,
    StaticOrWeakIvRule,
    WeakCryptoRule,
)


class TestCryptoRules(unittest.TestCase):
    # -----------------------------------------------------------------------
    # Broken Ciphers (DES, 3DES, RC4, Blowfish) Tests
    # -----------------------------------------------------------------------

    def test_broken_ciphers_positive(self) -> None:
        rule = BrokenCipherRule()
        code = """
        Cipher des = Cipher.getInstance("DES/CBC/PKCS5Padding");
        Cipher tripleDes = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        Cipher rc4 = Cipher.getInstance("RC4");
        Cipher blowfish = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
        """
        findings = rule.evaluate({"files": {"CryptoHelper.java": code}})
        self.assertEqual(len(findings), 4)
        for f in findings:
            self.assertEqual(f.category, FindingCategory.CRYPTO_FLAW)
            self.assertEqual(f.severity, Severity.HIGH)
            self.assertIn("Static inspection detected instantiation of deprecated cipher", f.description)
            self.assertTrue(len(f.remediation) > 0)

    def test_modern_cipher_negative(self) -> None:
        rule = BrokenCipherRule()
        code = """
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        Cipher chacha = Cipher.getInstance("ChaCha20-Poly1305");
        """
        findings = rule.evaluate({"files": {"SecureCipher.java": code}})
        self.assertEqual(findings, [])

    # -----------------------------------------------------------------------
    # Insecure ECB Mode Tests
    # -----------------------------------------------------------------------

    def test_explicit_ecb_mode_positive(self) -> None:
        rule = EcbModeCipherRule()
        code = 'Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");'
        findings = rule.evaluate({"files": {"Encryptor.java": code}})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("ECB mode does not use an Initialization Vector", findings[0].description)
        self.assertTrue(len(findings[0].remediation) > 0)

    def test_bare_aes_defaults_to_ecb_positive(self) -> None:
        rule = EcbModeCipherRule()
        code = 'Cipher c = Cipher.getInstance("AES");'
        findings = rule.evaluate({"files": {"LegacyCrypt.java": code}})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("defaults to AES/ECB/PKCS5Padding", findings[0].description)

    def test_gcm_mode_negative(self) -> None:
        rule = EcbModeCipherRule()
        code = 'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");'
        findings = rule.evaluate({"files": {"ModernCrypt.java": code}})
        self.assertEqual(findings, [])

    # -----------------------------------------------------------------------
    # Static / Weak IV Tests
    # -----------------------------------------------------------------------

    def test_static_byte_array_iv_positive(self) -> None:
        rule = StaticOrWeakIvRule()
        code = """
        byte[] ivBytes = "1234567890123456".getBytes();
        IvParameterSpec iv = new IvParameterSpec("static_iv_secret".getBytes());
        """
        findings = rule.evaluate({"files": {"IvManager.java": code}})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("hardcoded or zero-initialized IV", findings[0].description)
        self.assertTrue(len(findings[0].remediation) > 0)

    def test_zero_array_iv_positive(self) -> None:
        rule = StaticOrWeakIvRule()
        code = """
        byte[] zeroIv = new byte[16];
        IvParameterSpec iv = new IvParameterSpec(zeroIv);
        """
        findings = rule.evaluate({"files": {"ZeroIvHelper.java": code}})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("all-zero byte array", findings[0].description)

    def test_dynamic_secure_random_iv_negative(self) -> None:
        rule = StaticOrWeakIvRule()
        code = """
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        """
        findings = rule.evaluate({"files": {"SecureGcm.java": code}})
        self.assertEqual(findings, [])

    # -----------------------------------------------------------------------
    # Hardcoded Cryptographic Key Tests
    # -----------------------------------------------------------------------

    def test_hardcoded_crypto_key_positive_and_redacted(self) -> None:
        rule = HardcodedCryptoKeyRule()
        code = 'SecretKeySpec key = new SecretKeySpec("SuperSecretAESKey12345".getBytes(), "AES");'
        findings = rule.evaluate({"files": {"KeyHolder.java": code}})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("Static inspection detected hardcoded cryptographic key", findings[0].description)
        # Privacy guarantee: raw secret must be redacted!
        self.assertNotIn("SuperSecretAESKey12345", findings[0].evidence)
        self.assertIn("Su********45", findings[0].evidence)
        self.assertTrue(len(findings[0].remediation) > 0)

    # -----------------------------------------------------------------------
    # Conservative Obsolete Hashing Tests
    # -----------------------------------------------------------------------

    def test_md5_in_security_context_positive(self) -> None:
        rule = InsecureContextHashRule()
        code = """
        public String hashPassword(String password) throws Exception {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            return bytesToHex(hash);
        }
        """
        findings = rule.evaluate({"files": {"UserAuth.java": code}})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.MEDIUM)
        self.assertIn("MD5", findings[0].title)
        self.assertIn("password", findings[0].description)
        self.assertTrue(len(findings[0].remediation) > 0)

    def test_md5_file_checksum_suppressed_negative(self) -> None:
        """Normal checksum or cache calculation must NOT be flagged as credential vulnerability."""
        rule = InsecureContextHashRule()
        code = """
        public String calculateFileChecksum(File downloadFile) throws Exception {
            MessageDigest md = MessageDigest.getInstance("MD5");
            // Compute download file checksum for integrity
            return computeChecksum(downloadFile, md);
        }
        """
        findings = rule.evaluate({"files": {"DownloadManager.java": code}})
        self.assertEqual(findings, [])

    def test_sha1_etag_cache_key_suppressed_negative(self) -> None:
        """SHA-1 used for HTTP ETag or image cache key must be suppressed."""
        rule = InsecureContextHashRule()
        code = """
        public String generateCacheKey(String imageUrl) throws Exception {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            return toHex(md.digest(imageUrl.getBytes()));
        }
        """
        findings = rule.evaluate({"files": {"ImageCache.java": code}})
        self.assertEqual(findings, [])

    def test_sha1_signature_security_context_positive(self) -> None:
        rule = InsecureContextHashRule()
        code = """
        public byte[] signToken(byte[] secretKey, byte[] data) throws Exception {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(secretKey);
            return md.digest(data);
        }
        """
        findings = rule.evaluate({"files": {"TokenSigner.java": code}})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.MEDIUM)
        self.assertIn("SHA-1", findings[0].title)

    # -----------------------------------------------------------------------
    # Insecure Random Seed Tests
    # -----------------------------------------------------------------------

    def test_static_seed_secure_random_positive(self) -> None:
        rule = InsecureRandomSeedRule()
        code = """
        SecureRandom sr = new SecureRandom();
        sr.setSeed(123456789L);
        """
        findings = rule.evaluate({"files": {"RandomHelper.java": code}})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("Static Seed Configured on SecureRandom", findings[0].title)
        self.assertTrue(len(findings[0].remediation) > 0)

    def test_util_random_in_crypto_context_positive(self) -> None:
        rule = InsecureRandomSeedRule()
        code = """
        byte[] keyBytes = new byte[16];
        new Random().nextBytes(keyBytes);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        """
        findings = rule.evaluate({"files": {"InsecureKeyGen.java": code}})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("Insecure java.util.Random", findings[0].title)

    def test_default_secure_random_negative(self) -> None:
        rule = InsecureRandomSeedRule()
        code = """
        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        """
        findings = rule.evaluate({"files": {"SafeRandom.java": code}})
        self.assertEqual(findings, [])

    # -----------------------------------------------------------------------
    # Rule Metadata & Alias Verification
    # -----------------------------------------------------------------------

    def test_all_crypto_rules_instantiation(self) -> None:
        for rule_cls in ALL_CRYPTO_RULES:
            rule = rule_cls()
            self.assertTrue(rule.rule_id.startswith("CRY-"))
            self.assertTrue(len(rule.title) > 0)
            self.assertEqual(rule.category, FindingCategory.CRYPTO_FLAW)
            self.assertTrue(callable(rule.evaluate))

    def test_backwards_compatible_alias(self) -> None:
        self.assertIs(WeakCryptoRule, BrokenCipherRule)


if __name__ == "__main__":
    unittest.main()
