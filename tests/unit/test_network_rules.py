"""Unit tests for static network/security communication rules.

Verifies detection of:
- HTTP URLs
- HTTPS URLs (suppression)
- localhost / test URLs (suppression)
- XML schema & namespace false-positive suppression
- Trust-all X.509 certificate validation patterns
- Permissive HostnameVerifier implementations
- SSL/TLS certificate validation bypass patterns
- Insecure WebView network settings
- Tracking & advertising domain matching
- Strict static evidence phrasing guarantees (never claiming runtime PII transmission)
"""

from __future__ import annotations

import unittest

from data_leak_detector.core.models import (
    ApplicationMetadata,
    Confidence,
    FindingCategory,
    ManifestData,
    ParsedAPKData,
    Severity,
)
from data_leak_detector.rules.network_rules import (
    ALL_NETWORK_RULES,
    CleartextHttpUrlRule,
    CleartextTrafficConfigRule,
    CleartextTrafficRule,
    InsecureWebViewNetworkRule,
    PermissiveHostnameVerifierRule,
    SslValidationBypassRule,
    ThirdPartyEndpointRule,
    TrackingAndAdEndpointRule,
    TrustAllCertificatesRule,
)


class TestNetworkRules(unittest.TestCase):
    def test_http_url_detection(self) -> None:
        rule = CleartextHttpUrlRule()
        context = {
            "strings": [
                "http://insecure-backend.mycompany.org/api/v1/auth",
                "http://telemetry.service-provider.net:8080/collect",
            ]
        }
        findings = rule.evaluate(context)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].category, FindingCategory.NETWORK_INDICATOR)
        self.assertEqual(findings[0].severity, Severity.MEDIUM)
        self.assertEqual(findings[0].confidence, Confidence.HIGH)
        self.assertIn("Static analysis detected a hardcoded unencrypted HTTP URL", findings[0].description)
        self.assertIn("Static analysis alone cannot determine", findings[0].description)

    def test_https_url_suppressed(self) -> None:
        """HTTPS URLs must not be flagged as cleartext HTTP."""
        rule = CleartextHttpUrlRule()
        context = {
            "strings": [
                "https://secure-backend.mycompany.org/api/v1/auth",
                "https://api.github.com/repos",
                "https://accounts.google.com/o/oauth2/v2/auth",
            ]
        }
        findings = rule.evaluate(context)
        self.assertEqual(findings, [])

    def test_localhost_and_test_urls_suppressed(self) -> None:
        """Localhost, loopback, and test domains must be suppressed from cleartext findings."""
        rule = CleartextHttpUrlRule()
        context = {
            "strings": [
                "http://localhost:8080/debug",
                "http://127.0.0.1:3000/api",
                "http://10.0.2.2:8000/test",  # Android emulator host loopback
                "http://0.0.0.0:9000",
                "http://api.test/v1",
                "http://service.local/status",
                "http://internal.localhost:5000",
                "http://example.com/spec",
                "http://sample.com/data",
            ]
        }
        findings = rule.evaluate(context)
        self.assertEqual(findings, [])

    def test_xml_schema_and_namespace_suppression(self) -> None:
        """Standard XML schemas and Android namespaces must be suppressed as false positives."""
        rule = CleartextHttpUrlRule()
        context = {
            "strings": [
                "http://schemas.android.com/apk/res/android",
                "http://schemas.android.com/apk/res-auto",
                "http://schemas.android.com/tools",
                "http://www.w3.org/2000/xmlns/",
                "http://www.w3.org/1999/xhtml",
                "http://apache.org/xml/features/disallow-doctype-decl",
                "http://xml.org/sax/features/validation",
                "http://json-schema.org/draft-07/schema#",
                "http://java.sun.com/xml/jaxp/properties/schemaLanguage",
            ]
        }
        findings = rule.evaluate(context)
        self.assertEqual(findings, [])

    def test_trust_all_certificates_empty_check_server_trusted(self) -> None:
        rule = TrustAllCertificatesRule()
        code = """
        class InsecureClient {
            X509TrustManager tm = new X509TrustManager() {
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    // Empty: trusts all server certificates without validation
                }
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                public X509Certificate[] getAcceptedIssuers() { return null; }
            };
        }
        """
        findings = rule.evaluate({"files": {"InsecureClient.java": code}})
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertEqual(findings[0].confidence, Confidence.HIGH)
        self.assertIn("Static", findings[0].description)
        self.assertIn("checkServerTrusted", findings[0].evidence)

    def test_trust_all_class_name_detection(self) -> None:
        rule = TrustAllCertificatesRule()
        context = {
            "strings": [
                "Lcom/example/net/TrustAllCertificates;",
                "Lcom/example/net/TrustAllSSLSocketFactory;",
            ]
        }
        findings = rule.evaluate(context)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].title, "Trust-All Certificate Manager Reference")
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_trust_all_smali_bytecode_detection(self) -> None:
        rule = TrustAllCertificatesRule()
        smali_code = """
        .method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
            .registers 3
            return-void
        .end method
        """
        findings = rule.evaluate({"files": {"TrustManager.smali": smali_code}})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("Smali return-void in checkServerTrusted", findings[0].evidence)

    def test_permissive_hostname_verifier_detection(self) -> None:
        rule = PermissiveHostnameVerifierRule()
        code = """
        HostnameVerifier verifier1 = org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
        HostnameVerifier verifier2 = new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
        """
        findings = rule.evaluate({"files": {"NetworkClient.java": code}})
        self.assertGreaterEqual(len(findings), 2)
        titles = [f.title for f in findings]
        self.assertTrue(any("Permissive HostnameVerifier" in t for t in titles))
        for f in findings:
            self.assertEqual(f.severity, Severity.HIGH)
            self.assertEqual(f.confidence, Confidence.HIGH)
            self.assertIn("Static", f.description)

    def test_permissive_hostname_verifier_lambda(self) -> None:
        rule = PermissiveHostnameVerifierRule()
        code = "client.setHostnameVerifier((hostname, session) -> true);"
        findings = rule.evaluate({"files": {"Client.java": code}})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("(hostname, session) -> true", findings[0].evidence)

    def test_ssl_validation_bypass_handler_proceed(self) -> None:
        rule = SslValidationBypassRule()
        code = """
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
                handler.proceed();
            }
        });
        """
        findings = rule.evaluate({"files": {"MyWebView.java": code}})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "WebView SSL Error Bypass (handler.proceed)")
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertEqual(findings[0].confidence, Confidence.HIGH)
        self.assertIn("Static code analysis identified", findings[0].description)

    def test_ssl_context_bypass_init(self) -> None:
        rule = SslValidationBypassRule()
        code = """
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, new TrustManager[] { new InsecureTrustManager() }, new SecureRandom());
        """
        findings = rule.evaluate({"files": {"SslConfig.java": code}})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("SSLContext Custom TrustManager Initialization", findings[0].title)

    def test_insecure_webview_settings(self) -> None:
        rule = InsecureWebViewNetworkRule()
        code = """
        WebSettings settings = webView.getSettings();
        settings.setAllowUniversalAccessFromFileURLs(true);
        settings.setAllowFileAccessFromFileURLs(true);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        """
        findings = rule.evaluate({"files": {"WebViewActivity.java": code}})
        self.assertEqual(len(findings), 3)
        for f in findings:
            self.assertEqual(f.severity, Severity.MEDIUM)
            self.assertEqual(f.confidence, Confidence.HIGH)
            self.assertIn("Static inspection detected", f.description)

    def test_tracking_domain_matches_and_strict_phrasing(self) -> None:
        rule = TrackingAndAdEndpointRule()
        context = {
            "strings": [
                "https://region1.google-analytics.com/collect",
                "https://api.crashlytics.com/v2/reports",
                "https://app.appsflyer.com/api/v4/event",
                "https://graph.facebook.com/tr/?id=12345",
            ]
        }
        findings = rule.evaluate(context)
        self.assertGreaterEqual(len(findings), 4)

        for f in findings:
            self.assertEqual(f.category, FindingCategory.NETWORK_INDICATOR)
            self.assertEqual(f.severity, Severity.MEDIUM)
            self.assertEqual(f.confidence, Confidence.HIGH)

            # Strict Phrasing Verification:
            # 1. Never state "PII was transmitted to this domain."
            self.assertNotIn("PII was transmitted", f.description)
            self.assertNotIn("PII was transmitted", f.title)
            self.assertNotIn("PII was transmitted", f.evidence)

            # 2. Must clearly state static resources contain endpoint and static analysis alone cannot determine transmission
            self.assertIn("The application's static resources contain an endpoint associated with tracking", f.description)
            self.assertIn("Static analysis alone cannot determine whether sensitive information is transmitted to this endpoint", f.description)

    def test_cleartext_traffic_config_rule(self) -> None:
        rule = CleartextTrafficConfigRule()

        # Test manifest configuration
        manifest = ManifestData(package_name="com.test.app", uses_cleartext_traffic=True)
        findings_manifest = rule.evaluate({"manifest_info": manifest})
        self.assertEqual(len(findings_manifest), 1)
        self.assertEqual(findings_manifest[0].severity, Severity.HIGH)
        self.assertIn("Cleartext Traffic Permitted in Manifest", findings_manifest[0].title)

        # Test network security configuration XML
        net_sec_xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <network-security-config>
            <base-config cleartextTrafficPermitted="true">
                <trust-anchors><certificates src="system" /></trust-anchors>
            </base-config>
        </network-security-config>
        """
        findings_xml = rule.evaluate({"network_security_config_xml": net_sec_xml})
        self.assertEqual(len(findings_xml), 1)
        self.assertEqual(findings_xml[0].severity, Severity.HIGH)
        self.assertIn("Cleartext Traffic Permitted in Network Security Config", findings_xml[0].title)

    def test_third_party_endpoint_rule(self) -> None:
        rule = ThirdPartyEndpointRule()
        meta = ApplicationMetadata(
            filename="app.apk",
            sha256="b" * 64,
            file_size=2048,
            package_name="com.bankcorp.mobile",
        )
        parsed = ParsedAPKData(
            metadata=meta,
            manifest_info=ManifestData(package_name="com.bankcorp.mobile"),
        )
        context = {
            "parsed_apk": parsed,
            "strings": [
                # First party (suppressed based on package com.bankcorp.mobile -> bankcorp.com)
                "https://api.bankcorp.com/v1/accounts",
                # Platform (suppressed)
                "https://play.google.com/store/apps",
                # Tracking domain (suppressed from generic 3rd party rule because it's handled by Tracking rule)
                "https://google-analytics.com/collect",
                # Real third-party endpoint (detected)
                "https://api.stripe.com/v1/tokens",
                "https://api.twilio.com/2010-04-01/Accounts",
            ],
        }
        findings = rule.evaluate(context)
        detected_hosts = [f.evidence for f in findings]
        self.assertTrue(any("stripe.com" in h for h in detected_hosts))
        self.assertTrue(any("twilio.com" in h for h in detected_hosts))
        self.assertFalse(any("bankcorp.com" in h for h in detected_hosts))
        self.assertFalse(any("play.google.com" in h for h in detected_hosts))
        self.assertFalse(any("google-analytics.com" in h for h in detected_hosts))

        for f in findings:
            self.assertEqual(f.severity, Severity.LOW)
            self.assertEqual(f.confidence, Confidence.MEDIUM)
            self.assertIn("Static analysis alone cannot determine", f.description)

    def test_all_network_rules_instantiation(self) -> None:
        """Verify all network rules in ALL_NETWORK_RULES instantiate and have required fields."""
        for rule_cls in ALL_NETWORK_RULES:
            rule = rule_cls()
            self.assertTrue(rule.rule_id.startswith("NET-"))
            self.assertTrue(len(rule.title) > 0)
            self.assertEqual(rule.category, FindingCategory.NETWORK_INDICATOR)
            self.assertIn(rule.default_severity, (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL, Severity.INFO))
            self.assertTrue(callable(rule.evaluate))

    def test_backwards_compatible_alias(self) -> None:
        self.assertIs(CleartextTrafficRule, CleartextHttpUrlRule)


if __name__ == "__main__":
    unittest.main()
