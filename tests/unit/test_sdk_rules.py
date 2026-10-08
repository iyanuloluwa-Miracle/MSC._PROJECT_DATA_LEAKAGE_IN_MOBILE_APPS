"""Unit tests for static third-party SDK identification and SDK Permission Exposure rules.

Tests:
- Identification of SDKs across categories (analytics, advertising, crash reporting, social, payments, location, push notifications)
- Informational non-malicious finding generation
- SDK Permission Exposure generation when host requests sensitive permissions (e.g., location, contacts)
- Non-exposure case when host requests no sensitive permissions
- Non-claim verification (ensuring it never asserts the SDK actually collected data)
- Custom configurable SDK catalog support
- Backwards compatible rule aliases
"""

from __future__ import annotations

import unittest

from data_leak_detector.core.models import (
    ApplicationMetadata,
    FindingCategory,
    ParsedAPKData,
    Severity,
)
from data_leak_detector.rules.sdk_rules import (
    ALL_SDK_RULES,
    SdkPermissionExposureRule,
    ThirdPartySdkIdentificationRule,
    ThirdPartyTrackerRule,
)


class TestSdkRules(unittest.TestCase):
    # -----------------------------------------------------------------------
    # Multi-Category SDK Identification Tests
    # -----------------------------------------------------------------------

    def test_identify_advertising_and_analytics_sdks(self) -> None:
        rule = ThirdPartySdkIdentificationRule()
        context = {
            "classes": [
                "com.google.android.gms.ads.AdView",
                "com.google.android.gms.measurement.AppMeasurement",
                "com.appsflyer.AppsFlyerLib",
            ]
        }
        findings = rule.evaluate(context)
        self.assertEqual(len(findings), 3)

        detected_names = [f.title for f in findings]
        self.assertTrue(any("Google AdMob" in t for t in detected_names))
        self.assertTrue(any("Firebase Analytics" in t for t in detected_names))
        self.assertTrue(any("AppsFlyer" in t for t in detected_names))

        for f in findings:
            self.assertEqual(f.category, FindingCategory.TRACKING_SDK)
            self.assertEqual(f.severity, Severity.INFO)
            self.assertIn("Static analysis identified the presence of third-party SDK", f.description)
            self.assertTrue(len(f.remediation) > 0)

    def test_identify_social_and_crash_reporting_sdks(self) -> None:
        rule = ThirdPartySdkIdentificationRule()
        context = {
            "classes": [
                "com.facebook.login.LoginManager",
                "io.sentry.Sentry",
                "com.google.firebase.crashlytics.FirebaseCrashlytics",
            ]
        }
        findings = rule.evaluate(context)
        self.assertEqual(len(findings), 3)

        categories = [f.description for f in findings]
        self.assertTrue(any("social" in d for d in categories))
        self.assertTrue(any("crash reporting" in d for d in categories))

    def test_identify_payments_location_push_sdks(self) -> None:
        rule = ThirdPartySdkIdentificationRule()
        context = {
            "activities": [
                "com.stripe.android.view.PaymentSheetActivity",
                "com.mapbox.maps.MapActivity",
                "com.onesignal.NotificationOpenedActivity",
            ]
        }
        findings = rule.evaluate(context)
        self.assertEqual(len(findings), 3)

        categories = [f.description for f in findings]
        self.assertTrue(any("payments" in d for d in categories))
        self.assertTrue(any("location" in d for d in categories))
        self.assertTrue(any("push notifications" in d for d in categories))

    def test_no_sdks_present_negative(self) -> None:
        rule = ThirdPartySdkIdentificationRule()
        context = {
            "classes": [
                "com.example.myapp.MainActivity",
                "com.example.myapp.Utils",
            ]
        }
        findings = rule.evaluate(context)
        self.assertEqual(findings, [])

    # -----------------------------------------------------------------------
    # SDK Permission Exposure Tests
    # -----------------------------------------------------------------------

    def test_sdk_permission_exposure_location_positive(self) -> None:
        """Analytics or Ad SDK present with location permissions must generate exposure indicator."""
        rule = SdkPermissionExposureRule()
        meta = ApplicationMetadata(
            filename="app.apk",
            sha256="c" * 64,
            file_size=1024,
            package_name="com.test.app",
        )
        parsed = ParsedAPKData(
            metadata=meta,
            activities=["com.google.android.gms.ads.AdActivity"],
            permissions=[
                "android.permission.INTERNET",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION",
            ],
        )
        findings = rule.evaluate(parsed)
        self.assertEqual(len(findings), 1)

        f = findings[0]
        self.assertEqual(f.category, FindingCategory.TRACKING_SDK)
        self.assertEqual(f.severity, Severity.MEDIUM)
        self.assertIn("SDK Permission Exposure", f.title)
        self.assertIn("Location", f.title)

        # Critical requirement: NEVER claim SDK collected data; state potential exposure indicator
        desc_lower = f.description.lower()
        self.assertNotIn("sdk collected", desc_lower)
        self.assertNotIn("collected location", desc_lower)
        self.assertIn("sdk permission exposure", desc_lower)
        self.assertIn("static analysis alone cannot determine", desc_lower)
        self.assertTrue(len(f.remediation) > 0)

    def test_sdk_permission_exposure_contacts_and_social(self) -> None:
        rule = SdkPermissionExposureRule()
        context = {
            "classes": ["com.facebook.ads.AudienceNetworkAds"],
            "permissions": [
                "android.permission.INTERNET",
                "android.permission.READ_CONTACTS",
            ],
        }
        findings = rule.evaluate(context)
        self.assertEqual(len(findings), 1)
        self.assertIn("Contacts", findings[0].title)
        self.assertIn("READ_CONTACTS", findings[0].description)

    def test_sdk_present_without_sensitive_permissions_negative(self) -> None:
        """When host app only requests harmless or no sensitive permissions, NO exposure is flagged."""
        rule = SdkPermissionExposureRule()
        context = {
            "classes": ["com.amplitude.api.AmplitudeClient"],
            "permissions": [
                "android.permission.INTERNET",
                "android.permission.ACCESS_NETWORK_STATE",
            ],
        }
        findings = rule.evaluate(context)
        self.assertEqual(findings, [])

    def test_sensitive_permissions_without_sdk_negative(self) -> None:
        """When app requests location permissions but has no third-party ad/analytics SDK, NO exposure is flagged."""
        rule = SdkPermissionExposureRule()
        context = {
            "classes": ["com.firstparty.navigation.GpsTracker"],
            "permissions": [
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION",
            ],
        }
        findings = rule.evaluate(context)
        self.assertEqual(findings, [])

    # -----------------------------------------------------------------------
    # Configurable Catalog & Alias Tests
    # -----------------------------------------------------------------------

    def test_custom_configurable_catalog(self) -> None:
        custom_catalog = [
            {
                "id": "custom_tracker",
                "name": "CustomTelemetrySDK",
                "category": "analytics",
                "package_pattern": r"com\.custom\.telemetry",
                "sensitive_families": ["location"],
            }
        ]
        detect_rule = ThirdPartySdkIdentificationRule(sdk_catalog=custom_catalog)
        exposure_rule = SdkPermissionExposureRule(sdk_catalog=custom_catalog)

        context = {
            "classes": ["com.custom.telemetry.Agent"],
            "permissions": ["android.permission.ACCESS_FINE_LOCATION"],
        }

        det_findings = detect_rule.evaluate(context)
        self.assertEqual(len(det_findings), 1)
        self.assertIn("CustomTelemetrySDK", det_findings[0].title)

        exp_findings = exposure_rule.evaluate(context)
        self.assertEqual(len(exp_findings), 1)
        self.assertIn("CustomTelemetrySDK", exp_findings[0].title)

    def test_all_sdk_rules_instantiation(self) -> None:
        for rule_cls in ALL_SDK_RULES:
            rule = rule_cls()
            self.assertTrue(rule.rule_id.startswith("SDK-"))
            self.assertTrue(len(rule.title) > 0)
            self.assertEqual(rule.category, FindingCategory.TRACKING_SDK)
            self.assertTrue(callable(rule.evaluate))

    def test_backwards_compatible_alias(self) -> None:
        self.assertIs(ThirdPartyTrackerRule, ThirdPartySdkIdentificationRule)


if __name__ == "__main__":
    unittest.main()
