"""Unit tests for all 10 manifest-focused static analysis security rules."""

from __future__ import annotations

import unittest
from pathlib import Path

from data_leak_detector.core.models import (
    ApplicationMetadata,
    ComponentDetail,
    FindingCategory,
    ManifestData,
    ParsedAPKData,
    Severity,
)
from data_leak_detector.rules.manifest_rules import (
    AllowBackupRule,
    CleartextTrafficPermittedRule,
    DebuggableRule,
    ExcessivePermissionCombinationRule,
    ExportedActivityRule,
    ExportedProviderRule,
    ExportedReceiverRule,
    ExportedServiceRule,
    NetworkSecurityConfigRule,
    SensitiveComponentExposureRule,
)


class TestManifestRules(unittest.TestCase):
    def _create_context(
        self,
        allow_backup: bool | None = None,
        debuggable: bool | None = None,
        uses_cleartext: bool | None = None,
        net_sec_config: str | None = None,
        target_sdk: int | None = 30,
        components: list[ComponentDetail] | None = None,
        permissions: list[str] | None = None,
    ) -> ParsedAPKData:
        meta = ApplicationMetadata(
            filename="test.apk",
            sha256="a" * 64,
            file_size=1024,
            package_name="com.test.manifestapp",
            target_sdk=target_sdk,
        )
        manifest = ManifestData(
            package_name="com.test.manifestapp",
            target_sdk=target_sdk,
            allow_backup=allow_backup,
            debuggable=debuggable,
            uses_cleartext_traffic=uses_cleartext,
            network_security_config=net_sec_config,
            components=components or [],
        )
        return ParsedAPKData(
            metadata=meta,
            manifest_info=manifest,
            permissions=permissions or [],
        )

    def test_debuggable_rule(self) -> None:
        rule = DebuggableRule()

        # Debuggable = True
        ctx_vuln = self._create_context(debuggable=True)
        findings = rule.evaluate(ctx_vuln)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertEqual(findings[0].category, FindingCategory.MANIFEST_MISCONFIG)
        self.assertIn("OWASP-M1", findings[0].owasp_reference or "")

        # Debuggable = False or None
        ctx_safe = self._create_context(debuggable=False)
        self.assertEqual(len(rule.evaluate(ctx_safe)), 0)

        ctx_none = self._create_context(debuggable=None)
        self.assertEqual(len(rule.evaluate(ctx_none)), 0)

    def test_allow_backup_rule(self) -> None:
        rule = AllowBackupRule()

        # Explicitly true
        ctx_true = self._create_context(allow_backup=True)
        findings = rule.evaluate(ctx_true)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.MEDIUM)
        self.assertIn("OWASP-M2", findings[0].owasp_reference or "")

        # Default true (None)
        ctx_none = self._create_context(allow_backup=None)
        findings_none = rule.evaluate(ctx_none)
        self.assertEqual(len(findings_none), 1)

        # Explicitly false (safe)
        ctx_safe = self._create_context(allow_backup=False)
        self.assertEqual(len(rule.evaluate(ctx_safe)), 0)

    def test_cleartext_traffic_permitted_rule(self) -> None:
        rule = CleartextTrafficPermittedRule()

        # Explicitly True on API 30
        ctx_explicit = self._create_context(uses_cleartext=True, target_sdk=30)
        findings = rule.evaluate(ctx_explicit)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)

        # Legacy API 26 with unconfigured cleartext
        ctx_legacy = self._create_context(uses_cleartext=None, target_sdk=26)
        findings_leg = rule.evaluate(ctx_legacy)
        self.assertEqual(len(findings_leg), 1)
        self.assertEqual(findings_leg[0].severity, Severity.MEDIUM)

        # Explicitly False (safe)
        ctx_safe = self._create_context(uses_cleartext=False, target_sdk=30)
        self.assertEqual(len(rule.evaluate(ctx_safe)), 0)

    def test_network_security_config_rule(self) -> None:
        rule = NetworkSecurityConfigRule()

        # Missing on API 28+
        ctx_missing = self._create_context(target_sdk=29, net_sec_config=None)
        findings = rule.evaluate(ctx_missing)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.LOW)

        # Present on API 28+
        ctx_present = self._create_context(
            target_sdk=29, net_sec_config="@xml/network_security_config"
        )
        self.assertEqual(len(rule.evaluate(ctx_present)), 0)

        # Legacy API < 24
        ctx_legacy = self._create_context(target_sdk=21, net_sec_config=None)
        self.assertEqual(len(rule.evaluate(ctx_legacy)), 0)

    def test_exported_activity_rule(self) -> None:
        rule = ExportedActivityRule()

        comps = [
            # Vulnerable: exported without permission, not launcher
            ComponentDetail(
                component_type="activity",
                name="com.test.app.SecretSettingsActivity",
                exported=True,
                permission=None,
                is_main_launcher=False,
            ),
            # Safe: main launcher activity
            ComponentDetail(
                component_type="activity",
                name="com.test.app.MainActivity",
                exported=True,
                permission=None,
                is_main_launcher=True,
            ),
            # Safe: exported with permission
            ComponentDetail(
                component_type="activity",
                name="com.test.app.ProtectedActivity",
                exported=True,
                permission="com.test.permission.INTERNAL_ACCESS",
                is_main_launcher=False,
            ),
            # Safe: not exported
            ComponentDetail(
                component_type="activity",
                name="com.test.app.PrivateActivity",
                exported=False,
                permission=None,
                is_main_launcher=False,
            ),
        ]
        ctx = self._create_context(components=comps)
        findings = rule.evaluate(ctx)

        self.assertEqual(len(findings), 1)
        self.assertIn("SecretSettingsActivity", findings[0].title)
        self.assertEqual(findings[0].severity, Severity.MEDIUM)

    def test_exported_service_rule(self) -> None:
        rule = ExportedServiceRule()

        comps = [
            ComponentDetail(
                component_type="service",
                name="com.test.app.VulnerableSyncService",
                exported=True,
                permission=None,
            ),
            ComponentDetail(
                component_type="service",
                name="com.test.app.ProtectedService",
                exported=True,
                permission="android.permission.BIND_JOB_SERVICE",
            ),
            ComponentDetail(
                component_type="service",
                name="com.test.app.InternalService",
                exported=False,
                permission=None,
            ),
        ]
        ctx = self._create_context(components=comps)
        findings = rule.evaluate(ctx)

        self.assertEqual(len(findings), 1)
        self.assertIn("VulnerableSyncService", findings[0].title)
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_exported_receiver_rule(self) -> None:
        rule = ExportedReceiverRule()

        comps = [
            ComponentDetail(
                component_type="receiver",
                name="com.test.app.ExposedBootReceiver",
                exported=True,
                permission=None,
            ),
            ComponentDetail(
                component_type="receiver",
                name="com.test.app.ProtectedReceiver",
                exported=True,
                permission="com.test.permission.RECEIVE_EVENT",
            ),
        ]
        ctx = self._create_context(components=comps)
        findings = rule.evaluate(ctx)

        self.assertEqual(len(findings), 1)
        self.assertIn("ExposedBootReceiver", findings[0].title)
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_exported_provider_rule(self) -> None:
        rule = ExportedProviderRule()

        comps = [
            # Vulnerable: exported without read or write permissions
            ComponentDetail(
                component_type="provider",
                name="com.test.app.UserDataProvider",
                exported=True,
                permission=None,
                read_permission=None,
                write_permission=None,
            ),
            # Safe: exported with read_permission
            ComponentDetail(
                component_type="provider",
                name="com.test.app.ProtectedProvider",
                exported=True,
                permission=None,
                read_permission="com.test.app.READ_DATA",
                write_permission=None,
            ),
            # Safe: internal not exported
            ComponentDetail(
                component_type="provider",
                name="com.test.app.InternalProvider",
                exported=False,
            ),
        ]
        ctx = self._create_context(components=comps)
        findings = rule.evaluate(ctx)

        self.assertEqual(len(findings), 1)
        self.assertIn("UserDataProvider", findings[0].title)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_sensitive_component_exposure_rule(self) -> None:
        rule = SensitiveComponentExposureRule()

        comps = [
            # Vulnerable: exported activity with 'auth' and 'login' action
            ComponentDetail(
                component_type="activity",
                name="com.test.app.AuthHandlerActivity",
                exported=True,
                permission=None,
                actions=["com.test.app.action.AUTH_LOGIN"],
            ),
            # Safe: exported activity with harmless generic action
            ComponentDetail(
                component_type="activity",
                name="com.test.app.ViewActivity",
                exported=True,
                permission=None,
                actions=["android.intent.action.VIEW"],
            ),
            # Safe: has permission
            ComponentDetail(
                component_type="service",
                name="com.test.app.AdminService",
                exported=True,
                permission="com.test.permission.ADMIN",
                actions=["com.test.app.action.ADMIN_RESET"],
            ),
        ]
        ctx = self._create_context(components=comps)
        findings = rule.evaluate(ctx)

        self.assertEqual(len(findings), 1)
        self.assertIn("AuthHandlerActivity", findings[0].title)
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_excessive_permission_combination_rule(self) -> None:
        rule = ExcessivePermissionCombinationRule()

        # INTERNET + LOCATION + SMS
        ctx_combo = self._create_context(
            permissions=[
                "android.permission.INTERNET",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_SMS",
            ]
        )
        findings = rule.evaluate(ctx_combo)
        # Should flag 2 combination vectors: Location and SMS
        self.assertEqual(len(findings), 2)
        titles = [f.title for f in findings]
        self.assertTrue(any("Geolocation" in t for t in titles))
        self.assertTrue(any("SMS" in t for t in titles))

        # Sensitive perms without INTERNET -> No finding
        ctx_no_net = self._create_context(
            permissions=[
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_SMS",
            ]
        )
        self.assertEqual(len(rule.evaluate(ctx_no_net)), 0)


if __name__ == "__main__":
    unittest.main()
