"""Generator for authorized academic demonstration APK.

Constructs an educational synthetic APK package with realistic security flaws,
manifest configurations, permission combinations, and tracking indicators.
All generated credentials and endpoints are synthetic and safe for academic demonstration.
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path


def generate_demo_apk(output_path: Path | str) -> Path:
    """Generate an authorized educational demonstration APK with realistic static indicators."""
    target_path = Path(output_path).resolve()
    target_path.parent.mkdir(parents=True, exist_ok=True)

    manifest_xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
        '    package="org.academic.dataleakdemo"\n'
        '    android:versionCode="102"\n'
        '    android:versionName="1.2.0">\n'
        '\n'
        '    <!-- Dangerous Permissions accessing sensitive user hardware and data -->\n'
        '    <uses-permission android:name="android.permission.INTERNET" />\n'
        '    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />\n'
        '    <uses-permission android:name="android.permission.READ_CONTACTS" />\n'
        '    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />\n'
        '    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />\n'
        '\n'
        '    <application\n'
        '        android:label="Academic Demo App"\n'
        '        android:debuggable="true"\n'
        '        android:allowBackup="true"\n'
        '        android:usesCleartextTraffic="true">\n'
        '\n'
        '        <!-- Exported Launcher Activity -->\n'
        '        <activity\n'
        '            android:name="org.academic.dataleakdemo.MainActivity"\n'
        '            android:exported="true">\n'
        '            <intent-filter>\n'
        '                <action android:name="android.intent.action.MAIN" />\n'
        '                <category android:name="android.intent.category.LAUNCHER" />\n'
        '            </intent-filter>\n'
        '        </activity>\n'
        '\n'
        '        <!-- Exported Background Service without permission protection -->\n'
        '        <service\n'
        '            android:name="org.academic.dataleakdemo.DataSyncService"\n'
        '            android:exported="true" />\n'
        '\n'
        '        <!-- Exported Content Provider exposing data to third parties -->\n'
        '        <provider\n'
        '            android:name="org.academic.dataleakdemo.UserDataProvider"\n'
        '            android:authorities="org.academic.dataleakdemo.provider"\n'
        '            android:exported="true" />\n'
        '    </application>\n'
        '</manifest>\n'
    )

    dex_bytecode = (
        b"dex\n035\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"Lorg/academic/dataleakdemo/MainActivity;\x00"
        b"Lorg/academic/dataleakdemo/DataSyncService;\x00"
        b"Lorg/academic/dataleakdemo/CryptoManager;\x00"
        # Insecure Network URLs
        b"http://api.insecure-telemetry.example.org/v1/sync\x00"
        b"http://tracking-analytics.partner-network.com/collect\x00"
        # Hardcoded Secret Credentials (masked upon detection)
        b"AIzaSyD-DemoMockGoogleApiKey123456789\x00"
        b"AKIAIOSFODNN7DEMO001\x00"
        b"ghp_DemoMockGithubAccessToken1234567890abcdef\x00"
        # Insecure Cryptography Algorithms & Modes
        b"AES/ECB/PKCS5Padding\x00"
        b"DES/CBC/PKCS5Padding\x00"
        b"MD5\x00"
        b"SHA-1\x00"
        # Insecure Local Storage & SharedPreferences
        b"getSharedPreferences\x00"
        b"user_credentials_plaintext\x00"
        b"MODE_WORLD_READABLE\x00"
        # Third-Party Tracking & Advertising SDK Identifiers
        b"com.facebook.ads.AudienceNetworkAds\x00"
        b"com.google.android.gms.ads.MobileAds\x00"
        b"com.appsflyer.AppsFlyerLib\x00"
        b"com.flurry.android.FlurryAgent\x00"
    )

    raw_config_json = (
        b'{\n'
        b'  "app_environment": "academic_test",\n'
        b'  "backend_service_url": "http://insecure-internal.academic-demo.org/api",\n'
        b'  "analytics_provider": "AppsFlyer",\n'
        b'  "backup_secret_token": "AKIAIOSFODNN7BACKUP99"\n'
        b'}\n'
    )

    with zipfile.ZipFile(target_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest_xml.encode("utf-8"))
        zf.writestr("classes.dex", dex_bytecode)
        zf.writestr("res/raw/config.json", raw_config_json)

    print(f"Successfully generated demonstration APK at: {target_path}")
    print(f"File size: {target_path.stat().st_size} bytes")
    return target_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate an authorized academic demonstration APK with multi-category static flaws."
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("sample_apks") / "demo_vulnerable_app.apk",
        help="Target output path for the demonstration APK (default: sample_apks/demo_vulnerable_app.apk)",
    )
    args = parser.parse_args()
    generate_demo_apk(args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
