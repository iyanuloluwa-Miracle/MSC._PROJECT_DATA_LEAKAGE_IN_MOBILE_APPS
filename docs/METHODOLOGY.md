# Static Analysis & Risk Scoring Methodology

This document provides a comprehensive explanation of how the **Mobile Data Leak Detector** analyzes Android application packages (APKs) to identify security vulnerabilities, tracking behaviors, and data leakage risks.

Written in clear, accessible language, this document explains the technical procedures under the hood while maintaining rigorous academic and professional accuracy.

---

## Table of Contents
1. [What Is Static APK Analysis?](#1-what-is-static-apk-analysis)
2. [Phase 1: Package Validation & Safe Decompression](#2-phase-1-package-validation--safe-decompression)
3. [Phase 2: Android Manifest Inspection](#3-phase-2-android-manifest-inspection)
4. [Phase 3: Permission Auditing & Risk Categorization](#4-phase-3-permission-auditing--risk-categorization)
5. [Phase 4: Pattern & Rule-Based Detection](#5-phase-4-pattern--rule-based-detection)
   - [Hardcoded Secrets & API Keys](#hardcoded-secrets--api-keys)
   - [Network Communication Security](#network-communication-security)
   - [Local Data Storage Hygiene](#local-data-storage-hygiene)
   - [Cryptographic Implementations](#cryptographic-implementations)
   - [Third-Party Trackers & SDKs](#third-party-trackers--sdks)
6. [Phase 5: Transparent Risk Scoring Algorithm](#6-phase-5-transparent-risk-scoring-algorithm)
   - [Base Severity Weights](#base-severity-weights)
   - [Confidence Multipliers](#confidence-multipliers)
   - [Mitigating Repetition & Diminishing Returns](#mitigating-repetition--diminishing-returns)
   - [Guardrails & Score Caps](#guardrails--score-caps)
   - [Rating Bands](#rating-bands)
7. [Methodological Limitations](#7-methodological-limitations)
   - [What Static Analysis Can See](#what-static-analysis-can-see)
   - [What Static Analysis Cannot See](#what-static-analysis-cannot-see)

---

## 1. What Is Static APK Analysis?

An Android app is distributed as an **APK (Android Package Kit)** file, which is a specialized ZIP archive containing compiled code (`.dex` files), resource files, certificates, and the application blueprint (`AndroidManifest.xml`).

There are two primary ways to evaluate an app:
1. **Dynamic Analysis**: Installing the app on an Android phone or emulator and monitoring its behavior while it is running.
2. **Static Analysis**: Examining the app’s code and blueprints *without ever running or installing it*.

The **Mobile Data Leak Detector** uses **Static Analysis**. 

### Why Static Analysis?
- **Speed & Efficiency**: Scans complete in seconds without requiring phone emulators, USB debugging, or simulated user clicks.
- **Complete Path Coverage**: Inspects all code paths, including dormant features or background services that might not trigger during a short test run.
- **100% Offline Privacy**: Because code is inspected directly on your local computer, sensitive internal apps can be audited safely without uploading them to external cloud services.

---

## 2. Phase 1: Package Validation & Safe Decompression

Before parsing any code, the detector validates the file to ensure stability and security:
- **Header & Format Check**: Verifies that the file starts with the standard ZIP magic bytes (`PK\x03\x04`) and conforms to Android packaging standards.
- **Decompression Safety (Zip-Bomb Defense)**: Implements strict file count and extracted size limits (e.g., maximum 10,000 files and 500 MB decompressed size) to defend against maliciously crafted archives designed to freeze computers.
- **Path Traversal Protection**: Ensures no file names inside the archive contain relative path escapes (such as `../../`) that could overwrite system files.

---

## 3. Phase 2: Android Manifest Inspection

Every Android app includes a mandatory file named `AndroidManifest.xml`. It serves as the application's legal contract with the Android operating system. 

The detector decodes this binary XML file using **AndroGuard** and audits key configuration flags:

| Manifest Feature | What the Detector Inspects | Why It Matters for Privacy |
| :--- | :--- | :--- |
| **`android:debuggable`** | Checks if the debug flag is left set to `true`. | If enabled in production, an attacker with physical or ADB access can attach a debugger and extract private memory data. |
| **`android:allowBackup`** | Checks if application backup is enabled without filters. | If enabled, all private databases and settings can be copied off the phone via a computer backup cable without root privileges. |
| **`usesCleartextTraffic`** | Checks if unencrypted HTTP traffic is permitted. | If true, the app allows transmission of data over open HTTP rather than encrypted HTTPS. |
| **Exported Components** | Scans for activities, services, receivers, and content providers marked `android:exported="true"`. | Exported components can be triggered by any other app on the phone, potentially exposing private data or capabilities. |

---

## 4. Phase 3: Permission Auditing & Risk Categorization

Permissions grant apps access to restricted device hardware and personal data. The detector cross-references every requested permission against an embedded knowledge base (`permission_metadata.json`):

1. **Protection Level Classification**:
   - **Normal Permissions**: Low-risk capabilities granted automatically upon install (e.g., `ACCESS_NETWORK_STATE`, `VIBRATE`).
   - **Dangerous Permissions**: High-impact capabilities that directly access private personal information (e.g., `READ_CONTACTS`, `ACCESS_FINE_LOCATION`, `RECORD_AUDIO`, `CAMERA`).
   - **Signature / System Permissions**: Privileged capabilities reserved for device manufacturers or system apps.
2. **Sensitive Data Tagging**:
   - Permissions that touch personal data (location, messages, biometric sensors, contacts) are explicitly tagged with user-friendly privacy warnings.
3. **Dangerous Permission Combinations**:
   - The detector looks for synergistic risk patterns: for instance, an app requesting both `INTERNET` and `ACCESS_FINE_LOCATION` poses a far higher leakage risk than an app requesting location alone without internet access.

---

## 5. Phase 4: Pattern & Rule-Based Detection

The detector scans the compiled Dalvik Executable (`.dex`) files and decoded layout resources using specialized, high-performance pattern matching rules across five core domains:

### Hardcoded Secrets & API Keys
Developers sometimes mistakenly leave private credentials in their code instead of using secure cloud vaults:
- Searches for AWS access keys, Google API keys, OAuth client secrets, private RSA/EC keys, database connection strings, and generic hardcoded passwords.
- **Automatic Redaction**: All matched credential values are masked in the UI and exported reports (`[REDACTED_SECRET]`) to ensure secrets are never exposed during reviews.

### Network Communication Security
Inspects how the app talks to internet servers:
- Flags unencrypted `http://` URLs used for API calls or telemetry.
- Detects unsafe network security configs that allow cleartext traffic across all domains.
- Detects dangerous SSL/TLS bypasses (such as custom `TrustManager` classes that accept invalid certificates, or `AllowAllHostnameVerifier`).

### Local Data Storage Hygiene
Evaluates how user data is saved on the device:
- Detects files created with `MODE_WORLD_READABLE` or `MODE_WORLD_WRITEABLE` (which allows any other installed app to read or modify the file).
- Flags sensitive personal data written to shared external storage (SD cards) rather than private internal storage.
- Detects plaintext SQLite databases storing user credentials without encryption (SQLCipher).

### Cryptographic Implementations
Verifies that the app uses modern, mathematically sound encryption:
- Flags broken or obsolete encryption algorithms (such as DES, 3DES, RC4, or Blowfish).
- Flags weak hash algorithms (MD5, SHA-1) used in security-sensitive contexts.
- Flags insecure encryption modes (such as AES in ECB mode, which fails to hide data patterns).
- Detects static, hardcoded encryption keys or fixed Initialization Vectors (IVs).

### Third-Party Trackers & SDKs
Analyzes third-party libraries bundled inside the app using an extensive signature database (`sdk_patterns.json` and `tracking_patterns.json`):
- Identifies advertising networks, behavioral analytics platforms, location brokers, and social media tracking SDKs.
- Evaluates what device identifiers (IMEI, Android ID, MAC address) or personal attributes these SDKs are designed to collect.

---

## 6. Phase 5: Transparent Risk Scoring Algorithm

Rather than producing a generic or arbitrary score, the application implements a fully **explainable, deterministic scoring model**:

```
Raw Finding Score = Severity Base Weight  x  Confidence Multiplier
```

### Base Severity Weights
Each severity tier carries an explicit point weight reflecting potential security impact:
- **Critical**: 25.0 points
- **High**: 15.0 points
- **Medium**: 8.0 points
- **Low**: 3.0 points
- **Info**: 0.0 points (Purely informational)

### Confidence Multipliers
To prevent low-confidence guesses from distorting results, findings are scaled by confidence:
- **High Confidence**: Multiplier of `1.0` (100% weight)
- **Medium Confidence**: Multiplier of `0.75` (75% weight)
- **Low Confidence**: Multiplier of `0.5` (50% weight)

### Mitigating Repetition & Diminishing Returns
If an app contains the same mistake 100 times in different places (such as repeated calls to an insecure logging function), adding 100 full penalties would unrealistically inflate the score to 100 immediately. 

The algorithm applies **diminishing returns decay** for repeated triggers of the same rule:
- 1st occurrence: `100%` weight (`1.0`)
- 2nd occurrence: `50%` weight (`0.5`)
- 3rd occurrence: `25%` weight (`0.25`)
- 4th+ occurrences: `0%` weight (Recorded as evidence, but no additional points added)

### Guardrails & Score Caps
The algorithm applies two key balancing guardrails:
1. **Low-Severity Aggregate Cap (Max 15.0 points)**: A large collection of minor issues can never artificially push an otherwise safe app into High or Critical risk.
2. **Category Cap (Max 35.0 points)**: No single category (e.g., *Network* or *Storage*) can push an app beyond 35 points on its own, ensuring a holistic multi-domain evaluation.

### Rating Bands
The final score is bounded strictly between **0.0 and 100.0** and mapped to five qualitative rating bands:

```
[ 0.0 - 19.9 ]  Minimal Risk
[ 20.0 - 39.9 ] Low Risk
[ 40.0 - 59.9 ] Medium Risk
[ 60.0 - 79.9 ] High Risk
[ 80.0 - 100.0] Critical Risk
```

---

## 7. Methodological Limitations

Static analysis is an indispensable first line of defense, but like all automated security approaches, it has natural boundaries. Being transparent about these boundaries is essential for sound risk assessment:

### What Static Analysis Can See
- Architectural flaws and manifest misconfigurations.
- Hardcoded secrets, keys, and credentials embedded in code or resources.
- Dangerous permissions and permission combination risks.
- The presence of tracking and behavioral advertising SDKs.
- Insecure coding patterns (weak ciphers, disabled SSL checks, cleartext URLs).

### What Static Analysis Cannot See
- **Active Real-Time Network Traffic**: Static analysis cannot verify whether an app actually sends data during a specific user session; it only verifies that the code contains the instructions to do so.
- **Backend Server Security**: If an app sends data to an HTTPS server, static analysis cannot evaluate whether that remote server stores or protects the data securely.
- **Heavy Runtime Code Packers / Encrypted Payloads**: If an app dynamically downloads its code from the internet after installation or uses proprietary runtime encryption (e.g., commercial banking packers), static inspection can only examine the outer loading shell.
- **Contextual Intent**: Static tools cannot judge business necessity. For example, access to the microphone is expected in a voice recorder, but concerning in a wallpaper app.

> [!TIP]
> **Best Practice Recommendation**: Static analysis should be used as a primary triage filter. Apps flagged with **High** or **Critical** static risk should undergo manual code review or dynamic traffic capture before deployment in sensitive environments.
