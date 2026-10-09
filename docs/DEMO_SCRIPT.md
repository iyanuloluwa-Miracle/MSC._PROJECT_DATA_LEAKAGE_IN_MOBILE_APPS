# Academic Demonstration Script (3–5 Minutes)

This document provides a structured, timed demonstration script for presenting the **Mobile Data Leak Detector** during a university dissertation defense, academic viva, or technical presentation.

---

## Demonstration Overview

- **Audience**: University professors, dissertation examiners, peer researchers, and software engineers.
- **Duration**: 3 to 5 minutes.
- **Core Value Proposition**: Demonstrates a 100% offline, privacy-preserving static analyzer that uncovers data leaks, dangerous permission combinations, hardcoded credentials, and third-party advertising trackers in Android APKs without executing untrusted code.
- **Pre-Generated Demonstration APK**: `sample_apks/demo_vulnerable_app.apk` (Generated via `python scripts/generate_demo_apk.py`).

---

## Pre-Demonstration Setup Checklist (T-Minus 5 Minutes)

1. **Verify Demonstration APK**:
   ```powershell
   # If not already created, generate the authorized benchmark package
   python scripts/generate_demo_apk.py
   ```
2. **Launch Application**:
   - Standalone: Double-click `dist\data_leak_detector\data_leak_detector.exe`
   - From Source: Run `python run_app.py`
3. **Have a Destination Ready**: Open your `Documents` or `Desktop` folder in File Explorer to quickly show exported PDF reports.

---

## 3–5 Minute Timed Presentation Script

```
+---------------------------------------------------------------------------------+
| TIMELINE OVERVIEW                                                               |
| 0:00 - 0:35  [Act I]    Problem Motivation & Clean Application Launch           |
| 0:35 - 1:15  [Act II]   APK Selection & Pre-Scan Metadata Inspection            |
| 1:15 - 2:00  [Act III]  Live Multi-Stage Pipeline & Transparent Feedback        |
| 2:00 - 2:50  [Act IV]   Results Dashboard: Risk Score & Permission Audit        |
| 2:50 - 3:45  [Act V]    Vulnerability Inspection, Redaction & Remediation       |
| 3:45 - 4:25  [Act VI]   Audit Report Generation (PDF Export)                    |
| 4:25 - 5:00  [Act VII]  Local Scan History & Closing Summary                    |
+---------------------------------------------------------------------------------+
```

---

### Act I: Problem Motivation & Application Launch (0:00 – 0:35)

- **UI Action**: Show the open application on the **Scanner** tab.
- **Presenter Narrative**:
  > *"Good morning, members of the committee. Modern Android apps frequently leak sensitive user information—not because of zero-day exploits, but due to architectural oversights, over-privileged permissions, and unvetted third-party tracking SDKs.*
  >
  > *Dynamic testing requires rooting devices and simulating network traffic, but it misses dormant code and exposes internal corporate apps to cloud inspection. To solve this, I developed the Mobile Data Leak Detector: a completely offline, automated static security analyzer built with Python, Tkinter, and AndroGuard."*

---

### Act II: APK Selection & Metadata Inspection (0:35 – 1:15)

- **UI Action**:
  1. Point out the **DropZone** in the Scanner tab.
  2. Click **Browse File...**.
  3. Select `sample_apks/demo_vulnerable_app.apk`.
- **Presenter Narrative**:
  > *"Here, the examiner can choose any standard APK. For today's demonstration, I am selecting our authorized benchmark application: `demo_vulnerable_app.apk`.*
  >
  > *Notice that upon selection, the software immediately validates the archive integrity and computes its cryptographic identity: file size (1.5 KB), package location, and SHA-256 hash preview. This ensures full forensic traceability before any analysis code executes."*

---

### Act III: Live Multi-Stage Pipeline & Status Feedback (1:15 – 2:00)

- **UI Action**: Click **▶ Start Static Analysis**.
- **Visual Cues**: Direct the committee’s attention to the animated progress bar, percentage counter, and dynamic stage label updating in real time:
  - *Stage: VALIDATING (10%)*
  - *Stage: PARSING (25%)*
  - *Stage: DECOMPILING (45%)*
  - *Stage: ANALYZING_PERMISSIONS (55%)*
  - *Stage: SCANNING_MANIFEST (65%)*
  - *Stage: SCANNING_SECRETS (70%)*
  - *Stage: SCANNING_NETWORK (75%)*
  - *Stage: SCANNING_STORAGE (80%)*
  - *Stage: SCANNING_CRYPTO (85%)*
  - *Stage: SCANNING_SDKS (90%)*
  - *Stage: SCORING (95%)*
  - *Stage: COMPLETED (100%)*
- **Presenter Narrative**:
  > *"When I click 'Start Static Analysis', the scan executes asynchronously on a background worker thread, ensuring the user interface remains completely responsive.*
  >
  > *Notice the transparent stage progression. Rather than displaying an ambiguous spinner, the software informs the auditor of each distinct phase: validating zip structure, extracting AndroidManifest.xml, auditing dangerous permissions, scanning DEX bytecode strings, and executing our security rules across network, secrets, storage, cryptography, and third-party SDKs."*

---

### Act IV: Results Dashboard, Risk Score & Permission Audit (2:00 – 2:50)

- **UI Action**: The application automatically switches to the **Results** screen.
  1. Highlight the top **Risk Summary Card** showing **Overall Risk Score: 100/100 (CRITICAL)**.
  2. Scroll down to the **Permissions View**.
- **Presenter Narrative**:
  > *"Upon scan completion, we are presented with a comprehensive audit dashboard.*
  >
  > *At the top, our explainable risk-scoring algorithm aggregates all findings into a normalized index from 0 to 100. This app receives a 100/100 Critical rating.*
  >
  > *In the Permissions table below, we see 5 declared permissions. Note how dangerous permissions—such as `ACCESS_FINE_LOCATION`, `READ_CONTACTS`, and `READ_EXTERNAL_STORAGE`—are highlighted in red with plain-language explanations. More importantly, our engine flags the synergistic risk: requesting both location and internet creates an active geolocation exfiltration pathway."*

---

### Act V: Vulnerability Findings, Redaction & Remediation Advice (2:50 – 3:45)

- **UI Action**:
  1. Use the **Severity Dropdown** to filter by **Critical** or **High**.
  2. Locate the finding: **"Hardcoded Google API Key"** or **"Exported Content Provider Unprotected"**.
  3. Click **+ Details** on the finding card to expand it.
- **Presenter Narrative**:
  > *"Now let's examine the specific security findings. We have 26 identified issues across manifest configuration, hardcoded secrets, and tracking SDKs.*
  >
  > *When I expand this finding card, notice three critical technical features:*
  > *1. **Privacy-Preserving Secret Redaction**: The detected Google API key is automatically masked as `[REDACTED_SECRET]` in the evidence block. Raw credentials are never exposed during audits or logged in plaintext.*
  > *2. **Actionable Remediation**: Rather than just pointing out a problem, the card gives developers concrete advice on moving secrets into Android KeyStore or environment vaults.*
  > *3. **Standards Mapping**: Every finding is mapped directly to international security standards, including OWASP Mobile Top 10 (M1: Insecure Data Storage, M5: Insecure Communication)."*

---

### Act VI: Audit Report Generation (PDF Export) (3:45 – 4:25)

- **UI Action**:
  1. Click the **Export PDF** button in the top-right toolbar.
  2. Select your `Documents` folder and save the file.
  3. Open the generated PDF file.
- **Presenter Narrative**:
  > *"For formal reporting, the auditor can export findings with a single click. I'll click 'Export PDF'.*
  >
  > *The engine compiles a publication-ready PDF containing our executive summary, metric charts, permission classification matrix, and detailed remediation cards. All sensitive tokens remain properly redacted in the document."*

---

### Act VII: Scan History & Closing Summary (4:25 – 5:00)

- **UI Action**:
  1. Click the **History** tab in the main navigation.
  2. Show the newly added scan record in the historical table.
  3. Double-click the record (or click **View Result**) to show instant reloading from SQLite.
- **Presenter Narrative**:
  > *"Finally, navigating to the History tab reveals our local SQLite audit database. Every scan is indexed by package name, file hash, timestamp, and risk score.*
  >
  > *Double-clicking any past record reloads its complete findings instantaneously without re-analyzing the binary.*
  >
  > *In summary, the Mobile Data Leak Detector provides a rapid, explainable, and 100% offline static analysis capability that bridges the gap between high-level compliance and low-level bytecode inspection. Thank you, and I look forward to your questions."*

---

## Backup Demonstration Procedure (Fallback Plan)

During live academic presentations, unexpected environment constraints (such as missing Java runtimes or strict classroom permissions) can occur. The application was deliberately engineered to handle these scenarios gracefully.

### Scenario: JADX, Apktool, or Java Are Missing / Unavailable

1. **Verify Built-in Engine Status**:
   - Open **Settings** > Click **Check Tools**.
   - Point out to the committee:
     - **AndroGuard Static Parser**: `AVAILABLE` (Green)
     - **apktool Resource Extractor**: `UNAVAILABLE` (Yellow/Gray)
     - **jadx Java Decompiler**: `UNAVAILABLE` (Yellow/Gray)
2. **Explain Graceful Degradation Rationale**:
   - Explain to the examiners:
     > *"As designed in our threat model and packaging architecture, the detector does not depend on external decompiler binaries. When JADX or Apktool are absent, the application automatically engages its native internal DEX parser to harvest bytecode strings, manifests, and JSON resources directly."*
3. **Execute the Standard Scan**:
   - Return to **Scanner** and click **Start Static Analysis**.
   - The scan will execute and finish in under 3 seconds.
   - Point out that **all 26 findings, permission audits, and risk scores are detected identically**, with clear informational notices recorded in the metrics rather than failing with an unhandled exception.
