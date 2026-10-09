# Mobile Data Leak Detector — User Guide

Welcome to the **Mobile Data Leak Detector**! This guide walks you through using the application to analyze Android applications (APKs) for security weaknesses, tracking behaviors, and potential privacy risks. 

You do not need to be a software engineer or security researcher to understand this tool. Everything is designed with clear summaries, color-coded indicators, and plain-language explanations.

---

## Table of Contents
1. [Overview](#1-overview)
2. [How to Select an APK](#2-how-to-select-an-apk)
3. [How to Run an Analysis](#3-how-to-run-an-analysis)
4. [How to Interpret Risk Scores](#4-how-to-interpret-risk-scores)
5. [How to Interpret Finding Severities](#5-how-to-interpret-finding-severities)
6. [How to Inspect App Permissions](#6-how-to-inspect-app-permissions)
7. [How to Search and Filter Findings](#7-how-to-search-and-filter-findings)
8. [How to Export Audit Reports](#8-how-to-export-audit-reports)
9. [How to View and Manage Scan History](#9-how-to-view-and-manage-scan-history)
10. [Batch Scanning (Analyzing Multiple Apps)](#10-batch-scanning-analyzing-multiple-apps)

---

## 1. Overview

The **Mobile Data Leak Detector** inspects Android installation files (`.apk` files) on your computer. It performs **static analysis**, which means it examines the app’s code and blueprints without running the app or installing it on any mobile device. 

> [!NOTE]
> **Privacy Guarantee**: The application works completely offline. Your files are never uploaded to the cloud, and no analysis data leaves your computer.

---

## 2. How to Select an APK

An **APK** (Android Package Kit) is the file format Android uses to distribute and install mobile apps.

1. Open the application.
2. From the top navigation bar, ensure you are on the **Scanner** tab.
3. Click the **Browse APK** button.
4. In the file selection window, navigate to the folder on your computer where your `.apk` file is saved.
5. Select the file and click **Open**.

The file path will appear in the input box, and the **Start Analysis** button will become active.

---

## 3. How to Run an Analysis

1. After selecting your APK, click the **Start Analysis** button.
2. An animated progress bar and status message will appear showing current progress:
   - *Validating APK package integrity...*
   - *Reading app blueprint and permissions...*
   - *Evaluating security and privacy rules...*
   - *Calculating overall risk score...*
3. Once the scan finishes, the application will automatically switch to the **Results** screen.

> [!TIP]
> Most standard apps take between 2 and 15 seconds to scan. If you ever need to stop an ongoing scan, click **Cancel Analysis**.

---

## 4. How to Interpret Risk Scores

At the top of the Results screen, you will see a prominent **Risk Summary Card** displaying an **Overall Risk Score** between **0 and 100**, accompanied by a color-coded rating badge.

```
+-------------------------------------------------------------+
|  Overall Risk Score: 68 / 100       Rating: [ HIGH RISK ]    |
|  Summary: High risk of sensitive credential exposure.        |
+-------------------------------------------------------------+
```

### Risk Score Ranges

| Score Range | Risk Rating | Color | What It Means in Plain Language |
| :---: | :---: | :---: | :--- |
| **0 – 24** | **LOW** | Green | The app follows good security hygiene. Few or minor issues detected that pose minimal risk to privacy. |
| **25 – 49** | **MEDIUM** | Yellow | The app contains moderate security gaps or requests permissions that warrant attention, but no immediate catastrophic leaks were found. |
| **50 – 74** | **HIGH** | Orange | The app has serious weaknesses (such as unencrypted network traffic or broad personal data access) that could expose user data. |
| **75 – 100** | **CRITICAL** | Red | The app contains dangerous practices, such as hardcoded secret passwords, disabled security verification, or high-risk tracker bundles. |

> [!NOTE]
> The risk score does **not** mean an app is definitely malicious. Rather, it measures how many security weaknesses and tracking indicators are present that could allow data leakage.

---

## 5. How to Interpret Finding Severities

Below the summary score, you will find individual security and privacy issues flagged by the analysis. Each finding is tagged with a **Severity Badge**:

- **CRITICAL (Red)**: Serious flaw that directly compromises privacy or security (for example, a secret API key embedded in the app code, or SSL encryption disabled).
- **HIGH (Orange)**: Major misconfiguration or unsafe data practice (such as sending user information over unencrypted HTTP or storing private files where any app can read them).
- **MEDIUM (Yellow)**: Moderate risk that could assist an attacker or represents unnecessary data sharing (such as third-party advertising trackers embedded without clear safeguards).
- **LOW (Blue)**: Minor divergence from security best practices (for example, leaving backup enabled for general app preferences).
- **INFO (Gray)**: Informational observation (such as identifying an integrated software development kit).

### Expanding Finding Cards
Every finding card displays:
1. **Title & Severity**: A quick headline describing the issue.
2. **Category & Confidence**: The area of concern (e.g., *Network*, *Storage*, *Secrets*) and how certain the detector is (*High*, *Medium*, or *Low*).
3. **Plain-Language Explanation**: What this issue means in everyday words.
4. **Expand Details (`+ Details`)**: Click this button to see:
   - **Evidence**: The code or configuration snippet where the issue was found (sensitive credentials like passwords and tokens are automatically masked as `[REDACTED_SECRET]` to protect your privacy).
   - **Impact**: What could happen if this weakness is exploited.
   - **Remediation**: How a developer can fix the issue.
   - **OWASP Reference**: The international mobile security standard mapping.

---

## 6. How to Inspect App Permissions

Android applications must declare which device capabilities they want to use. Many privacy leaks happen simply because an app requests more access than it needs.

1. On the Results screen, scroll to the **Permissions View** or switch to the permissions section.
2. You will see a structured list of every permission requested by the app.
3. Each permission entry shows:
   - **Permission Name**: (e.g., `android.permission.ACCESS_FINE_LOCATION`).
   - **Protection Level**: *Normal* (safe capabilities like internet access) or *Dangerous* (direct access to private data like contacts, microphone, or GPS).
   - **Risk Classification**: Flagged as *Critical*, *High*, *Medium*, or *Low*.
   - **Plain-Language Description**: What device feature this grants access to.
   - **Reason for Concern**: Why this permission matters for user privacy (for example: *"Allows reading exact geographic coordinates at any time"*).

---

## 7. How to Search and Filter Findings

If an app produces dozens of findings, use the built-in filters to focus on what matters most:

- **Filter by Severity**: Click the severity dropdown to view only *Critical*, *High*, *Medium*, *Low*, or *All*.
- **Filter by Category**: Choose specific categories such as *Permissions*, *Network*, *Storage*, *Secrets*, *Cryptography*, *Third-Party SDK*, or *Manifest*.
- **Search Bar**: Type any keyword (e.g., `"token"`, `"tracking"`, `"http"`, `"location"`) to instantly filter findings in real time.

---

## 8. How to Export Audit Reports

You can export complete, professional audit reports to share with colleagues, clients, or developers:

1. On the Results screen, locate the **Export Buttons** in the top-right toolbar:
   - **Export PDF**: Generates a formatted, publication-ready PDF document including a cover summary, metric cards, permission tables, finding details, and recommended remediations.
   - **Export HTML**: Generates an interactive web-based report that you can open in any browser.
   - **Export TXT**: Generates a clean, plain-text report suitable for quick note-taking, terminal reading, or archival.
2. Click your preferred format.
3. Choose the destination folder on your computer and save the file.
4. A confirmation prompt will notify you when the report is saved.

---

## 9. How to View and Manage Scan History

The application keeps a local history of past scans so you can review previous results without re-analyzing the APK:

1. Click the **History** tab in the main navigation.
2. You will see a chronological list of analyzed apps showing:
   - Application Name and Package Identifier
   - App Version
   - Date and Time of Analysis
   - Risk Score and Rating Badge
3. **Open Previous Result**: Double-click any row or click **View Result** to reload the complete findings in the Results view.
4. **Search History**: Use the search box to find past scans by app name or package name.
5. **Sort Scans**: Toggle between *Newest First* and *Oldest First*.
6. **Delete Scan**: Select a row and click **Delete** to remove that scan from your history.
7. **Clear All History**: Click **Clear All** to wipe all historical records (requires confirmation).

---

## 10. Batch Scanning (Analyzing Multiple Apps)

If you have a collection of APK files you want to inspect together:

1. Click the **Batch** tab in the navigation bar.
2. Click **Add APKs** and select multiple `.apk` files at once.
3. The queue displays each app with its status: *Waiting*, *Analyzing*, *Complete*, or *Failed*.
4. Click **Start Batch**. The app processes the files sequentially to conserve system memory and CPU.
5. Once complete, you can review scores directly in the table or click **Export Batch CSV** to save a summary spreadsheet.
