# Troubleshooting Guide

This guide provides quick solutions for common questions and issues you might encounter while using the **Mobile Data Leak Detector**.

---

## Quick Diagnostic Checklist
Before diving into specific issues, verify these three basic checks:
1. Is your file a valid, standard Android `.apk` file?
2. Does your computer have at least 1 GB of free disk space in your temporary directory?
3. Are you running the latest version of the application?

---

## Table of Contents
1. [APK Fails to Load or Parse](#1-apk-fails-to-load-or-parse)
2. [Warning: "External Tools Unavailable"](#2-warning-external-tools-unavailable)
3. [Analysis Is Taking Very Long or Times Out](#3-analysis-is-taking-very-long-or-times-out)
4. [Cannot Export Reports (PDF, HTML, or TXT)](#4-cannot-export-reports-pdf-html-or-txt)
5. [Display, Font, or Dark Theme Issues](#5-display-font-or-dark-theme-issues)
6. [How to View Application Logs](#6-how-to-view-application-logs)
7. [How to Reset Settings to Default](#7-how-to-reset-settings-to-default)

---

## 1. APK Fails to Load or Parse

### Symptom
When you select an APK and click **Start Analysis**, an error dialog appears stating:
*"Invalid APK format"*, *"Corrupted ZIP archive"*, or *"Failed to parse package structure"*.

### Causes & Solutions

#### A. The file is a "Split APK" or App Bundle (`.xapk`, `.apks`, `.apkm`)
- **Cause**: Many third-party app stores distribute modern Android apps as split archive bundles (`.xapk` or `.apks`) rather than a single unified `.apk` file.
- **Solution**: The detector requires a standard standalone `.apk` package (the base APK). If you have an `.xapk` or `.apks` file, you can rename its extension to `.zip`, extract it with your archive manager, and analyze the `base.apk` file found inside.

#### B. Incomplete or Corrupted Download
- **Cause**: The APK file was only partially downloaded or was corrupted during transfer.
- **Solution**: Re-download the APK from its source. Verify the file size matches the download source.

#### C. The File Exceeds Safety Size Limits (Default: 200 MB)
- **Cause**: To protect your computer from memory exhaustion and zip-bomb attacks, the detector enforces a maximum APK file size limit (200 MB by default).
- **Solution**:
  1. Open the **Settings** tab in the application.
  2. Increase the **Maximum APK Size** limit.
  3. Click **Save Settings** and retry your scan.

#### D. The APK Uses Proprietary Commercial Obfuscation / Packing
- **Cause**: Certain enterprise or financial banking apps use runtime packers (such as DexGuard, SecNeo, or Bangcle) that encrypt the underlying code files on disk until the app is launched on an actual physical phone.
- **Solution**: The detector will still extract and audit the `AndroidManifest.xml` and permissions, but code-level string rules will report fewer findings because the code is encrypted by the proprietary packer.

---

## 2. Warning: "External Tools Unavailable"

### Symptom
In the Settings screen or during a scan, you see a notice indicating:
*"Apktool unavailable"* or *"JADX unavailable"*.

### Solution
> [!NOTE]
> **This is NOT a failure and does NOT prevent you from analyzing apps.**

- The application includes a full internal static engine powered by AndroGuard. It decodes manifests, extracts permissions, checks certificates, and analyzes compiled DEX code automatically.
- External tools (JADX and Apktool) are purely optional enhancements for deeper smali decompilation.
- If you wish to connect them:
  1. Install Java 11+ and download JADX / Apktool.
  2. Go to **Settings > Tool Executables**.
  3. Enter their paths or ensure they are added to your system `PATH`.
  4. Click **Check Tools** to verify.

---

## 3. Analysis Is Taking Very Long or Times Out

### Symptom
The scan progress bar stops advancing for more than 2 minutes, or displays a timeout notification.

### Causes & Solutions
- **Extremely Large Codebases**: Mobile apps containing 5 or more large multi-DEX files (such as 150 MB games or large social media apps) can take 30 to 60 seconds to scan thoroughly.
- **Subprocess Timeout**:
  1. Open the **Settings** tab.
  2. Increase the **Subprocess Timeout (seconds)** setting (for example, from `120` to `240` seconds).
  3. Click **Save Settings**.
- **Memory Pressure**: Close heavy background applications (like virtual machines or web browsers with dozens of tabs) to free up RAM before scanning large files.

---

## 4. Cannot Export Reports (PDF, HTML, or TXT)

### Symptom
Clicking **Export PDF**, **Export HTML**, or **Export TXT** displays an error message or fails to save the file.

### Causes & Solutions
- **Protected Folder Permission**:
  - If you try to save directly into a system-protected directory (such as `C:\Windows\` or `C:\Program Files\`), Windows will block file creation.
  - **Solution**: Save reports to your standard user folders, such as **Documents**, **Desktop**, or **Downloads**.
- **File Is Open in Another Program**:
  - If you already have `report.pdf` open in an Adobe Acrobat or browser window, Windows locks the file from being overwritten.
  - **Solution**: Close the open PDF viewer before re-exporting.

---

## 5. Display, Font, or Dark Theme Issues

### Symptom
Text appears blurry, buttons overlap, or colors are difficult to read in high-glare environments.

### Solutions
- **High-Contrast Mode**:
  1. Go to **Settings**.
  2. Check the box for **High Contrast / Accessibility Mode**.
  3. Click **Save Settings**. The interface immediately switches to high-contrast monochrome with prominent border outlines and large typography.
- **Windows Display Scaling (DPI)**:
  - On 4K / High-DPI laptop screens, ensure Windows Display Scaling is set to 100%, 125%, or 150% in *Windows Settings > System > Display*. The application automatically applies DPI-aware font scaling on startup.

---

## 6. How to View Application Logs

When troubleshooting an unexpected error, the application records technical logs:

1. Press `Win + R` on Windows (or open your file manager).
2. Type or paste the following path into the address bar:
   - **Windows**: `%LOCALAPPDATA%\MobileDataLeakDetector\logs\`
   - **macOS**: `~/Library/Application Support/MobileDataLeakDetector/logs/`
   - **Linux**: `~/.local/share/MobileDataLeakDetector/logs/`
3. Open **`app.log`** in Notepad or any text editor.

> [!NOTE]
> **Privacy Guarantee**: All sensitive passwords, API keys, and private tokens are automatically redacted in `app.log` as `[REDACTED_SECRET]`.

---

## 7. How to Reset Settings to Default

If settings were accidentally changed and scans are behaving unexpectedly:

1. Open the **Settings** tab.
2. Scroll to the bottom of the screen.
3. Click the **Reset to Defaults** button.
4. Confirm the prompt.
5. All timeouts, file size limits, rule choices, and tool paths will be restored to their factory defaults.
