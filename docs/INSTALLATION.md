# Installation & Getting Started Guide

This guide explains how to install and run the **Mobile Data Leak Detector** on Windows, macOS, and Linux. 

Whether you downloaded the pre-packaged standalone application or want to run it from source code, the setup is straightforward and designed to work right out of the box.

---

## Table of Contents
1. [System Requirements](#1-system-requirements)
2. [Option A: Running the Standalone Application (Recommended)](#2-option-a-running-the-standalone-application-recommended)
   - [Windows Installation](#windows-installation)
   - [macOS Installation](#macos-installation)
   - [Linux Installation](#linux-installation)
3. [Option B: Running from Source Code (Python)](#3-option-b-running-from-source-code-python)
4. [Optional External Tools (JADX & Apktool)](#4-optional-external-tools-jadx--apktool)
   - [Do I Need Them?](#do-i-need-them)
   - [How to Connect Them in Settings](#how-to-connect-them-in-settings)
5. [Where Settings & Data Are Stored](#5-where-settings--data-are-stored)
6. [Updating or Uninstalling](#6-updating-or-uninstalling)

---

## 1. System Requirements

The application runs locally on your computer. It does not require high-end hardware:

- **Operating System**:
  - Windows 10 or Windows 11 (64-bit)
  - macOS 11 (Big Sur) or newer
  - Linux (Ubuntu 20.04+, Debian 11+, Fedora 36+, or equivalent)
- **Memory (RAM)**: 4 GB minimum (8 GB recommended for scanning large apps over 100 MB)
- **Disk Space**: Approximately 200 MB for the application; extra temporary space when scanning APKs
- **Internet Connection**: **None required**. The application is 100% offline and privacy-preserving.

---

## 2. Option A: Running the Standalone Application (Recommended)

The standalone release contains everything needed to run the tool, including the Python runtime and all analysis engines. You do not need to install Python.

### Windows Installation

1. **Download & Extract**:
   - Download the release ZIP archive (`MobileDataLeakDetector-Windows-x64.zip`).
   - Right-click the `.zip` file and select **Extract All...**. Choose a destination folder (such as your `Desktop` or `Program Files`).
2. **Launch the Application**:
   - Open the extracted folder `data_leak_detector`.
   - Double-click **`data_leak_detector.exe`**.
3. **Windows SmartScreen Note**:
   - If Windows shows a blue *"Windows protected your PC"* message on the first launch, click **More info**, then click **Run anyway**. This happens with newly published open-source applications that have not yet acquired commercial digital certificates.
4. The application will launch directly without opening an unwanted black terminal window.

---

### macOS Installation

1. **Download & Extract**:
   - Download the macOS archive (`MobileDataLeakDetector-macOS.zip`).
   - Double-click to uncompress the folder.
2. **Move to Applications**:
   - Drag `MobileDataLeakDetector.app` into your **Applications** folder.
3. **Gatekeeper Note**:
   - If macOS displays a message saying the developer cannot be verified:
     - Open **System Settings** > **Privacy & Security**.
     - Scroll down to the *Security* section.
     - Click **Open Anyway** next to Mobile Data Leak Detector.
4. Launch the app from Launchpad or Finder.

---

### Linux Installation

1. **Download & Extract**:
   - Download the tarball (`MobileDataLeakDetector-Linux-x86_64.tar.gz`).
   - Extract it using your archive manager or run:
     ```bash
     tar -xzf MobileDataLeakDetector-Linux-x86_64.tar.gz
     cd data_leak_detector
     ```
2. **Run**:
   - Make sure the binary has executable permissions:
     ```bash
     chmod +x data_leak_detector
     ./data_leak_detector
     ```
3. *(Optional)* Create a desktop launcher shortcut in `~/.local/share/applications/` to launch it from your application menu.

---

## 3. Option B: Running from Source Code (Python)

If you prefer running directly from Python or are developing custom rules:

1. **Install Python**:
   - Ensure Python 3.10, 3.11, or 3.12 is installed on your computer.
   - On Windows, verify that *"Add Python to PATH"* was checked during installation.
2. **Download or Clone the Repository**:
   ```bash
   git clone https://github.com/your-username/DATA-LEAKAGE-IN-MOBILE-APPS.git
   cd DATA-LEAKAGE-IN-MOBILE-APPS
   ```
3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
4. **Launch the Application**:
   ```bash
   python run_app.py
   ```

---

## 4. Optional External Tools (JADX & Apktool)

### Do I Need Them?
**No! You do not need to install them.** 

The detector comes with a powerful built-in static analysis engine (powered by AndroGuard) that performs complete manifest decoding, permission auditing, certificate verification, and DEX string pattern inspection.

| Tool | Purpose | Is It Required? |
| :--- | :--- | :---: |
| **Built-in Engine (AndroGuard)** | Core static analysis, permissions, strings, secrets | **Included** (Always Active) |
| **Apktool** | Decodes detailed Android XML layouts and resources | *Optional* |
| **JADX** | Decompiles bytecode into readable Java source files | *Optional* |
| **Java (JRE 11+)** | Required only if you choose to run JADX or Apktool | *Optional* |

If JADX or Apktool are missing, the detector automatically and silently uses its internal engines. No scans will fail due to missing external tools.

### How to Connect Them in Settings
If you already have JADX or Apktool installed on your computer and want to enable them:

1. Open the application and click the **Settings** tab.
2. Scroll to the **Tool Executables** section.
3. If they are installed globally in your system `PATH`, the application detects them automatically.
4. Alternatively, click **Browse...** next to *JADX Path* or *Apktool Path* and select the executable or `.jar` file on your hard drive.
5. Click **Check Tools** in the diagnostics card at the top of the Settings screen. You will see a green **AVAILABLE** status when detected.
6. Click **Save Settings**.

---

## 5. Where Settings & Data Are Stored

The application writes configuration and scan history to your standard user directory, keeping the program folder clean:

- **Windows**: `C:\Users\<YourUsername>\AppData\Local\MobileDataLeakDetector\`
- **Linux**: `~/.local/share/MobileDataLeakDetector/`
- **macOS**: `~/Library/Application Support/MobileDataLeakDetector/`

Inside this folder, you will find:
- `settings.json`: Your saved preferences and rule choices.
- `analysis_history.sqlite3`: The local database storing past scan results.
- `logs/app.log`: Application log file for diagnostic troubleshooting.

---

## 6. Updating or Uninstalling

- **To Update**: Download the new release and extract it to replace the previous application folder. Your scan history and settings are stored separately in your user data directory, so updating will not erase your past scan history.
- **To Uninstall**: Delete the application folder. To completely erase all scan history and settings, delete the `MobileDataLeakDetector` folder in your local application data path described in Section 5.
