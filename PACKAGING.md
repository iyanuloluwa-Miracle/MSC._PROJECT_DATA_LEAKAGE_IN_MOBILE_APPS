# Standalone Distribution Guide

This document describes the architecture, configuration, build procedures, and licensing considerations for packaging and distributing the **Mobile Data Leak Detector** as a standalone application using **PyInstaller**.

---

## 1. Distribution Architecture & Rationale

### 1.1 One-Directory (`onedir`) Strategy vs. One-File (`onefile`)
By default, the build system produces a **one-directory (`onedir`)** package located in `dist/data_leak_detector/`. 

| Feature | One-Directory (`onedir`) | One-File (`onefile`) |
| :--- | :--- | :--- |
| **Startup Latency** | **Fast & Instantaneous** (files pre-extracted) | Slow (unzips entire bundle into `%TEMP%` on every launch) |
| **Resource Resolution** | Deterministic relative paths alongside binary | Requires unpacking into ephemeral runtime directories (`_MEIPASS`) |
| **Debugging & Diagnostics** | Missing DLLs or assets easily visible in directory | Harder to debug runtime extraction failures |
| **Antivirus / EDR Trust** | Lower false-positive rate | High false-positive rate from heuristic scanners analyzing packed binaries |
| **Recommended Target** | **Production & Enterprise Distribution** | Portable single-executable transfers |

Starting with an `onedir` build provides an auditable, reliable artifact that can be directly zipped or passed to an installer creator (such as Inno Setup, WiX, NSIS, or native package managers) without the performance and extraction overhead of `onefile`.

---

## 2. Packaged Resources & Runtime Resolution

### 2.1 Bundled Resources
The application depends on three core JSON pattern databases located in `resources/`:
- `permission_metadata.json`: Android permission definitions, classification, protection levels, and risk descriptions.
- `sdk_patterns.json`: Signatures for identifying third-party advertising, analytics, social, and payment SDKs.
- `tracking_patterns.json`: Endpoint regexes, tracking hosts, and privacy-sensitive data parameter patterns.

### 2.2 Frozen Path Resolution
When executing inside a packaged bundle, Python's `sys.frozen` flag is set to `True`, and PyInstaller defines `sys._MEIPASS` pointing to the bundle directory.

The application configuration layer (`data_leak_detector.core.config.AppConfig`) automatically detects this state:
```python
if getattr(sys, "frozen", False):
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        self.resources_dir = Path(meipass) / "resources"
    else:
        self.resources_dir = Path(sys.executable).resolve().parent / "resources"
    if not self.resources_dir.exists():
        fallback = self.base_dir / "resources"
        if fallback.exists():
            self.resources_dir = fallback
    # Writable scratch directory in user temporary storage
    self.temp_dir = Path(tempfile.gettempdir()) / "MobileDataLeakDetector_temp"
else:
    self.resources_dir = self.base_dir / "resources"
    self.temp_dir = self.base_dir / "temp_decompiled"
```

### 2.3 User Data & SQLite Automatic Initialization
The application operates fully offline and writes user-specific state to standard operating system locations rather than the program installation directory:
- **Windows**: `%LOCALAPPDATA%\MobileDataLeakDetector`
- **Linux**: `${XDG_DATA_HOME:-~/.local/share}/MobileDataLeakDetector`
- **macOS**: `~/Library/Application Support/MobileDataLeakDetector`

Upon launching, the application automatically:
1. Creates the user application-data and logs directories if missing.
2. Initializes the SQLite database schema (`analysis_history.sqlite3`) idempotently.
3. Configures sanitized, secret-redacting log output to both console (when available) and `%LOCALAPPDATA%\MobileDataLeakDetector\logs\app.log`.

---

## 3. External Tool Licensing & Packaging Strategy

### 3.1 Why JADX and Apktool Are Not Bundled
Static analysis tools often rely on external decompilers such as **JADX** and **Apktool**. However, bundling them directly into the standalone binary distribution is deliberately avoided due to licensing and packaging constraints:

1. **Licensing Implications**:
   - **JADX** is licensed under Apache 2.0.
   - **Apktool** incorporates components under Apache 2.0, but relies on Smali/Baksmali (BSD) and components that can introduce distribution license conflicts.
2. **Java Runtime Dependency**:
   - Both JADX and Apktool require a compatible Java Runtime Environment (JRE / OpenJDK 11+). Bundling a full JRE would inflate package size by several hundred megabytes and introduce separate Oracle/OpenJDK redistribution terms.
3. **Platform Independence**:
   - Apktool and JADX provide separate scripts (`.bat` on Windows, Bash scripts on Unix) and architecture-specific binaries.

### 3.2 User-Configured and PATH-Based Integration
The application implements **graceful degradation**:
- If neither JADX nor Apktool is installed, the engine performs static analysis, manifest parsing, permission auditing, certificate verification, and DEX string inspection directly via the bundled **AndroGuard** library.
- If external tools are available on the system `PATH` or configured via **Settings > Tool Executables**, the engine leverages them for high-fidelity smali decompilation and resource decoding.
- The **Settings View** provides a **"Check Tools"** button to verify JADX, Apktool, and Java availability in the user's current environment.

---

## 4. Platform-Specific Build Procedures

> [!IMPORTANT]
> **PyInstaller does NOT cross-compile.** A Windows `.exe` must be built on Windows, a macOS `.app` on macOS, and a Linux binary on Linux. Do not attempt to produce Windows binaries from Linux without an emulated environment (e.g., Wine), which is not recommended for production.

### 4.1 Prerequisites (All Platforms)
1. Python 3.10+ (matching the deployment architecture, e.g., 64-bit).
2. Install project dependencies and PyInstaller:
   ```bash
   pip install -r requirements.txt  # or pip install -e .
   pip install pyinstaller
   ```

---

### 4.2 Building on Windows

1. **Verify Environment**:
   ```powershell
   python --version
   python -m PyInstaller --version
   ```

2. **Execute Spec Build**:
   ```powershell
   python -m PyInstaller data_leak_detector.spec --clean --noconfirm
   ```

3. **Output Location**:
   - The compiled distribution directory is created at `dist\data_leak_detector\`.
   - The primary binary is `dist\data_leak_detector\data_leak_detector.exe`.

4. **Production Windowed Mode (`noconsole`)**:
   - `data_leak_detector.spec` specifies `console=False`, preventing a blank terminal/command-prompt window from opening.
   - Per-monitor DPI awareness is handled at startup via `ctypes.windll.shcore.SetProcessDpiAwareness(1)`.

5. **Packaging for End Users**:
   - Compress the entire `dist\data_leak_detector\` folder into a ZIP archive:
     ```powershell
     Compress-Archive -Path dist\data_leak_detector -DestinationPath dist\MobileDataLeakDetector-Windows-x64.zip
     ```
   - Alternatively, compile using an installer generator such as Inno Setup.

---

### 4.3 Building on macOS

1. **Install Build Dependencies**:
   ```bash
   brew install python@3.12
   pip3 install -e .
   pip3 install pyinstaller
   ```

2. **Adjust `.spec` for macOS App Bundle (Optional)**:
   On macOS, an app bundle can be built by adding `BUNDLE` to `data_leak_detector.spec`:
   ```python
   app = BUNDLE(
       coll,
       name='MobileDataLeakDetector.app',
       icon=None,
       bundle_identifier='com.dataleakdetector.app',
       info_plist={
           'NSHighResolutionCapable': 'True',
           'CFBundleShortVersionString': '0.1.0',
       },
   )
   ```

3. **Build Command**:
   ```bash
   python3 -m PyInstaller data_leak_detector.spec --clean --noconfirm
   ```

4. **Code Signing and Gatekeeper (Notarization)**:
   - On macOS 10.15+, executables must be signed and notarized by Apple to run without security warnings:
     ```bash
     codesign --deep --force --options runtime --sign "Developer ID Application: Your Name" dist/MobileDataLeakDetector.app
     xcrun notarytool submit dist/MobileDataLeakDetector.zip --keychain-profile "AC_PASSWORD" --wait
     xcrun stapler staple dist/MobileDataLeakDetector.app
     ```

---

### 4.4 Building on Linux

1. **Install Build Dependencies**:
   ```bash
   sudo apt-get update
   sudo apt-get install -y python3 python3-pip python3-tk libtk8.6 libtcl8.6
   pip3 install -e .
   pip3 install pyinstaller
   ```

2. **Execute Spec Build**:
   ```bash
   python3 -m PyInstaller data_leak_detector.spec --clean --noconfirm
   ```

3. **Output Location**:
   - Binary directory created at `dist/data_leak_detector/`.
   - Executable entry point: `dist/data_leak_detector/data_leak_detector`.

4. **Desktop Integration**:
   Create a standard FreeDesktop `.desktop` entry in `~/.local/share/applications/mobile-data-leak-detector.desktop`:
   ```desktop
   [Desktop Entry]
   Type=Application
   Name=Mobile Data Leak Detector
   Comment=Static Android Vulnerability and Data Leakage Analyzer
   Exec=/opt/data_leak_detector/data_leak_detector
   Terminal=false
   Categories=Development;Security;
   ```

5. **Creating a Portable Tarball or AppImage**:
   ```bash
   tar -czvf MobileDataLeakDetector-Linux-x86_64.tar.gz -C dist data_leak_detector
   ```

---

## 5. Verification & Smoke Testing Checklist

After generating the package on any operating system, verify using the following steps:

1. **Directory Integrity**:
   - Verify `dist/data_leak_detector/resources/` exists.
   - Verify all 3 pattern databases are present:
     - `permission_metadata.json`
     - `sdk_patterns.json`
     - `tracking_patterns.json`
2. **Launch Verification**:
   - Execute the binary directly.
   - Confirm the main Tkinter window displays immediately.
   - Confirm **no residual black terminal or console window** opens behind the GUI.
3. **Database & Config Creation**:
   - Confirm `%LOCALAPPDATA%\MobileDataLeakDetector\` (or OS equivalent) is created automatically.
   - Confirm `analysis_history.sqlite3` and `settings.json` are generated.
   - Confirm log entries are written to `logs/app.log`.
4. **Analysis Pipeline Test**:
   - Run a test scan on a sample APK.
   - Confirm findings, risk score, and permissions populate in ResultsView.
   - Confirm reports can be exported to PDF, HTML, and TXT.
5. **Tool Diagnostics**:
   - Open Settings > Check Tools.
   - Confirm tool status displays gracefully without unhandled exceptions whether tools are present or absent.
