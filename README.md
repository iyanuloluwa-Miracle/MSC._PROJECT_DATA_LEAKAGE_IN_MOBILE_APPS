# Mobile Data Leak Detector

An academic research prototype desktop application for **static-only** detection of potential data leakage risks, security vulnerabilities, and privacy violations in Android applications (APK).

---

## 🔬 Core Product Constraints & Principles

1. **Strictly Static Analysis**: APK files are treated purely as static archives and bytecode packages. APKs are **never executed, installed, or dynamically loaded**.
2. **Static Indicators, Not Exfiltration Proof**: Network endpoints, URLs, and transmission methods discovered during analysis represent **static risk indicators**, not runtime verification of active data leakage.
3. **100% Offline & Local**: No APK bytecode, metadata, or analysis findings are ever transmitted to external servers. All persistence is managed locally via SQLite.
4. **Subprocess Safety**: External CLI tools (`jadx`, `apktool`) are accessed via safe subprocess wrappers (no `shell=True`, explicit timeouts, graceful degradation if tools are missing). Temporary decompilation artifacts are cleaned up automatically.
5. **Privacy by Design**: Sensitive API keys and credentials detected during scans are automatically redacted in logs and sanitized in reports.

---

## 🏗️ Repository Architecture

The project follows a standard `src`-based Python project structure:

```text
DATA-LEAKAGE-IN-MOBILE-APPS/
├── .gitignore
├── ARCHITECTURE.md                  # Comprehensive architectural specification & requirement traceability
├── README.md                        # Project overview and setup instructions
├── TASKS.md                         # Phased development backlog mapped to requirements
├── docs/                            # Research notes, methodologies, and user documentation
├── resources/                       # Static pattern databases and permission metadata
│   ├── permission_metadata.json
│   ├── sdk_patterns.json
│   └── tracking_patterns.json
├── scripts/                         # Operational and maintenance scripts
├── src/
│   └── data_leak_detector/
│       ├── __init__.py
│       ├── app.py                   # Desktop application entry point
│       ├── core/                    # Models, configuration, exceptions, and logging
│       │   ├── __init__.py
│       │   ├── config.py
│       │   ├── exceptions.py
│       │   ├── logging_config.py
│       │   └── models.py
│       ├── analysis/                # Core analysis orchestrator, APK parser, and adapters
│       │   ├── __init__.py
│       │   ├── apk_parser.py
│       │   ├── engine.py
│       │   ├── permission_analyzer.py
│       │   ├── risk_scorer.py
│       │   ├── tool_adapters.py
│       │   └── vulnerability_detector.py
│       ├── rules/                   # Pluggable static vulnerability detection rules
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── crypto_rules.py
│       │   ├── manifest_rules.py
│       │   ├── network_rules.py
│       │   ├── sdk_rules.py
│       │   ├── secret_rules.py
│       │   └── storage_rules.py
│       ├── reporting/               # PDF (ReportLab), HTML, and text report formatters
│       │   ├── __init__.py
│       │   ├── html_report.py
│       │   ├── pdf_report.py
│       │   ├── report_generator.py
│       │   └── text_report.py
│       ├── storage/                 # Local SQLite database manager
│       │   ├── __init__.py
│       │   └── database.py
│       └── ui/                      # Tkinter / ttk Desktop graphical user interface
│           ├── __init__.py
│           ├── analyze_view.py
│           ├── history_view.py
│           ├── main_window.py
│           ├── results_view.py
│           ├── settings_view.py
│           └── widgets.py
└── tests/                           # Unit and integration test suites
    ├── fixtures/
    ├── integration/
    └── unit/
```

---

## 📋 Requirement Traceability Summary

Detailed requirements and their architectural mapping are documented in [ARCHITECTURE.md](file:///c:/Users/Iyanu/OneDrive/Desktop/DATA-LEAKAGE-IN-MOBILE-APPS/ARCHITECTURE.md):

- **FR-01 APK Analysis**: Deconstruction of APK structures, manifests, and DEX bytecode.
- **FR-02 Permission Auditing**: Comprehensive categorization of dangerous and signature-level permissions.
- **FR-03 Data-Leak Indicator Detection**: Statically identifying unencrypted endpoints and third-party trackers.
- **FR-04 Vulnerability Identification**: Rule-based detection of hardcoded secrets, weak crypto, and manifest flaws.
- **FR-05 Report Generation**: Exporting formal audit documents to PDF (via ReportLab), HTML, and Text.
- **NFR-01 to NFR-06**: Usability, Performance, Reliability, Scalability, Portability, and Privacy/Security.

---

## 🚀 Getting Started

### 1. Prerequisites
- **Python**: Version 3.10+ (tested on Python 3.12 64-bit).
- **Tkinter**: Standard Python graphical interface library (bundled with standard Python for Windows/macOS).
- *(Optional)* **JADX**: Java decompiler CLI (`jadx` on PATH) for extended Java source inspection.
- *(Optional)* **Apktool**: Android resource decoder CLI (`apktool` on PATH) for resource XML deconstruction.

### 2. Environment Setup

Clone or open the repository workspace and install the required dependencies:

```bash
# Install core static analysis dependencies
python -m pip install androguard pillow reportlab
```

### 3. Graceful Degradation & Tool Diagnostics

The application is engineered to degrade gracefully when optional external CLI tools are not present:
- **Missing `jadx`**: Analysis continues seamlessly using AndroGuard's native DEX bytecode and instruction parsing.
- **Missing `apktool`**: Resource and manifest inspection continues using AndroGuard's internal AXML parser and resource table decoder.
- **No Third-Party Binaries Bundled**: The application operates safely without requiring bundled third-party executables.

You can inspect the system tool availability at any time using the built-in diagnostic function:

```python
from data_leak_detector.analysis.tool_adapters import get_tool_diagnostics

status = get_tool_diagnostics()
# Returns:
# {
#     "AndroGuard": "AVAILABLE",
#     "apktool": "AVAILABLE" or "UNAVAILABLE",
#     "jadx": "AVAILABLE" or "UNAVAILABLE"
# }
```

### 4. Running Automated Tests

#### Execute All Unit Tests
```bash
python scripts/run_tests.py
```
Or directly via Python's `unittest` module:
```bash
python -m unittest discover -s tests/unit
```

#### Integration Testing with Real APK Files
By default, integration tests that require a live APK are skipped. To run the integration suite against a real target APK, supply the `TEST_APK_PATH` environment variable:

```bash
# Windows PowerShell
$env:TEST_APK_PATH = "C:\path\to\target.apk"
python scripts/run_tests.py

# Linux / macOS
TEST_APK_PATH="/path/to/target.apk" python scripts/run_tests.py
```

