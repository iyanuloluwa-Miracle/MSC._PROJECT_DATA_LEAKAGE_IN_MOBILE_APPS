# Changelog

All notable changes to the **Mobile Data Leak Detector** project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-10-09

### Added
- **Core Architecture & Models**:
  - Strongly typed dataclass domain models (`ApplicationMetadata`, `ManifestData`, `PermissionFinding`, `SecurityFinding`, `AnalysisMetrics`, `AnalysisResult`).
  - Strict static-only analysis paradigm: zero dynamic execution, zero network telemetry, 100% offline privacy boundary.
  - Automatic credential redaction filter (`SensitiveDataFilter`) masking Google API keys, AWS tokens, GitHub tokens, Slack keys, and generic secrets in all logs and reports.
  - Safe path resolution and Zip Slip protection (`is_safe_zip_path`).

- **Static Analysis Engine & APK Parsing**:
  - `APKParser` leveraging AndroGuard for static APK archive validation, streaming SHA-256 computation, manifest binary XML extraction, and DEX bytecode string parsing.
  - `_PlainManifestFallback` adapter enabling parsing of educational test/demonstration APKs containing plain-text manifests.
  - Subprocess adapters for external decompilation tools (`JadxAdapter`, `ApktoolAdapter`) with graceful degradation to native bytecode inspection when tools are absent.
  - `PermissionAnalyzer` auditing Android permissions against a curated metadata baseline (`permission_metadata.json`), flagging dangerous permissions and synergistic exfiltration combinations (e.g. `ACCESS_FINE_LOCATION` + `INTERNET`).
  - Central `AnalysisEngine` orchestrating a 12-stage analysis pipeline with non-blocking cooperative cancellation support (`CancellationToken`).

- **Pluggable Static Detection Rules (36 Rules)**:
  - `manifest_rules.py`: Flags `android:allowBackup=true`, `android:debuggable=true`, `usesCleartextTraffic=true`, missing network security configs, and unprotected exported components.
  - `secret_rules.py`: Identifies hardcoded Google API keys, AWS credentials, generic API tokens, OAuth secrets, database credentials, and private keys.
  - `network_rules.py`: Detects cleartext `http://` URLs, trust-all X.509 managers, permissive hostname verifiers, and third-party advertising/tracking endpoints.
  - `storage_rules.py`: Flags `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` storage, unencrypted external storage access, and plaintext SharedPreferences/SQLite storage.
  - `crypto_rules.py`: Identifies broken ciphers (DES, 3DES, RC4), ECB encryption modes, static IVs, hardcoded cryptographic keys, and obsolete hashing (MD5, SHA-1).
  - `sdk_rules.py`: Matches package structures against `sdk_patterns.json` across 7 SDK categories and evaluates SDK Permission Exposure.
  - `RiskScorer`: Computes explainable 0–100 composite risk scores with severity base weights, confidence multipliers, repetition decay, category caps (35 pts), and low-severity caps (15 pts).

- **Local Persistence & Database**:
  - `DatabaseManager` providing local SQLite storage in OS standard user application data directories (`%LOCALAPPDATA%`, `~/.local/share`, `~/Library/Application Support`).
  - Parameterized SQL queries exclusively to prevent SQL injection (CWE-89).
  - Automatic idempotent schema migrations for applications, analysis runs, permission findings, and security findings.
  - Search, sort, pagination, and deletion operations for historical scans.

- **Multi-Format Reporting Engine**:
  - `PDFReportGenerator`: Publication-grade multi-page PDF audit reports via ReportLab Platypus featuring executive summaries, metric cards, permission tables, and finding cards.
  - `HTMLReportGenerator`: Standalone, interactive HTML reports with responsive layouts and embedded CSS.
  - `TextReportGenerator`: Terminal-friendly plaintext audit summaries for command-line reading and archiving.

- **Desktop User Interface (Tkinter / ttk)**:
  - Responsive desktop layout with left sidebar navigation (`MainWindow`).
  - `AnalyzeView`: File drop zone displaying file size and SHA-256 fingerprint, asynchronous background worker threading, and real-time stage progress updates.
  - `ResultsView`: Summary dashboard with metric cards, risk score gauge, severity and category dropdown filters, search bar, and expandable finding cards.
  - `BatchView`: Sequential queue-based batch scanning for multi-APK collections with CSV summary export.
  - `HistoryView`: Query interface for viewing past scan records, searching by package/name, and reloading historical results.
  - `SettingsView`: External tool diagnostic checker, timeout configuration, rule toggles, and high-contrast / accessibility mode.

- **Dissertation Evaluation & Comparison Tooling**:
  - `scripts/evaluate.py`: Automated dissertation evaluation harness computing detection counts, timing distributions (mean, median, min, max), and empirical accuracy metrics (precision, recall, F1) against ground truth.
  - `scripts/compare_results.py`: Cross-tool comparison framework ingesting MobSF and RiskInDroid CSV exports to evaluate finding overlap and divergence.
  - `scripts/profile_workflow.py`: Micro-profiler measuring execution durations across all analysis stages.
  - `scripts/generate_demo_apk.py`: Benchmark generator creating an authorized educational test APK (`sample_apks/demo_vulnerable_app.apk`).

- **Standalone Distribution & Packaging**:
  - `data_leak_detector.spec`: One-directory (`onedir`) PyInstaller specification bundling all JSON metadata resources into `resources/`.
  - Production windowed execution without console popups (`console=False`).
  - `PACKAGING.md`: Documenting platform-specific build instructions for Windows, macOS, and Linux.

- **User & Technical Documentation**:
  - `docs/USER_GUIDE.md`: Comprehensive end-user guide for non-technical users.
  - `docs/INSTALLATION.md`: Installation procedures for standalone executables and Python source.
  - `docs/INTERPRETING_RESULTS.md`: Guide explaining the distinctions between static indicators, potential vulnerabilities, confirmed vulnerabilities, and actual data leaks.
  - `docs/TROUBLESHOOTING.md`: Common error solutions and diagnostics.
  - `docs/METHODOLOGY.md`: Detailed explanation of static analysis procedures, rules, and scoring algorithms.
  - `docs/DEMO_SCRIPT.md`: 3–5 minute presentation script and backup demonstration procedure.
  - `docs/REQUIREMENTS_TRACEABILITY.md`: Formal verification audit against FR-01 through FR-05 and NFR-01 through NFR-06.
