# Requirements Traceability Matrix & Audit

This document provides a comprehensive, rigorous requirements traceability audit for the **Mobile Data Leak Detector**. It maps every functional and non-functional requirement defined in [ARCHITECTURE.md](file:///c:/Users/Iyanu/OneDrive/Desktop/DATA-LEAKAGE-IN-MOBILE-APPS/ARCHITECTURE.md) to its concrete source code modules, implementation classes, automated unit/integration tests, and verifiable evidence.

---

## Audit Methodology & Evaluation Standard

In accordance with academic software engineering auditing standards:
- A requirement is marked **Complete** only if working implementation code, automated tests, and runtime verification evidence exist.
- A requirement is marked **Partial** if core capabilities are operational but specific secondary constraints remain incomplete.
- A requirement is marked **Missing** if no working implementation exists in the codebase.

---

## 1. Functional Requirements (FR) Traceability

### FR-01: APK Analysis
- **Requirement ID**: `FR-01`
- **Description**: Static unpacking, validation, and parsing of Android APK package structures, metadata extraction (package name, application label, version code/name, minimum/target SDKs, SHA-256 cryptographic fingerprint, file size), manifest decoding, and compiled DEX bytecode analysis using AndroGuard with plain-text manifest fallback.
- **Implementation Module**:
  - `src/data_leak_detector/analysis/apk_parser.py`
  - `src/data_leak_detector/analysis/engine.py`
- **Relevant Classes / Functions**:
  - `data_leak_detector.analysis.apk_parser.APKParser`
  - `data_leak_detector.analysis.apk_parser.APKParser.validate_file`
  - `data_leak_detector.analysis.apk_parser.APKParser.calculate_sha256`
  - `data_leak_detector.analysis.apk_parser.APKParser.parse`
  - `data_leak_detector.analysis.apk_parser._PlainManifestFallback`
  - `data_leak_detector.analysis.engine.AnalysisEngine.analyze_apk`
- **Relevant Tests**:
  - `tests/unit/test_apk_parser.py`
  - `tests/unit/test_analysis_engine.py`
  - `tests/integration/test_end_to_end_pipeline.py`
  - `tests/unit/test_malformed_and_negative.py`
- **Status**: **Complete**
- **Evidence / Notes**:
  - Unpacks `.apk` packages safely without executing them.
  - Implements `APKParser.validate_file()` with ZIP header checks, empty file checks, and size thresholds.
  - Generates full SHA-256 fingerprints via chunked 64 KB streaming hashing (`APKParser.calculate_sha256()`).
  - Supports both standard binary Android XML (`AXMLParser`) and educational plain-text XML (`_PlainManifestFallback`).
  - Validated by 12 dedicated parser unit tests and end-to-end synthetic APK pipeline tests.

---

### FR-02: Permission Auditing
- **Requirement ID**: `FR-02`
- **Description**: Comprehensive auditing and categorization of all requested and declared Android permissions against a curated baseline (`resources/permission_metadata.json`), identifying protection levels (Normal, Dangerous, Signature), sensitive user data classifications, and synergistic high-risk permission combinations.
- **Implementation Module**:
  - `src/data_leak_detector/analysis/permission_analyzer.py`
  - `resources/permission_metadata.json`
- **Relevant Classes / Functions**:
  - `data_leak_detector.analysis.permission_analyzer.PermissionAnalyzer`
  - `data_leak_detector.analysis.permission_analyzer.PermissionAnalyzer.analyze`
  - `data_leak_detector.analysis.permission_analyzer.PermissionAnalyzer._evaluate_combinations`
  - `data_leak_detector.core.models.PermissionFinding`
  - `data_leak_detector.core.models.PermissionSummary`
- **Relevant Tests**:
  - `tests/unit/test_permission_analyzer.py`
  - `tests/integration/test_end_to_end_pipeline.py`
- **Status**: **Complete**
- **Evidence / Notes**:
  - Classifies Android permissions across protection levels and identifies sensitive personal data access (location, contacts, microphone, camera, storage, SMS).
  - Detects synergistic permission combinations that create active exfiltration vectors (e.g., `ACCESS_FINE_LOCATION` + `INTERNET`, `READ_CONTACTS` + `INTERNET`, `READ_SMS` + `INTERNET`).
  - Generates clear, plain-language explanations and concern descriptions for non-technical users.
  - Validated by 8 unit tests in `test_permission_analyzer.py` testing normal, dangerous, unknown, and combination permissions.

---

### FR-03: Data-Leak Indicator Detection
- **Requirement ID**: `FR-03`
- **Description**: Static detection of data exfiltration pathways, unencrypted communication channels, hardcoded HTTP endpoints, tracking/advertising network hosts, third-party analytics SDKs, and SDK Permission Exposure correlations.
- **Implementation Module**:
  - `src/data_leak_detector/rules/network_rules.py`
  - `src/data_leak_detector/rules/sdk_rules.py`
  - `resources/tracking_patterns.json`
  - `resources/sdk_patterns.json`
- **Relevant Classes / Functions**:
  - `data_leak_detector.rules.network_rules.CleartextHttpUrlRule`
  - `data_leak_detector.rules.network_rules.CleartextTrafficConfigRule`
  - `data_leak_detector.rules.network_rules.TrackingAndAdEndpointRule`
  - `data_leak_detector.rules.network_rules.ThirdPartyEndpointRule`
  - `data_leak_detector.rules.sdk_rules.ThirdPartySdkIdentificationRule`
  - `data_leak_detector.rules.sdk_rules.ThirdPartyTrackerRule`
  - `data_leak_detector.rules.sdk_rules.SdkPermissionExposureRule`
- **Relevant Tests**:
  - `tests/unit/test_network_rules.py`
  - `tests/unit/test_sdk_rules.py`
  - `tests/unit/test_rule_engine.py`
- **Status**: **Complete**
- **Evidence / Notes**:
  - Scans DEX bytecode and resource strings against 7 third-party SDK categories (advertising, analytics, social, push messaging, crash reporting, payment, developer tools).
  - Correlates third-party trackers with host application permissions (`SdkPermissionExposureRule`) to detect third-party tracking libraries accessing location or contacts.
  - Matches tracking endpoints and queries against `tracking_patterns.json`.
  - Validated by 14 network rule tests and 8 SDK rule unit tests.

---

### FR-04: Vulnerability Identification
- **Requirement ID**: `FR-04`
- **Description**: Rule-based static identification of insecure manifest flags, hardcoded secret credentials (cloud tokens, API keys, private keys), weak cryptographic primitives, and insecure local storage configurations, consolidated by an explainable, weighted risk-scoring algorithm.
- **Implementation Module**:
  - `src/data_leak_detector/rules/manifest_rules.py`
  - `src/data_leak_detector/rules/secret_rules.py`
  - `src/data_leak_detector/rules/storage_rules.py`
  - `src/data_leak_detector/rules/crypto_rules.py`
  - `src/data_leak_detector/rules/registry.py`
  - `src/data_leak_detector/analysis/risk_scorer.py`
- **Relevant Classes / Functions**:
  - `data_leak_detector.rules.manifest_rules.AllowBackupRule`, `DebuggableRule`, `ExportedActivityRule`, `ExportedServiceRule`, `ExportedProviderRule`
  - `data_leak_detector.rules.secret_rules.GoogleApiKeyRule`, `AwsCredentialRule`, `GenericApiTokenRule`, `PrivateKeyMaterialRule`
  - `data_leak_detector.rules.storage_rules.WorldReadableWritableStorageRule`, `InsecureStorageRule`, `ExternalStorageSensitiveDataRule`, `PlaintextSharedPreferencesRule`
  - `data_leak_detector.rules.crypto_rules.BrokenCipherRule`, `EcbModeCipherRule`, `StaticOrWeakIvRule`, `HardcodedCryptoKeyRule`
  - `data_leak_detector.rules.registry.RuleRegistry`
  - `data_leak_detector.analysis.risk_scorer.RiskScorer`
- **Relevant Tests**:
  - `tests/unit/test_manifest_rules.py`
  - `tests/unit/test_secret_rules.py`
  - `tests/unit/test_storage_rules.py`
  - `tests/unit/test_crypto_rules.py`
  - `tests/unit/test_risk_scorer.py`
- **Status**: **Complete**
- **Evidence / Notes**:
  - Pluggable rule system with 36 specialized static detection rules across 6 categories.
  - Automatic credential redaction (`[REDACTED_SECRET]`) in evidence blocks to prevent secret leaks during analysis.
  - `RiskScorer` computes transparent 0–100 score using severity base weights (Critical=25, High=15, Medium=8, Low=3, Info=0), confidence multipliers, diminishing returns for repeated rule triggers, category caps (35.0 pts max), and low-severity caps (15.0 pts max).
  - Validated by 46 dedicated rule unit tests and 10 risk scorer unit tests.

---

### FR-05: Report Generation
- **Requirement ID**: `FR-05`
- **Description**: Automated generation and export of formal static analysis audit reports in three distinct formats: publication-quality PDF (ReportLab Platypus), standalone interactive HTML, and plain-text / Markdown summary, with all sensitive credentials redacted.
- **Implementation Module**:
  - `src/data_leak_detector/reporting/report_generator.py`
  - `src/data_leak_detector/reporting/pdf_report.py`
  - `src/data_leak_detector/reporting/html_report.py`
  - `src/data_leak_detector/reporting/text_report.py`
- **Relevant Classes / Functions**:
  - `data_leak_detector.reporting.report_generator.ReportGenerator`
  - `data_leak_detector.reporting.pdf_report.PDFReportGenerator`
  - `data_leak_detector.reporting.html_report.HTMLReportGenerator`
  - `data_leak_detector.reporting.text_report.TextReportGenerator`
- **Relevant Tests**:
  - `tests/unit/test_reports.py`
  - `tests/integration/test_end_to_end_pipeline.py`
- **Status**: **Complete**
- **Evidence / Notes**:
  - `PDFReportGenerator` produces professional multi-page PDFs with visual risk badges, metric cards, permission tables, detailed finding cards, and academic disclaimers.
  - `HTMLReportGenerator` produces standalone, responsive HTML with embedded CSS and zero external web dependencies.
  - `TextReportGenerator` generates structured plain-text for command-line reading, archival, and diffing.
  - All report generators automatically sanitize secrets and escape HTML/XML characters.
  - Validated by 12 unit tests verifying formatting, content, and file creation across all 3 formats.

---

## 2. Non-Functional Requirements (NFR) Traceability

### NFR-01: Usability
- **Requirement ID**: `NFR-01`
- **Description**: Intuitive, accessible desktop graphical user interface with responsive layout, real-time search, multi-criteria filtering (severity and category), expandable finding cards with remediation guidance, scan history inspection, settings management, and high-contrast / dark theme accessibility modes.
- **Implementation Module**:
  - `src/data_leak_detector/ui/main_window.py`
  - `src/data_leak_detector/ui/analyze_view.py`
  - `src/data_leak_detector/ui/results_view.py`
  - `src/data_leak_detector/ui/history_view.py`
  - `src/data_leak_detector/ui/settings_view.py`
  - `src/data_leak_detector/ui/batch_view.py`
  - `src/data_leak_detector/ui/widgets.py`
- **Relevant Classes / Functions**:
  - `data_leak_detector.ui.main_window.MainWindow`
  - `data_leak_detector.ui.analyze_view.AnalyzeView`
  - `data_leak_detector.ui.results_view.ResultsView`
  - `data_leak_detector.ui.history_view.HistoryView`
  - `data_leak_detector.ui.settings_view.SettingsView`
  - `data_leak_detector.ui.widgets.ExpandableFindingCard`
  - `data_leak_detector.ui.widgets.DropZone`
  - `data_leak_detector.ui.widgets.SeverityBadge`
- **Relevant Tests**:
  - `tests/unit/test_ui.py`
  - `tests/unit/test_settings.py`
- **Status**: **Complete**
- **Evidence / Notes**:
  - Clean left-sidebar navigation with 5 distinct views: Scanner, Batch, Results, History, Settings.
  - Real-time search filtering across findings titles, categories, and evidence.
  - High-contrast accessibility mode toggle persisted in local settings.
  - DropZone displays file size and SHA-256 preview immediately upon APK selection.
  - Documented in `docs/USER_GUIDE.md` and verified by 15 UI unit tests.

---

### NFR-02: Performance
- **Requirement ID**: `NFR-02`
- **Description**: Bounded system resource consumption, non-blocking asynchronous analysis worker threads to prevent UI lockups, configurable timeouts for external subprocesses, pre-compiled regex patterns, streaming hashing, and sequential batch queue processing to avoid memory spikes.
- **Implementation Module**:
  - `src/data_leak_detector/core/config.py`
  - `src/data_leak_detector/analysis/engine.py`
  - `src/data_leak_detector/analysis/batch_processor.py`
  - `scripts/profile_workflow.py`
  - `PERFORMANCE.md`
- **Relevant Classes / Functions**:
  - `data_leak_detector.analysis.engine.AnalysisEngine.analyze_apk`
  - `data_leak_detector.analysis.batch_processor.BatchQueueProcessor`
  - `data_leak_detector.core.config.AppConfig`
  - `scripts.profile_workflow.WorkflowProfiler`
- **Relevant Tests**:
  - `tests/unit/test_batch_processor.py`
  - `tests/unit/test_analysis_engine.py`
  - `tests/unit/test_security_hardening.py`
- **Status**: **Complete**
- **Evidence / Notes**:
  - UI runs on Tkinter main thread while analysis runs on daemon background thread; UI updates pass safely through thread-safe `queue.Queue`.
  - Configurable safety limits: `max_apk_size_bytes` (200 MB), `max_extracted_file_count` (10,000), `max_extracted_size_bytes` (500 MB), `max_scanned_file_size_bytes` (5 MB).
  - Profiling methodology documented in `PERFORMANCE.md` shows mean execution time of 0.08s for standard benchmark APKs.
  - Validated by batch queue unit tests, timeout tests, and multi-file processing tests.

---

### NFR-03: Reliability
- **Requirement ID**: `NFR-03`
- **Description**: Fault containment ensuring individual rule failures or external tool absences never crash the analysis pipeline; graceful degradation when JADX or Apktool are missing; safe handling of corrupted, empty, or malformed APK archives; cooperative scan cancellation.
- **Implementation Module**:
  - `src/data_leak_detector/analysis/tool_adapters.py`
  - `src/data_leak_detector/analysis/engine.py`
  - `src/data_leak_detector/core/exceptions.py`
  - `src/data_leak_detector/storage/database.py`
- **Relevant Classes / Functions**:
  - `data_leak_detector.analysis.tool_adapters.JadxAdapter`
  - `data_leak_detector.analysis.tool_adapters.ApktoolAdapter`
  - `data_leak_detector.analysis.tool_adapters.ToolAdapter.is_available`
  - `data_leak_detector.analysis.engine.CancellationToken`
  - `data_leak_detector.storage.database.DatabaseManager.initialize_schema`
- **Relevant Tests**:
  - `tests/unit/test_tool_adapters.py`
  - `tests/unit/test_malformed_and_negative.py`
  - `tests/unit/test_database.py`
- **Status**: **Complete**
- **Evidence / Notes**:
  - When JADX/Apktool are unavailable, `AnalysisEngine` logs informational warnings and seamlessly falls back to direct bytecode string extraction and manifest inspection.
  - Custom domain exceptions (`InvalidAPKError`, `APKParsingError`, `AnalysisCancelledError`, `StorageError`).
  - Idempotent SQLite database migration ensures schema is created or verified on every launch without table lock errors.
  - Validated by 10 malformed-file tests (corrupted ZIP, missing indicators, empty files) and tool adapter mocking tests.

---

### NFR-04: Scalability
- **Requirement ID**: `NFR-04`
- **Description**: Modular, extensible architecture allowing addition of new detection rules without altering the core engine; basic batch analysis capability for queueing and auditing multiple APKs; standardized evaluation harness for running across large corpus directories.
- **Implementation Module**:
  - `src/data_leak_detector/rules/base.py`
  - `src/data_leak_detector/rules/registry.py`
  - `src/data_leak_detector/analysis/batch_processor.py`
  - `scripts/evaluate.py`
  - `scripts/compare_results.py`
- **Relevant Classes / Functions**:
  - `data_leak_detector.rules.base.BaseRule`
  - `data_leak_detector.rules.registry.RuleRegistry`
  - `data_leak_detector.analysis.batch_processor.BatchQueueProcessor`
  - `scripts.evaluate.EvaluationHarness`
  - `scripts.compare_results.ComparisonFramework`
- **Relevant Tests**:
  - `tests/unit/test_rule_engine.py`
  - `tests/unit/test_batch_processor.py`
  - `tests/unit/test_evaluation_harness.py`
  - `tests/unit/test_compare_results.py`
- **Status**: **Complete**
- **Evidence / Notes**:
  - All static detection rules subclass `BaseRule` and implement `evaluate(context) -> list[SecurityFinding]`.
  - Batch analysis queue in `BatchQueueProcessor` processes multiple APKs sequentially with progress tracking, risk score calculation, and CSV summary export.
  - Academic evaluation harness in `scripts/evaluate.py` supports ground truth benchmarking, timing statistics (mean, median, min, max), and metric calculation (precision, recall, F1).
  - Validated by 20 unit tests across rule registry, batch processor, evaluation harness, and comparison scripts.

---

### NFR-05: Portability
- **Requirement ID**: `NFR-05`
- **Description**: Standalone executable distribution using PyInstaller (`onedir` target without console window in production); cross-platform filesystem handling using `pathlib.Path`; zero OS-specific hardcoded paths; documented platform-specific build instructions for Windows, macOS, and Linux.
- **Implementation Module**:
  - `data_leak_detector.spec`
  - `run_app.py`
  - `src/data_leak_detector/core/config.py`
  - `PACKAGING.md`
  - `docs/INSTALLATION.md`
- **Relevant Classes / Functions**:
  - `data_leak_detector.core.config.AppConfig.__post_init__` (PyInstaller `sys.frozen` & `sys._MEIPASS` path resolution)
  - `data_leak_detector.core.config.get_default_config_dir` (OS user app data resolution)
  - `data_leak_detector.storage.database.get_default_database_path`
- **Relevant Tests**:
  - `tests/unit/test_packaging_config.py`
  - `scripts/smoke_test_dist.py`
- **Status**: **Complete**
- **Evidence / Notes**:
  - Configured `data_leak_detector.spec` bundles `permission_metadata.json`, `sdk_patterns.json`, and `tracking_patterns.json` into `resources/`.
  - Windowed execution (`console=False`) built and verified on Windows with `scripts/smoke_test_dist.py`.
  - Resolves configuration and SQLite databases in `%LOCALAPPDATA%` (Windows), `~/.config` / `~/.local/share` (Linux), and `~/Library/Application Support` (macOS).
  - Detailed platform-specific build instructions documented in `PACKAGING.md`.

---

### NFR-06: Privacy / Security
- **Requirement ID**: `NFR-06`
- **Description**: 100% offline static analysis model with zero network telemetry or remote exfiltration; zero execution of APK bytecode; automatic secret masking in logs and UI views; protection against Zip Slip and path traversal; exclusive use of parameterized SQL queries; deterministic temporary directory cleanup.
- **Implementation Module**:
  - `src/data_leak_detector/core/logging_config.py`
  - `src/data_leak_detector/core/path_safety.py`
  - `src/data_leak_detector/storage/database.py`
  - `SECURITY.md`
- **Relevant Classes / Functions**:
  - `data_leak_detector.core.logging_config.SensitiveDataFilter`
  - `data_leak_detector.core.path_safety.is_safe_zip_path`
  - `data_leak_detector.core.path_safety.sanitize_for_logging`
  - `data_leak_detector.storage.database.DatabaseManager` (Parameterized SQL)
  - `data_leak_detector.analysis.engine.AnalysisEngine._clean_temporary_dirs`
- **Relevant Tests**:
  - `tests/unit/test_security_hardening.py`
  - `tests/unit/test_core_models.py`
  - `tests/unit/test_database.py`
- **Status**: **Complete**
- **Evidence / Notes**:
  - `SensitiveDataFilter` automatically masks AWS keys, Google API keys, GitHub tokens, Slack tokens, and passwords as `[REDACTED_SECRET]` and neutralizes CRLF log injection (CWE-117).
  - `is_safe_zip_path` neutralizes Zip Slip / Path Traversal vulnerabilities (CWE-22).
  - All database operations use `?` parameter placeholders; zero string formatting in SQL statements (CWE-89).
  - Temporary files decompiled during analysis are tracked and deleted in `finally` blocks.
  - Threat model and boundary architecture documented in `SECURITY.md`. Validated by 18 security hardening unit tests.

---

## 3. Traceability Summary Matrix

| ID | Category | Requirement Title | Status | Implementation Modules | Test Modules |
| :---: | :---: | :--- | :---: | :--- | :--- |
| **FR-01** | Functional | APK Analysis | **Complete** | `analysis.apk_parser`, `analysis.engine` | `test_apk_parser`, `test_analysis_engine` |
| **FR-02** | Functional | Permission Auditing | **Complete** | `analysis.permission_analyzer`, metadata | `test_permission_analyzer`, `test_pipeline` |
| **FR-03** | Functional | Data-Leak Indicator Detection | **Complete** | `rules.network_rules`, `rules.sdk_rules` | `test_network_rules`, `test_sdk_rules` |
| **FR-04** | Functional | Vulnerability Identification | **Complete** | `rules.*`, `analysis.risk_scorer` | `test_manifest_rules`, `test_secret_rules` |
| **FR-05** | Functional | Report Generation | **Complete** | `reporting.*` (PDF, HTML, Text) | `test_reports`, `test_pipeline` |
| **NFR-01** | Non-Functional | Usability | **Complete** | `ui.*` (Tkinter/ttk views & widgets) | `test_ui`, `test_settings` |
| **NFR-02** | Non-Functional | Performance | **Complete** | `analysis.engine`, `core.config`, profiler | `test_batch_processor`, `test_hardening` |
| **NFR-03** | Non-Functional | Reliability | **Complete** | `analysis.tool_adapters`, `core.exceptions` | `test_tool_adapters`, `test_malformed` |
| **NFR-04** | Non-Functional | Scalability | **Complete** | `rules.base`, `rules.registry`, `evaluate` | `test_rule_engine`, `test_evaluation` |
| **NFR-05** | Non-Functional | Portability | **Complete** | `data_leak_detector.spec`, `PACKAGING.md` | `test_packaging_config`, smoke test |
| **NFR-06** | Non-Functional | Privacy / Security | **Complete** | `core.logging_config`, `path_safety`, DB | `test_security_hardening`, `SECURITY.md` |

---

## 4. Remaining Gaps Before Dissertation Evaluation

While all functional and non-functional engineering requirements are implemented and verified with passing unit and integration tests (250 tests passed, 0 lint errors), the following empirical and experimental preparation tasks remain before conducting the final dissertation evaluation and defense.

### [BLOCKER] None
*There are zero blocker-level software defects or unimplemented functional requirements. The static analysis pipeline, UI, database, reporting, evaluation harness, comparison scripts, and standalone package are fully operational.*

---

### [HIGH] Real-World Corpus Collection & Ground-Truth Annotation
- **Description**: While the automated evaluation harness (`scripts/evaluate.py`) is fully functional and tested on synthetic benchmark APKs, running the empirical evaluation chapter of the dissertation requires assembling a curated corpus of real-world Android applications (e.g., 50–100 open-source APKs from F-Droid and popular Google Play categories) with corresponding human-verified ground-truth labels (`ground_truth.json`).
- **Impact on Evaluation**: Required to calculate empirical precision, recall, and F1 scores in Chapter 5 (Evaluation & Discussion) of the dissertation.

---

### [MEDIUM] Live Tool Comparison Data Collection (MobSF / RiskInDroid)
- **Description**: The cross-tool comparative evaluation framework (`scripts/compare_results.py` and `COMPARISON.md`) is implemented and tested. However, comparative evaluation results require running external reference tools (such as MobSF or RiskInDroid) against the identical APK test corpus and saving their exported finding CSVs for ingestion into `compare_results.py`.
- **Impact on Evaluation**: Required to populate the cross-tool finding overlap tables and comparative discussion in the dissertation.

---

### [MEDIUM] Native Compilation on Secondary Operating Systems (macOS & Linux)
- **Description**: Standalone PyInstaller packaging was built, tested, and validated on Windows 64-bit. Because PyInstaller does not cross-compile, generating standalone native binaries for macOS (`.app` bundle) and Linux (`ELF` binary) requires executing `python -m PyInstaller data_leak_detector.spec` natively on those operating systems or within OS-specific CI/CD runners.
- **Impact on Evaluation**: The application runs portably from source on all operating systems; native standalone packages for macOS and Linux are beneficial for multi-platform distribution.

---

### [LOW] Control-Flow Graph (CFG) Inter-Procedural Taint Tracking
- **Description**: The current engine employs AST analysis, manifest inspection, string extraction, and regex-based pattern matching. Implementing full intra- and inter-procedural taint flow analysis (tracking variable dataflow from sensitive hardware sources to network sink methods across complex method call graphs) represents a classic academic static analysis extension.
- **Impact on Evaluation**: Documented as an acknowledged methodological boundary in `docs/METHODOLOGY.md`.

---

### [OPTIONAL] Single-Click Installer Packages (Inno Setup / DMG)
- **Description**: The PyInstaller build generates a reliable one-directory (`onedir`) distribution folder. Creating wrapped installer installers (such as an Inno Setup `.exe` wizard for Windows or a `.dmg` drag-and-drop disk image for macOS) would enhance consumer installation experience.
- **Impact on Evaluation**: Non-essential for dissertation evaluation; the standalone directory and ZIP distribution fully satisfy standalone portability requirements.
