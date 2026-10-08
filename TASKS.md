# Mobile Data Leak Detector: Task Roadmap & Requirement Mapping

This task backlog maps all upcoming engineering deliverables to the functional and non-functional requirements established in [ARCHITECTURE.md](file:///c:/Users/Iyanu/OneDrive/Desktop/DATA-LEAKAGE-IN-MOBILE-APPS/ARCHITECTURE.md).

---

## Phase 1: Environment, Dependencies & Foundational Models
- [x] **TASK-101: Project Layout and Architecture Documentation**
  - *Requirements*: NFR-04, NFR-05
  - Setup src-based directory structure, `.gitignore`, `ARCHITECTURE.md`, `TASKS.md`, and `README.md`.
- [x] **TASK-102: Baseline Resource Metadata & Pattern Files**
  - *Requirements*: FR-02, FR-03, FR-04
  - Create `permission_metadata.json`, `sdk_patterns.json`, and `tracking_patterns.json`.
- [ ] **TASK-103: Dependency Specification (`requirements.txt` / `pyproject.toml`)**
  - *Requirements*: NFR-05
  - Define pinned versions for `androguard`, `reportlab`, `pillow`, `pytest`.
- [x] **TASK-104: Core Domain Models & Redaction Unit Tests**
  - *Requirements*: NFR-03, NFR-06
  - Implement full model serialization, JSON validation, and test suite for `SensitiveDataFilter`.

---

## Phase 2: Static Analysis Engine & APK Parsing
- [x] **TASK-201: AndroGuard Static Parser (`apk_parser.py`)**
  - *Requirements*: FR-01, NFR-02, NFR-03
  - Implement safe APK parsing, SHA-256 calculation, AndroidManifest extraction, string pool retrieval, and DEX analysis.
- [x] **TASK-202: External Tool Subprocess Adapters (`tool_adapters.py`)**
  - *Requirements*: FR-01, NFR-03, NFR-06
  - Implement `JadxAdapter` and `ApktoolAdapter` with `shutil.which` detection, timeouts, error traps, and context-managed cleanup.
- [x] **TASK-203: Permission Auditing Module (`permission_analyzer.py`)**
  - *Requirements*: FR-02, FR-03
  - Implement permission risk evaluation and correlation of dangerous combos (e.g., location + cellular state + internet).

---

## Phase 3: Rule Engine & Vulnerability Detection
- [x] **TASK-301: Manifest Security Rules (`manifest_rules.py`)**
  - *Requirements*: FR-04
  - Implement checks for `allowBackup`, `debuggable`, exported components without permissions.
- [x] **TASK-302: Network Indicator Detection (`network_rules.py`)**
  - *Requirements*: FR-03, NFR-06
  - Statically detect cleartext `http://` URLs, cleartext traffic configs, trust-all X.509 managers, permissive HostnameVerifiers, SSL bypasses, insecure WebView configs, tracking domains, and third-party endpoints.
- [x] **TASK-303: Secret & Credential Scanner (`secret_rules.py`)**
  - *Requirements*: FR-04, NFR-06
  - Detect high-entropy API tokens and cloud credentials with automatic redaction.
- [x] **TASK-304: Insecure Storage & Crypto Rules (`storage_rules.py`, `crypto_rules.py`)**
  - *Requirements*: FR-04
  - Statically detect world-readable storage calls, external sensitive storage, plaintext SharedPreferences/SQLite, logcat leaks, sensitive cache, weak ciphers (DES/3DES/RC4), ECB mode, static IVs, hardcoded keys, obsolete hashing in security contexts, and insecure PRNGs.
- [x] **TASK-305: Tracking & Telemetry SDK Detector (`sdk_rules.py`)**
  - *Requirements*: FR-03
  - Match package and class hierarchies against configurable `sdk_patterns.json` (7 categories), generate informational findings, and evaluate SDK Permission Exposure against host permissions.
- [x] **TASK-306: Weighted Risk Scorer (`risk_scorer.py`)**
  - *Requirements*: FR-01, FR-04
  - Calculate normalized composite risk score (0-100) and severity rating using explainable severity base weights, confidence multipliers, low-severity cap, category caps, and deduplication.

---

## Phase 4: Local Persistence & Storage
- [ ] **TASK-401: SQLite Database Manager (`database.py`)**
  - *Requirements*: NFR-06, NFR-03
  - Implement local SQLite tables for scans, metadata, and findings with query methods for history views.

---

## Phase 5: Reporting Engine
- [ ] **TASK-501: PDF Report Generation via ReportLab (`pdf_report.py`)**
  - *Requirements*: FR-05, NFR-06
  - Design academic-grade PDF audit report with executive summary, findings table, and redacted evidence.
- [ ] **TASK-502: HTML & Markdown / Plaintext Formatters (`html_report.py`, `text_report.py`)**
  - *Requirements*: FR-05
  - Implement standalone HTML and terminal-friendly report exports.

---

## Phase 6: Tkinter Desktop User Interface
- [ ] **TASK-601: Main Window & Theme Styling (`main_window.py`, `widgets.py`)**
  - *Requirements*: NFR-01
  - Create responsive ttk Notebook frame, custom badges, and layout hierarchy.
- [ ] **TASK-602: Analyze View & Background Threading (`analyze_view.py`)**
  - *Requirements*: NFR-01, NFR-02
  - Implement file selection, background worker threading for non-blocking analysis, and progress indicators.
- [ ] **TASK-603: Results View & Visual Gauges (`results_view.py`)**
  - *Requirements*: NFR-01, FR-05
  - Display treeview of findings, risk score cards, and export action buttons.
- [ ] **TASK-604: History View & Search (`history_view.py`)**
  - *Requirements*: NFR-01
  - Table view of historical scans with search filtering and report re-export.
- [ ] **TASK-605: Settings View (`settings_view.py`)**
  - *Requirements*: NFR-01, NFR-03
  - Display detected external tool status, configure timeouts, and manage rule sensitivity.

---

## Phase 7: Verification, Automated Testing & Documentation
- [ ] **TASK-701: Comprehensive Unit & Integration Tests**
  - *Requirements*: NFR-03, NFR-04
  - Synthetic test APK fixtures, rule execution tests, database roundtrip tests.
- [ ] **TASK-702: End-to-End Desktop Verification & User Guide**
  - *Requirements*: NFR-01, NFR-05, NFR-06
  - Execute end-to-end static audit on sample APKs and complete documentation in `docs/`.
