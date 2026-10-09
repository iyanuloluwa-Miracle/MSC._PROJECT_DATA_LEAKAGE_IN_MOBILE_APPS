# Security Policy and Threat Model

## 1. Threat Model and Security Boundaries

The **Mobile Data Leak Detector** is a specialized static security and privacy audit tool for Android Application Packages (`.apk`). Because the target applications being audited may originate from untrusted, malicious, or adversarial sources, this application is engineered under a **Zero-Trust Model** for all input files and package contents.

```
+-------------------------------------------------------------------------------+
|                             UNTRUSTED ZONE                                    |
|   Target APK Packages (Potential Zip Slip, Zip Bombs, Malformed Metadata)     |
+-------------------------------------------------------------------------------+
                                      |
                                      v [Strict Validation & Sanitization]
+-------------------------------------------------------------------------------+
|                            ANALYSIS BOUNDARY                                  |
|   - Pure Static Analysis Only (Never executes, loads, or installs target APK) |
|   - Strict Resource Limits (File size, entry counts, decompression ratio)      |
|   - Subprocess Isolation (shell=False, NUL byte check, execution timeouts)    |
|   - Temporary Directory Sandbox (Guaranteed cleanup on exit/cancellation)     |
+-------------------------------------------------------------------------------+
                                      |
                                      v [Sanitized Data Flow & Redaction]
+-------------------------------------------------------------------------------+
|                              TRUSTED ZONE                                     |
|   - Local SQLite Persistence (Parameterized queries only, zero binaries)      |
|   - UI & Reports (Masked secrets, validated output paths, safe CSV export)    |
|   - Sanitized Logs (CRLF log injection neutralized, CWE-117)                  |
+-------------------------------------------------------------------------------+
```

---

## 2. Security Boundaries & Assumptions

### What We Trust
1. **The Host Operating System & Python Runtime**: We assume the integrity of the underlying OS and Python environment.
2. **Local User Configuration**: Configuration files stored in the user's local application data directory.
3. **Approved External CLI Binaries (Optional)**: JADX and Apktool when installed on the host system PATH or explicitly configured by the auditor.

### What We DO NOT Trust
1. **Target APK Files**: We do not trust archive headers, compression ratios, entry filenames, or file counts.
2. **Package Metadata**: We do not trust package names, application labels, version strings, or component names extracted from `AndroidManifest.xml`.
3. **Decompiled Code & Resources**: We do not trust string contents, file extensions, or character encodings in extracted resources.
4. **Log & Export Destinations**: We do not trust user-supplied or auto-generated export filenames without path and device validation.

---

## 3. Dedicated Security Controls & Defense-in-Depth

### 1. Temporary-Directory Cleanup
All temporary directories created during static decompilation or resource extraction are created in designated temporary storage via `tempfile.mkdtemp`. Cleanup is enforced within `finally:` blocks and context managers. On Windows systems where decompilers or background indexers may lock files, cleanup incorporates read-only permission unlocking (`stat.S_IWRITE` via `os.chmod`) before removal, preventing disk leakage.

### 2. File Path Validation
All input and output file paths are validated against path traversal sequences and Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`). NUL bytes (`\x00`) are strictly rejected.

### 3. ZIP / APK Decompression Safety (Zip Slip Defense - CWE-22)
Untrusted archives may attempt directory traversal by specifying entry filenames such as `../../etc/cron.d/evil` or `..\AppData\evil.bat`. The detector inspects every entry via `is_safe_zip_path()`. Entries with directory traversal sequences, absolute paths, Windows drive specifiers, or NUL bytes are rejected immediately, raising `InvalidAPKError`.

### 4. Decompression Bomb & Resource Limits (Zip Bomb Defense)
To prevent disk and memory exhaustion attacks from malicious zip bombs:
- **Maximum APK Size**: Enforced before opening (`max_apk_size_bytes`, default 200MB).
- **Maximum Extracted Entry Count**: Enforced via archive entry count inspection (`max_extracted_file_count`, default 10,000 files).
- **Maximum Extracted Size**: Cumulative uncompressed size is calculated before full decompression (`max_extracted_size_bytes`, default 500MB).
- **Compression Ratio Verification**: Individual archive entries with excessive compression ratios (>200:1 on large files) are flagged and rejected.

### 5. Extremely Large Resource Handling
When scanning decompiled source files or textual assets, individual file reads are capped by `max_scanned_file_size_bytes` (default 5MB). Files exceeding this threshold are bypassed from in-memory string scanning to avoid memory exhaustion.

### 6. Subprocess Command Injection Defense
External tools (Apktool, JADX) are invoked through `ToolAdapter` using `subprocess.run`:
- `shell=False` is strictly enforced across all external processes.
- Arguments are passed as an explicit list of string tokens (`list[str]`), eliminating shell interpreter tokenization.
- Every argument is inspected for NUL bytes (`\x00`) to prevent argument truncation attacks.

### 7. Subprocess Timeouts
All external subprocess executions enforce strict timeouts (`subprocess_timeout_seconds`, default 120s). If an external decompiler hangs or encounters pathological bytecode, the process is terminated and the static engine continues via graceful fallback.

### 8. SQL Injection Defense
The local persistence layer (`DatabaseManager`) uses Python's standard `sqlite3` library:
- **100% Parameterized SQL**: All queries and insertions strictly utilize SQL placeholder binding (`?`).
- **Zero Dynamic SQL Formatting**: Untrusted package names, versions, and hashes are never concatenated or formatted into query strings.
- **Zero Binary Storage**: APK binary data is never written to SQLite; only metadata and findings are stored.

### 9. Secret Redaction
Hardcoded credentials, API keys, OAuth tokens, and AWS secrets identified during static scanning are never exposed in plaintext:
- Regex-based masking (`[REDACTED_SECRET]`) is applied across all user-facing views: UI finding cards, PDF audit reports, HTML reports, and plain-text summaries.
- Evidence snippets preserve only non-sensitive context boundaries.

### 10. Log Sanitization & CRLF Injection Neutralization (CWE-117)
Attackers can craft APK package names or filenames containing carriage returns (`\r`) or line feeds (`\n`) to inject forged log records or spoof audit events. The detector routes all log events through `SensitiveDataFilter`:
- Carriage returns and newlines are sanitized to literal escaped representations (`\r`, `\n`).
- Non-printable ASCII control characters are transformed into hex representations.
- Sensitive credentials matching known secret formats are automatically masked before writing to log sinks.

### 11. Output Path Validation
Before generating PDF, HTML, TXT audit reports, or batch CSV summaries, the destination path is resolved and validated:
- Rejects paths containing NUL bytes (`\x00`).
- Rejects destinations matching operating system reserved names.
- Parent directories are verified and created safely.

### 12. Malformed Unicode Handling
Decompiled source files and asset text extracted from obfuscated or malformed APKs are decoded using `errors="replace"`. Unmapped or corrupted byte sequences are replaced with standard Unicode replacement characters (`\ufffd`) rather than causing pipeline crashes.

### 13. Malformed APK Handling
APKs with missing manifests, malformed binary XML, or corrupted DEX bytecode headers are caught gracefully by `APKParser`. Parsing failures generate structured `InvalidAPKError` or `APKParsingError` exceptions without crashing the orchestration engine or user interface.

### 14. Corrupted ZIP Archive Handling
Archives are inspected before parsing using `zipfile.is_zipfile` and `zf.testzip()`. Damaged archive headers, bad CRC checksums, or truncated ZIP structures are rejected early with clear error feedback.

### 15. Cooperative Analysis Cancellation
Auditors can cancel running scans at any time. The `AnalysisEngine` checks cancellation tokens between every major pipeline phase (validation, parsing, decompilation, permission audit, rule scanning, scoring). Cancellation immediately halts subsequent phases and executes clean-up handlers.

### 16. Analyzer Exception Isolation
Static rules are executed inside isolated error-handling wrappers (`_execute_rules`). If an unexpected bug or malformed token triggers an unhandled exception inside an individual rule, the error is recorded as a warning in `AnalysisMetrics` and the engine continues evaluating remaining rules.

### 17. CSV Formula Injection Defense (CWE-123)
When exporting batch audit summaries to CSV:
- All cell values (filenames, package names, timestamps) are inspected.
- Values beginning with dangerous formula calculation prefixes (`=`, `+`, `-`, `@`, `\t`, `\r`) are automatically prepended with a single quote (`'`), neutralizing spreadsheet formula execution.
- Sensitive finding evidence is never included in batch CSV summaries.

---

## 4. Configurable Security Limits

All operational security caps are customizable in `AppConfig` and persist across application sessions:

| Parameter | Default | Description |
|---|---|---|
| `max_apk_size_bytes` | `209,715,200` (200 MB) | Maximum permitted size of input APK file |
| `max_extracted_file_count` | `10,000` | Maximum number of files extracted from an archive |
| `max_extracted_size_bytes` | `524,288,000` (500 MB) | Cumulative uncompressed size ceiling |
| `max_scanned_file_size_bytes` | `5,242,880` (5 MB) | Maximum size of an individual decompiled file read into memory |
| `subprocess_timeout_seconds` | `120` seconds | Execution timeout for external tools (JADX, Apktool) |

---

## 5. Vulnerability Disclosure Policy

If you discover a security vulnerability or bypass in Mobile Data Leak Detector, please report it responsibly:
- **Do not** open public GitHub issues for security vulnerabilities.
- Provide a clear Proof of Concept (PoC) demonstrating the bypass or vulnerability.
- Include details on the execution environment, operating system, and target APK sample.
