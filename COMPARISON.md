# Cross-Tool Research Comparison Framework

This document details the comparative research framework implemented in `scripts/compare_results.py`. It establishes a reproducible, decoupled methodology for benchmarking our static Android data leakage detector against industry and academic tools such as **MobSF (Mobile Security Framework)** and **RiskInDroid**.

---

## 1. Principles & Ethical Research Boundaries

1. **Decoupled Architecture:** No internal tool dependencies or fragile private API hooks are introduced. Our tool remains completely standalone.
2. **Strict Privacy & Offline Safety:** APK packages are **never automatically uploaded** to external cloud services or third-party web endpoints. All analyses and comparisons run entirely on the local system.
3. **Impartial Academic Comparison:** Divergence in findings between tools is **not** treated as an error or inaccuracy. Differing results reflect distinct threat models, heuristic baselines, and detection granularities.

---

## 2. External Tool CSV Import Specification

To compare results, findings from external tools are imported via a standardized CSV format:

### Schema Headers
```csv
apk_hash,tool,finding_category,finding_name,severity
```

| Field Name | Type | Description | Example |
|---|---|---|---|
| `apk_hash` | String | SHA-256 cryptographic digest of the APK (case-insensitive) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `tool` | String | Identifier of comparison tool | `MobSF`, `RiskInDroid`, `AndroBugs` |
| `finding_category` | String | Category of the finding | `Insecure Communication`, `Hardcoded Secret`, `Permission` |
| `finding_name` | String | Descriptive title or rule name | `Cleartext HTTP Traffic Allowed`, `Google API Key Found` |
| `severity` | String | Severity rating | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |

### Sample Import CSV (`external_tools_results.csv`)
```csv
apk_hash,tool,finding_category,finding_name,severity
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,MobSF,Insecure Communication,Cleartext HTTP Traffic Allowed,HIGH
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,MobSF,Hardcoded Secret,Google API Key Disclosed,HIGH
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,RiskInDroid,Permissions,Dangerous Camera Permission,MEDIUM
```

---

## 3. Canonical Category Normalization

Disparate tools apply divergent taxonomies for security and privacy defects. The comparison engine standardizes raw category strings into canonical research dimensions:

| Canonical Category | Standard Name | Common Mapped Equivalents |
|---|---|---|
| `PERMISSION` | Permissions | `Dangerous Permission`, `Permission Risk`, `uses-permission` |
| `NETWORK_INDICATOR` | Network Security | `Insecure Communication`, `Cleartext Traffic`, `SSL/TLS Misconfiguration` |
| `HARDCODED_SECRET` | Hardcoded Secrets | `Hardcoded API Key`, `Private Key`, `Token Leak`, `Credential` |
| `STORAGE_INSECURITY` | Insecure Storage | `Insecure Data Storage`, `World-Readable File`, `Plaintext SharedPreferences` |
| `CRYPTO_FLAW` | Cryptography Flaws | `Broken Cryptography`, `Weak Cipher`, `ECB Mode`, `Hardcoded Salt` |
| `TRACKING_SDK` | Third-Party & Tracking SDKs | `Adware / Tracker`, `Analytics Telemetry`, `Tracker Library` |
| `MANIFEST_MISCONFIG` | Manifest Misconfigurations | `Android Security Misconfiguration`, `Debuggable`, `AllowBackup` |
| `OTHER` | Other Security Issues | Unmatched / general informational items |

---

## 4. Evaluated Overlap Metrics

For each package (identified by `apk_hash`), the comparison harness evaluates:

1. **Common Findings (Intersection):**
   Findings flagged by both our tool and the comparison tool matching on normalized category and title keywords ($O \cap E$).
2. **Unique to Our Tool:**
   Specialized privacy and data leak findings flagged by our tool but absent in the comparison tool ($O \setminus E$).
3. **Unique to Comparison Tool:**
   Findings identified by the comparison tool but not flagged by our tool ($E \setminus O$).
4. **Category Overlaps:**
   Binary detection matrix per category: whether both tools identified issues in that domain for the application.
5. **Jaccard Similarity Index:**
   Measures structural concordance between finding sets:
   $$J(O, E) = \frac{|O \cap E|}{|O \cup E|}$$
   Where $J=1.0$ indicates identical reporting and $J=0.0$ represents completely disjoint outputs.

---

## 5. Methodological Limitations

When presenting cross-tool comparisons in an academic dissertation, the following methodological factors must be explicitly stated:

### 5.1 Divergent Threat Models & Analytical Scopes
- **MobSF:** Designed as a broad, general-purpose mobile security auditing suite covering OWASP Top 10 vulnerabilities (e.g., tapjacking, intent spoofing, exported components, deep link validation).
- **RiskInDroid:** Focuses primarily on machine-learning-driven malware classification based on empirical permission risk vectors.
- **Our Tool:** Specifically specialized in **private user data leakage paths**, transmission of device identifiers, unencrypted storage of PII, and SDK Permission Exposure.
- *Implication:* A finding present in MobSF but missing in our tool often indicates an out-of-scope vulnerability (e.g. Activity tapjacking) rather than a detection failure.

### 5.2 Rule Granularity & Aggregation Differences
- One tool may report 1 finding for `"Cleartext HTTP"` representing the general manifest flag `usesCleartextTraffic="true"`.
- Another tool may emit 14 distinct findings, one for every hardcoded `http://` URL discovered across decompiled classes.
- *Implication:* Raw finding counts must not be naively compared without normalizing rule aggregation levels.

### 5.3 Static Over-Approximation & False Positive Tendencies
- Static analysis is inherently over-approximate. The presence of a finding in tool $A$ that is absent in tool $B$ does **not** prove that tool $A$ is more accurate, nor does it prove tool $B$ produced a false negative.
- Both tools may trigger heuristics on benign patterns (such as documentation URLs or test credentials). Verification requires dynamic validation or manual ground-truth reverse engineering.

### 5.4 Decompilation Engine & Obfuscation Handling
- MobSF, RiskInDroid, and our tool use different decompilation pipelines (AndroGuard bytecode disassembler vs. JADX/baksmali).
- Heavily obfuscated packages (ProGuard, DexGuard) or split-APKs can be decompiled to varying depths, directly impacting string discovery and call-graph reconstruction.

---

## 6. Execution Instructions

### Running the Comparison Script
```bash
python scripts/compare_results.py \
  --our-results evaluation_output/evaluation_results.json \
  --external-results tests/fixtures/mobsf_sample_results.csv \
  --output-dir comparison_output
```

### Outputs Generated:
- `comparison_output/comparison_summary.csv`: Tabular spreadsheet containing per-APK overlap counts and Jaccard similarity scores.
- `comparison_output/comparison_summary.json`: Complete JSON document containing dataset summaries, category overlap matrices, and the formal methodological disclaimer.
