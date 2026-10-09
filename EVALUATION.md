# Empirical Evaluation Methodology & Benchmark Framework

This document outlines the evaluation methodology, metric definitions, and benchmark architecture implemented in `scripts/evaluate.py` for empirical dissertation assessment.

---

## 1. Objectives & Evaluation Design

The evaluation framework addresses two central research questions:
1. **Detection Performance & Accuracy:** When evaluated against an annotated corpus of Android packages with established ground truth, what are the detection capabilities, false-positive tendencies, and precision/recall trade-offs of the static analysis engine?
2. **Computational Feasibility & Scalability:** What are the execution throughput, latency distributions, and resource constraints of the multi-stage static analysis pipeline across diverse APK file sizes?

---

## 2. Metrics & Mathematical Definitions

The evaluation harness implements standard information retrieval and binary classification metrics adapted for static vulnerability analysis.

### 2.1 Confusion Matrix Definitions

For a given Android package $i$, let:
- $E_i$ be the set of expected vulnerability rule identifiers defined in the ground truth dataset ($E_i \subseteq \mathcal{R}$).
- $D_i$ be the set of rule identifiers flagged by the static analysis engine ($D_i \subseteq \mathcal{R}$).

The confusion matrix counts are defined as:

$$\text{True Positives } (TP_i) = |D_i \cap E_i|$$
*(Flaws present in ground truth that were correctly detected by the tool)*

$$\text{False Positives } (FP_i) = |D_i \setminus E_i|$$
*(Rules flagged by the tool that were not specified in ground truth — potential over-approximations)*

$$\text{False Negatives } (FN_i) = |E_i \setminus D_i|$$
*(Vulnerabilities specified in ground truth that the static engine failed to flag — potential under-approximations)*

Across a dataset of $N$ evaluated applications, cumulative totals are aggregated:
$$\text{Total } TP = \sum_{i=1}^N TP_i, \quad \text{Total } FP = \sum_{i=1}^N FP_i, \quad \text{Total } FN = \sum_{i=1}^N FN_i$$

---

### 2.2 Classification Metrics

#### Precision
Precision measures the proportion of flagged findings that correspond to genuine vulnerabilities:

$$\text{Precision} = \frac{TP}{TP + FP}$$

- **High Precision:** Minimizes false alarms, ensuring security analysts do not waste time investigating benign application behaviors.
- **Low Precision:** Indicates excessive noise or over-sensitive heuristics.

#### Recall (True Positive Rate / Sensitivity)
Recall measures the proportion of genuine vulnerabilities in the ground truth that were successfully identified:

$$\text{Recall} = \frac{TP}{TP + FN}$$

- **High Recall:** Minimizes missed security flaws, ensuring comprehensive audit coverage.
- **Low Recall:** Indicates blind spots in static patterns or tool limitations (e.g., obfuscation, dynamic reflection).

#### F1-Score
The F1-Score is the harmonic mean of Precision and Recall, providing a balanced single-metric representation:

$$F_1 = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}} = \frac{2 \cdot TP}{2 \cdot TP + FP + FN}$$

---

### 2.3 Edge Case & Division-by-Zero Safeguards

In static analysis evaluation, benign applications may contain zero expected vulnerabilities ($|E_i| = 0$), and an effective tool may produce zero findings ($|D_i| = 0$). Standard floating-point evaluation without safeguards results in undefined $\frac{0}{0}$ states.

The evaluation harness implements the following mathematical boundary conditions:

| Scenario | Condition | Handled Value | Rationale |
|---|---|:---:|---|
| Perfect Clean App | $TP = 0, FP = 0, FN = 0$ | $P=1.0, R=1.0, F_1=1.0$ | No flaws existed and none were falsely reported; behavior is completely correct. |
| Complete Miss | $TP = 0, FN > 0$ | $R=0.0, F_1=0.0$ | All genuine flaws were missed. |
| Pure False Alarms | $TP = 0, FP > 0$ | $P=0.0, F_1=0.0$ | All reported findings were spurious. |
| Zero Precision & Recall | $P + R = 0$ | $F_1 = 0.0$ | Harmonic mean fallback preventing division by zero. |

---

## 3. Scientific Integrity: Detection Telemetry vs. Empirical Accuracy

> [!IMPORTANT]
> **Ground Truth Boundary:** The evaluation harness enforces strict separation between raw detection telemetry and empirical accuracy metrics.

1. **No Ground Truth Fabrication:** The framework will never invent, guess, or synthesize ground truth labels.
2. **Telemetry Only Mode:** When evaluating an unlabeled collection of real-world APKs where no verified ground truth exists:
   - The tool outputs execution timings, permission tallies, and severity counts.
   - The tool **omits** precision, recall, and F1 calculations, explicitly marking them as `None`/unclaimed in both JSON and CSV exports.
   - Raw detection counts are reported as empirical observations of heuristic triggers, not as proven security vulnerabilities.

---

## 4. Performance & Efficiency Benchmarks

To quantify operational throughput, execution duration ($t_i$) in seconds is measured with nanosecond precision (`time.perf_counter()`) for each target package.

The evaluation harness reports five key performance statistics:

1. **Mean Analysis Time ($\mu$):**
   $$\mu = \frac{1}{N} \sum_{i=1}^N t_i$$
   Provides overall expected runtime per application.

2. **Median Analysis Time:**
   $$\text{Median} = \text{percentile}_{50}(t_1, \dots, t_N)$$
   Robust measure of central tendency unaffected by extreme outliers (e.g. unusually large APKs with hundreds of megabytes of resources).

3. **Minimum Analysis Time ($\min$):**
   Smallest observed duration (typically lightweight APKs with small DEX bytecode size).

4. **Maximum Analysis Time ($\max$):**
   Largest observed duration, characterizing worst-case latency under resource constraints.

5. **Total Analysis Time:**
   Cumulative processor time for entire batch execution.

---

## 5. Ground Truth Dataset Schema (`ground_truth.json`)

To enable accuracy evaluation, provide a JSON file specifying expected rule IDs or categories mapped to APK identifiers.

### Format Specification:
```json
{
  "apks": {
    "vulnerable_app_1.apk": {
      "app_name": "InsecureBank",
      "package": "com.insecurebank.v1",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "expected_rules": [
        "SEC-001",
        "NET-001",
        "STR-001",
        "CRY-001"
      ],
      "notes": "Intentionally vulnerable training sample"
    },
    "benign_app_2.apk": {
      "package": "com.secure.calculator",
      "expected_rules": [],
      "notes": "Clean utility application without known data leaks"
    }
  }
}
```

The matching algorithm looks up entries by **filename**, **SHA-256 hash**, or **Android package name**, ensuring flexibility when evaluating renamed files.

---

## 6. Execution Guide

### 6.1 Basic Evaluation (No Ground Truth — Telemetry & Timing)
```bash
python scripts/evaluate.py path/to/apk_directory
```
Produces:
- `evaluation_results.csv`: Table of per-application risk scores, permission counts, and durations.
- `evaluation_results.json`: Summary statistics and performance benchmarks.

### 6.2 Empirical Evaluation (With Ground Truth)
```bash
python scripts/evaluate.py path/to/apk_directory --ground-truth path/to/ground_truth.json --output-dir evaluation_output
```
Produces:
- `evaluation_results.csv`: Includes per-application $TP$, $FP$, $FN$, Precision, Recall, and F1.
- `evaluation_results.json`: Complete dataset-level and per-rule confusion matrix analysis.

### 6.3 Command Options
- `apk_dir`: (Positional) Directory containing target `.apk` files authorized for analysis.
- `--ground-truth, -g`: Optional path to `ground_truth.json`.
- `--output-dir, -o`: Directory for output artifacts (defaults to current directory).
- `--limit, -l`: Limit processing to the first $k$ APKs.
- `--fail-fast`: Immediately halt execution if an unhandled error occurs on any APK.

---

## 7. Output Artifacts Specification

### `evaluation_results.csv` Columns:
1. `filename`: Target APK filename.
2. `sha256`: SHA-256 cryptographic digest.
3. `package`: Android application package identifier.
4. `file_size`: Package archive size in bytes.
5. `analysis_duration`: Execution time in seconds.
6. `risk_score`: Aggregated score (0.0 to 100.0).
7. `risk_rating`: Categorical severity rating (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
8. `number_of_permissions`: Total declared/requested permissions.
9. `dangerous_permissions`: Count of sensitive/dangerous permissions.
10. `critical_findings`: Count of Critical-severity detections.
11. `high_findings`: Count of High-severity detections.
12. `medium_findings`: Count of Medium-severity detections.
13. `low_findings`: Count of Low-severity detections.
14. `rule_errors`: Warnings or parsing exceptions encountered during evaluation.
15. *(Optional, Ground Truth Mode)*: `true_positives`, `false_positives`, `false_negatives`, `precision`, `recall`, `f1_score`.

### `evaluation_results.json` Top-Level Keys:
- `metadata`: Timestamp, target directory, total APK count, ground truth configuration.
- `performance_benchmarks`: Mean, median, minimum, maximum, and total analysis duration.
- `summary_detection_counts`: Aggregated findings across severity levels and average risk score.
- `accuracy_evaluation`: Cumulative TP, FP, FN, overall precision/recall/F1, and breakdown per rule ID.
- `apks`: Array of individual application evaluation records.
