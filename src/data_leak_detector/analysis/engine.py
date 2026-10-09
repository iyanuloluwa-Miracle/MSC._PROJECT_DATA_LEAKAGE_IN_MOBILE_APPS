"""Static Analysis Engine orchestrator.

Coordinates APK validation, static parsing, resource preparation/decompilation,
modular rule execution across vulnerability categories, finding aggregation and
deduplication, transparent risk scoring, and performance telemetry.

Guarantees:
- Pure Python domain orchestration layer (Zero Tkinter or UI dependencies).
- Cooperative cancellation support checked between every analysis stage.
- Graceful degradation on external tool failures (JADX, Apktool) with recorded warnings.
- Guaranteed temporary artifact cleanup in all execution paths including errors/cancellations.
- Deterministic finding deduplication.
- Typed AnalysisResult output with execution telemetry.
"""

from __future__ import annotations

import inspect
import logging
import os
import re
import shutil
import tempfile
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Sequence

from data_leak_detector.analysis.apk_parser import APKParser
from data_leak_detector.analysis.permission_analyzer import PermissionAnalyzer
from data_leak_detector.analysis.risk_scorer import RiskScorer
from data_leak_detector.analysis.tool_adapters import (
    ApktoolAdapter,
    JadxAdapter,
)
from data_leak_detector.core.config import AppConfig
from data_leak_detector.core.exceptions import (
    AnalysisCancelledError,
    ExternalToolError,
)
from data_leak_detector.core.logging_config import SensitiveDataFilter
from data_leak_detector.core.path_safety import is_safe_zip_path
from data_leak_detector.core.models import (
    AnalysisMetrics,
    AnalysisResult,
    ParsedAPKData,
    SecurityFinding,
)
from data_leak_detector.rules.base import BaseRule
from data_leak_detector.rules.crypto_rules import ALL_CRYPTO_RULES
from data_leak_detector.rules.manifest_rules import ALL_MANIFEST_RULES
from data_leak_detector.rules.network_rules import ALL_NETWORK_RULES
from data_leak_detector.rules.registry import RuleRegistry
from data_leak_detector.rules.sdk_rules import ALL_SDK_RULES
from data_leak_detector.rules.secret_rules import ALL_SECRET_RULES
from data_leak_detector.rules.storage_rules import ALL_STORAGE_RULES


logger = logging.getLogger(__name__)


class AnalysisStage(str, Enum):
    """Sequential progress stages emitted during static analysis pipeline execution."""

    VALIDATING = "VALIDATING"
    PARSING = "PARSING"
    DECOMPILING = "DECOMPILING"
    ANALYZING_PERMISSIONS = "ANALYZING_PERMISSIONS"
    SCANNING_MANIFEST = "SCANNING_MANIFEST"
    SCANNING_SECRETS = "SCANNING_SECRETS"
    SCANNING_NETWORK = "SCANNING_NETWORK"
    SCANNING_STORAGE = "SCANNING_STORAGE"
    SCANNING_CRYPTO = "SCANNING_CRYPTO"
    SCANNING_SDKS = "SCANNING_SDKS"
    SCORING = "SCORING"
    COMPLETE = "COMPLETE"


STAGE_PROGRESS: dict[AnalysisStage, float] = {
    AnalysisStage.VALIDATING: 0.05,
    AnalysisStage.PARSING: 0.15,
    AnalysisStage.DECOMPILING: 0.25,
    AnalysisStage.ANALYZING_PERMISSIONS: 0.40,
    AnalysisStage.SCANNING_MANIFEST: 0.50,
    AnalysisStage.SCANNING_SECRETS: 0.60,
    AnalysisStage.SCANNING_NETWORK: 0.70,
    AnalysisStage.SCANNING_STORAGE: 0.80,
    AnalysisStage.SCANNING_CRYPTO: 0.88,
    AnalysisStage.SCANNING_SDKS: 0.94,
    AnalysisStage.SCORING: 0.98,
    AnalysisStage.COMPLETE: 1.00,
}


@dataclass
class ProgressUpdate:
    """Structured progress notification event."""

    progress: float
    stage: AnalysisStage
    message: str


class CancellationToken:
    """Thread-safe cooperative cancellation token for static analysis jobs."""

    def __init__(self) -> None:
        self._cancelled = False

    def cancel(self) -> None:
        """Signal cooperative cancellation."""
        self._cancelled = True

    @property
    def is_cancelled(self) -> bool:
        """Return True if cancellation has been requested."""
        return self._cancelled


class AnalysisEngine:
    """Central orchestration layer coordinating static Android vulnerability analysis.
    
    Zero Tkinter dependency: Pure service suitable for CLI, worker threads, or UI callers.
    """

    def __init__(
        self,
        config: AppConfig | None = None,
        registry: RuleRegistry | None = None,
        jadx_adapter: JadxAdapter | None = None,
        apktool_adapter: ApktoolAdapter | None = None,
        permission_analyzer: PermissionAnalyzer | None = None,
        risk_scorer: RiskScorer | None = None,
    ) -> None:
        self.config = config or AppConfig()
        self.registry = registry
        self.jadx_adapter = jadx_adapter or JadxAdapter(
            timeout_seconds=self.config.subprocess_timeout_seconds
        )
        self.apktool_adapter = apktool_adapter or ApktoolAdapter(
            timeout_seconds=self.config.subprocess_timeout_seconds
        )
        self.permission_analyzer = permission_analyzer or PermissionAnalyzer()
        self.risk_scorer = risk_scorer or RiskScorer()
        self._cancelled = False

    def cancel(self) -> None:
        """Signal cooperative cancellation to any running analysis."""
        self._cancelled = True

    def reset(self) -> None:
        """Reset internal cancellation state."""
        self._cancelled = False

    @property
    def is_cancelled(self) -> bool:
        """Check if engine-level cancellation was requested."""
        return self._cancelled

    def analyze_apk(
        self,
        apk_path: Path | str,
        progress_callback: Callable[..., None] | None = None,
        cancel_callback: Callable[[], bool] | None = None,
        cancellation_token: Any = None,
    ) -> AnalysisResult:
        """Execute the end-to-end static analysis pipeline on the provided APK.

        Args:
            apk_path: Path to target Android APK package.
            progress_callback: Optional progress listener accepting (fraction, stage_name)
                or (fraction, stage_name, message) or ProgressUpdate.
            cancel_callback: Optional callable returning True if cancellation is requested.
            cancellation_token: Optional token exposing an `is_cancelled` attribute.

        Returns:
            AnalysisResult containing parsed metadata, findings, risk score, and metrics.

        Raises:
            InvalidAPKError: If the APK does not exist or has an invalid structure.
            APKParsingError: If AndroGuard fails fatally during static inspection.
            AnalysisCancelledError: If cancellation is requested before or between stages.
            DetectorError: If any other unrecoverable domain failure occurs.
        """
        self._cancelled = False
        target_path = Path(apk_path).resolve()
        started_at = datetime.now(timezone.utc)
        warnings: list[str] = []
        temp_dirs_to_clean: list[Path] = []
        files_examined = 0
        rules_executed = 0

        logger.info(
            SensitiveDataFilter.redact(f"Starting static analysis on APK: {target_path}")
        )

        try:
            # -----------------------------------------------------------------
            # 1. VALIDATING Stage
            # -----------------------------------------------------------------
            self._check_cancellation(cancel_callback, cancellation_token)
            self._emit_progress(
                progress_callback,
                AnalysisStage.VALIDATING,
                STAGE_PROGRESS[AnalysisStage.VALIDATING],
                "Validating APK package archive and structure...",
            )

            parser = self._create_apk_parser(target_path)
            parser.validate_file()

            # -----------------------------------------------------------------
            # 2. PARSING Stage
            # -----------------------------------------------------------------
            self._check_cancellation(cancel_callback, cancellation_token)
            self._emit_progress(
                progress_callback,
                AnalysisStage.PARSING,
                STAGE_PROGRESS[AnalysisStage.PARSING],
                "Calculating hash and parsing static Android manifest...",
            )

            sha256_hash = parser.calculate_sha256()
            parsed_apk = parser.parse()
            if not parsed_apk.metadata.sha256:
                parsed_apk.metadata.sha256 = sha256_hash

            # -----------------------------------------------------------------
            # 3. DECOMPILING Stage (Optional tools with graceful degradation)
            # -----------------------------------------------------------------
            self._check_cancellation(cancel_callback, cancellation_token)
            self._emit_progress(
                progress_callback,
                AnalysisStage.DECOMPILING,
                STAGE_PROGRESS[AnalysisStage.DECOMPILING],
                "Preparing decompiled sources and extracted static resources...",
            )

            scan_temp_dir = self._create_temp_dir("mld_scan_")
            temp_dirs_to_clean.append(scan_temp_dir)

            extracted_files, extracted_strings, tool_warnings = (
                self._prepare_static_resources(target_path, scan_temp_dir, parsed_apk)
            )
            warnings.extend(tool_warnings)
            files_examined = max(len(extracted_files), 1)

            # Build comprehensive analysis context for static rules
            classes_list = self._extract_classes_and_packages(extracted_files, parsed_apk)
            context = self._build_rule_context(
                parsed_apk=parsed_apk,
                extracted_files=extracted_files,
                extracted_strings=extracted_strings,
                classes=classes_list,
            )

            # -----------------------------------------------------------------
            # 4. ANALYZING_PERMISSIONS Stage
            # -----------------------------------------------------------------
            self._check_cancellation(cancel_callback, cancellation_token)
            self._emit_progress(
                progress_callback,
                AnalysisStage.ANALYZING_PERMISSIONS,
                STAGE_PROGRESS[AnalysisStage.ANALYZING_PERMISSIONS],
                "Auditing declared permissions against sensitive data families...",
            )

            permission_summary = self.permission_analyzer.analyze(parsed_apk)
            permission_findings = permission_summary.findings

            # -----------------------------------------------------------------
            # 5-10. VULNERABILITY RULES Scanning Stages
            # -----------------------------------------------------------------
            all_findings: list[SecurityFinding] = []

            scanning_stages = [
                (
                    AnalysisStage.SCANNING_MANIFEST,
                    "Evaluating manifest configuration and exported component rules...",
                    self._get_rules_for_stage(AnalysisStage.SCANNING_MANIFEST),
                ),
                (
                    AnalysisStage.SCANNING_SECRETS,
                    "Scanning textual resources for hardcoded secrets and credentials...",
                    self._get_rules_for_stage(AnalysisStage.SCANNING_SECRETS),
                ),
                (
                    AnalysisStage.SCANNING_NETWORK,
                    "Scanning static communication endpoints and network security...",
                    self._get_rules_for_stage(AnalysisStage.SCANNING_NETWORK),
                ),
                (
                    AnalysisStage.SCANNING_STORAGE,
                    "Checking persistent storage patterns and logging indicators...",
                    self._get_rules_for_stage(AnalysisStage.SCANNING_STORAGE),
                ),
                (
                    AnalysisStage.SCANNING_CRYPTO,
                    "Evaluating cryptographic algorithms, modes, and key material...",
                    self._get_rules_for_stage(AnalysisStage.SCANNING_CRYPTO),
                ),
                (
                    AnalysisStage.SCANNING_SDKS,
                    "Identifying third-party SDKs and SDK Permission Exposure...",
                    self._get_rules_for_stage(AnalysisStage.SCANNING_SDKS),
                ),
            ]

            for stage, stage_msg, stage_rules in scanning_stages:
                self._check_cancellation(cancel_callback, cancellation_token)
                self._emit_progress(
                    progress_callback,
                    stage,
                    STAGE_PROGRESS[stage],
                    stage_msg,
                )

                stage_findings, stage_executed, stage_warnings = self._execute_rules(
                    rules=stage_rules,
                    context=context,
                )
                all_findings.extend(stage_findings)
                rules_executed += stage_executed
                warnings.extend(stage_warnings)

            # -----------------------------------------------------------------
            # 8 & 9. AGGREGATE & DEDUPLICATE Findings
            # -----------------------------------------------------------------
            deduped_findings = self.deduplicate_findings(all_findings)

            # -----------------------------------------------------------------
            # 10. SCORING Stage
            # -----------------------------------------------------------------
            self._check_cancellation(cancel_callback, cancellation_token)
            self._emit_progress(
                progress_callback,
                AnalysisStage.SCORING,
                STAGE_PROGRESS[AnalysisStage.SCORING],
                "Computing transparent academic risk score and rating...",
            )

            risk_result = self.risk_scorer.calculate(
                findings=deduped_findings,
                permissions=permission_findings,
            )

            # -----------------------------------------------------------------
            # 11. Performance Metrics Collection
            # -----------------------------------------------------------------
            completed_at = datetime.now(timezone.utc)
            duration_seconds = max(
                0.001, round((completed_at - started_at).total_seconds(), 3)
            )

            metrics = AnalysisMetrics(
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration_seconds,
                files_examined=files_examined,
                rules_executed=rules_executed,
                warnings=warnings,
            )

            # -----------------------------------------------------------------
            # 12. COMPLETE Stage
            # -----------------------------------------------------------------
            self._emit_progress(
                progress_callback,
                AnalysisStage.COMPLETE,
                STAGE_PROGRESS[AnalysisStage.COMPLETE],
                "Static analysis scan completed successfully.",
            )

            logger.info(
                f"Analysis completed in {duration_seconds}s. "
                f"Findings: {len(deduped_findings)}, Score: {risk_result.score:.1f} ({risk_result.rating.value})"
            )

            return AnalysisResult(
                analysis_id=uuid.uuid4().hex,
                application=parsed_apk.metadata,
                overall_risk_score=risk_result.score,
                risk_rating=risk_result.rating,
                metrics=metrics,
                permissions=permission_findings,
                findings=deduped_findings,
                analyzer_version="0.1.0",
            )

        finally:
            # -----------------------------------------------------------------
            # 12. Guaranteed cleanup of temporary artifacts even after exceptions
            # -----------------------------------------------------------------
            self._clean_temporary_dirs(temp_dirs_to_clean)

    # Convenience alias for analyze_apk
    analyze = analyze_apk

    def _create_apk_parser(self, apk_path: Path) -> APKParser:
        """Factory method creating an APKParser instance."""
        return APKParser(apk_path, config=self.config)

    def _create_temp_dir(self, prefix: str) -> Path:
        """Create a dedicated temporary directory."""
        temp_base = self.config.temp_dir if self.config.temp_dir.exists() else None
        temp_dir = tempfile.mkdtemp(prefix=prefix, dir=temp_base)
        return Path(temp_dir)

    def _clean_temporary_dirs(self, temp_dirs: list[Path]) -> None:
        """Safely delete all recorded temporary directories, handling locked/read-only files."""
        def _handle_remove_readonly(func: Any, path: str, exc: Any) -> None:
            import stat
            try:
                os.chmod(path, stat.S_IWRITE)
                func(path)
            except Exception:
                pass

        for d in temp_dirs:
            try:
                if d.exists():
                    shutil.rmtree(d, onerror=_handle_remove_readonly)
                    logger.debug(f"Removed temporary directory: {d}")
            except Exception as e:
                logger.warning(f"Failed to remove temporary directory {d}: {e}")

    def _check_cancellation(
        self,
        cancel_callback: Callable[[], bool] | None = None,
        cancellation_token: Any = None,
    ) -> None:
        """Check for cancellation request and raise domain exception if cancelled."""
        if self._cancelled:
            logger.info("Static analysis cancelled via AnalysisEngine.cancel()")
            raise AnalysisCancelledError("Static analysis scan was cancelled by user request.")
        if cancel_callback and cancel_callback():
            logger.info("Static analysis cancelled via cancel_callback")
            raise AnalysisCancelledError("Static analysis scan was cancelled by user request.")
        if cancellation_token and getattr(cancellation_token, "is_cancelled", False):
            logger.info("Static analysis cancelled via cancellation_token")
            raise AnalysisCancelledError("Static analysis scan was cancelled by user request.")

    def _emit_progress(
        self,
        callback: Callable[..., None] | None,
        stage: AnalysisStage,
        progress: float,
        message: str,
    ) -> None:
        """Invoke progress callback with flexible arity support."""
        if callback is None:
            return
        try:
            sig = inspect.signature(callback)
            params = list(sig.parameters.values())
            has_varargs = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params)
            if has_varargs:
                callback(progress, stage.value, message)
                return

            param_count = len(params)
            if param_count == 1:
                callback(ProgressUpdate(progress=progress, stage=stage, message=message))
            elif param_count == 2:
                callback(progress, stage.value)
            elif param_count >= 3:
                callback(progress, stage.value, message)
            else:
                callback()
        except Exception as e:
            logger.debug(f"Progress callback invocation raised an exception: {e}")

    def _prepare_static_resources(
        self,
        apk_path: Path,
        scan_temp_dir: Path,
        parsed_apk: ParsedAPKData,
    ) -> tuple[dict[str, str], set[str], list[str]]:
        """Decompile or extract textual assets, string pools, and XML structures.
        
        Degrades gracefully with logged warnings if optional external CLI tools fail.
        """
        extracted_files: dict[str, str] = {}
        extracted_strings: set[str] = set()
        warnings: list[str] = []

        # 1. Manifest raw XML
        if parsed_apk.manifest_info and parsed_apk.manifest_info.raw_xml:
            extracted_files["AndroidManifest.xml"] = parsed_apk.manifest_info.raw_xml

        # 2. JADX Decompilation (Optional)
        jadx_dir = scan_temp_dir / "jadx_src"
        if self.jadx_adapter.is_available():
            try:
                success = self.jadx_adapter.run(apk_path, jadx_dir)
                if success and jadx_dir.exists():
                    self._harvest_directory_text_files(
                        jadx_dir,
                        extracted_files,
                        valid_extensions=(".java", ".kt"),
                        prefix="jadx/",
                    )
                else:
                    warnings.append(
                        "JADX decompilation returned non-zero code. Proceeding with bytecode inspection."
                    )
            except ExternalToolError as e:
                warnings.append(
                    f"JADX decompilation failed ({e}). Proceeding with bytecode inspection."
                )
            except Exception as e:
                warnings.append(
                    f"Unexpected error executing JADX ({e}). Proceeding with bytecode inspection."
                )
        else:
            warnings.append(
                "JADX decompiler is not available on PATH. Java source decompilation skipped."
            )

        # 3. Apktool Resource Decoding (Optional)
        apktool_dir = scan_temp_dir / "apktool_res"
        if self.apktool_adapter.is_available():
            try:
                success = self.apktool_adapter.run(apk_path, apktool_dir)
                if success and apktool_dir.exists():
                    self._harvest_directory_text_files(
                        apktool_dir,
                        extracted_files,
                        valid_extensions=(".xml", ".json", ".properties", ".txt"),
                        prefix="apktool/",
                    )
                else:
                    warnings.append(
                        "Apktool decoding returned non-zero code. Proceeding with direct archive resources."
                    )
            except ExternalToolError as e:
                warnings.append(
                    f"Apktool resource decoding failed ({e}). Proceeding with direct archive resources."
                )
            except Exception as e:
                warnings.append(
                    f"Unexpected error executing Apktool ({e}). Proceeding with direct archive resources."
                )
        else:
            warnings.append(
                "Apktool is not available on PATH. Resource decoding skipped."
            )

        # 4. Direct Archive Extraction (Always available fallback)
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                for entry_name in zf.namelist():
                    if not is_safe_zip_path(entry_name):
                        continue

                    # Extract printable strings from DEX bytecode pools
                    if entry_name.endswith(".dex"):
                        try:
                            dex_bytes = zf.read(entry_name)
                            dex_strings = re.findall(rb"[\x20-\x7E]{4,}", dex_bytes)
                            for s in dex_strings:
                                try:
                                    extracted_strings.add(s.decode("ascii"))
                                except UnicodeDecodeError:
                                    pass
                        except Exception as e:
                            logger.debug(f"Failed extracting strings from {entry_name}: {e}")

                    # Fallback text resources if apktool wasn't run
                    elif entry_name.endswith((".json", ".properties", ".txt")):
                        if (
                            entry_name not in extracted_files
                            and len(extracted_files) < self.config.max_extracted_file_count
                        ):
                            try:
                                raw_bytes = zf.read(entry_name)
                                if len(raw_bytes) <= self.config.max_scanned_file_size_bytes:
                                    extracted_files[entry_name] = raw_bytes.decode(
                                        "utf-8", errors="replace"
                                    )
                            except Exception:
                                pass
        except Exception as e:
            logger.debug(f"Direct ZIP inspection error: {e}")

        return extracted_files, extracted_strings, warnings

    def _harvest_directory_text_files(
        self,
        base_dir: Path,
        extracted_files: dict[str, str],
        valid_extensions: tuple[str, ...],
        prefix: str = "",
        max_file_size: int | None = None,
    ) -> None:
        """Walk a directory and store matching text files into the extracted_files dictionary."""
        effective_max = (
            max_file_size
            if max_file_size is not None
            else self.config.max_scanned_file_size_bytes
        )
        for root, _, files in os.walk(base_dir):
            for file_name in files:
                if len(extracted_files) >= self.config.max_extracted_file_count:
                    logger.warning("Reached maximum extracted file count limit.")
                    return
                if file_name.endswith(valid_extensions):
                    file_path = Path(root) / file_name
                    try:
                        if file_path.stat().st_size <= effective_max:
                            rel_path = f"{prefix}{file_path.relative_to(base_dir)}"
                            extracted_files[rel_path] = file_path.read_text(
                                encoding="utf-8", errors="replace"
                            )
                    except Exception as e:
                        logger.debug(f"Could not read decompiled file {file_path}: {e}")

    def _extract_classes_and_packages(
        self,
        extracted_files: dict[str, str],
        parsed_apk: ParsedAPKData,
    ) -> list[str]:
        """Aggregate candidate classes and packages from decompiled sources and components."""
        classes: set[str] = set()

        for comp in (
            parsed_apk.activities
            + parsed_apk.services
            + parsed_apk.receivers
            + parsed_apk.providers
            + parsed_apk.libraries
        ):
            classes.add(comp)

        for path_str in extracted_files.keys():
            if path_str.endswith((".java", ".kt")):
                clean_path = path_str
                for pfx in ("jadx/", "apktool/"):
                    if clean_path.startswith(pfx):
                        clean_path = clean_path[len(pfx) :]
                class_candidate = clean_path.rsplit(".", 1)[0].replace("/", ".").replace("\\", ".")
                classes.add(class_candidate)

        return sorted(classes)

    def _build_rule_context(
        self,
        parsed_apk: ParsedAPKData,
        extracted_files: dict[str, str],
        extracted_strings: set[str],
        classes: list[str],
    ) -> dict[str, Any]:
        """Construct the unified evaluation context matching all static rule signatures."""
        return {
            "parsed_apk": parsed_apk,
            "manifest_info": parsed_apk.manifest_info,
            "metadata": parsed_apk.metadata,
            "permissions": list(parsed_apk.permissions),
            "activities": list(parsed_apk.activities),
            "services": list(parsed_apk.services),
            "receivers": list(parsed_apk.receivers),
            "providers": list(parsed_apk.providers),
            "libraries": list(parsed_apk.libraries),
            "strings": list(extracted_strings),
            "files": extracted_files,
            "classes": classes,
            "packages": [c.rsplit(".", 1)[0] for c in classes if "." in c],
        }

    def _get_rules_for_stage(self, stage: AnalysisStage) -> list[BaseRule]:
        """Resolve rule instances to evaluate for a given scanning stage."""
        # If a custom registry is injected, pull rules from it
        if self.registry is not None:
            category_mapping = {
                AnalysisStage.SCANNING_MANIFEST: "MANIFEST_MISCONFIG",
                AnalysisStage.SCANNING_SECRETS: "HARDCODED_SECRET",
                AnalysisStage.SCANNING_NETWORK: "NETWORK_INDICATOR",
                AnalysisStage.SCANNING_STORAGE: "STORAGE_INSECURITY",
                AnalysisStage.SCANNING_CRYPTO: "CRYPTO_FLAW",
                AnalysisStage.SCANNING_SDKS: "TRACKING_SDK",
            }
            target_cat = category_mapping.get(stage)
            rules: list[BaseRule] = []
            for r in self.registry.get_enabled_rules():
                cat_val = getattr(r.category, "value", r.category)
                if cat_val == target_cat:
                    rules.append(r)
            return rules

        # Default rules mapped per stage
        default_rule_classes: dict[AnalysisStage, list[type[BaseRule]]] = {
            AnalysisStage.SCANNING_MANIFEST: ALL_MANIFEST_RULES,
            AnalysisStage.SCANNING_SECRETS: ALL_SECRET_RULES,
            AnalysisStage.SCANNING_NETWORK: ALL_NETWORK_RULES,
            AnalysisStage.SCANNING_STORAGE: ALL_STORAGE_RULES,
            AnalysisStage.SCANNING_CRYPTO: ALL_CRYPTO_RULES,
            AnalysisStage.SCANNING_SDKS: ALL_SDK_RULES,
        }

        rule_cls_list = default_rule_classes.get(stage, [])
        return [cls() for cls in rule_cls_list]

    def _execute_rules(
        self,
        rules: Sequence[BaseRule],
        context: dict[str, Any],
    ) -> tuple[list[SecurityFinding], int, list[str]]:
        """Safely execute a list of rules with complete fault isolation."""
        findings: list[SecurityFinding] = []
        executed_count = 0
        warnings: list[str] = []

        for rule in rules:
            if not getattr(rule, "enabled", True):
                continue

            try:
                rule_findings = rule.evaluate(context)
                if rule_findings:
                    findings.extend(rule_findings)
                executed_count += 1
            except Exception as exc:
                executed_count += 1
                sanitized_err = SensitiveDataFilter.redact(str(exc))
                rule_name = getattr(rule, "rule_id", "UNKNOWN_RULE")
                logger.error(
                    f"Rule '{rule_name}' raised an unhandled exception during evaluation: {sanitized_err}"
                )
                warnings.append(f"Rule {rule_name} failed during execution: {sanitized_err}")

        return findings, executed_count, warnings

    @staticmethod
    def deduplicate_findings(findings: Sequence[SecurityFinding]) -> list[SecurityFinding]:
        """Deduplicate equivalent findings while preserving discovery order.
        
        Two findings are considered equivalent if they share the same rule_id,
        title, evidence, and location.
        """
        seen: set[tuple[str, str, str, str | None]] = set()
        deduped: list[SecurityFinding] = []

        for finding in findings:
            key = (
                finding.rule_id,
                finding.title,
                finding.evidence,
                finding.location,
            )
            if key not in seen:
                seen.add(key)
                deduped.append(finding)

        return deduped
