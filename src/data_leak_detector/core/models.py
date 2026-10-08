"""Domain models and data structures for static analysis."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Type, TypeVar, Union


T = TypeVar("T", bound="BaseModel")


class Severity(str, Enum):
    """Vulnerability and risk severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    """Confidence level in static indicator match."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RiskRating(str, Enum):
    """Overall APK risk rating."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    MINIMAL = "MINIMAL"


class FindingCategory(str, Enum):
    """Categorization for static findings."""

    PERMISSION = "PERMISSION"
    NETWORK_INDICATOR = "NETWORK_INDICATOR"
    HARDCODED_SECRET = "HARDCODED_SECRET"
    STORAGE_INSECURITY = "STORAGE_INSECURITY"
    CRYPTO_FLAW = "CRYPTO_FLAW"
    TRACKING_SDK = "TRACKING_SDK"
    MANIFEST_MISCONFIG = "MANIFEST_MISCONFIG"


def _format_datetime(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _parse_datetime(val: Any) -> datetime:
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        # Support trailing Z
        clean_val = val.replace("Z", "+00:00")
        return datetime.fromisoformat(clean_val)
    raise ValueError(f"Expected datetime or ISO string, got {type(val).__name__}: {val!r}")


def _serialize_value(val: Any) -> Any:
    if isinstance(val, Enum):
        return val.value
    if isinstance(val, (datetime,)):
        return _format_datetime(val)
    if isinstance(val, Path):
        return str(val)
    if isinstance(val, list):
        return [_serialize_value(item) for item in val]
    if isinstance(val, dict):
        return {k: _serialize_value(v) for k, v in val.items()}
    if hasattr(val, "to_dict"):
        return val.to_dict()
    return val


@dataclass
class BaseModel:
    """Base model with serialization and deserialization helpers."""

    def to_dict(self) -> dict[str, Any]:
        """Serialize dataclass model to JSON-safe dictionary."""
        result: dict[str, Any] = {}
        for k, v in self.__dict__.items():
            result[k] = _serialize_value(v)
        return result

    def to_json(self, indent: int = 2) -> str:
        """Serialize model directly to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


@dataclass
class ApplicationMetadata(BaseModel):
    """Structural and cryptographic metadata extracted from target APK."""

    filename: str
    sha256: str
    file_size: int
    package_name: str
    file_path: Path | None = None
    app_name: str | None = None
    version_name: str | None = None
    version_code: Union[int, str, None] = None
    min_sdk: Union[int, str, None] = None
    target_sdk: Union[int, str, None] = None
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.filename or not self.filename.strip():
            raise ValueError("Application filename cannot be empty.")
        if not self.package_name or not self.package_name.strip():
            raise ValueError("Application package_name cannot be empty.")
        if self.file_size < 0:
            raise ValueError(f"file_size cannot be negative, got {self.file_size}.")
        if self.sha256:
            if not re.fullmatch(r"[0-9a-fA-F]{64}", self.sha256.strip()):
                raise ValueError(f"Invalid SHA-256 hash format: {self.sha256!r}")
        else:
            raise ValueError("sha256 hash cannot be empty.")

        if self.file_path is not None and not isinstance(self.file_path, Path):
            self.file_path = Path(self.file_path)

        if not isinstance(self.analyzed_at, datetime):
            self.analyzed_at = _parse_datetime(self.analyzed_at)

    @classmethod
    def from_dict(cls: Type[ApplicationMetadata], data: dict[str, Any]) -> ApplicationMetadata:
        """Reconstruct ApplicationMetadata from dictionary."""
        d = dict(data)
        file_path = Path(d["file_path"]) if d.get("file_path") else None
        analyzed_at = _parse_datetime(d["analyzed_at"]) if "analyzed_at" in d else datetime.now(timezone.utc)
        return cls(
            filename=d["filename"],
            sha256=d["sha256"],
            file_size=int(d["file_size"]),
            package_name=d["package_name"],
            file_path=file_path,
            app_name=d.get("app_name"),
            version_name=d.get("version_name"),
            version_code=d.get("version_code"),
            min_sdk=d.get("min_sdk"),
            target_sdk=d.get("target_sdk"),
            analyzed_at=analyzed_at,
        )

    @classmethod
    def from_json(cls: Type[ApplicationMetadata], json_str: str) -> ApplicationMetadata:
        """Reconstruct ApplicationMetadata from JSON string."""
        return cls.from_dict(json.loads(json_str))


@dataclass
class ComponentDetail(BaseModel):
    """Detailed metadata for an Android component (activity, service, receiver, provider)."""

    component_type: str  # "activity", "service", "receiver", "provider"
    name: str
    exported: bool = False
    permission: str | None = None
    read_permission: str | None = None
    write_permission: str | None = None
    has_intent_filter: bool = False
    is_main_launcher: bool = False
    actions: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls: Type[ComponentDetail], data: dict[str, Any]) -> ComponentDetail:
        """Reconstruct ComponentDetail from dictionary."""
        d = dict(data)
        return cls(
            component_type=d["component_type"],
            name=d["name"],
            exported=bool(d.get("exported", False)),
            permission=d.get("permission"),
            read_permission=d.get("read_permission"),
            write_permission=d.get("write_permission"),
            has_intent_filter=bool(d.get("has_intent_filter", False)),
            is_main_launcher=bool(d.get("is_main_launcher", False)),
            actions=list(d.get("actions", [])),
        )

    @classmethod
    def from_json(cls: Type[ComponentDetail], json_str: str) -> ComponentDetail:
        """Reconstruct ComponentDetail from JSON string."""
        return cls.from_dict(json.loads(json_str))


@dataclass
class ManifestData(BaseModel):
    """Extracted manifest metadata, components, and security flags."""

    package_name: str
    app_name: str | None = None
    version_name: str | None = None
    version_code: Union[int, str, None] = None
    min_sdk: Union[int, str, None] = None
    target_sdk: Union[int, str, None] = None
    allow_backup: bool | None = None
    debuggable: bool | None = None
    uses_cleartext_traffic: bool | None = None
    network_security_config: str | None = None
    raw_xml: str | None = None
    components: list[ComponentDetail] = field(default_factory=list)

    @classmethod
    def from_dict(cls: Type[ManifestData], data: dict[str, Any]) -> ManifestData:
        """Reconstruct ManifestData from dictionary."""
        d = dict(data)
        components = [
            c if isinstance(c, ComponentDetail) else ComponentDetail.from_dict(c)
            for c in d.get("components", [])
        ]
        return cls(
            package_name=d["package_name"],
            app_name=d.get("app_name"),
            version_name=d.get("version_name"),
            version_code=d.get("version_code"),
            min_sdk=d.get("min_sdk"),
            target_sdk=d.get("target_sdk"),
            allow_backup=d.get("allow_backup"),
            debuggable=d.get("debuggable"),
            uses_cleartext_traffic=d.get("uses_cleartext_traffic"),
            network_security_config=d.get("network_security_config"),
            raw_xml=d.get("raw_xml"),
            components=components,
        )

    @classmethod
    def from_json(cls: Type[ManifestData], json_str: str) -> ManifestData:
        """Reconstruct ManifestData from JSON string."""
        return cls.from_dict(json.loads(json_str))


@dataclass
class ParsedAPKData(BaseModel):
    """Complete statically extracted structure from an APK."""

    metadata: ApplicationMetadata
    permissions: list[str] = field(default_factory=list)
    declared_permissions: list[str] = field(default_factory=list)
    activities: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    receivers: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    features: list[str] = field(default_factory=list)
    libraries: list[str] = field(default_factory=list)
    manifest_info: ManifestData | None = None
    is_valid_apk: bool = True

    @classmethod
    def from_dict(cls: Type[ParsedAPKData], data: dict[str, Any]) -> ParsedAPKData:
        """Reconstruct ParsedAPKData from dictionary."""
        d = dict(data)
        meta = (
            d["metadata"]
            if isinstance(d["metadata"], ApplicationMetadata)
            else ApplicationMetadata.from_dict(d["metadata"])
        )
        manifest_info = None
        if d.get("manifest_info"):
            manifest_info = (
                d["manifest_info"]
                if isinstance(d["manifest_info"], ManifestData)
                else ManifestData.from_dict(d["manifest_info"])
            )

        return cls(
            metadata=meta,
            permissions=list(d.get("permissions", [])),
            declared_permissions=list(d.get("declared_permissions", [])),
            activities=list(d.get("activities", [])),
            services=list(d.get("services", [])),
            receivers=list(d.get("receivers", [])),
            providers=list(d.get("providers", [])),
            features=list(d.get("features", [])),
            libraries=list(d.get("libraries", [])),
            manifest_info=manifest_info,
            is_valid_apk=bool(d.get("is_valid_apk", True)),
        )

    @classmethod
    def from_json(cls: Type[ParsedAPKData], json_str: str) -> ParsedAPKData:
        """Reconstruct ParsedAPKData from JSON string."""
        return cls.from_dict(json.loads(json_str))


@dataclass
class PermissionFinding(BaseModel):
    """Audited Android permission and its data leakage implications."""

    permission: str
    protection_level: str
    risk_level: Severity
    description: str
    reason: str
    source: str = "manifest"
    confidence: Confidence = Confidence.HIGH
    classification: str | None = None
    user_friendly_description: str | None = None
    family: str | None = None
    is_sensitive_user_data: bool = False
    is_heuristic_warning: bool = False

    def __post_init__(self) -> None:
        if not self.permission or not self.permission.strip():
            raise ValueError("Permission name cannot be empty.")
        if not isinstance(self.risk_level, Severity):
            self.risk_level = Severity(self.risk_level)
        if not isinstance(self.confidence, Confidence):
            self.confidence = Confidence(self.confidence)

    @classmethod
    def from_dict(cls: Type[PermissionFinding], data: dict[str, Any]) -> PermissionFinding:
        """Reconstruct PermissionFinding from dictionary."""
        d = dict(data)
        return cls(
            permission=d["permission"],
            protection_level=d.get("protection_level", "unknown"),
            risk_level=Severity(d["risk_level"]),
            description=d.get("description", ""),
            reason=d.get("reason", ""),
            source=d.get("source", "manifest"),
            confidence=Confidence(d.get("confidence", Confidence.HIGH.value)),
            classification=d.get("classification"),
            user_friendly_description=d.get("user_friendly_description"),
            family=d.get("family"),
            is_sensitive_user_data=bool(d.get("is_sensitive_user_data", False)),
            is_heuristic_warning=bool(d.get("is_heuristic_warning", False)),
        )

    @classmethod
    def from_json(cls: Type[PermissionFinding], json_str: str) -> PermissionFinding:
        """Reconstruct PermissionFinding from JSON string."""
        return cls.from_dict(json.loads(json_str))


@dataclass
class PermissionSummary(BaseModel):
    """Aggregated statistical breakdown of evaluated permissions."""

    total_permissions: int = 0
    dangerous_permissions: int = 0
    normal_permissions: int = 0
    signature_permissions: int = 0
    unknown_custom_permissions: int = 0
    sensitive_user_data_permissions: int = 0
    findings: list[PermissionFinding] = field(default_factory=list)
    sensitive_families: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls: Type[PermissionSummary], data: dict[str, Any]) -> PermissionSummary:
        """Reconstruct PermissionSummary from dictionary."""
        d = dict(data)
        findings = [
            f if isinstance(f, PermissionFinding) else PermissionFinding.from_dict(f)
            for f in d.get("findings", [])
        ]
        return cls(
            total_permissions=int(d.get("total_permissions", 0)),
            dangerous_permissions=int(d.get("dangerous_permissions", 0)),
            normal_permissions=int(d.get("normal_permissions", 0)),
            signature_permissions=int(d.get("signature_permissions", 0)),
            unknown_custom_permissions=int(d.get("unknown_custom_permissions", 0)),
            sensitive_user_data_permissions=int(d.get("sensitive_user_data_permissions", 0)),
            findings=findings,
            sensitive_families=list(d.get("sensitive_families", [])),
        )

    @classmethod
    def from_json(cls: Type[PermissionSummary], json_str: str) -> PermissionSummary:
        """Reconstruct PermissionSummary from JSON string."""
        return cls.from_dict(json.loads(json_str))


@dataclass
class SecurityFinding(BaseModel):
    """A distinct static vulnerability or data-leak indicator."""

    rule_id: str
    title: str
    category: Union[FindingCategory, str]
    severity: Severity
    confidence: Confidence
    description: str
    evidence: str
    location: str | None = None
    impact: str | None = None
    remediation: str | None = None
    owasp_reference: str | None = None
    is_static_indicator: bool = True

    def __post_init__(self) -> None:
        if not self.rule_id or not self.rule_id.strip():
            raise ValueError("SecurityFinding rule_id cannot be empty.")
        if not self.title or not self.title.strip():
            raise ValueError("SecurityFinding title cannot be empty.")
        if not isinstance(self.severity, Severity):
            self.severity = Severity(self.severity)
        if not isinstance(self.confidence, Confidence):
            self.confidence = Confidence(self.confidence)
        if isinstance(self.category, str):
            try:
                self.category = FindingCategory(self.category)
            except ValueError:
                pass  # Keep as custom category string if not in enum

    @classmethod
    def from_dict(cls: Type[SecurityFinding], data: dict[str, Any]) -> SecurityFinding:
        """Reconstruct SecurityFinding from dictionary."""
        d = dict(data)
        cat = d.get("category", FindingCategory.MANIFEST_MISCONFIG.value)
        try:
            category_val = FindingCategory(cat)
        except ValueError:
            category_val = cat

        return cls(
            rule_id=d["rule_id"],
            title=d["title"],
            category=category_val,
            severity=Severity(d["severity"]),
            confidence=Confidence(d["confidence"]),
            description=d.get("description", ""),
            evidence=d.get("evidence", ""),
            location=d.get("location"),
            impact=d.get("impact"),
            remediation=d.get("remediation"),
            owasp_reference=d.get("owasp_reference"),
            is_static_indicator=d.get("is_static_indicator", True),
        )

    @classmethod
    def from_json(cls: Type[SecurityFinding], json_str: str) -> SecurityFinding:
        """Reconstruct SecurityFinding from JSON string."""
        return cls.from_dict(json.loads(json_str))


@dataclass
class AnalysisMetrics(BaseModel):
    """Execution timing and telemetry metrics for the static scan."""

    started_at: datetime
    completed_at: datetime
    duration_seconds: float
    files_examined: int = 0
    rules_executed: int = 0
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.started_at, datetime):
            self.started_at = _parse_datetime(self.started_at)
        if not isinstance(self.completed_at, datetime):
            self.completed_at = _parse_datetime(self.completed_at)
        if self.duration_seconds < 0:
            raise ValueError(f"duration_seconds cannot be negative, got {self.duration_seconds}.")
        if self.files_examined < 0:
            raise ValueError(f"files_examined cannot be negative, got {self.files_examined}.")
        if self.rules_executed < 0:
            raise ValueError(f"rules_executed cannot be negative, got {self.rules_executed}.")
        if self.completed_at < self.started_at:
            raise ValueError("completed_at cannot precede started_at.")

    @classmethod
    def from_dict(cls: Type[AnalysisMetrics], data: dict[str, Any]) -> AnalysisMetrics:
        """Reconstruct AnalysisMetrics from dictionary."""
        d = dict(data)
        return cls(
            started_at=_parse_datetime(d["started_at"]),
            completed_at=_parse_datetime(d["completed_at"]),
            duration_seconds=float(d["duration_seconds"]),
            files_examined=int(d.get("files_examined", 0)),
            rules_executed=int(d.get("rules_executed", 0)),
            warnings=list(d.get("warnings", [])),
        )

    @classmethod
    def from_json(cls: Type[AnalysisMetrics], json_str: str) -> AnalysisMetrics:
        """Reconstruct AnalysisMetrics from JSON string."""
        return cls.from_dict(json.loads(json_str))


@dataclass
class AnalysisResult(BaseModel):
    """Complete aggregated outcome of a static APK analysis scan."""

    analysis_id: str
    application: ApplicationMetadata
    overall_risk_score: float
    risk_rating: RiskRating
    metrics: AnalysisMetrics
    permissions: list[PermissionFinding] = field(default_factory=list)
    findings: list[SecurityFinding] = field(default_factory=list)
    analyzer_version: str = "0.1.0"

    def __post_init__(self) -> None:
        if not self.analysis_id or not self.analysis_id.strip():
            raise ValueError("AnalysisResult analysis_id cannot be empty.")
        if not (0.0 <= self.overall_risk_score <= 100.0):
            raise ValueError(
                f"overall_risk_score must be between 0.0 and 100.0, got {self.overall_risk_score}."
            )
        if not isinstance(self.risk_rating, RiskRating):
            self.risk_rating = RiskRating(self.risk_rating)

    @classmethod
    def from_dict(cls: Type[AnalysisResult], data: dict[str, Any]) -> AnalysisResult:
        """Reconstruct AnalysisResult from dictionary."""
        d = dict(data)
        app_meta = (
            d["application"]
            if isinstance(d["application"], ApplicationMetadata)
            else ApplicationMetadata.from_dict(d["application"])
        )
        metrics = (
            d["metrics"]
            if isinstance(d["metrics"], AnalysisMetrics)
            else AnalysisMetrics.from_dict(d["metrics"])
        )
        permissions = [
            p if isinstance(p, PermissionFinding) else PermissionFinding.from_dict(p)
            for p in d.get("permissions", [])
        ]
        findings = [
            f if isinstance(f, SecurityFinding) else SecurityFinding.from_dict(f)
            for f in d.get("findings", [])
        ]
        return cls(
            analysis_id=d["analysis_id"],
            application=app_meta,
            overall_risk_score=float(d["overall_risk_score"]),
            risk_rating=RiskRating(d["risk_rating"]),
            metrics=metrics,
            permissions=permissions,
            findings=findings,
            analyzer_version=d.get("analyzer_version", "0.1.0"),
        )

    @classmethod
    def from_json(cls: Type[AnalysisResult], json_str: str) -> AnalysisResult:
        """Reconstruct AnalysisResult from JSON string."""
        return cls.from_dict(json.loads(json_str))


# Backward compatibility aliases
Finding = SecurityFinding
PermissionDetail = PermissionFinding
APKMetadata = ApplicationMetadata


@dataclass
class RiskScore(BaseModel):
    """Academic prototype risk score calculation result and explainability breakdown."""

    score: float
    rating: RiskRating = RiskRating.MINIMAL
    level: Union[Severity, str, None] = None
    summary: str = ""
    disclaimer: str = (
        "This risk score is a heuristic prioritisation metric developed for this research prototype "
        "and should not be interpreted as CVSS or proof of exploitation."
    )
    breakdown: dict[str, Any] = field(default_factory=dict)
    category_scores: dict[str, float] = field(default_factory=dict)
    findings_evaluated: int = 0
    findings_deduplicated: int = 0
    rule_contributions: dict[str, float] = field(default_factory=dict)
    explanations: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not (0.0 <= self.score <= 100.0):
            raise ValueError(f"Score must be between 0.0 and 100.0, got {self.score}")
        if not isinstance(self.rating, RiskRating):
            try:
                self.rating = RiskRating(self.rating)
            except ValueError:
                self.rating = RiskRating.MINIMAL
        if self.level is None:
            severity_map = {
                RiskRating.CRITICAL: Severity.CRITICAL,
                RiskRating.HIGH: Severity.HIGH,
                RiskRating.MEDIUM: Severity.MEDIUM,
                RiskRating.LOW: Severity.LOW,
                RiskRating.MINIMAL: Severity.INFO,
            }
            self.level = severity_map.get(self.rating, Severity.INFO)

    @classmethod
    def from_dict(cls: Type[RiskScore], data: dict[str, Any]) -> RiskScore:
        """Reconstruct RiskScore from dictionary."""
        d = dict(data)
        rating_raw = d.get("rating", d.get("level", "MINIMAL"))
        try:
            rating_val = RiskRating(rating_raw)
        except ValueError:
            rating_val = RiskRating.MINIMAL

        return cls(
            score=float(d["score"]),
            rating=rating_val,
            level=d.get("level"),
            summary=d.get("summary", ""),
            disclaimer=d.get(
                "disclaimer",
                "This risk score is a heuristic prioritisation metric developed for this research prototype "
                "and should not be interpreted as CVSS or proof of exploitation.",
            ),
            breakdown=dict(d.get("breakdown", {})),
            category_scores=dict(d.get("category_scores", {})),
            findings_evaluated=int(d.get("findings_evaluated", 0)),
            findings_deduplicated=int(d.get("findings_deduplicated", 0)),
            rule_contributions=dict(d.get("rule_contributions", {})),
            explanations=list(d.get("explanations", [])),
        )

    @classmethod
    def from_json(cls: Type[RiskScore], json_str: str) -> RiskScore:
        """Reconstruct RiskScore from JSON string."""
        return cls.from_dict(json.loads(json_str))


RiskScoreResult = RiskScore

