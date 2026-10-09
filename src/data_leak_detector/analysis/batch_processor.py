"""Batch analysis queue orchestrator for multi-APK static security assessments.

Guarantees:
- Predictable queueing instead of uncontrolled concurrent system resource consumption.
- Memory protection by executing conservatively (sequential processing by default).
- Clear lifecycle states: Waiting, Analyzing, Complete, Failed, Cancelled.
- CSV export of summary statistics without exposing sensitive evidence or raw secrets.
- Decoupled from Tkinter: Fully testable and usable in CLI, background services, and GUI.
"""

from __future__ import annotations

import csv
import gc
import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Sequence

from data_leak_detector.analysis.engine import AnalysisEngine, CancellationToken
from data_leak_detector.core.config import AppConfig
from data_leak_detector.core.exceptions import AnalysisCancelledError
from data_leak_detector.core.models import AnalysisResult
from data_leak_detector.core.path_safety import validate_output_path

logger = logging.getLogger(__name__)


class BatchItemStatus(str, Enum):
    """Lifecycle states of an APK item within a batch audit run."""

    WAITING = "Waiting"
    ANALYZING = "Analyzing"
    COMPLETE = "Complete"
    FAILED = "Failed"
    CANCELLED = "Cancelled"


@dataclass
class BatchItem:
    """Represents an individual APK within a batch queue."""

    apk_path: Path
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    filename: str = ""
    status: BatchItemStatus = BatchItemStatus.WAITING
    progress: float = 0.0
    current_stage: str = "Waiting"
    result: AnalysisResult | None = None
    error_message: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    cancellation_token: CancellationToken = field(default_factory=CancellationToken)

    def __post_init__(self) -> None:
        if isinstance(self.apk_path, str):
            self.apk_path = Path(self.apk_path)
        if not self.filename:
            self.filename = self.apk_path.name

    @property
    def risk_score(self) -> float | None:
        """Return numeric risk score (0-100) if analysis succeeded, otherwise None."""
        if self.result and hasattr(self.result, "overall_risk_score"):
            return float(self.result.overall_risk_score)
        return None

    @property
    def risk_rating(self) -> str | None:
        """Return categorical risk rating band if analysis succeeded, otherwise None."""
        if self.result and hasattr(self.result, "risk_rating"):
            rating = self.result.risk_rating
            return rating.value.upper() if hasattr(rating, "value") else str(rating).upper()
        return None

    @property
    def package_name(self) -> str | None:
        """Return application package identifier if extracted."""
        if self.result and self.result.application:
            return self.result.application.package_name
        return None

    @property
    def sha256(self) -> str | None:
        """Return application package SHA-256 hash if computed."""
        if self.result and self.result.application:
            return self.result.application.sha256
        return None

    @property
    def severity_counts(self) -> dict[str, int]:
        """Aggregate security finding counts across severity tiers."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        if self.result:
            for f in self.result.findings:
                sev = f.severity.value.lower() if hasattr(f.severity, "value") else str(f.severity).lower()
                if sev in counts:
                    counts[sev] += 1
        return counts

    @property
    def duration_seconds(self) -> float:
        """Analysis execution duration in seconds."""
        if self.result and self.result.metrics:
            return float(self.result.metrics.duration_seconds)
        if self.started_at and self.completed_at:
            return max(0.0, (self.completed_at - self.started_at).total_seconds())
        return 0.0


def _sanitize_csv_cell(value: Any) -> str:
    """Neutralize CSV formula injection (CWE-123) for untrusted values."""
    s = str(value) if value is not None else ""
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{s}"
    return s


def export_batch_summary_csv(items: Sequence[BatchItem], output_path: Path | str) -> Path:
    """Export batch results summary to CSV.

    Guarantees:
    - Contains strictly statistical and metadata columns.
    - Zero sensitive evidence, decoded secrets, or source snippets are written to disk.
    - Output path is validated against traversal and Windows reserved names.
    - Cell contents are sanitized against CSV formula injection (CWE-123).
    - Output path is returned as a Path object.
    """
    target = validate_output_path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    headers = [
        "filename",
        "package",
        "SHA-256",
        "analysis timestamp",
        "risk score",
        "risk rating",
        "critical count",
        "high count",
        "medium count",
        "low count",
        "analysis duration",
    ]

    with open(target, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)

        for item in items:
            # Timestamp formatting
            if item.result and item.result.metrics and item.result.metrics.completed_at:
                ts = item.result.metrics.completed_at.isoformat()
            elif item.completed_at:
                ts = item.completed_at.isoformat()
            else:
                ts = ""

            # Score and rating
            score_str = f"{item.risk_score:.1f}" if item.risk_score is not None else ""
            rating_str = item.risk_rating or ""

            # Severity counts
            if item.result is not None:
                counts = item.severity_counts
                crit = str(counts.get("critical", 0))
                hi = str(counts.get("high", 0))
                med = str(counts.get("medium", 0))
                lo = str(counts.get("low", 0))
                duration_str = f"{item.duration_seconds:.2f}s"
            else:
                crit = ""
                hi = ""
                med = ""
                lo = ""
                duration_str = f"{item.duration_seconds:.2f}s" if item.duration_seconds > 0 else ""

            row = [
                _sanitize_csv_cell(item.filename),
                _sanitize_csv_cell(item.package_name or ""),
                _sanitize_csv_cell(item.sha256 or ""),
                _sanitize_csv_cell(ts),
                _sanitize_csv_cell(score_str),
                _sanitize_csv_cell(rating_str),
                _sanitize_csv_cell(crit),
                _sanitize_csv_cell(hi),
                _sanitize_csv_cell(med),
                _sanitize_csv_cell(lo),
                _sanitize_csv_cell(duration_str),
            ]
            writer.writerow(row)

    logger.info("Batch summary exported to CSV: %s (%d items)", target, len(items))
    return target


class BatchProcessor:
    """Queue and orchestrator for executing batch static analyses.

    Attributes:
        max_concurrent: Maximum number of concurrent APK analyses. Defaults to 1 (sequential)
                        to protect host CPU and RAM resources from decompiler saturation.
    """

    def __init__(
        self,
        engine: AnalysisEngine | None = None,
        config: AppConfig | None = None,
        max_concurrent: int = 1,
    ) -> None:
        self.config = config or AppConfig()
        self.engine = engine or AnalysisEngine(config=self.config)
        self.max_concurrent = max(1, max_concurrent)
        self._items: list[BatchItem] = []
        self._lock = threading.Lock()
        self._worker_thread: threading.Thread | None = None
        self._is_running = False
        self._global_cancel = threading.Event()

    # -------------------------------------------------------------------------
    # QUEUE MANAGEMENT
    # -------------------------------------------------------------------------
    @property
    def items(self) -> list[BatchItem]:
        """Return a copy of the queued batch items."""
        with self._lock:
            return list(self._items)

    @property
    def is_running(self) -> bool:
        """Return True if batch analysis is currently active."""
        return self._is_running

    def add_apk(self, apk_path: Path | str) -> BatchItem:
        """Add an APK file to the batch queue."""
        item = BatchItem(apk_path=Path(apk_path))
        with self._lock:
            self._items.append(item)
        return item

    def add_apks(self, paths: Sequence[Path | str]) -> list[BatchItem]:
        """Add multiple APK files to the batch queue."""
        added: list[BatchItem] = []
        with self._lock:
            for p in paths:
                item = BatchItem(apk_path=Path(p))
                self._items.append(item)
                added.append(item)
        return added

    def remove_item(self, item_id: str) -> bool:
        """Remove a non-running APK item from the queue."""
        with self._lock:
            for idx, itm in enumerate(self._items):
                if itm.id == item_id:
                    if itm.status == BatchItemStatus.ANALYZING:
                        itm.cancellation_token.cancel()
                    self._items.pop(idx)
                    return True
        return False

    def clear(self) -> None:
        """Clear all items from the batch queue. If running, stops running jobs."""
        if self._is_running:
            self.cancel_all()
        with self._lock:
            self._items.clear()

    # -------------------------------------------------------------------------
    # EXECUTION: SYNCHRONOUS AND ASYNCHRONOUS
    # -------------------------------------------------------------------------
    def process_all(
        self,
        item_callback: Callable[[BatchItem], None] | None = None,
    ) -> list[BatchItem]:
        """Process all queued items synchronously in the current thread.

        Processes items sequentially (FIFO) to conserve host memory.
        Ideal for headless testing, scripts, and non-blocking worker threads.
        """
        self._global_cancel.clear()
        self._is_running = True

        try:
            for item in self.items:
                if self._global_cancel.is_set():
                    if item.status == BatchItemStatus.WAITING:
                        item.status = BatchItemStatus.CANCELLED
                        item.current_stage = "Cancelled"
                        if item_callback:
                            item_callback(item)
                    continue

                if item.status != BatchItemStatus.WAITING:
                    continue

                self._process_single_item(item, item_callback)

                # Memory protection: Run garbage collection between APKs
                gc.collect()

        finally:
            self._is_running = False

        return self.items

    def start(
        self,
        on_item_updated: Callable[[BatchItem], None] | None = None,
        on_complete: Callable[[], None] | None = None,
    ) -> None:
        """Launch batch execution in a dedicated background daemon thread."""
        if self._is_running:
            logger.warning("BatchProcessor is already running.")
            return

        def _worker() -> None:
            try:
                self.process_all(item_callback=on_item_updated)
            finally:
                if on_complete:
                    try:
                        on_complete()
                    except Exception as exc:
                        logger.error("Error in batch completion callback: %s", exc)

        self._worker_thread = threading.Thread(target=_worker, daemon=True, name="BatchProcessorWorker")
        self._worker_thread.start()

    def _process_single_item(
        self,
        item: BatchItem,
        callback: Callable[[BatchItem], None] | None = None,
    ) -> None:
        """Execute static analysis on a single item with cooperative cancellation and memory cleanup."""
        if item.cancellation_token.is_cancelled or self._global_cancel.is_set():
            item.status = BatchItemStatus.CANCELLED
            item.current_stage = "Cancelled"
            if callback:
                callback(item)
            return

        item.status = BatchItemStatus.ANALYZING
        item.current_stage = "Initializing"
        item.started_at = datetime.now(timezone.utc)
        item.progress = 0.0
        if callback:
            callback(item)

        def _progress(prog: float, stage: Any, msg: str = "") -> None:
            item.progress = prog
            item.current_stage = str(stage.value if hasattr(stage, "value") else stage)
            if callback:
                callback(item)

        try:
            result = self.engine.analyze_apk(
                apk_path=item.apk_path,
                progress_callback=_progress,
                cancellation_token=item.cancellation_token,
            )
            item.result = result
            item.status = BatchItemStatus.COMPLETE
            item.current_stage = "Complete"
            item.progress = 1.0
            item.completed_at = datetime.now(timezone.utc)

        except AnalysisCancelledError:
            item.status = BatchItemStatus.CANCELLED
            item.current_stage = "Cancelled"
            item.completed_at = datetime.now(timezone.utc)

        except Exception as exc:
            logger.error("Batch item '%s' failed: %s", item.filename, exc)
            item.status = BatchItemStatus.FAILED
            item.current_stage = f"Failed: {exc}"
            item.error_message = str(exc)
            item.completed_at = datetime.now(timezone.utc)

        finally:
            if callback:
                callback(item)

    # -------------------------------------------------------------------------
    # CANCELLATION
    # -------------------------------------------------------------------------
    def cancel_item(self, item_id: str) -> bool:
        """Cancel a specific item in the queue."""
        with self._lock:
            for itm in self._items:
                if itm.id == item_id:
                    itm.cancellation_token.cancel()
                    if itm.status == BatchItemStatus.WAITING:
                        itm.status = BatchItemStatus.CANCELLED
                        itm.current_stage = "Cancelled"
                    return True
        return False

    def cancel_all(self) -> None:
        """Cancel all items currently waiting or executing."""
        self._global_cancel.set()
        with self._lock:
            for itm in self._items:
                itm.cancellation_token.cancel()
                if itm.status == BatchItemStatus.WAITING:
                    itm.status = BatchItemStatus.CANCELLED
                    itm.current_stage = "Cancelled"

    # -------------------------------------------------------------------------
    # CSV EXPORT
    # -------------------------------------------------------------------------
    def export_csv(self, output_path: Path | str) -> Path:
        """Export current batch items to a CSV summary file."""
        return export_batch_summary_csv(self.items, output_path)
