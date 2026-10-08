"""Domain exceptions for Mobile Data Leak Detector."""


class DetectorError(Exception):
    """Base exception for all domain-specific errors."""


class InvalidAPKError(DetectorError):
    """Raised when the target file does not exist, is not a file, or is not a valid ZIP/APK archive."""


class APKParsingError(DetectorError):
    """Raised when an APK cannot be opened, unpacked, or parsed statically."""


class ExternalToolError(DetectorError):
    """Raised when an external CLI tool execution fails or times out."""


class ToolExecutionError(ExternalToolError):
    """Raised when an external tool execution fails or times out."""


class ToolNotFoundError(ExternalToolError):
    """Raised when a required external tool binary is not installed or detected."""


class RuleExecutionError(DetectorError):
    """Raised when an error occurs during static rule evaluation."""


class StorageError(DetectorError):
    """Raised when SQLite database operations fail."""


class ReportGenerationError(DetectorError):
    """Raised when PDF or export report generation fails."""
