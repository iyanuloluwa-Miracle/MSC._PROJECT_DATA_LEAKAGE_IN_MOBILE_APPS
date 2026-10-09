"""Security validation and sanitization utilities for file paths, archive entries, and logs.

Guarantees:
- Protection against Path Traversal and Zip Slip vulnerabilities (CWE-22).
- Neutralization of Log Injection and CRLF attacks (CWE-117).
- Defense against Windows reserved device filenames (CON, PRN, AUX, NUL, COM1-9, LPT1-9).
- Zero trust for metadata, filenames, or labels extracted from untrusted APK packages.
"""

from __future__ import annotations

import re
from pathlib import Path

# Reserved Windows device names that cannot be opened as regular files
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
}


def sanitize_untrusted_filename(name: str | None, default: str = "unnamed.apk") -> str:
    """Sanitize a filename originating from an untrusted APK archive or user input.

    Guarantees:
    - Strips path components, traversal sequences ('../', '..\\').
    - Removes NUL bytes ('\\x00') and ASCII control characters.
    - Prevents collision with Windows reserved filenames.
    - Returns a safe basename string.
    """
    if not name:
        return default

    # Remove NUL bytes and control characters
    cleaned = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", str(name))

    # Strip Windows and POSIX path separators to yield only the basename
    cleaned = cleaned.replace("\\", "/").split("/")[-1].strip()

    # Strip leading/trailing dots and spaces
    cleaned = cleaned.strip(". ")

    # Remove any lingering directory traversal tokens
    cleaned = re.sub(r"\.\.+", "", cleaned)

    if not cleaned:
        return default

    # Check for reserved device name (e.g., "CON.apk", "NUL")
    stem = Path(cleaned).stem.upper()
    if stem in WINDOWS_RESERVED_NAMES:
        cleaned = f"safe_{cleaned}"

    return cleaned


def is_safe_zip_path(entry_name: str) -> bool:
    """Check if a ZIP archive entry name is safe against Zip Slip path traversal.

    Returns False if entry:
    - Contains NUL bytes.
    - Is an absolute path (leading '/' or '\\').
    - Specifies a Windows drive letter (e.g. 'C:').
    - Contains directory traversal elements ('..').
    """
    if not entry_name or not isinstance(entry_name, str):
        return False

    # Reject NUL bytes
    if "\x00" in entry_name:
        return False

    # Normalize slashes
    normalized = entry_name.replace("\\", "/")

    # Reject absolute paths
    if normalized.startswith("/"):
        return False

    # Reject Windows drive specifier (e.g. "C:/evil.txt" or "D:")
    if len(normalized) >= 2 and normalized[1] == ":":
        return False

    # Reject any traversal element '..'
    segments = normalized.split("/")
    for seg in segments:
        if seg == "..":
            return False

    return True


def validate_output_path(output_path: Path | str) -> Path:
    """Validate and resolve an export destination path against device and traversal attacks.

    Raises:
        ValueError: If path contains NUL bytes, reserved names, or invalid structure.
    """
    raw_str = str(output_path)
    if "\x00" in raw_str:
        raise ValueError("Output path contains illegal NUL byte.")

    path_obj = Path(output_path)
    stem = path_obj.stem.upper()
    if stem in WINDOWS_RESERVED_NAMES:
        raise ValueError(f"Output path uses reserved operating system device name: {stem}")

    try:
        resolved = path_obj.resolve()
        return resolved
    except Exception as exc:
        raise ValueError(f"Invalid output path: {exc}") from exc


def sanitize_for_logging(text: str) -> str:
    """Neutralize CRLF log injection (CWE-117) and non-printable control characters.

    Replaces carriage return and newline characters with literal escaped tokens
    and replaces non-printable control bytes.
    """
    if not text:
        return ""

    # Replace newlines and carriage returns with escaped equivalents
    sanitized = text.replace("\r", "\\r").replace("\n", "\\n")

    # Replace any other control characters (except tab) with hex representations
    return re.sub(
        r"[\x00-\x08\x0b-\x1f\x7f]",
        lambda m: f"\\x{ord(m.group(0)):02x}",
        sanitized,
    )
