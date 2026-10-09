"""Reusable secret redaction and entropy verification utilities."""

from __future__ import annotations

import math
import re


# Common test, example, and placeholder patterns to filter false positives
PLACEHOLDER_SUBSTRINGS = (
    "example",
    "placeholder",
    "insert_here",
    "insert_your",
    "your_key",
    "your_api_key",
    "your_token",
    "your_secret",
    "api_key_here",
    "change_me",
    "test_key",
    "test_secret",
    "fake_key",
    "fake_secret",
    "sample_key",
    "sample_secret",
    "dummy",
    "secret_here",
    "my_secret",
    "foobar",
    "1234567890",
    "abcdef123456",
    "null",
    "undefined",
    "00000000",
    "xxxxxxxx",
)

PLACEHOLDER_REGEXES = [
    re.compile(r"^(.)\1{5,}$"),         # Repeated character like "aaaaaa" or "111111"
    re.compile(r"(?i)^(your|my|test|sample|dummy|demo|fake)[-_]?(api|key|secret|token|password)"),
    re.compile(r"(?i)(insert[-_]?your[-_]?(api[-_]?key|secret|token)?)"),
]


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string (bits of entropy per character).
    
    Higher values (> 2.8 for alphanumeric strings) indicate random/cryptographic keys.
    """
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {char: data.count(char) for char in set(data)}
    for count in frequencies.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy


def is_placeholder_or_sample(value: str) -> bool:
    """Determine whether a potential secret value is a placeholder, sample, or dummy test string."""
    clean = value.strip().lower()

    if len(clean) < 8:
        return True

    for placeholder in PLACEHOLDER_SUBSTRINGS:
        if placeholder in clean:
            return True

    for pattern in PLACEHOLDER_REGEXES:
        if pattern.search(clean):
            return True

    # Extremely low variety (e.g. only 2 unique chars like "abababababababab")
    if len(set(clean)) <= 2:
        return True

    return False


def redact_secret(
    secret: str,
    prefix_len: int = 8,
    suffix_len: int = 3,
    mask: str = "********",
) -> str:
    """Redact a secret string, preserving non-sensitive prefix and suffix for audit recognition.
    
    Example:
        Original: 'AIzaSyABC123456789XYZ'
        Output:   'AIzaSyAB********XYZ'
    """
    if not secret:
        return ""

    trimmed = secret.strip()
    total_len = len(trimmed)

    # For short strings, mask the center or replace entirely
    if total_len <= prefix_len + suffix_len:
        if total_len <= 6:
            return mask
        keep = 2
        return trimmed[:keep] + mask + trimmed[-keep:]

    return trimmed[:prefix_len] + mask + trimmed[-suffix_len:]


def redact_text_secrets(text: str) -> str:
    """Scans freeform text for common secret patterns and masks them with redacted tokens."""
    if not text:
        return ""

    patterns = [
        # Google API Key
        (re.compile(r"(AIza[0-9A-Za-z\-_]{30,45})"), 8, 3),
        # AWS Access Key ID
        (re.compile(r"(AKIA[0-9A-Z]{16})"), 6, 2),
        # GitHub Personal Token
        (re.compile(r"(gh[pousr]_[A-Za-z0-9_]{36,120})"), 6, 3),
        # Slack Token
        (re.compile(r"(xox[baprs]-[0-9a-zA-Z-]{24,80})"), 6, 3),
    ]

    result = text
    for regex, pref, suff in patterns:
        def repl(match: re.Match) -> str:
            val = match.group(0)
            return redact_secret(val, prefix_len=pref, suffix_len=suff)
        result = regex.sub(repl, result)

    # Password / credentials in key-value format: password=foobar
    kv_pattern = re.compile(
        r"(?i)(password|secret|token|api_key|client_secret)\s*([=:])\s*([\"']?)([^\"'\s,;]+)([\"']?)"
    )

    def kv_repl(match: re.Match) -> str:
        key, sep, q1, val, q2 = match.groups()
        masked_val = redact_secret(val, prefix_len=2, suffix_len=2)
        return f"{key}{sep}{q1}{masked_val}{q2}"

    result = kv_pattern.sub(kv_repl, result)
    return result
