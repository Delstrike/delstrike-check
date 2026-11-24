"""Secret redaction. The CLI never prints a secret value: findings name the key or the kind of token, never the value.

`redact()` is applied to any line used for a fingerprint, so even hashed material never contains a raw secret.
"""
from __future__ import annotations

import re

MASK = "[redacted]"

TOKEN_PATTERNS = [
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"\bsb_(?:secret|publishable)_[A-Za-z0-9_-]{10,}"),
    re.compile(r"\bsk-(?:proj-|ant-|svcacct-|admin-)?[A-Za-z0-9_-]{16,}"),
    re.compile(r"\b[rsp]k_(?:live|test)_[A-Za-z0-9]{10,}"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S),
    re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@'\"]+):[^@\s/'\"]{3,}@"),
]
ENV_VALUE = re.compile(r"^(\s*(?:export\s+)?[A-Za-z_][\w.-]*\s*[=:]\s*)(.+)$")


def mask(value: str) -> str:
    """Only a short, non-reversible hint: the first 4 characters."""
    return f"{value[:4]}…{MASK}" if len(value) >= 12 else MASK


def redact(text: str) -> str:
    if not text:
        return text
    for pat in TOKEN_PATTERNS:
        text = pat.sub(MASK, text)
    return text


def redact_env_line(line: str) -> str:
    m = ENV_VALUE.match(line)
    return f"{m.group(1)}{MASK}" if m and m.group(2).strip() else redact(line)
