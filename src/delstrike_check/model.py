"""Core data types: severities, confidences, rules and findings."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Iterable

if TYPE_CHECKING:
    from .context import Context

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}   # info=0 … critical=4
CONFIDENCES = ("high", "medium", "low")
CONF_RANK = {"low": 0, "medium": 1, "high": 2}
DOCS_BASE = "https://www.delstrike.com/checkpoint/rules/"


def max_severity(*sevs: str) -> str:
    return max(sevs, key=lambda s: SEV_RANK[s])


@dataclass(frozen=True)
class Rule:
    id: str                         # stable forever: used in suppressions and on the website
    severity: str                   # default severity; a finding may adjust it
    confidence: str                 # default confidence; a finding may adjust it
    cwe: tuple[int, ...]
    owasp: str
    stack: str                      # Supabase | Firebase | AI | Secrets | Dependencies
    detect: Callable[["Context"], Iterable["Finding"]]
    since: str = "0.1.0"
    aliases: tuple[str, ...] = ()
    opt_in: bool = False            # only runs with an explicit flag (--deps)
    star: bool = False
    severity_mix: str | None = None  # severity depends on the case (shown on the website)

    @property
    def docs(self) -> str:
        return DOCS_BASE + self.id

    def matches(self, rule_id: str) -> bool:
        rid = rule_id.strip().upper()
        return rid == self.id or rid in self.aliases


@dataclass
class Finding:
    rule_id: str
    severity: str
    confidence: str
    file: str
    lines: list[int]
    message: str
    snippet: str = ""               # normalized, redacted text used only for the fingerprint
    extra: dict = field(default_factory=dict)

    def fingerprint(self) -> str:
        """id + file + normalized snippet, without line numbers: survives code moving around."""
        norm = re.sub(r"\s+", " ", self.snippet).strip() or self.message
        return hashlib.sha256(f"{self.rule_id}|{self.file}|{norm}".encode("utf-8")).hexdigest()[:32]

    def sort_key(self) -> tuple:
        return (-SEV_RANK[self.severity], -CONF_RANK[self.confidence], self.file, self.lines[0] if self.lines else 0,
                self.rule_id)
