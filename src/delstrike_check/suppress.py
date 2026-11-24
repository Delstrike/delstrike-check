"""Suppressions: `.delstrike.toml` at the root and inline `delstrike-ignore RULE: reason` comments.

A reason is mandatory. A suppression without one is not applied, and the scan says so. A broken
`.delstrike.toml` never hides findings: the scan warns and continues without suppressions.
"""
from __future__ import annotations

import fnmatch
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .checks import canonical_id
from .model import Finding

INLINE = re.compile(r"delstrike-ignore\s+([A-Z0-9][A-Z0-9,\s-]*?[A-Z0-9])\s*(?::\s*(.*?))?\s*(?:\*/|-->|$)")
CONFIG_NAMES = (".delstrike.toml",)


@dataclass
class Ignore:
    rule: str
    path: str | None
    reason: str


@dataclass
class Config:
    exclude: list[str]
    ignores: list[Ignore]
    file: str | None


def load(root: Path, warnings: list[str], t) -> Config:
    for name in CONFIG_NAMES:
        p = root / name
        if not p.is_file():
            continue
        try:
            data = tomllib.loads(p.read_text(encoding="utf-8", errors="replace"))
        except tomllib.TOMLDecodeError as e:
            warnings.append(t("ui.config_error", file=name, error=str(e)))
            return Config([], [], name)
        except OSError:
            return Config([], [], None)
        exclude = [str(x) for x in data.get("exclude", []) if isinstance(x, str)] if isinstance(data.get("exclude"), list) \
            else []
        ignores = []
        for i, item in enumerate(data.get("ignore", []) if isinstance(data.get("ignore"), list) else [], 1):
            if not isinstance(item, dict):
                continue
            rid = canonical_id(str(item.get("rule", "")))
            reason = str(item.get("reason", "")).strip()
            if not rid:
                warnings.append(t("ui.ignore_unknown", file=name, n=i, rule=item.get("rule", "")))
                continue
            if not reason:
                warnings.append(t("ui.ignore_no_reason", file=name, n=i, rule=rid))
                continue
            path = item.get("path")
            ignores.append(Ignore(rid, str(path) if path else None, reason))
        return Config(exclude, ignores, name)
    return Config([], [], None)


def _path_match(rel: str, pattern: str) -> bool:
    pattern = pattern.lstrip("./")
    return fnmatch.fnmatch(rel, pattern) or rel == pattern or rel.startswith(pattern.rstrip("/") + "/") or \
        (pattern.endswith("/**") and rel.startswith(pattern[:-3]))


def inline_reason(finding: Finding, text: str | None, warnings: list[str], t) -> str | None:
    """Reason of an inline suppression on a finding line or the line above it."""
    if not text or "delstrike-ignore" not in text:
        return None
    lines = text.splitlines()
    for ln in finding.lines:
        for idx in (ln - 1, ln - 2):
            if not 0 <= idx < len(lines):
                continue
            m = INLINE.search(lines[idx])
            if not m:
                continue
            ids = {canonical_id(x.strip()) for x in re.split(r"[,\s]+", m.group(1)) if x.strip()}
            if finding.rule_id not in ids:
                continue
            reason = (m.group(2) or "").strip()
            if not reason:
                warnings.append(t("ui.inline_no_reason", file=finding.file, line=idx + 1, rule=finding.rule_id))
                return None
            return reason
    return None


def apply(findings: list[Finding], cfg: Config, read_text, warnings: list[str], t) -> tuple[list[Finding], list[dict]]:
    kept, suppressed = [], []
    for f in findings:
        reason = None
        for ig in cfg.ignores:
            if ig.rule == f.rule_id and (ig.path is None or _path_match(f.file, ig.path)):
                reason, source = ig.reason, cfg.file
                break
        if reason is None:
            reason = inline_reason(f, read_text(f.file), warnings, t)
            source = "inline"
        if reason:
            suppressed.append({"id": f.rule_id, "file": f.file, "lines": f.lines, "severity": f.severity,
                               "reason": reason, "source": source, "fingerprint": f.fingerprint()})
        else:
            kept.append(f)
    return kept, suppressed
