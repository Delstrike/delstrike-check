"""`scan(path, options) -> Report`: the single entry point used by the CLI, the GitHub Action and CHECKPOINT."""
from __future__ import annotations

import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path

from . import suppress
from .checks import RULES
from .context import Context
from .i18n import Translator
from .inventory import count_loc, detect_stack, walk
from .model import SEV_RANK, CONF_RANK, SEVERITIES, Finding, Rule

DEFAULT_MAX_FILE_SIZE = 1_000_000


@dataclass
class Options:
    include_all: bool = False            # --all: also medium and low confidence
    deps: bool = False                   # --deps: query api.osv.dev (the only network access)
    exclude: list[str] = field(default_factory=list)
    lang: str = "en"
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    debug: bool = False


@dataclass
class Report:
    path: str
    version: str
    stack: list[str]
    apps: list[str]
    loc_own: int
    files_scanned: int
    findings: list[Finding]
    hidden: list[Finding]
    suppressed: list[dict]
    warnings: list[str]
    errors: list[str]
    rules: list[Rule]
    deps: bool
    seconds: float
    skipped_large: list[str]
    supabase_schema: bool
    firebase_rules: bool
    t: Translator

    def summary(self) -> dict[str, int]:
        out = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            out[f.severity] += 1
        return out

    def rule(self, rule_id: str) -> Rule:
        return next(r for r in self.rules if r.id == rule_id)


def _group(findings: list[Finding]) -> list[Finding]:
    """Same rule, file and message → one finding with the list of lines."""
    merged: dict[tuple, Finding] = {}
    for f in findings:
        key = (f.rule_id, f.file, f.message, f.severity, f.confidence)
        if key in merged:
            m = merged[key]
            m.lines = sorted(set(m.lines) | set(f.lines))
        else:
            merged[key] = Finding(f.rule_id, f.severity, f.confidence, f.file, sorted(set(f.lines)), f.message, f.snippet,
                                  dict(f.extra))
    return sorted(merged.values(), key=Finding.sort_key)


def scan(path: str | Path, options: Options | None = None) -> Report:
    from . import __version__
    options = options or Options()
    t0 = time.monotonic()
    root = Path(path)
    if not root.is_dir():
        raise NotADirectoryError(str(path))
    t = Translator(options.lang)
    warnings: list[str] = []
    cfg = suppress.load(root, warnings, t)
    inv = walk(root, list(options.exclude) + cfg.exclude, options.max_file_size)
    ctx = Context(inv, options, t)
    ctx.warnings = warnings
    detect_stack(inv, ctx.read)
    count_loc(inv, ctx.read)

    rules = [r for r in RULES if not r.opt_in or (r.id == "DEPS-OSV" and options.deps)]
    raw: list[Finding] = []
    errors: list[str] = []
    for rule in rules:
        try:
            raw.extend(rule.detect(ctx) or [])
        except Exception as e:  # a failing rule never stops the scan
            errors.append(t("ui.rule_error", rule=rule.id, error=type(e).__name__))
            if options.debug:
                errors.append(traceback.format_exc())
    grouped = _group(raw)
    kept, suppressed = suppress.apply(grouped, cfg, ctx.text_of, warnings, t)
    shown = [f for f in kept if options.include_all or f.confidence == "high"]
    hidden = [f for f in kept if f not in shown]
    if inv.skipped_large:
        warnings.append(t("ui.skipped_large", count=len(inv.skipped_large),
                          size=f"{options.max_file_size / 1_000_000:g}MB"))
    files_scanned = sum(1 for f in inv.files if not f.ignored)
    return Report(
        path=str(path), version=__version__, stack=inv.stack, apps=inv.apps, loc_own=inv.loc_own,
        files_scanned=files_scanned, findings=shown, hidden=hidden, suppressed=suppressed, warnings=warnings,
        errors=errors, rules=rules, deps=options.deps, seconds=round(time.monotonic() - t0, 2),
        skipped_large=sorted(inv.skipped_large),
        supabase_schema=any(m.tables or m.policies for m in ctx.sql_models.values()),
        firebase_rules=any(f.name.endswith(".rules") or f.name == "database.rules.json" for f in ctx.repo_files()),
        t=t,
    )


__all__ = ["Options", "Report", "scan", "SEV_RANK", "CONF_RANK"]
