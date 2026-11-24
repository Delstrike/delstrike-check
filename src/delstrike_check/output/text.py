"""Terminal output. Never says "secure" or "safe": it says what these checks found, and what they can't see."""
from __future__ import annotations

import shutil
import textwrap

from .common import SEV_LABEL, cant_see, checks_count, lines_label, stack_label

COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[1;33m", "low": "\033[1;34m",
          "info": "\033[2m", "dim": "\033[2m", "bold": "\033[1m", "reset": "\033[0m", "verify": "\033[35m"}


def render_text(report, color: bool = False, quiet: bool = False) -> str:
    t = report.t
    c = (lambda k: COLORS[k]) if color else (lambda k: "")
    width = max(60, min(shutil.get_terminal_size((100, 20)).columns, 110))
    out: list[str] = [""]
    privacy = t("ui.privacy_deps") if report.deps else t("ui.privacy_local")
    out.append("  " + c("bold") + t("ui.header", version=report.version, stack=stack_label(report),
                                     loc=f"{report.loc_own:,}", privacy=privacy) + c("reset"))
    if report.apps:
        out.append("  " + c("dim") + t("ui.apps", count=len(report.apps), apps=", ".join(report.apps)) + c("reset"))
    out.append("")
    for f in report.findings:
        sev = SEV_LABEL[f.severity]
        tag = f"{c(f.severity)}{sev:<5}{c('reset')}"
        verify = f"  {c('verify')}{t('ui.to_verify_label')}{c('reset')}" if f.confidence != "high" else ""
        out.append(f"  {tag} {c('bold')}{f.rule_id:<20}{c('reset')} {f.file}:{lines_label(f.lines)}{verify}")
        for para in f.message.split("\n"):
            out += textwrap.wrap(para, width=width - 8, initial_indent="        ", subsequent_indent="        ")
        fix = f.extra.get("drop") or t.rule(f.rule_id, "fix_short")
        out += textwrap.wrap(f"{t('ui.fix_label')} {fix}", width=width - 8, initial_indent="        ",
                             subsequent_indent="             ")
        out.append("        " + c("dim") + t("ui.explain_cmd", rule=f.rule_id) + c("reset"))
        out.append("")
    summary = report.summary()
    parts = [f"{n} {report.t('ui.severity.' + s)}" for s, n in summary.items() if n]
    if not report.findings:
        key = "ui.no_issues_hidden" if report.hidden else "ui.no_issues"
        out.append("  " + c("bold") + t(key, count=checks_count(report)) + c("reset"))
    if report.hidden:
        parts.append(t("ui.to_verify", count=len(report.hidden)))
    if report.suppressed:
        parts.append(t("ui.suppressed", count=len(report.suppressed)))
    if parts:
        out.append("  " + " · ".join(parts))
    for w in report.warnings:
        out += textwrap.wrap("! " + w, width=width - 4, initial_indent="  ", subsequent_indent="    ")
    for e in report.errors:
        out += ["  ! " + ln for ln in e.splitlines()]
    if not quiet:
        out.append("")
        for line in cant_see(report):
            out += ["  " + c("dim") + ln + c("reset") for ln in line.split("\n")]
        out.append("  " + t("ui.hook"))
    out.append("")
    return "\n".join(out)
