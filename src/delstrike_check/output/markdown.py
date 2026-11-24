"""Markdown summary to paste in an issue or PR, or to send to an agency."""
from __future__ import annotations

from .common import cant_see, checks_count, lines_label, stack_label


def _esc(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def render_md(report) -> str:
    t = report.t
    out = [f"## {t('ui.md_title')}", ""]
    privacy = t("ui.privacy_deps") if report.deps else t("ui.privacy_local")
    out.append(f"**{t('ui.md_scope')}:** {stack_label(report)} · {report.loc_own:,} own lines · {privacy}")
    out.append("")
    summary = report.summary()
    counts = " · ".join(f"**{n}** {t('ui.severity.' + s)}" for s, n in summary.items() if n)
    extra = []
    if report.hidden:
        extra.append(t("ui.to_verify", count=len(report.hidden)))
    if report.suppressed:
        extra.append(t("ui.suppressed", count=len(report.suppressed)))
    if report.findings:
        out.append(" · ".join([counts, *extra]))
        out.append("")
        out.append(f"| {t('ui.md_severity')} | {t('ui.md_finding')} | {t('ui.md_where')} |")
        out.append("|---|---|---|")
        for f in report.findings:
            title = t.rule(f.rule_id, "title")
            rule = report.rule(f.rule_id)
            out.append(f"| {t('ui.severity.' + f.severity)} | [`{f.rule_id}`]({rule.docs}) {_esc(title)} | "
                       f"`{f.file}:{lines_label(f.lines)}` |")
        out.append("")
        for f in report.findings:
            out.append(f"### `{f.rule_id}` · `{f.file}:{lines_label(f.lines)}`")
            out.append("")
            out.append(_esc(f.message))
            out.append("")
            out.append(f"**{t('ui.fix_label')}** {t.rule(f.rule_id, 'fix')}")
            out.append("")
    else:
        out.append(t("ui.md_none", count=checks_count(report)) + (" " + " · ".join(extra) if extra else ""))
        out.append("")
    for line in cant_see(report):
        out.append("> " + line.replace("\n", " "))
    out.append("")
    out.append("---")
    out.append(t("ui.md_footer", version=report.version))
    out.append("")
    return "\n".join(out)
