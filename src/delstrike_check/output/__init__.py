"""Output formats: text (terminal), json (stable contract), sarif (GitHub code scanning) and md (issue/PR)."""
from __future__ import annotations

from .json_out import render_json
from .markdown import render_md
from .sarif import render_sarif
from .text import render_text

FORMATS = ("text", "json", "sarif", "md")


def render(report, fmt: str, color: bool = False, quiet: bool = False) -> str:
    if fmt == "json":
        return render_json(report)
    if fmt == "sarif":
        return render_sarif(report)
    if fmt == "md":
        return render_md(report)
    return render_text(report, color=color, quiet=quiet)
