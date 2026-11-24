"""Documentation generated from the rules: one source for `explain`, the website and the README.

    python -m delstrike_check.docs --out <dir>          # rules.json (website) + one <ID>.md per rule
    python -m delstrike_check.docs --readme README.md   # refresh the rules table between the markers
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from .checks import RULES
from .i18n import Translator

START, END = "<!-- rules:start -->", "<!-- rules:end -->"
MIX = {"mediumHigh": "Medium–High", "criticalHigh": "High–Critical", "infoCritical": "Info–Critical",
       "perOsv": "Per advisory"}


def rule_dicts(lang: str = "en") -> list[dict]:
    t = Translator(lang)
    out = []
    for r in RULES:
        d = {"id": r.id, "title": t.rule(r.id, "title"), "severity": r.severity, "confidence": r.confidence,
             "stack": r.stack, "detects": t.rule(r.id, "detects"), "why": t.rule(r.id, "why"), "fix": t.rule(r.id, "fix"),
             "code": t.rule(r.id, "code"), "references": t.raw(f"rules.{r.id}.references") or [],
             "cwe": list(r.cwe), "owasp": r.owasp, "since": r.since, "docs": r.docs}
        if r.aliases:
            d["aliases"] = list(r.aliases)
        if r.severity_mix:
            d["severityMix"] = r.severity_mix
        if r.star:
            d["star"] = True
        if r.opt_in:
            d["optIn"] = True
        out.append(d)
    return out


def rule_markdown(d: dict) -> str:
    sev = MIX.get(d.get("severityMix", ""), d["severity"].title())
    lines = [f"# {d['id']}: {d['title']}", "",
             f"**Severity:** {sev} · **Confidence:** {d['confidence'].title()} · **Stack:** {d['stack']} · "
             f"**CWE:** {', '.join(str(c) for c in d['cwe'])} · **OWASP:** {d['owasp']}"
             + (" · runs only with `--deps`" if d.get("optIn") else ""), ""]
    if d.get("aliases"):
        lines += [f"Also reported as: {', '.join(d['aliases'])}", ""]
    lines += ["## What it detects", "", d["detects"], "", "## Why it matters", "", d["why"], "", "## How to fix it", "",
              d["fix"], "", f"```{d['code']['lang']}", d["code"]["text"], "```", ""]
    if d["references"]:
        lines += ["## References", ""] + [f"- <{u}>" for u in d["references"]] + [""]
    lines += ["## Suppress it", "", "With a reason, in `.delstrike.toml`:", "", "```toml", "[[ignore]]",
              f'rule = "{d["id"]}"', 'reason = "Why this is fine in this project"', "```", ""]
    return "\n".join(lines)


def readme_table() -> str:
    rows = ["| Rule | Severity | Confidence | Stack | What it catches |", "|---|---|---|---|---|"]
    for d in rule_dicts():
        sev = MIX.get(d.get("severityMix", ""), d["severity"].title())
        name = f"[`{d['id']}`]({d['docs']})" + (" ★" if d.get("star") else "")
        title = d["title"] + (" (`--deps`)" if d.get("optIn") else "")
        rows.append(f"| {name} | {sev} | {d['confidence'].title()} | {d['stack']} | {title} |")
    return "\n".join(rows)


def update_readme(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    new = re.sub(re.escape(START) + r".*?" + re.escape(END), f"{START}\n{readme_table()}\n{END}", text, flags=re.S)
    if new != text:
        path.write_text(new, encoding="utf-8")
        return True
    return False


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m delstrike_check.docs")
    p.add_argument("--out", type=Path, help="folder for rules.json and one <ID>.md per rule")
    p.add_argument("--readme", type=Path, help="README to refresh between the rules markers")
    a = p.parse_args(argv)
    if not a.out and not a.readme:
        p.error("pass --out and/or --readme")
    if a.out:
        a.out.mkdir(parents=True, exist_ok=True)
        data = rule_dicts()
        (a.out / "rules.json").write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        for d in data:
            (a.out / f"{d['id']}.md").write_text(rule_markdown(d), encoding="utf-8")
        print(f"{len(data)} rules written to {a.out}")
    if a.readme:
        print("README updated" if update_readme(a.readme) else "README already up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
