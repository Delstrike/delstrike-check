"""SARIF 2.1.0 for GitHub code scanning (Security tab)."""
from __future__ import annotations

import json

from .common import SARIF_LEVEL, SECURITY_SEVERITY

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def render_sarif(report) -> str:
    t = report.t
    rules, index = [], {}
    for i, r in enumerate(report.rules):
        index[r.id] = i
        code = t.rule(r.id, "code") or {}
        help_md = (f"**{t('ui.explain_why')}.** {t.rule(r.id, 'why')}\n\n**{t('ui.explain_fix')}.** {t.rule(r.id, 'fix')}"
                   f"\n\n```{code.get('lang', '')}\n{code.get('text', '')}\n```\n\n[{r.docs}]({r.docs})")
        rules.append({
            "id": r.id,
            "name": r.id.title().replace("-", ""),
            "shortDescription": {"text": t.rule(r.id, "title")},
            "fullDescription": {"text": t.rule(r.id, "why")},
            "help": {"text": t.rule(r.id, "fix"), "markdown": help_md},
            "helpUri": r.docs,
            "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
            "properties": {
                "security-severity": SECURITY_SEVERITY[r.severity],
                "precision": {"high": "high", "medium": "medium", "low": "low"}[r.confidence],
                "tags": ["security", r.stack.lower(), *[f"external/cwe/cwe-{c}" for c in r.cwe]],
            },
        })
    results = []
    for f in report.findings:
        loc = lambda line: {"physicalLocation": {"artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"},  # noqa: E731
                                                 "region": {"startLine": max(1, line)}}}
        res = {
            "ruleId": f.rule_id,
            "ruleIndex": index[f.rule_id],
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f.message.replace("\n", " ")},
            "locations": [loc(f.lines[0] if f.lines else 1)],
            "partialFingerprints": {"delstrikeFingerprint/v1": f.fingerprint()},
            "properties": {"severity": f.severity, "confidence": f.confidence,
                           "security-severity": SECURITY_SEVERITY[f.severity]},
        }
        if len(f.lines) > 1:
            res["relatedLocations"] = [{"id": i, **loc(ln)} for i, ln in enumerate(f.lines[1:], 1)]
        results.append(res)
    doc = {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "delstrike-check", "version": report.version, "semanticVersion": report.version,
                                "informationUri": "https://www.delstrike.com/checkpoint/cli", "rules": rules}},
            "results": results,
            "properties": {"suppressed": len(report.suppressed), "hidden": len(report.hidden)},
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
