"""JSON output. A stable contract: changing it is a major version (schema_version)."""
from __future__ import annotations

import json

SCHEMA_VERSION = "1"


def finding_dict(report, f) -> dict:
    rule = report.rule(f.rule_id)
    d = {
        "id": f.rule_id, "title": report.t.rule(f.rule_id, "title"), "severity": f.severity,
        "confidence": f.confidence, "file": f.file, "lines": f.lines, "message": f.message.replace("\n", " "),
        "fix": report.t.rule(f.rule_id, "fix"), "cwe": list(rule.cwe), "owasp": rule.owasp, "docs": rule.docs,
        "fingerprint": f.fingerprint(),
    }
    if f.extra:
        d["details"] = f.extra
    return d


def to_dict(report) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "delstrike-check", "version": report.version},
        "target": {"path": report.path, "stack": report.stack, "apps": report.apps, "loc_own": report.loc_own,
                   "files_scanned": report.files_scanned},
        "network": "osv.dev (package names and versions only)" if report.deps else "none",
        "rules": [r.id for r in report.rules],
        "findings": [finding_dict(report, f) for f in report.findings],
        "hidden": {"count": len(report.hidden), "hint": "--all"},
        "suppressed": report.suppressed,
        "summary": report.summary(),
        "warnings": report.warnings,
        "errors": report.errors,
        "seconds": report.seconds,
    }


def render_json(report) -> str:
    return json.dumps(to_dict(report), indent=2, ensure_ascii=False) + "\n"
