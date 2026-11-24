from __future__ import annotations

SEV_LABEL = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW", "info": "INFO"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def lines_label(lines: list[int]) -> str:
    if not lines:
        return ""
    if len(lines) == 1:
        return str(lines[0])
    shown = ",".join(str(x) for x in lines[:8])
    return shown + ("…" if len(lines) > 8 else "")


def checks_count(report) -> int:
    return len(report.rules)


def cant_see(report) -> list[str]:
    t = report.t
    out = []
    if "Supabase" in report.stack and not report.supabase_schema:
        out.append(t("ui.cant_see_schema"))
    if "Firebase" in report.stack and not report.firebase_rules:
        out.append(t("ui.cant_see_rules"))
    out.append(t("ui.cant_see"))
    return out


def stack_label(report) -> str:
    return " + ".join(report.stack[:4]) if report.stack else report.t("ui.stack_unknown")
