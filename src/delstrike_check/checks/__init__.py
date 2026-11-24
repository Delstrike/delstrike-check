"""The rule registry. Order here is the order of `delstrike-check rules` and of the website."""
from __future__ import annotations

from ..model import Rule
from . import auth, deps, firebase, secrets, server_fn, supabase

RULES: tuple[Rule, ...] = (
    Rule("SB-EDGE-NOAUTH", "high", "high", (306, 862), "A01:2025", "Supabase", server_fn.detect_noauth, star=True),
    Rule("SB-EDGE-JWT-OFF", "high", "high", (306,), "A07:2025", "Supabase", server_fn.detect_jwt_off, star=True,
         severity_mix="mediumHigh"),
    Rule("SB-SERVICE-ROLE-KEY", "critical", "high", (798, 200), "A04:2025", "Supabase", secrets.detect_service_role),
    Rule("SB-POLICY-OPEN", "high", "high", (862, 639), "A01:2025", "Supabase", supabase.detect_policy_open),
    Rule("SB-RLS-OFF", "critical", "high", (862,), "A01:2025", "Supabase", supabase.detect_rls_off),
    Rule("SB-POLICY-OVERLAP", "high", "high", (863,), "A01:2025", "Supabase", supabase.detect_policy_overlap, star=True),
    Rule("SB-RPC-DEFINER", "medium", "medium", (250, 862), "A01:2025", "Supabase", supabase.detect_rpc_definer),
    Rule("AI-PROXY-OPEN", "high", "high", (770, 306), "A06:2025", "AI", server_fn.detect_ai_proxy, star=True),
    Rule("FB-RULES-OPEN", "critical", "high", (862, 284), "A01:2025", "Firebase", firebase.detect_rules_open,
         severity_mix="criticalHigh"),
    Rule("SB-BUCKET-PUBLIC", "medium", "medium", (552, 862), "A01:2025", "Supabase", supabase.detect_bucket_public),
    Rule("SB-NO-SCHEMA", "info", "high", (1059,), "A02:2025", "Supabase", supabase.detect_no_schema),
    Rule("AUTH-CONFIG", "low", "high", (287, 1390), "A07:2025", "Supabase", auth.detect_auth_config,
         aliases=("FB-AUTH-ANON",)),
    Rule("ENV-COMMITTED", "critical", "high", (538, 798), "A04:2025", "Secrets", secrets.detect_env_committed,
         severity_mix="infoCritical"),
    Rule("SECRET-KNOWN", "critical", "high", (798,), "A04:2025", "Secrets", secrets.detect_known),
    Rule("DEPS-OSV", "medium", "high", (1395,), "A03:2025", "Dependencies", deps.detect_deps, opt_in=True,
         severity_mix="perOsv"),
)


def find_rule(rule_id: str) -> Rule | None:
    return next((r for r in RULES if r.matches(rule_id)), None)


def canonical_id(rule_id: str) -> str | None:
    r = find_rule(rule_id)
    return r.id if r else None
