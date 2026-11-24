"""Supabase database checks from migrations: RLS, policies, SECURITY DEFINER functions, buckets, missing schema."""
from __future__ import annotations

import re
import tomllib
from typing import TYPE_CHECKING, Iterable

from ..model import Finding
from ..sql import PUBLIC_SCHEMAS, Policy

if TYPE_CHECKING:
    from ..context import Context

GLOBAL_READ_MIN = 3
USER_CONTENT = re.compile(r"upload|document|doc|invoice|receipt|avatar|attachment|file|private|user|contract|"
                          r"passport|identity|id[-_]?card|kyc|cv|resume|medical|report|statement|photo|selfie|scan|source",
                          re.I)
ACTIONS = {"all": "read, create, change or delete", "select": "read", "insert": "create", "update": "change",
           "delete": "delete"}


def _covers(a: str, b: str) -> bool:
    return a == b or "all" in (a, b)


def _supabase(ctx: "Context") -> bool:
    return ctx.inv.has("Supabase")


def detect_rls_off(ctx: "Context") -> Iterable[Finding]:
    if not _supabase(ctx):
        return
    for model in ctx.sql_models.values():
        for (schema, name), t in sorted(model.tables.items()):
            if schema not in PUBLIC_SCHEMAS or t.rls:
                continue
            revoked = t.revoked_anon or model.revoke_all_tables
            sev = "high" if revoked else "critical"
            if t.disabled_at:
                file, line, key = t.disabled_at[0], t.disabled_at[1], "disabled"
            else:
                file, line, key = t.file, t.line, "default"
            if revoked:
                key += "_revoked"
            yield Finding("SB-RLS-OFF", sev, "high", file, [line], ctx.t.msg("SB-RLS-OFF", key, table=name),
                          snippet=f"table {schema}.{name}")


def _policy_scan(ctx: "Context") -> list[Finding]:
    cached = getattr(ctx, "_policy_cache", None)
    if cached is not None:
        return cached
    out: list[Finding] = []
    for model in ctx.sql_models.values():
        by_table: dict[str, list[Policy]] = {}
        for (schema, table, _), p in model.policies.items():
            if schema in PUBLIC_SCHEMAS:
                by_table.setdefault(table, []).append(p)
        global_read: list[Policy] = []
        for table, pols in sorted(by_table.items()):
            owners = [q for q in pols if q.owner and q.permissive]
            for p in sorted(pols, key=lambda x: (x.file, x.line)):
                if not p.permissive or not (p.is_open or p.login_only):
                    continue
                anon_open = p.anon and p.is_open
                action = ACTIONS[p.cmd]
                overlap = [q for q in owners if _covers(p.cmd, q.cmd)]
                snip = f"policy {table} {p.name}"
                if overlap:
                    sev = "high" if anon_open or p.writes else "medium"
                    who = "anyone, without signing in," if anon_open else "any signed-in user"
                    out.append(Finding("SB-POLICY-OVERLAP", sev, "high", p.file, [p.line],
                                       ctx.t.msg("SB-POLICY-OVERLAP", "default", table=table, policy=p.name, cmd=p.cmd,
                                                 who=who, action=action, owner_policy=overlap[0].name),
                                       snippet=snip, extra={"table": table, "policy": p.name, "drop":
                                                            f'drop policy "{p.name}" on public.{table};'}))
                elif anon_open:
                    out.append(Finding("SB-POLICY-OPEN", "high" if p.writes else "medium", "high", p.file, [p.line],
                                       ctx.t.msg("SB-POLICY-OPEN", "anon_write" if p.writes else "anon_read", table=table,
                                                 policy=p.name, action=action), snippet=snip,
                                       extra={"table": table, "policy": p.name}))
                elif not p.writes and p.is_open:
                    global_read.append(p)
                else:
                    out.append(Finding("SB-POLICY-OPEN", "high" if p.writes else "medium", "medium", p.file, [p.line],
                                       ctx.t.msg("SB-POLICY-OPEN", "session_write" if p.writes else "session_read",
                                                 table=table, policy=p.name, action=action), snippet=snip,
                                       extra={"table": table, "policy": p.name}))
        if len(global_read) >= GLOBAL_READ_MIN:
            first = min(global_read, key=lambda x: (x.file, x.line))
            tables = sorted({p.table for p in global_read})
            out.append(Finding("SB-POLICY-OPEN", "medium", "medium", first.file, [first.line],
                               ctx.t.msg("SB-POLICY-OPEN", "global_read", count=len(tables), tables=", ".join(tables)),
                               snippet="global-read " + ",".join(tables), extra={"tables": tables}))
        else:
            for p in global_read:
                out.append(Finding("SB-POLICY-OPEN", "medium", "medium", p.file, [p.line],
                                   ctx.t.msg("SB-POLICY-OPEN", "session_read", table=p.table, policy=p.name,
                                             action="read"), snippet=f"policy {p.table} {p.name}",
                                   extra={"table": p.table, "policy": p.name}))
    ctx._policy_cache = out
    return out


def detect_policy_open(ctx: "Context") -> Iterable[Finding]:
    return [f for f in _policy_scan(ctx) if f.rule_id == "SB-POLICY-OPEN"]


def detect_policy_overlap(ctx: "Context") -> Iterable[Finding]:
    return [f for f in _policy_scan(ctx) if f.rule_id == "SB-POLICY-OVERLAP"]


def detect_rpc_definer(ctx: "Context") -> Iterable[Finding]:
    for model in ctx.sql_models.values():
        for (schema, name), d in sorted(model.definers.items()):
            if schema not in PUBLIC_SCHEMAS or d.trigger or d.auth:
                continue
            if name in model.revoked_fns or model.revoke_default_fns:
                continue
            yield Finding("SB-RPC-DEFINER", "medium", "medium", d.file, [d.line],
                          ctx.t.msg("SB-RPC-DEFINER", "default", function=name), snippet=f"definer {schema}.{name}")


def _config_buckets(text: str) -> dict[str, int]:
    out: dict[str, int] = {}
    try:
        data = tomllib.loads(text)
        public = {n for n, v in ((data.get("storage") or {}).get("buckets") or {}).items()
                  if isinstance(v, dict) and v.get("public") is True}
    except tomllib.TOMLDecodeError:
        return out
    cur = None
    for i, ln in enumerate(text.splitlines(), 1):
        m = re.match(r"\s*\[storage\.buckets\.\"?([\w-]+)\"?\]", ln)
        if m:
            cur = m.group(1)
        elif re.match(r"\s*\[", ln):
            cur = None
        elif cur in public and re.match(r"\s*public\s*=\s*true", ln):
            out[cur] = i
    return out


def detect_bucket_public(ctx: "Context") -> Iterable[Finding]:
    buckets: list[tuple[str, str, int]] = []
    for model in ctx.sql_models.values():
        buckets += [(b.id, b.file, b.line) for b in model.buckets.values() if b.public]
    for f, text in ctx.config_tomls:
        buckets += [(name, f.rel, line) for name, line in _config_buckets(text).items()]
    seen = set()
    for bid, file, line in buckets:
        if bid in seen:
            continue
        seen.add(bid)
        if USER_CONTENT.search(bid):
            yield Finding("SB-BUCKET-PUBLIC", "medium", "medium", file, [line],
                          ctx.t.msg("SB-BUCKET-PUBLIC", "user_content", bucket=bid), snippet=f"bucket {bid}")
        else:
            yield Finding("SB-BUCKET-PUBLIC", "low", "low", file, [line],
                          ctx.t.msg("SB-BUCKET-PUBLIC", "default", bucket=bid), snippet=f"bucket {bid}")


def detect_no_schema(ctx: "Context") -> Iterable[Finding]:
    if not _supabase(ctx):
        return
    if any(m.tables or m.policies for m in ctx.sql_models.values()):
        return
    anchor = None
    for f in ctx.repo_files():
        if f.name == "package.json":
            text = ctx.read(f) or ""
            for i, ln in enumerate(text.splitlines(), 1):
                if "@supabase/" in ln:
                    anchor = (f.rel, i)
                    break
        if anchor:
            break
    if not anchor and ctx.config_tomls:
        anchor = (ctx.config_tomls[0][0].rel, 1)
    if not anchor:
        anchor = (next((f.rel for f in ctx.repo_files() if f.name in ("requirements.txt", "pyproject.toml")), "."), 1)
    yield Finding("SB-NO-SCHEMA", "info", "high", anchor[0], [anchor[1]], ctx.t.msg("SB-NO-SCHEMA", "default"),
                  snippet="no-schema")
