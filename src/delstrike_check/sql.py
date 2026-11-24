"""Static parser for Supabase / PostgreSQL migrations and schema dumps.

Rebuilds the FINAL state of tables, Row Level Security, policies, SECURITY DEFINER functions, grants and storage
buckets by applying the files in name order (Supabase migrations start with a timestamp). Comments are blanked
out keeping line numbers. Nothing is executed and nothing is sent anywhere.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

PUBLIC_SCHEMAS = {"public"}
NAME = r"(?:\"[^\"]+\"|[\w$]+)(?:\s*\.\s*(?:\"[^\"]+\"|[\w$]+))?"
NAMES = rf"{NAME}(?:\s*,\s*{NAME})*"
RE_CREATE_TABLE = re.compile(rf"\bcreate\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?({NAME})", re.I)
RE_DROP_TABLE = re.compile(rf"\bdrop\s+table\s+(?:if\s+exists\s+)?({NAMES})", re.I)
RE_RLS = re.compile(rf"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?({NAME})\s+(enable|disable|force|no\s+force)\s+row\s+level"
                    r"\s+security", re.I)
RE_POLICY = re.compile(r"\bcreate\s+policy\s+(\"[^\"]+\"|[\w$]+)\s+on\s+(?:table\s+)?(" + NAME + r")(.*?);", re.I | re.S)
RE_ALTER_POLICY = re.compile(r"\balter\s+policy\s+(\"[^\"]+\"|[\w$]+)\s+on\s+(?:table\s+)?(" + NAME + r")(.*?);", re.I | re.S)
RE_DROP_POLICY = re.compile(r"\bdrop\s+policy\s+(?:if\s+exists\s+)?(\"[^\"]+\"|[\w$]+)\s+on\s+(?:table\s+)?(" + NAME + r")",
                            re.I)
RE_FUNC = re.compile(rf"\bcreate\s+(?:or\s+replace\s+)?function\s+({NAME})\s*\(", re.I)
RE_REVOKE_FN = re.compile(rf"\brevoke\s+(?:all|execute)(?:\s+privileges)?\s+on\s+(?:function|routine)\s+({NAME})\s*(?:\([^)]*\))?"
                          r"\s+from\s+([^;]+);", re.I)
RE_REVOKE_DEFAULT_FN = re.compile(r"\balter\s+default\s+privileges\b[^;]*\brevoke\s+(?:all|execute)[^;]*\bon\s+functions\s+from"
                                  r"\s+[^;]*\b(?:public|anon)\b", re.I)
RE_REVOKE_TABLE = re.compile(rf"\brevoke\s+[\w\s,]+?\s+on\s+(?:table\s+)?(?!all\s+tables)({NAMES})\s+from\s+([^;]+);", re.I)
RE_REVOKE_ALL_TABLES = re.compile(r"\brevoke\s+[\w\s,]+?\s+on\s+all\s+tables\s+in\s+schema\s+public\s+from\s+[^;]*\banon\b"
                                  r"|\balter\s+default\s+privileges\b[^;]*\brevoke\s+[^;]*\bon\s+tables\s+from\s+[^;]*\banon\b",
                                  re.I)
RE_BUCKET_INSERT = re.compile(r"\binsert\s+into\s+storage\s*\.\s*buckets\s*\(([^)]*)\)\s*values\s*(.*?);", re.I | re.S)
RE_BUCKET_UPDATE = re.compile(r"\bupdate\s+storage\s*\.\s*buckets\s+set\s+([^;]*?)\bwhere\s+([^;]*);", re.I | re.S)
AUTH_IN_SQL = re.compile(r"\bauth\s*\.\s*(?:uid|jwt|role)\s*\(|current_setting\s*\(\s*'request\.jwt|\bauth\.users\b.*\bid\s*=",
                         re.I)
OWNER_COND = re.compile(r"\bauth\s*\.\s*(?:uid|jwt)\s*\(", re.I)
LOGIN_ONLY = re.compile(
    r"^\(*\s*(?:auth\s*\.\s*role\s*\(\s*\)\s*=\s*'authenticated'(?:::text)?"
    r"|\(?\s*(?:select\s+)?auth\s*\.\s*uid\s*\(\s*\)\s*\)?\s+is\s+not\s+null"
    r"|\(?\s*(?:select\s+)?auth\s*\.\s*role\s*\(\s*\)\s*\)?\s*=\s*'authenticated'(?:::text)?)\s*\)*$", re.I)
TRUE_COND = re.compile(r"\(*\s*true\s*\)*", re.I)


def blank_comments(sql: str) -> str:
    """Remove SQL comments but keep newlines, so line numbers stay valid. String literals are left alone."""
    out, i, n = [], 0, len(sql)
    while i < n:
        c = sql[i]
        if c == "'":
            j = i + 1
            while j < n:
                if sql[j] == "'" and j + 1 < n and sql[j + 1] == "'":
                    j += 2
                    continue
                if sql[j] == "'":
                    break
                j += 1
            out.append(sql[i:j + 1])
            i = j + 1
        elif sql.startswith("--", i):
            j = sql.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", sql[i:j]))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def tname(raw: str) -> tuple[str, str]:
    parts = [p.strip().strip('"').lower() for p in re.split(r"\s*\.\s*", raw.strip())]
    return ("public", parts[0]) if len(parts) == 1 else (parts[0], parts[1])


def split_names(raw: str) -> list[tuple[str, str]]:
    return [tname(m.group(0)) for m in re.finditer(NAME, raw)]


def line_at(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def clause(body: str, kw: str) -> str | None:
    """Content inside the parentheses after `using` / `with check`, honouring nested parentheses."""
    m = re.search(rf"\b{kw}\s*\(", body, re.I)
    if not m:
        return None
    depth, i = 1, m.end()
    while i < len(body) and depth:
        depth += {"(": 1, ")": -1}.get(body[i], 0)
        i += 1
    return body[m.end():i - 1].strip()


def _roles(body: str) -> set[str] | None:
    m = re.search(r"\bto\s+([\w\s,\"]+?)(?=\s+using\b|\s+with\b|\s*$)", body, re.I | re.S)
    if not m:
        return None
    return {r.strip().strip('"').lower() for r in m.group(1).split(",") if r.strip()}


@dataclass
class Table:
    schema: str
    name: str
    file: str
    line: int
    rls: bool = False
    disabled_at: tuple[str, int] | None = None
    revoked_anon: bool = False


@dataclass
class Policy:
    schema: str
    table: str
    name: str
    file: str
    line: int
    cmd: str = "all"
    roles: set[str] = field(default_factory=lambda: {"public"})
    using: str | None = None
    check: str | None = None
    permissive: bool = True

    def _conds(self) -> list[str]:
        return [c for c in (self.using, self.check) if c is not None]

    @property
    def is_open(self) -> bool:
        return any(TRUE_COND.fullmatch(c) for c in self._conds())

    @property
    def login_only(self) -> bool:
        return not self.is_open and any(LOGIN_ONLY.fullmatch(re.sub(r"\s+", " ", c)) for c in self._conds())

    @property
    def owner(self) -> bool:
        return not (self.is_open or self.login_only) and any(OWNER_COND.search(c) for c in self._conds())

    @property
    def anon(self) -> bool:
        return bool(self.roles & {"anon", "public"})

    @property
    def writes(self) -> bool:
        return self.cmd in ("all", "insert", "update", "delete")


@dataclass
class Definer:
    schema: str
    name: str
    file: str
    line: int
    trigger: bool
    auth: bool


@dataclass
class Bucket:
    id: str
    public: bool
    file: str
    line: int


@dataclass
class SqlModel:
    files: int = 0
    tables: dict[tuple[str, str], Table] = field(default_factory=dict)
    policies: dict[tuple[str, str, str], Policy] = field(default_factory=dict)
    definers: dict[tuple[str, str], Definer] = field(default_factory=dict)
    revoked_fns: set[str] = field(default_factory=set)
    revoke_default_fns: bool = False
    revoke_all_tables: bool = False
    buckets: dict[str, Bucket] = field(default_factory=dict)


def _function_parts(sql: str, start: int) -> tuple[str, str, int]:
    """(header + attributes without the body, body, end position) for a CREATE FUNCTION at `start`."""
    m = re.compile(r"\$([A-Za-z_]\w*)?\$").search(sql, start)
    semi = sql.find(";", start)
    if not m or (semi >= 0 and semi < m.start() and not re.search(r"\bas\s*$", sql[start:m.start()], re.I)):
        # SQL-standard body without dollar quoting (rare): header up to the first semicolon
        end = len(sql) if semi < 0 else semi
        return sql[start:end], "", end
    tag = m.group(0)
    close = sql.find(tag, m.end())
    if close < 0:
        return sql[start:m.start()], sql[m.end():], len(sql)
    end = sql.find(";", close)
    end = len(sql) if end < 0 else end
    return sql[start:m.start()] + " " + sql[close + len(tag):end], sql[m.end():close], end


def _sql_values(raw: str) -> list[str]:
    vals, cur, q = [], [], False
    for ch in raw:
        if ch == "'":
            q = not q
            cur.append(ch)
        elif ch == "," and not q:
            vals.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        vals.append("".join(cur).strip())
    return vals


def _unquote(v: str) -> str:
    v = v.strip()
    return v[1:-1].replace("''", "'") if len(v) >= 2 and v[0] == v[-1] == "'" else v


def _apply_policy_body(p: Policy, body: str, create: bool) -> None:
    if create:
        m = re.search(r"\bfor\s+(all|select|insert|update|delete)\b", body, re.I)
        p.cmd = m.group(1).lower() if m else "all"
        p.permissive = not re.search(r"\bas\s+restrictive\b", body, re.I)
    roles = _roles(body)
    if roles is not None:
        p.roles = roles
    using, check = clause(body, "using"), clause(body, r"with\s+check")
    if create or using is not None:
        p.using = using
    if create or check is not None:
        p.check = check


def analyze(files: list[tuple[str, str]]) -> SqlModel:
    """files: [(relative path, text)]. Applied in name order."""
    model = SqlModel(files=len(files))
    for rel, raw in sorted(files, key=lambda x: x[0]):
        sql = blank_comments(raw)
        events: list[tuple[int, str, re.Match]] = []
        for kind, rx in (("table", RE_CREATE_TABLE), ("drop_table", RE_DROP_TABLE), ("rls", RE_RLS), ("policy", RE_POLICY),
                         ("alter_policy", RE_ALTER_POLICY), ("drop_policy", RE_DROP_POLICY), ("func", RE_FUNC),
                         ("revoke_fn", RE_REVOKE_FN), ("revoke_table", RE_REVOKE_TABLE), ("bucket", RE_BUCKET_INSERT),
                         ("bucket_update", RE_BUCKET_UPDATE)):
            events.extend((m.start(), kind, m) for m in rx.finditer(sql))
        if RE_REVOKE_DEFAULT_FN.search(sql):
            model.revoke_default_fns = True
        if RE_REVOKE_ALL_TABLES.search(sql):
            model.revoke_all_tables = True
        for pos, kind, m in sorted(events, key=lambda e: e[0]):
            ln = line_at(sql, pos)
            if kind == "table":
                key = tname(m.group(1))
                model.tables.setdefault(key, Table(key[0], key[1], rel, ln))
            elif kind == "drop_table":
                for key in split_names(m.group(1)):
                    model.tables.pop(key, None)
                    for pk in [k for k in model.policies if k[:2] == key]:
                        model.policies.pop(pk)
            elif kind == "rls":
                key = tname(m.group(1))
                t = model.tables.setdefault(key, Table(key[0], key[1], rel, ln))
                action = m.group(2).lower()
                if action == "enable":
                    t.rls, t.disabled_at = True, None
                elif action == "disable":
                    t.rls, t.disabled_at = False, (rel, ln)
            elif kind == "policy":
                key = tname(m.group(2))
                name = m.group(1).strip('"')
                p = Policy(key[0], key[1], name, rel, ln)
                _apply_policy_body(p, m.group(3), create=True)
                model.policies[(*key, name.lower())] = p
            elif kind == "alter_policy":
                key = tname(m.group(2))
                name = m.group(1).strip('"').lower()
                p = model.policies.get((*key, name))
                if not p:
                    continue
                body = m.group(3)
                rn = re.match(r"\s*rename\s+to\s+(\"[^\"]+\"|[\w$]+)", body, re.I)
                if rn:
                    model.policies.pop((*key, name))
                    p.name = rn.group(1).strip('"')
                    model.policies[(*key, p.name.lower())] = p
                else:
                    _apply_policy_body(p, body, create=False)
                    p.file, p.line = rel, ln
            elif kind == "drop_policy":
                key = tname(m.group(2))
                model.policies.pop((*key, m.group(1).strip('"').lower()), None)
            elif kind == "func":
                head, body, _ = _function_parts(sql, m.start())
                if re.search(r"\bsecurity\s+definer\b", head, re.I):
                    key = tname(m.group(1))
                    model.definers[key] = Definer(key[0], key[1], rel, ln,
                                                  bool(re.search(r"\breturns\s+(?:event_)?trigger\b", head, re.I)),
                                                  bool(AUTH_IN_SQL.search(body)))
                else:
                    model.definers.pop(tname(m.group(1)), None)   # redefined without SECURITY DEFINER
            elif kind == "revoke_fn":
                if re.search(r"\b(?:public|anon)\b", m.group(2), re.I):
                    model.revoked_fns.add(tname(m.group(1))[1])
            elif kind == "revoke_table":
                if re.search(r"\banon\b", m.group(2), re.I):
                    for key in split_names(m.group(1)):
                        if key in model.tables:
                            model.tables[key].revoked_anon = True
            elif kind == "bucket":
                cols = [c.strip().strip('"').lower() for c in m.group(1).split(",")]
                for tup in re.finditer(r"\(((?:[^()']|'(?:[^']|'')*')*)\)", m.group(2)):
                    vals = _sql_values(tup.group(1))
                    row = dict(zip(cols, vals))
                    bid = _unquote(row.get("id") or row.get("name") or "")
                    if not bid:
                        continue
                    public = (row.get("public") or "").strip().lower() in ("true", "'true'", "'t'", "t")
                    model.buckets[bid] = Bucket(bid, public, rel, line_at(sql, m.start() + tup.start()))
            elif kind == "bucket_update":
                pm = re.search(r"\bpublic\s*=\s*(true|false)", m.group(1), re.I)
                im = re.search(r"\b(?:id|name)\s*=\s*'([^']+)'", m.group(2), re.I)
                if pm and im:
                    b = model.buckets.get(im.group(1))
                    public = pm.group(1).lower() == "true"
                    if b:
                        b.public = public
                        b.file, b.line = rel, ln
                    else:
                        model.buckets[im.group(1)] = Bucket(im.group(1), public, rel, ln)
    return model
