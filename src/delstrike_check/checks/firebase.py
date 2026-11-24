"""Firebase security rules (Firestore, Storage, Realtime Database): FB-RULES-OPEN."""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Iterable

from ..model import Finding

if TYPE_CHECKING:
    from ..context import Context

ALLOW = re.compile(r"\ballow\s+([a-z ,]+?)\s*(?::\s*if\b(.*?))?;", re.I | re.S)
SIGNED_IN = re.compile(r"request\s*\.\s*auth\s*(?:\.\s*uid\s*)?!=\s*null", re.I)
TEST_MODE = re.compile(r"request\s*\.\s*time\s*<\s*timestamp\s*\.\s*date\s*\(", re.I)
RTDB_RULE = re.compile(r"\"\.(read|write)\"\s*:\s*(true|\"[^\"]*\")", re.I)


def _blank_comments(text: str) -> str:
    keep = lambda m: re.sub(r"[^\n]", " ", m.group(0))   # noqa: E731
    text = re.sub(r"/\*.*?\*/", keep, text, flags=re.S)
    return re.sub(r"(?<![:\"'])//[^\n]*", keep, text)


def _norm(cond: str) -> str:
    c = re.sub(r"\s+", " ", cond).strip()
    while c.startswith("(") and c.endswith(")"):
        c = c[1:-1].strip()
    return c


def _rules_files(ctx: "Context"):
    for f in ctx.repo_files():
        if f.is_test:
            continue
        if f.name.endswith(".rules") or f.name == "database.rules.json" or re.search(r"(^|/)database\.rules\.json$", f.rel):
            yield f


def detect_rules_open(ctx: "Context") -> Iterable[Finding]:
    for f in _rules_files(ctx):
        raw = ctx.read(f) or ""
        if f.name.endswith(".json"):
            for m in RTDB_RULE.finditer(raw):
                val = m.group(2).strip('"').strip()
                line = raw.count("\n", 0, m.start()) + 1
                kind = m.group(1).lower()
                if val.lower() == "true":
                    yield Finding("FB-RULES-OPEN", "critical", "high", f.rel, [line],
                                  ctx.t.msg("FB-RULES-OPEN", "rtdb_true", op=kind), snippet=m.group(0))
                elif re.fullmatch(r"\(?\s*auth\s*!==?\s*null\s*\)?", val, re.I):
                    yield Finding("FB-RULES-OPEN", "high", "high", f.rel, [line],
                                  ctx.t.msg("FB-RULES-OPEN", "rtdb_signed_in", op=kind), snippet=m.group(0))
                elif re.search(r"\bnow\s*<\s*\d{10,}", val):
                    yield Finding("FB-RULES-OPEN", "critical", "high", f.rel, [line],
                                  ctx.t.msg("FB-RULES-OPEN", "test_mode"), snippet=m.group(0))
            continue
        text = _blank_comments(raw)
        if "allow" not in text:
            continue
        for m in ALLOW.finditer(text):
            ops = re.sub(r"\s+", "", m.group(1))
            cond = m.group(2)
            line = text.count("\n", 0, m.start()) + 1
            snip = re.sub(r"\s+", " ", m.group(0))
            if cond is None:
                yield Finding("FB-RULES-OPEN", "critical", "high", f.rel, [line],
                              ctx.t.msg("FB-RULES-OPEN", "always", ops=ops), snippet=snip)
                continue
            c = _norm(cond)
            if c.lower() == "true":
                yield Finding("FB-RULES-OPEN", "critical", "high", f.rel, [line],
                              ctx.t.msg("FB-RULES-OPEN", "true", ops=ops), snippet=snip)
            elif TEST_MODE.search(c) and "auth" not in c:
                yield Finding("FB-RULES-OPEN", "critical", "high", f.rel, [line],
                              ctx.t.msg("FB-RULES-OPEN", "test_mode"), snippet=snip)
            elif SIGNED_IN.fullmatch(c):
                yield Finding("FB-RULES-OPEN", "high", "high", f.rel, [line],
                              ctx.t.msg("FB-RULES-OPEN", "signed_in", ops=ops), snippet=snip)
