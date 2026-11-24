"""Server functions (Supabase edge functions, Next.js API routes, Netlify/Vercel/Firebase functions).

SB-EDGE-NOAUTH, SB-EDGE-JWT-OFF and AI-PROXY-OPEN.
"""
from __future__ import annotations

import re
import tomllib
from functools import lru_cache
from typing import TYPE_CHECKING, Iterable

from ..context import EDGE_FN
from ..model import Finding

if TYPE_CHECKING:
    from ..context import Context
    from ..inventory import FileEntry

SERVICE_KEY_USE = re.compile(r"SERVICE_ROLE|sb_secret_|SUPABASE_SECRET_KEY|supabaseAdmin\b|createAdminClient\b|"
                             r"['\"]firebase-admin(?:/[\w-]+)?['\"]|admin\.firestore\(", re.I)
CALLER_AUTH = re.compile(
    r"auth\s*\.\s*getUser\s*\(|\bgetClaims\s*\(|verifyIdToken\s*\(|verifySessionCookie\s*\(|getServerSession\s*\(|"
    r"\bcurrentUser\s*\(|\bauth\s*\(\s*\)|getToken\s*\(|timingSafeEqual|jwtVerify\s*\(|jwt\.verify\s*\(|"
    r"role\s*(?:!==|===|!=|==)\s*['\"]service_role['\"]|['\"]service_role['\"]\s*(?:!==|===|!=|==)|"
    r"headers\.get\(\s*['\"][\w-]+['\"]\s*\)[^;\n]{0,80}(?:!==|===|!=|==)|(?:!==|===|!=|==)[^;\n]{0,80}headers\.get\(|"
    r"headers\[\s*['\"][\w-]+['\"]\s*\][^;\n]{0,80}(?:!==|===|!=|==)|"
    r"constructEvent(?:Async)?\s*\(|verifyWebhook|validateWebhook|requireSupabaseAuth|requireAuth\s*\(|requireUser\s*\(|"
    r"withAuth\s*\(|getAuth\s*\(\s*req|\bcontext\.auth\b|\brequest\.auth\b")
AI_CALL = re.compile(r"api\.openai\.com|new\s+OpenAI\s*\(|api\.anthropic\.com|new\s+Anthropic\s*\(|"
                     r"generativelanguage\.googleapis\.com|GoogleGenerativeAI\s*\(|new\s+GoogleGenAI\s*\(|api\.groq\.com|"
                     r"api\.mistral\.ai|openrouter\.ai/api|api\.deepseek\.com|api\.together\.xyz|api\.x\.ai|"
                     r"\b(?:streamText|generateText)\s*\(", re.I)
PROMPT_FROM_BODY = re.compile(
    r"\{[^}]*\b(?:prompt|messages|question|query|input|message|text|content)\b[^}]*\}\s*=\s*"
    r"(?:await\s+[\w.]+\.json\s*\(\s*\)|body\b|req\.body|request\.body|await\s+req\.json\s*\(\s*\))"
    r"|\b(?:body|req\.body|request\.body|data)\s*\.\s*(?:prompt|messages|question|input|message)\b", re.I | re.S)
RATE_LIMIT = re.compile(r"rate.?limit|ratelimit|\b429\b|quota|maxRequests|too many requests", re.I)
IMPORT = re.compile(r"import\s+(?:type\s+)?(?:(\{[^}]*\})|(\w+)|\*\s+as\s+(\w+))(?:\s*,\s*(\{[^}]*\}))?\s+from\s+['\"]([^'\"]+)['\"]")
EXTS = ("", ".ts", ".tsx", ".js", ".jsx", ".mjs", "/index.ts", "/index.js", "/index.tsx")


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _resolve(ctx: "Context", rel: str, spec: str) -> str | None:
    base = rel.rsplit("/", 1)[0] if "/" in rel else ""
    if spec.startswith("."):
        parts = (base.split("/") if base else []) + spec.split("/")
        stack: list[str] = []
        for p in parts:
            if p in ("", "."):
                continue
            if p == "..":
                if stack:
                    stack.pop()
            else:
                stack.append(p)
        cands = ["/".join(stack)]
    elif spec.startswith(("@/", "~/")):
        cands = [f"src/{spec[2:]}", spec[2:]]
    else:
        return None
    for c in cands:
        c = re.sub(r"\.(?:t|j)sx?$", "", c)
        for ext in EXTS:
            if c + ext in ctx.by_rel:
                return c + ext
    return None


def _segment(text: str, name: str) -> str:
    """Approximate source of an exported function/const `name` in a module."""
    m = re.search(rf"(?:function\s+{re.escape(name)}\b|(?:const|let|var)\s+{re.escape(name)}\s*=)", text)
    if not m:
        return ""
    nxt = re.search(r"\n(?:export\s+)?(?:async\s+)?(?:function|const|let|var|class)\s+\w+", text[m.end():])
    return text[m.start(): m.end() + (nxt.start() if nxt else len(text))]


def caller_checked(ctx: "Context", rel: str, text: str) -> bool:
    """The file, or a helper it imports one level deep (e.g. _shared/auth.ts), checks who is calling."""
    if CALLER_AUTH.search(text):
        return True
    for m in IMPORT.finditer(text):
        target = _resolve(ctx, rel, m.group(5))
        if not target:
            continue
        mod = ctx.text_of(target) or ""
        if not CALLER_AUTH.search(mod):
            continue
        names = []
        for grp in (m.group(1), m.group(4)):
            if grp:
                names += [n.split(" as ")[0].strip() for n in grp.strip("{} \n").split(",") if n.strip()]
        local = [n.split(" as ")[-1].strip() for grp in (m.group(1), m.group(4)) if grp
                 for n in grp.strip("{} \n").split(",") if n.strip()]
        if m.group(2) or m.group(3):          # default or namespace import: count the module if it's used
            alias = m.group(2) or m.group(3)
            if re.search(rf"\b{re.escape(alias)}\b\s*[.(]", text[m.end():]):
                return True
        for orig, alias in zip(names, local):
            seg = _segment(mod, orig) or ""
            if CALLER_AUTH.search(seg) and re.search(rf"\b{re.escape(alias)}\s*\(", text[m.end():]):
                return True
    return False


@lru_cache(maxsize=64)
def _jwt_off(text: str) -> dict[str, int]:
    """[functions.<name>] verify_jwt = false → {name: line}."""
    out: dict[str, int] = {}
    try:
        data = tomllib.loads(text)
        names = [n for n, v in (data.get("functions") or {}).items() if isinstance(v, dict) and v.get("verify_jwt") is False]
    except tomllib.TOMLDecodeError:
        names = None
    cur = None
    for i, ln in enumerate(text.splitlines(), 1):
        m = re.match(r"\s*\[functions\.\"?([\w-]+)\"?\]", ln)
        if m:
            cur = m.group(1)
            continue
        if re.match(r"\s*\[", ln):
            cur = None
        if cur and re.match(r"\s*verify_jwt\s*=\s*false\b", ln, re.I) and (names is None or cur in names):
            out[cur] = i
    return out


def _analysis(ctx: "Context") -> dict:
    cache = getattr(ctx, "_server_fn_cache", None)
    if cache is not None:
        return cache
    per_file = []
    edge_auth: dict[str, bool] = {}
    edge_noauth: set[str] = set()
    for f, text in ctx.server_functions:
        checked = caller_checked(ctx, f.rel, text)
        m = EDGE_FN.search(f.rel)
        if m:
            edge_auth[m.group(1)] = edge_auth.get(m.group(1), False) or checked
        per_file.append((f, text, checked))
    for f, text, checked in per_file:
        m = EDGE_FN.search(f.rel)
        if m and not checked and SERVICE_KEY_USE.search(text):
            edge_noauth.add(m.group(1))
    cache = {"files": per_file, "edge_auth": edge_auth, "edge_noauth": edge_noauth}
    ctx._server_fn_cache = cache
    return cache


def detect_noauth(ctx: "Context") -> Iterable[Finding]:
    for f, text, checked in _analysis(ctx)["files"]:
        if checked:
            continue
        svc = SERVICE_KEY_USE.search(text)
        if not svc:
            continue
        line = _line(text, svc.start())
        is_next = not EDGE_FN.search(f.rel)
        conf = "medium" if is_next and ctx.middleware_auth else "high"
        yield Finding("SB-EDGE-NOAUTH", "high", conf, f.rel, [line],
                      ctx.t.msg("SB-EDGE-NOAUTH", "middleware" if conf == "medium" else "default"),
                      snippet=text.splitlines()[line - 1] if text else "")


def detect_ai_proxy(ctx: "Context") -> Iterable[Finding]:
    for f, text, checked in _analysis(ctx)["files"]:
        if checked:
            continue
        ai = AI_CALL.search(text)
        if not ai or not PROMPT_FROM_BODY.search(text):
            continue
        line = _line(text, ai.start())
        key = "limited" if RATE_LIMIT.search(text) else "default"
        yield Finding("AI-PROXY-OPEN", "high", "high", f.rel, [line], ctx.t.msg("AI-PROXY-OPEN", key),
                      snippet=text.splitlines()[line - 1])


def detect_jwt_off(ctx: "Context") -> Iterable[Finding]:
    a = _analysis(ctx)
    for f, text in ctx.config_tomls:
        for name, line in _jwt_off(text).items():
            if a["edge_auth"].get(name):
                yield Finding("SB-EDGE-JWT-OFF", "info", "low", f.rel, [line],
                              ctx.t.msg("SB-EDGE-JWT-OFF", "self_checked", name=name), snippet=f"verify_jwt {name}")
            elif name in a["edge_noauth"]:
                yield Finding("SB-EDGE-JWT-OFF", "high", "high", f.rel, [line],
                              ctx.t.msg("SB-EDGE-JWT-OFF", "with_noauth", name=name), snippet=f"verify_jwt {name}")
            else:
                yield Finding("SB-EDGE-JWT-OFF", "medium", "high", f.rel, [line],
                              ctx.t.msg("SB-EDGE-JWT-OFF", "default", name=name), snippet=f"verify_jwt {name}")
