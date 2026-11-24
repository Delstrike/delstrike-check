"""Secrets: SB-SERVICE-ROLE-KEY, SECRET-KNOWN and ENV-COMMITTED. Values are never printed."""
from __future__ import annotations

import base64
import json
import re
from typing import TYPE_CHECKING, Iterable

from ..inventory import EXAMPLE_PATH
from ..model import Finding
from ..redact import redact, redact_env_line

if TYPE_CHECKING:
    from ..context import Context
    from ..inventory import FileEntry

JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.(eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{8,}")
SB_SECRET = re.compile(r"\bsb_secret_[A-Za-z0-9_-]{20,}")
PUBLIC_PREFIX = r"(?:NEXT_PUBLIC|VITE|EXPO_PUBLIC|PUBLIC|REACT_APP|NUXT_PUBLIC|GATSBY|VUE_APP)_"
PUBLIC_SERVICE_NAME = re.compile(rf"\b{PUBLIC_PREFIX}[A-Z0-9_]*(?:SERVICE_ROLE|SUPABASE_SECRET|SB_SECRET)[A-Z0-9_]*\b")
TEXT_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte", ".astro", ".json", ".toml",
            ".yml", ".yaml", ".html", ".py", ".sql", ".md", ".mdx", ".txt", ".sh", ".env", ".ini", ".cfg", ".conf", ".xml",
            ".properties", ".dart", ".kt", ".swift", ".java", ".go", ".rb", ".php", ".cs", ".ipynb", ".tf", ".tfvars"}
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "poetry.lock", "composer.lock",
             "Cargo.lock", "go.sum", "Pipfile.lock", "uv.lock", "deno.lock"}
KNOWN = [
    ("OpenAI", re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}")),
    ("OpenAI", re.compile(r"\bsk-[A-Za-z0-9]{48}\b")),
    ("Anthropic", re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{60,}")),
    ("Stripe", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{24,}")),
    ("AWS", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b")),
    ("GitHub", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{70,}")),
    ("Slack", re.compile(r"\bxox[bp]-[0-9A-Za-z-]{20,}")),
]
PLACEHOLDER = re.compile(r"x{4,}|X{4,}|\*{3,}|your|example|dummy|fake|placeholder|sample|changeme|redacted|<|>|\.\.\.|"
                         r"0{8,}|1234567890|abcdef(?:ghij)?|EXAMPLE", re.I)
ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[=:]\s*(.*?)\s*$")
SECRET_NAME = re.compile(r"SECRET|PRIVATE|PASSWORD|PASSWD|PWD|SERVICE_ROLE|TOKEN|API_?KEY|ACCESS_KEY|CLIENT_SECRET|"
                         r"DATABASE_URL|DB_URL|POSTGRES_URL|MONGO(?:DB)?_URI|REDIS_URL|CONNECTION_STRING|WEBHOOK|SIGNING|"
                         r"CREDENTIALS|AUTH_KEY|_KEY$", re.I)
PUBLISHABLE_NAME = re.compile(r"ANON_KEY|PUBLISHABLE|PUBLIC_KEY|_URL$|_ID$|_DOMAIN$|_HOST$|_PORT$|_REGION$|_BUCKET$|"
                              r"MEASUREMENT_ID|PROJECT_ID|SENDER_ID|APP_ID", re.I)
URL_CREDS = re.compile(r"://[^/\s:@]+:[^@\s/]{3,}@")


def jwt_role(token_payload: str) -> tuple[str | None, str | None]:
    try:
        data = json.loads(base64.urlsafe_b64decode(token_payload + "=" * (-len(token_payload) % 4)))
    except (ValueError, UnicodeDecodeError):
        return None, None
    if not isinstance(data, dict):
        return None, None
    return data.get("role"), data.get("iss")


def is_service_value(value: str) -> bool:
    if SB_SECRET.search(value):
        return True
    for m in JWT.finditer(value):
        role, iss = jwt_role(m.group(1))
        if role == "service_role" and iss != "supabase-demo":
            return True
    return False


def known_secret(value: str) -> str | None:
    for provider, rx in KNOWN:
        for m in rx.finditer(value):
            tok = m.group(0)
            if PLACEHOLDER.search(tok) or len(set(tok)) < 10:
                continue
            return provider
    return None


def _strip(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"`":
        v = v[1:-1]
    return re.sub(r"\s+#.*$", "", v).strip()


def env_entries(text: str) -> list[tuple[int, str, str]]:
    out = []
    for i, ln in enumerate(text.splitlines(), 1):
        if ln.lstrip().startswith("#"):
            continue
        m = ENV_LINE.match(ln)
        if m:
            out.append((i, m.group(1), _strip(m.group(2))))
    return out


def is_public_name(name: str) -> bool:
    return bool(re.match(PUBLIC_PREFIX, name))


def classify(name: str, value: str) -> str | None:
    """'secret', 'publishable' or None (empty or placeholder)."""
    if not value or PLACEHOLDER.search(value) or value.lower() in ("true", "false", "null", "none", "0", "1"):
        return None
    if is_service_value(value) or known_secret(value) or URL_CREDS.search(value):
        return "secret"
    if is_public_name(name) or PUBLISHABLE_NAME.search(name):
        return "publishable"
    if value.startswith(("AIza", "pk_live_", "pk_test_", "sb_publishable_")):
        return "publishable"
    if JWT.search(value):
        role, _ = jwt_role(JWT.search(value).group(1))
        if role == "anon":
            return "publishable"
    if SECRET_NAME.search(name) and len(value) >= 8:
        return "secret"
    return "publishable"


def _text_files(ctx: "Context") -> Iterable[tuple["FileEntry", str]]:
    for f in ctx.repo_files():
        if ctx.is_env(f) or f.name in LOCKFILES:
            continue
        if f.suffix not in TEXT_EXT and not f.name.startswith("."):
            continue
        text = ctx.read(f)
        if text:
            yield f, text


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _line_text(text: str, line: int) -> str:
    lines = text.splitlines()
    return lines[line - 1] if 0 < line <= len(lines) else ""


def detect_service_role(ctx: "Context") -> Iterable[Finding]:
    seen: set[tuple[str, int]] = set()

    def emit(f, line, key, text, conf="high", env=False):
        if (f.rel, line) in seen:
            return None
        seen.add((f.rel, line))
        lt = _line_text(text, line)
        return Finding("SB-SERVICE-ROLE-KEY", "critical", conf, f.rel, [line], ctx.t.msg("SB-SERVICE-ROLE-KEY", key),
                       snippet=redact_env_line(lt) if env else redact(lt))

    for f, text in _text_files(ctx):
        conf = "medium" if f.is_test or EXAMPLE_PATH.search(f.rel) else "high"
        if "eyJ" in text or "sb_secret_" in text:
            for rx in (JWT, SB_SECRET):
                for m in rx.finditer(text):
                    if rx is JWT:
                        role, iss = jwt_role(m.group(1))
                        if role != "service_role" or iss == "supabase-demo":
                            continue
                    fnd = emit(f, _line(text, m.start()), "in_code", text, conf)
                    if fnd:
                        yield fnd
        if f.suffix in (".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".astro", ".mjs"):
            for m in PUBLIC_SERVICE_NAME.finditer(text):
                fnd = emit(f, _line(text, m.start()), "public_name", text, conf)
                if fnd:
                    yield fnd
    for f in ctx.env_files():
        text = ctx.read(f) or ""
        for line, name, value in env_entries(text):
            if is_public_name(name) and (PUBLIC_SERVICE_NAME.search(name) or is_service_value(value)):
                fnd = emit(f, line, "public_env", text, env=True)
            elif f.in_repo and is_service_value(value):
                fnd = emit(f, line, "committed_env", text, env=True)
            else:
                fnd = None
            if fnd:
                yield fnd


def detect_known(ctx: "Context") -> Iterable[Finding]:
    for f, text in _text_files(ctx):
        if f.is_test or EXAMPLE_PATH.search(f.rel):
            continue
        hits: dict[str, list[int]] = {}
        for provider, rx in KNOWN:
            for m in rx.finditer(text):
                tok = m.group(0)
                if PLACEHOLDER.search(tok) or len(set(tok)) < 10:
                    continue
                hits.setdefault(provider, []).append(_line(text, m.start()))
        for provider, lines in hits.items():
            lines = sorted(set(lines))
            yield Finding("SECRET-KNOWN", "critical", "high", f.rel, lines,
                          ctx.t.msg("SECRET-KNOWN", "default", provider=provider),
                          snippet=f"{provider} " + redact(_line_text(text, lines[0])))
    for f in ctx.env_files():
        if f.in_repo:
            continue                     # committed .env files are reported by ENV-COMMITTED
        text = ctx.read(f) or ""
        for line, name, value in env_entries(text):
            provider = known_secret(value)
            if provider and is_public_name(name):
                yield Finding("SECRET-KNOWN", "critical", "high", f.rel, [line],
                              ctx.t.msg("SECRET-KNOWN", "public_env", provider=provider, name=name),
                              snippet=f"{provider} {name}")


def detect_env_committed(ctx: "Context") -> Iterable[Finding]:
    for f in ctx.env_files():
        if not f.in_repo:
            continue
        text = ctx.read(f) or ""
        secret, public = [], []
        for line, name, value in env_entries(text):
            kind = classify(name, value)
            if kind == "secret":
                secret.append((line, name))
            elif kind == "publishable":
                public.append((line, name))
        how = "tracked" if f.tracked else "not_ignored"
        if secret:
            names = ", ".join(n for _, n in secret[:6]) + ("…" if len(secret) > 6 else "")
            yield Finding("ENV-COMMITTED", "critical", "high", f.rel, [ln for ln, _ in secret],
                          ctx.t.msg("ENV-COMMITTED", f"secret_{how}", count=len(secret), names=names),
                          snippet="env secret " + ",".join(sorted(n for _, n in secret)))
        elif public:
            yield Finding("ENV-COMMITTED", "info", "high", f.rel, [public[0][0]],
                          ctx.t.msg("ENV-COMMITTED", f"public_{how}", count=len(public)),
                          snippet="env public " + ",".join(sorted(n for _, n in public)))
