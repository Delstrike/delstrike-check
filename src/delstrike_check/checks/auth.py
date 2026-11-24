"""AUTH-CONFIG (alias FB-AUTH-ANON): anonymous sign-in on, or email confirmation off."""
from __future__ import annotations

import re
import tomllib
from typing import TYPE_CHECKING, Iterable

from ..model import Finding

if TYPE_CHECKING:
    from ..context import Context


def _line_of(text: str, section: str, key: str) -> int:
    cur = None
    for i, ln in enumerate(text.splitlines(), 1):
        m = re.match(r"\s*\[([\w.\"-]+)\]", ln)
        if m:
            cur = m.group(1).replace('"', "")
        elif cur == section and re.match(rf"\s*{re.escape(key)}\s*=", ln):
            return i
    return 1


def detect_auth_config(ctx: "Context") -> Iterable[Finding]:
    anon_used = None

    def uses_anon() -> bool:
        nonlocal anon_used
        if anon_used is None:
            anon_used = ctx.uses_anywhere("signInAnonymously")
        return anon_used

    for f, text in ctx.config_tomls:
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            continue
        auth = data.get("auth") or {}
        if auth.get("enable_anonymous_sign_ins") is True:
            used = uses_anon()
            yield Finding("AUTH-CONFIG", "info" if used else "low", "high", f.rel,
                          [_line_of(text, "auth", "enable_anonymous_sign_ins")],
                          ctx.t.msg("AUTH-CONFIG", "sb_anon_used" if used else "sb_anon"), snippet="sb anonymous")
        email = auth.get("email") or {}
        if email.get("enable_confirmations") is False and auth.get("enable_signup", True) is not False \
                and email.get("enable_signup", True) is not False:
            yield Finding("AUTH-CONFIG", "low", "medium", f.rel, [_line_of(text, "auth.email", "enable_confirmations")],
                          ctx.t.msg("AUTH-CONFIG", "sb_confirm_off"), snippet="sb confirmations")
    for f in ctx.repo_files():
        if f.name != "firebase.json":
            continue
        text = ctx.read(f) or ""
        m = re.search(r"\"anonymous\"\s*:\s*(?:true|\{[^}]*\"enabled\"\s*:\s*true)", text)
        if m:
            used = uses_anon()
            yield Finding("AUTH-CONFIG", "info" if used else "low", "high", f.rel, [text.count("\n", 0, m.start()) + 1],
                          ctx.t.msg("AUTH-CONFIG", "fb_anon_used" if used else "fb_anon"), snippet="fb anonymous")
