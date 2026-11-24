"""Messages, rule titles, explanations and fixes. English only in 0.1; add `<lang>.json` to translate."""
from __future__ import annotations

import json
import locale
import os
from functools import lru_cache
from importlib import resources

AVAILABLE = ("en",)
DEFAULT = "en"


@lru_cache(maxsize=None)
def _load(lang: str) -> dict:
    return json.loads(resources.files(__package__).joinpath(f"{lang}.json").read_text(encoding="utf-8"))


def system_lang() -> str:
    for var in ("DELSTRIKE_LANG", "LC_ALL", "LC_MESSAGES", "LANG"):
        v = os.environ.get(var)
        if v:
            code = v.split(".")[0].split("_")[0].lower()
            return code if code in AVAILABLE else DEFAULT
    try:
        code = (locale.getlocale()[0] or "").split("_")[0].lower()
    except ValueError:
        code = ""
    return code if code in AVAILABLE else DEFAULT


class Translator:
    def __init__(self, lang: str = DEFAULT) -> None:
        self.lang = lang if lang in AVAILABLE else DEFAULT
        self.data = _load(self.lang)
        self.fallback = _load(DEFAULT)

    def _get(self, data: dict, key: str):
        cur = data
        for part in key.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return None
            cur = cur[part]
        return cur

    def raw(self, key: str):
        v = self._get(self.data, key)
        return v if v is not None else self._get(self.fallback, key)

    def __call__(self, key: str, **kw) -> str:
        v = self.raw(key)
        if not isinstance(v, str):
            return key
        try:
            return v.format(**kw) if kw else v
        except (KeyError, IndexError, ValueError):
            return v

    def rule(self, rule_id: str, field: str, **kw):
        return self(f"rules.{rule_id}.{field}", **kw) if field != "code" else self.raw(f"rules.{rule_id}.code")

    def msg(self, rule_id: str, key: str, **kw) -> str:
        return self(f"rules.{rule_id}.messages.{key}", **kw)
