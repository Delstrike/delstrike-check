"""Shared, read-once state for one scan. Each file is read at most once and shared by every rule."""
from __future__ import annotations

import re
from functools import cached_property
from typing import TYPE_CHECKING, Iterable

from . import sql as sqlmod
from .i18n import Translator
from .inventory import ENV_FILE, ENV_SAFE, FileEntry, Inventory, is_minified, read_text

if TYPE_CHECKING:
    from .scan import Options

SERVER_FN = re.compile(
    r"(?:^|/)supabase/functions/(?!_)[\w-]+/(?:[^/]+/)*[^/]+\.(?:t|j)sx?$"
    r"|(?:^|/)(?:src/)?pages/api/.+\.(?:t|j)sx?$"
    r"|(?:^|/)(?:src/)?app/(?:.*/)?route\.(?:t|j)sx?$"
    r"|(?:^|/)netlify/(?:edge-)?functions/.+\.(?:t|j)sx?$"
    r"|(?:^|/)api/[^/]+\.(?:t|j)sx?$"
    r"|(?:^|/)functions/src/.+\.(?:t|j)sx?$")
EDGE_FN = re.compile(r"(?:^|/)supabase/functions/(?!_)([\w-]+)/")


class Context:
    def __init__(self, inventory: Inventory, options: "Options", t: Translator) -> None:
        self.inv = inventory
        self.options = options
        self.t = t
        self.warnings: list[str] = []
        self._text: dict[str, str | None] = {}
        self.by_rel = {f.rel: f for f in inventory.files}

    # ------------------------------------------------------------ files
    def read(self, f: FileEntry) -> str | None:
        if f.rel not in self._text:
            text = read_text(f.path, self.options.max_file_size)
            if text is None and f.size > self.options.max_file_size:
                self.inv.skipped_large.append(f.rel)
            self._text[f.rel] = text
        return self._text[f.rel]

    def repo_files(self) -> Iterable[FileEntry]:
        """Files that are part of the repository (tracked, or not git-ignored)."""
        return (f for f in self.inv.files if not f.ignored)

    def text_of(self, rel: str) -> str | None:
        f = self.by_rel.get(rel)
        return self.read(f) if f else None

    def is_env(self, f: FileEntry) -> bool:
        return bool(ENV_FILE.search(f.rel)) and not ENV_SAFE.search(f.rel)

    def env_files(self) -> list[FileEntry]:
        """Every .env file present, including git-ignored ones (only public-prefixed variables matter there)."""
        return [f for f in self.inv.files if self.is_env(f)]

    def uses_anywhere(self, needle: str, exts: tuple[str, ...] = (".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".mjs",
                                                                   ".dart", ".kt", ".swift")) -> bool:
        return any(needle in (self.read(f) or "") for f in self.repo_files() if f.suffix in exts)

    # ------------------------------------------------------------ Supabase SQL, one model per Supabase project
    @cached_property
    def sql_models(self) -> dict[str, sqlmod.SqlModel]:
        groups: dict[str, list[tuple[str, str]]] = {}
        for f in self.repo_files():
            if f.suffix != ".sql" or f.is_test:
                continue
            text = self.read(f)
            if not text:
                continue
            parts = f.rel.split("/")
            root = "/".join(parts[:parts.index("supabase")]) if "supabase" in parts[:-1] else ""
            groups.setdefault(root, []).append((f.rel, text))
        return {root: sqlmod.analyze(files) for root, files in groups.items()}

    # ------------------------------------------------------------ server functions
    @cached_property
    def server_functions(self) -> list[tuple[FileEntry, str]]:
        out = []
        for f in self.repo_files():
            if f.is_test or not SERVER_FN.search(f.rel):
                continue
            text = self.read(f)
            if text and not is_minified(f.rel, text):
                out.append((f, text))
        return out

    @cached_property
    def config_tomls(self) -> list[tuple[FileEntry, str]]:
        out = []
        for f in self.repo_files():
            if re.search(r"(?:^|/)supabase/config\.toml$", f.rel):
                text = self.read(f)
                if text:
                    out.append((f, text))
        return out

    @cached_property
    def middleware_auth(self) -> bool:
        """A Next.js middleware that checks the session protects API routes it matches."""
        from .checks.server_fn import CALLER_AUTH
        for f in self.repo_files():
            if re.fullmatch(r"(?:src/)?(?:middleware|proxy)\.(?:t|j)s", f.rel):
                text = self.read(f) or ""
                if CALLER_AUTH.search(text) or re.search(r"\bclerkMiddleware\b|\bwithAuth\b|\bauthMiddleware\b|"
                                                         r"\bupdateSession\s*\(|getToken\s*\(", text):
                    return True
        return False
