"""File walk, exclusions, .gitignore and git index, stack detection, own lines of code and monorepo apps.

Only reads files. Never follows symlinks, never runs anything from the analyzed folder.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_EXCLUDE_DIRS = {
    "node_modules", "dist", ".next", "build", "vendor", "coverage",
    # tool and VCS folders: never source code
    ".git", ".hg", ".svn", ".venv", "venv", "__pycache__", ".turbo", ".vercel", ".netlify", ".output",
    ".svelte-kit", ".nuxt", ".expo", ".cache", ".parcel-cache", ".pytest_cache", ".mypy_cache", ".idea",
    ".firebase", "bower_components", "jspm_packages", ".yarn",
}
DEFAULT_EXCLUDE_GLOBS = ["*.min.js", "*.min.css", "*.map"]
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".bmp", ".tiff", ".psd", ".pdf", ".zip", ".gz", ".tgz",
    ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".class", ".exe", ".dll", ".so", ".dylib", ".o", ".a", ".wasm",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".avi", ".webm", ".wav", ".ogg", ".flac",
    ".sqlite", ".sqlite3", ".db", ".pyc", ".pyo", ".lockb", ".heic", ".glb", ".gltf", ".blend", ".fig", ".sketch",
}
CODE_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte", ".astro", ".py",
            ".sql", ".rules", ".dart", ".go", ".rb", ".php", ".java", ".kt", ".swift", ".rs", ".cs"}
# Code the user does not write: generated UI components, generated types and declarations
GENERATED = re.compile(r"(^|/)components/ui/[^/]+\.[jt]sx?$|(^|/)integrations/supabase/types\.ts$"
                       r"|(^|/)(?:database|supabase)\.types\.ts$|\.generated\.\w+$|\.gen\.\w+$|\.d\.ts$|(^|/)__generated__/",
                       re.I)
DATA_DIR = re.compile(r"(^|/)(?:data|fixtures?|mocks?|__mocks__|seeds?|samples?|sample-data)/", re.I)
CODE_KW = re.compile(r"\b(?:function|return|import|export|if\s*\(|for\s*\(|=>|await|class\s+\w+)")
TEST_PATH = re.compile(r"(^|/)(?:tests?|__tests__|spec|specs|e2e|cypress|playwright|fixtures?|__fixtures__|mocks?|__mocks__)/"
                       r"|\.(?:test|spec)\.[\w]+$|(^|/)test_[^/]+\.py$|_test\.(?:py|go)$", re.I)
EXAMPLE_PATH = re.compile(r"\.(?:example|sample|template|dist|defaults)(?:\.[\w]+)?$|(^|/)examples?/", re.I)
ENV_FILE = re.compile(r"(^|/)\.env(\.[\w.-]+)?$")
ENV_SAFE = re.compile(r"\.env\.(?:example|sample|template|dist|defaults)$", re.I)

NPM_STACK = {
    "next": "Next.js", "react": "React", "vite": "Vite", "vue": "Vue", "nuxt": "Nuxt", "svelte": "Svelte",
    "@sveltejs/kit": "SvelteKit", "astro": "Astro", "@remix-run/react": "Remix", "@tanstack/react-start": "TanStack Start",
    "expo": "Expo", "react-native": "React Native", "@angular/core": "Angular",
    "@supabase/supabase-js": "Supabase", "@supabase/ssr": "Supabase", "@supabase/auth-helpers-nextjs": "Supabase",
    "firebase": "Firebase", "firebase-admin": "Firebase", "firebase-functions": "Firebase",
    "openai": "OpenAI", "@anthropic-ai/sdk": "Anthropic", "@google/generative-ai": "Gemini", "@google/genai": "Gemini",
    "ai": "Vercel AI SDK", "express": "Express", "hono": "Hono", "fastify": "Fastify",
}
PY_STACK = {"supabase": "Supabase", "firebase-admin": "Firebase", "fastapi": "FastAPI", "flask": "Flask",
            "django": "Django", "openai": "OpenAI", "anthropic": "Anthropic"}
STACK_ORDER = ["Supabase", "Firebase", "Next.js", "React", "Vite", "Vue", "Nuxt", "Svelte", "SvelteKit", "Astro", "Remix",
               "TanStack Start", "Angular", "Expo", "React Native", "Express", "Hono", "Fastify", "FastAPI", "Flask",
               "Django", "OpenAI", "Anthropic", "Gemini", "Vercel AI SDK"]


# ---------------------------------------------------------------- .gitignore

def _glob_to_regex(pat: str) -> str:
    i, out = 0, []
    while i < len(pat):
        c = pat[i]
        if pat.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pat.startswith("/**", i) and i + 3 == len(pat):
            out.append("/.*")
            i += 3
        elif pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            j = pat.find("]", i + 1)
            if j < 0:
                out.append(re.escape(c))
                i += 1
            else:
                body = pat[i + 1:j].replace("\\", "\\\\")
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append(f"[{body}]")
                i = j + 1
        elif c == "\\" and i + 1 < len(pat):
            out.append(re.escape(pat[i + 1]))
            i += 2
        else:
            out.append(re.escape(c))
            i += 1
    return "".join(out)


@dataclass
class _IgnoreRule:
    base: str           # directory of the .gitignore, "" for the root
    regex: re.Pattern
    negate: bool
    dir_only: bool


class GitIgnore:
    """Reasonable .gitignore semantics: nested files, negation, anchoring, directory-only patterns, **."""

    def __init__(self) -> None:
        self.rules: list[_IgnoreRule] = []

    def add_file(self, base: str, text: str) -> None:
        for raw in text.splitlines():
            line = raw.rstrip()
            if not line or line.startswith("#"):
                continue
            negate = line.startswith("!")
            if negate:
                line = line[1:]
            if line.startswith("\\"):
                line = line[1:]
            dir_only = line.endswith("/")
            line = line.rstrip("/")
            if not line:
                continue
            anchored = "/" in line
            line = line.lstrip("/")
            rx = _glob_to_regex(line)
            rx = f"^{rx}$" if anchored else f"^(?:.*/)?{rx}$"
            try:
                self.rules.append(_IgnoreRule(base, re.compile(rx), negate, dir_only))
            except re.error:
                continue

    def _match(self, rel: str, is_dir: bool) -> bool | None:
        result = None
        for r in self.rules:
            if r.base and not rel.startswith(r.base + "/"):
                continue
            sub = rel[len(r.base) + 1:] if r.base else rel
            if r.dir_only and not is_dir:
                continue
            if r.regex.match(sub):
                result = not r.negate
        return result

    def ignored(self, rel: str, is_dir: bool = False) -> bool:
        parts = rel.split("/")
        for i in range(1, len(parts)):          # an ignored parent directory ignores everything below
            if self._match("/".join(parts[:i]), True):
                return True
        return bool(self._match(rel, is_dir))


# ---------------------------------------------------------------- git index (tracked files, no git binary)

def _varint(data: bytes, pos: int) -> tuple[int, int]:
    b = data[pos]
    pos += 1
    val = b & 0x7F
    while b & 0x80:
        b = data[pos]
        pos += 1
        val = ((val + 1) << 7) | (b & 0x7F)
    return val, pos


def read_git_index(index_path: Path) -> set[str] | None:
    """Paths tracked in a git index (versions 2, 3 and 4). None if it can't be read."""
    try:
        data = index_path.read_bytes()
    except OSError:
        return None
    if len(data) < 12 or data[:4] != b"DIRC":
        return None
    version, count = struct.unpack(">II", data[4:12])
    if version not in (2, 3, 4):
        return None
    pos, prev, paths = 12, b"", set()
    try:
        for _ in range(count):
            start = pos
            flags = struct.unpack(">H", data[pos + 60:pos + 62])[0]
            pos += 62
            if version >= 3 and flags & 0x4000:
                pos += 2
            if version == 4:
                strip, pos = _varint(data, pos)
                end = data.index(b"\x00", pos)
                name = prev[:len(prev) - strip] + data[pos:end]
                pos = end + 1
            else:
                end = data.index(b"\x00", pos)
                name = data[pos:end]
                pos = start + ((end - start + 8) // 8) * 8
            prev = name
            paths.add(name.decode("utf-8", errors="replace"))
    except (struct.error, ValueError, IndexError):
        return None
    return paths


def find_git(root: Path) -> tuple[Path, str] | None:
    """(.git directory, prefix of root inside the repository) for the closest repository above root."""
    cur = root.resolve()
    for parent in [cur, *cur.parents]:
        g = parent / ".git"
        if g.is_dir():
            prefix = cur.relative_to(parent).as_posix()
            return g, "" if prefix == "." else prefix
        if g.is_file():   # worktree or submodule: "gitdir: <path>"
            try:
                m = re.match(r"gitdir:\s*(.+)", g.read_text(encoding="utf-8", errors="replace").strip())
            except OSError:
                return None
            if m:
                gd = Path(m.group(1))
                gd = gd if gd.is_absolute() else (parent / gd)
                prefix = cur.relative_to(parent).as_posix()
                return gd, "" if prefix == "." else prefix
            return None
    return None


# ---------------------------------------------------------------- inventory

@dataclass
class FileEntry:
    rel: str
    path: Path
    size: int
    ignored: bool            # git-ignored and not tracked: not part of the repository
    tracked: bool | None     # True/False from the git index, None when there is no readable index

    @property
    def name(self) -> str:
        return self.rel.rsplit("/", 1)[-1]

    @property
    def suffix(self) -> str:
        n = self.name
        return n[n.rfind("."):].lower() if "." in n[1:] else ""

    @property
    def in_repo(self) -> bool:
        return self.tracked if self.tracked is not None else not self.ignored

    @property
    def is_test(self) -> bool:
        return bool(TEST_PATH.search(self.rel))


@dataclass
class Inventory:
    root: Path
    files: list[FileEntry] = field(default_factory=list)
    stack: list[str] = field(default_factory=list)
    apps: list[str] = field(default_factory=list)
    supabase_roots: list[str] = field(default_factory=list)
    loc_own: int = 0
    skipped_large: list[str] = field(default_factory=list)
    git: bool = False
    git_index: bool = False

    def has(self, tech: str) -> bool:
        return tech in self.stack


def _excluded(rel: str, globs: list[str]) -> bool:
    name = rel.rsplit("/", 1)[-1]
    for g in globs:
        g2 = g.rstrip("/")
        if fnmatch.fnmatch(rel, g2) or fnmatch.fnmatch(rel, g2 + "/*") or ("/" not in g2 and fnmatch.fnmatch(name, g2)):
            return True
        if g2.endswith("/**") and (rel == g2[:-3] or rel.startswith(g2[:-3] + "/")):
            return True
    return False


def read_text(path: Path, max_bytes: int) -> str | None:
    try:
        if path.stat().st_size > max_bytes:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def is_minified(rel: str, text: str) -> bool:
    if re.search(r"\.min\.(?:js|css)$", rel):
        return True
    lines = text.count("\n") + 1
    return len(text) > 5000 and len(text) / lines > 400


def loc_kind(rel: str, text: str) -> str:
    if GENERATED.search(rel):
        return "generated"
    if rel.lower().endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")):
        lines = [ln for ln in text.splitlines() if ln.strip()]
        if lines:
            ratio = sum(1 for ln in lines if CODE_KW.search(ln)) / len(lines)
            if (DATA_DIR.search(rel) and len(text) > 20_000 and ratio < 0.05) or (len(text) > 150_000 and ratio < 0.02):
                return "data"
    return "own"


def walk(root: Path, extra_excludes: list[str], max_bytes: int) -> Inventory:
    inv = Inventory(root=root)
    gi = GitIgnore()
    tracked: set[str] | None = None
    tracked_dirs: set[str] = set()
    git = find_git(root)
    if git:
        inv.git = True
        idx = read_git_index(git[0] / "index")
        if idx is not None:
            inv.git_index = True
            prefix = git[1]
            if prefix:
                idx = {p[len(prefix) + 1:] for p in idx if p.startswith(prefix + "/")}
            tracked = idx
            for p in idx:
                parts = p.split("/")
                for i in range(1, len(parts)):
                    tracked_dirs.add("/".join(parts[:i]))
    globs = DEFAULT_EXCLUDE_GLOBS + list(extra_excludes)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        if ".gitignore" in filenames:
            try:
                gi.add_file(rel_dir, (Path(dirpath) / ".gitignore").read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass
        keep = []
        for d in sorted(dirnames):
            rel = f"{rel_dir}/{d}" if rel_dir else d
            if d in DEFAULT_EXCLUDE_DIRS or _excluded(rel, globs) or (Path(dirpath) / d).is_symlink():
                continue
            if gi.ignored(rel, True) and rel not in tracked_dirs:
                continue
            keep.append(d)
        dirnames[:] = keep
        for name in sorted(filenames):
            rel = f"{rel_dir}/{name}" if rel_dir else name
            p = Path(dirpath) / name
            if _excluded(rel, globs) or p.is_symlink():
                continue
            suf = name[name.rfind("."):].lower() if "." in name[1:] else ""
            if suf in BINARY_EXT:
                continue
            try:
                size = p.stat().st_size
            except OSError:
                continue
            is_tracked = (rel in tracked) if tracked is not None else None
            ignored = False if is_tracked else gi.ignored(rel)
            inv.files.append(FileEntry(rel, p, size, ignored, is_tracked))
    return inv


def _req_name(spec: str) -> str:
    m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", spec)
    return m.group(1).lower().replace("_", "-") if m else ""


def _py_deps(name: str, text: str) -> set[str]:
    """Declared dependency names only (not keywords or descriptions)."""
    if name == "requirements.txt":
        return {_req_name(ln) for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith(("#", "-"))}
    import tomllib
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return set()
    proj = data.get("project") or {}
    specs = list(proj.get("dependencies") or [])
    for group in (proj.get("optional-dependencies") or {}).values():
        specs += list(group or [])
    for group in (data.get("dependency-groups") or {}).values():
        specs += [s for s in group or [] if isinstance(s, str)]
    poetry = ((data.get("tool") or {}).get("poetry") or {})
    names = {_req_name(s) for s in specs if isinstance(s, str)}
    names |= {k.lower() for k in (poetry.get("dependencies") or {})}
    return names - {""}


def detect_stack(inv: Inventory, read) -> None:
    """read(entry) -> text | None. Fills stack, apps and supabase_roots."""
    stack: set[str] = set()
    apps: set[str] = set()
    sb_roots: set[str] = set()
    for f in inv.files:
        if f.ignored:
            continue
        parts = f.rel.split("/")
        if "supabase" in parts[:-1]:
            i = parts.index("supabase")
            if i + 1 < len(parts) and (parts[i + 1] in ("migrations", "functions", "config.toml", "schemas")
                                       or f.suffix == ".sql"):
                sb_roots.add("/".join(parts[:i]))
                stack.add("Supabase")
        if f.name in ("firebase.json", "firestore.rules", "database.rules.json", "storage.rules"):
            stack.add("Firebase")
        if f.name == "package.json":
            text = read(f)
            try:
                j = json.loads(text or "{}")
            except ValueError:
                continue
            deps = {**(j.get("dependencies") or {}), **(j.get("devDependencies") or {})}
            for dep in deps:
                if dep in NPM_STACK:
                    stack.add(NPM_STACK[dep])
            app_dir = f.rel.rsplit("/", 1)[0] if "/" in f.rel else ""
            if app_dir and re.match(r"^(?:apps|packages|services)/[^/]+$", app_dir) and not f.is_test:
                apps.add(app_dir)
        elif f.name in ("requirements.txt", "pyproject.toml"):
            for dep in _py_deps(f.name, read(f) or ""):
                if dep in PY_STACK:
                    stack.add(PY_STACK[dep])
    inv.stack = [s for s in STACK_ORDER if s in stack]
    inv.apps = sorted(apps)
    inv.supabase_roots = sorted(sb_roots)


def count_loc(inv: Inventory, read) -> None:
    total = 0
    for f in inv.files:
        if f.ignored or f.suffix not in CODE_EXT or f.is_test:
            continue
        text = read(f)
        if not text or is_minified(f.rel, text):
            continue
        if loc_kind(f.rel, text) != "own":
            continue
        total += sum(1 for ln in text.splitlines() if ln.strip())
    inv.loc_own = total
