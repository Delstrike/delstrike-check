"""Test helpers. Fake secrets are built at runtime so this repository never contains a key-shaped literal
(GitHub push protection and secret scanners would rightly flag it)."""
from __future__ import annotations

import base64
import json
import random
import string
import struct
from pathlib import Path

import pytest

from delstrike_check import Options, scan


def b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def fake_jwt(role: str, iss: str = "supabase") -> str:
    return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64({'iss': iss, 'role': role, 'iat': 1700000000})}." + \
        "".join(random.Random(role).choices(string.ascii_letters + string.digits, k=43))


def rand(n: int, seed: str = "x", alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(random.Random(seed).choices(alphabet, k=n))


def fake_key(kind: str) -> str:
    return {
        "openai": "sk-" + "proj-" + rand(64, "o", string.ascii_letters + string.digits + "_-"),
        "stripe": "sk" + "_live_" + rand(32, "s"),
        "anthropic": "sk-" + "ant-api03-" + rand(90, "a", string.ascii_letters + string.digits + "_-"),
        "aws": "AK" + "IA" + rand(16, "w", string.ascii_uppercase + string.digits),
        "github": "gh" + "p_" + rand(36, "g"),
        "sb_secret": "sb" + "_secret_" + rand(32, "b"),
    }[kind]


def write(root: Path, files: dict[str, str | bytes]) -> Path:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8")
    return root


def git_index(paths: list[str]) -> bytes:
    """A minimal git index v2 listing `paths` as tracked."""
    body = b""
    for p in sorted(paths):
        name = p.encode()
        entry = b"\x00" * 40 + b"\x11" * 20 + struct.pack(">H", min(len(name), 0xFFF)) + name
        entry += b"\x00" * (8 - (len(entry) % 8))
        body += entry
    return b"DIRC" + struct.pack(">II", 2, len(paths)) + body + b"\x00" * 20


SUPABASE_PKG = json.dumps({"name": "app", "dependencies": {"@supabase/supabase-js": "^2.45.0", "react": "^18.3.1"}},
                          indent=2)
FIREBASE_PKG = json.dumps({"name": "app", "dependencies": {"firebase": "^11.0.0", "next": "15.0.0"}}, indent=2)


@pytest.fixture
def project(tmp_path):
    def make(files: dict[str, str | bytes], supabase: bool = True, tracked: list[str] | None = None) -> Path:
        base = {"package.json": SUPABASE_PKG} if supabase else {}
        write(tmp_path, {**base, **files})
        if tracked is not None:
            (tmp_path / ".git").mkdir(exist_ok=True)
            (tmp_path / ".git" / "index").write_bytes(git_index(tracked))
        return tmp_path
    return make


def run(path: Path, **kw):
    kw.setdefault("include_all", True)
    return scan(path, Options(**kw))


def ids(report, rule: str | None = None):
    return [f for f in report.findings if rule is None or f.rule_id == rule]
