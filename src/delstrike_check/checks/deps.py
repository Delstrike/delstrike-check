"""DEPS-OSV (only with --deps): lockfiles → api.osv.dev. Sends ONLY package name, ecosystem and version."""
from __future__ import annotations

import json
import math
import re
import urllib.error
import urllib.request
from typing import TYPE_CHECKING, Callable, Iterable

from ..model import Finding

if TYPE_CHECKING:
    from ..context import Context

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
MAX_DETAILS = 300
TIMEOUT = 30
GHSA = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


# ---------------------------------------------------------------- lockfile parsers → (name, version, dev|None, line)

def _npm_lock(text: str):
    try:
        j = json.loads(text)
    except ValueError:
        return []
    out = []
    for k, v in (j.get("packages") or {}).items():          # lockfileVersion 2/3
        if k and isinstance(v, dict) and v.get("version") and not v.get("link"):
            out.append((v.get("name") or k.split("node_modules/")[-1], v["version"], bool(v.get("dev")), f'"{k}"'))
    if not out:                                               # lockfileVersion 1
        def walk(deps):
            for name, v in (deps or {}).items():
                if isinstance(v, dict) and v.get("version"):
                    out.append((name, v["version"], bool(v.get("dev")), f'"{name}"'))
                    walk(v.get("dependencies"))
        walk(j.get("dependencies"))
    return out


def _pnpm_lock(text: str):
    return [(m.group(1), m.group(2), None, m.group(0).strip()) for m in
            re.finditer(r"^\s{2}['\"]?/?((?:@[\w.-]+/)?[\w.-]+)[@/](\d[\w.+-]*)(?:\([^)]*\))*['\"]?:\s*$", text, re.M)]


def _yarn_lock(text: str):
    return [(m.group(1), m.group(2), None, m.group(0).split("\n")[0]) for m in
            re.finditer(r"^\"?((?:@[\w.-]+/)?[\w.-]+)@[^\n]*:\n(?:\s+[^\n]*\n)*?\s+version:?\s+\"?([\w.+-]+)\"?", text, re.M)]


def _requirements(text: str):
    return [(m.group(1), m.group(2), None, m.group(0).strip()) for m in
            re.finditer(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([\w.+!-]+)", text, re.M)]


def _poetry_lock(text: str):
    return [(n, v, None, f'name = "{n}"') for n, v in
            re.findall(r'\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', text)]


def _composer_lock(text: str):
    try:
        j = json.loads(text)
    except ValueError:
        return []
    return [(p["name"], str(p["version"]).lstrip("v"), k == "packages-dev", f'"name": "{p["name"]}"')
            for k in ("packages", "packages-dev") for p in j.get(k, []) if p.get("name") and p.get("version")]


PARSERS: dict[str, tuple[str, Callable]] = {
    "package-lock.json": ("npm", _npm_lock), "npm-shrinkwrap.json": ("npm", _npm_lock),
    "pnpm-lock.yaml": ("npm", _pnpm_lock), "yarn.lock": ("npm", _yarn_lock),
    "requirements.txt": ("PyPI", _requirements), "poetry.lock": ("PyPI", _poetry_lock),
    "composer.lock": ("Packagist", _composer_lock),
}


def collect(ctx: "Context") -> list[dict]:
    pkgs: dict[tuple, dict] = {}
    for f in ctx.repo_files():
        if f.name not in PARSERS:
            continue
        text = ctx.read(f) or ""
        eco, parse = PARSERS[f.name]
        for name, ver, dev, needle in parse(text):
            key = (eco, name, ver)
            if key in pkgs:
                if dev is False:
                    pkgs[key]["dev"] = False
                continue
            pos = text.find(needle)
            pkgs[key] = {"ecosystem": eco, "name": name, "version": ver, "dev": dev, "file": f.rel,
                         "line": text.count("\n", 0, pos) + 1 if pos >= 0 else 1}
    return list(pkgs.values())


# ---------------------------------------------------------------- severity

def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    """CVSS 3.x base score from a vector string (FIRST specification)."""
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        iss = 1 - (1 - cia[m["C"]]) * (1 - cia[m["I"]]) * (1 - cia[m["A"]])
    except (KeyError, ValueError):
        return None
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    expl = 8.22 * av * ac * pr * ui
    return _roundup(min(1.08 * (impact + expl), 10)) if changed else _roundup(min(impact + expl, 10))


def score_to_sev(score: float) -> str:
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "info"


def vuln_severity(v: dict) -> str:
    ds = (v.get("database_specific") or {}).get("severity")
    if isinstance(ds, str) and ds.upper() in GHSA:
        return GHSA[ds.upper()]
    for s in v.get("severity") or []:
        vec = s.get("score", "")
        if isinstance(vec, str) and vec.startswith("CVSS:3"):
            sc = cvss3_score(vec)
            if sc is not None:
                return score_to_sev(sc)
    return "medium"


def fixed_versions(v: dict, name: str) -> list[str]:
    out = []
    for aff in v.get("affected") or []:
        if (aff.get("package") or {}).get("name") != name:
            continue
        for r in aff.get("ranges") or []:
            out += [e["fixed"] for e in r.get("events") or [] if e.get("fixed")]
    return out


# ---------------------------------------------------------------- network (only here)

def _post(url: str, body: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": _ua()})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:     # noqa: S310 - fixed https URL
        return json.loads(r.read().decode("utf-8"))


def _get(url: str) -> dict | None:
    req = urllib.request.Request(url, headers={"User-Agent": _ua()})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:  # noqa: S310 - fixed https URL
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError:
        return None


def _ua() -> str:
    from .. import __version__
    return f"delstrike-check/{__version__}"


def query_osv(pkgs: list[dict], post=None, get=None) -> tuple[dict[int, list[str]], dict[str, dict]]:
    post, get = post or _post, get or _get
    hits: dict[int, list[str]] = {}
    for i in range(0, len(pkgs), 1000):
        chunk = pkgs[i:i + 1000]
        res = post(OSV_BATCH, {"queries": [{"package": {"name": p["name"], "ecosystem": p["ecosystem"]},
                                            "version": p["version"]} for p in chunk]})
        for j, r in enumerate(res.get("results", [])):
            ids = [v["id"] for v in (r.get("vulns") or [])]
            if ids:
                hits[i + j] = ids
    details: dict[str, dict] = {}
    for vid in sorted({v for ids in hits.values() for v in ids})[:MAX_DETAILS]:
        d = get(OSV_VULN + vid)
        if d:
            details[vid] = d
    return hits, details


def _vkey(s: str):
    return [int(x) if x.isdigit() else x for x in re.split(r"[.\-+]", s)]


def detect_deps(ctx: "Context") -> Iterable[Finding]:
    pkgs = collect(ctx)
    if not pkgs:
        ctx.warnings.append(ctx.t("ui.deps_none"))
        return []
    try:
        hits, details = query_osv(pkgs)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        ctx.warnings.append(ctx.t("ui.deps_error", error=type(e).__name__))
        return []
    ctx.deps_checked = len(pkgs)
    out, dev_hits = [], []
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    for idx, ids in sorted(hits.items()):
        p = pkgs[idx]
        vulns = [details[i] for i in ids if i in details]
        groups, seen = [], set()
        for v in vulns:
            if v["id"] in seen:
                continue
            alias = {v["id"], *v.get("aliases", [])}
            seen |= alias
            groups.append((sorted(alias, key=lambda x: (not x.startswith("CVE-"), not x.startswith("GHSA"), x))[0],
                           vuln_severity(v)))
        if not groups:
            groups = [(i, "medium") for i in ids]
        sev = max((s for _, s in groups), key=lambda s: rank[s])
        fixed = sorted({fv for v in vulns for fv in fixed_versions(v, p["name"])}, key=_vkey)
        gids = [g for g, _ in groups]
        if p["dev"]:
            dev_hits.append((p, sev, gids))
            continue
        out.append(Finding("DEPS-OSV", sev, "high", p["file"], [p["line"]],
                           ctx.t.msg("DEPS-OSV", "runtime_fixed" if fixed else "runtime", package=p["name"],
                                     version=p["version"], count=len(gids),
                                     ids=", ".join(gids[:4]) + ("…" if len(gids) > 4 else ""),
                                     fixed=fixed[-1] if fixed else ""),
                           snippet=f"{p['ecosystem']}:{p['name']}@{p['version']}",
                           extra={"package": p["name"], "version": p["version"], "ecosystem": p["ecosystem"],
                                  "advisories": gids, "fixed": fixed[-1] if fixed else None, "dev": False}))
    if dev_hits:
        names = ", ".join(f"{p['name']}@{p['version']}" for p, _, _ in dev_hits[:5]) + ("…" if len(dev_hits) > 5 else "")
        files = sorted({p["file"] for p, _, _ in dev_hits})
        out.append(Finding("DEPS-OSV", "low", "high", files[0], [1],
                           ctx.t.msg("DEPS-OSV", "dev_group", count=len(dev_hits), names=names),
                           snippet="dev " + ",".join(sorted(p["name"] for p, _, _ in dev_hits)),
                           extra={"dev": True, "packages": [f"{p['name']}@{p['version']}" for p, _, _ in dev_hits]}))
    return out
