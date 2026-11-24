"""Inventory, suppressions, outputs, CLI, --deps (mocked: no network in tests) and robustness."""
from __future__ import annotations

import json
import time

import pytest

from conftest import fake_jwt, fake_key, git_index, ids, run, write
from delstrike_check import __main__ as cli
from delstrike_check import docs
from delstrike_check.checks import RULES, deps
from delstrike_check.inventory import GitIgnore, read_git_index
from delstrike_check.output import render

OPEN_SQL = "create table public.orders (id int);\n"


# ---------------------------------------------------------------- inventory

def test_gitignore_semantics():
    gi = GitIgnore()
    gi.add_file("", "node_modules/\n*.log\n/build\n.env*\n!.env.example\ndocs/**/*.tmp\n")
    gi.add_file("apps/web", "secret.txt\n")
    assert gi.ignored("debug.log") and gi.ignored("a/b/c.log")
    assert gi.ignored("build/x.js") and not gi.ignored("src/build.ts")
    assert gi.ignored(".env.local") and not gi.ignored(".env.example")
    assert gi.ignored("docs/a/b/x.tmp") and gi.ignored("apps/web/secret.txt") and not gi.ignored("secret.txt")


def test_git_index_v2_roundtrip(tmp_path):
    (tmp_path / "index").write_bytes(git_index(["a.txt", "src/deep/file.ts", ".env"]))
    assert read_git_index(tmp_path / "index") == {"a.txt", "src/deep/file.ts", ".env"}
    (tmp_path / "bad").write_bytes(b"nope")
    assert read_git_index(tmp_path / "bad") is None


def test_stack_monorepo_and_loc(project):
    root = project({
        "apps/web/package.json": json.dumps({"dependencies": {"next": "15.0.0", "@supabase/ssr": "1"}}),
        "apps/admin/package.json": json.dumps({"dependencies": {"vite": "6"}}),
        "apps/web/src/a.ts": "export const a = 1;\n\nexport const b = 2;\n",
        "src/components/ui/button.tsx": "export const Button = 1;\n" * 50,
        "node_modules/x/index.js": "module.exports = 1;\n" * 1000,
    })
    r = run(root)
    assert r.apps == ["apps/admin", "apps/web"]
    assert r.stack[:2] == ["Supabase", "Next.js"] and "Vite" in r.stack
    assert r.loc_own == 2


def test_monorepo_policies_are_per_supabase_project(project):
    root = project({
        "apps/a/supabase/migrations/1.sql": "create table t (id int);\nalter table t enable row level security;\n",
        "apps/b/supabase/migrations/1.sql": "create table t (id int);\n",
    })
    assert [f.file for f in ids(run(root), "SB-RLS-OFF")] == ["apps/b/supabase/migrations/1.sql"]


# ---------------------------------------------------------------- suppressions

def test_toml_suppression_with_reason(project):
    root = project({"supabase/migrations/1.sql": OPEN_SQL, ".delstrike.toml":
                    '[[ignore]]\nrule = "SB-RLS-OFF"\npath = "supabase/**"\nreason = "Read-only reference table"\n'})
    r = run(root)
    assert not ids(r, "SB-RLS-OFF")
    assert r.suppressed[0]["reason"] == "Read-only reference table"


def test_suppression_without_reason_is_not_applied(project):
    root = project({"supabase/migrations/1.sql": OPEN_SQL, ".delstrike.toml": '[[ignore]]\nrule = "SB-RLS-OFF"\n'})
    r = run(root)
    assert ids(r, "SB-RLS-OFF") and any("no reason" in w for w in r.warnings)


def test_broken_config_never_hides_findings(project):
    root = project({"supabase/migrations/1.sql": OPEN_SQL, ".delstrike.toml": 'exclude = ["supabase/**"\n[[ignore\n'})
    r = run(root)
    assert ids(r, "SB-RLS-OFF") and any("syntax error" in w for w in r.warnings)


def test_toml_exclude_and_alias(project):
    root = project({"supabase/migrations/1.sql": OPEN_SQL, "firebase.json": '{"anonymous": true}\n', ".delstrike.toml":
                    'exclude = ["supabase/**"]\n[[ignore]]\nrule = "fb-auth-anon"\nreason = "Guest mode is a feature"\n'})
    r = run(root)
    assert not ids(r, "SB-RLS-OFF") and not ids(r, "AUTH-CONFIG")


def test_inline_suppression(project):
    code = "// delstrike-ignore SB-EDGE-NOAUTH: called only by pg_cron with a secret\n" \
           "const admin = createClient(URL, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'));\n"
    sql = "create table public.a (id int); -- delstrike-ignore SB-RLS-OFF\n"
    r = run(project({"supabase/functions/cron/index.ts": code, "supabase/migrations/1.sql": sql}))
    assert not ids(r, "SB-EDGE-NOAUTH") and [s["source"] for s in r.suppressed] == ["inline"]
    assert ids(r, "SB-RLS-OFF") and any("has no reason" in w for w in r.warnings)


# ---------------------------------------------------------------- confidence filter and grouping

def test_default_hides_medium_confidence(project):
    root = project({"supabase/migrations/1.sql": "create function public.f() returns int language sql security definer "
                                                 "as $$ select 1 $$;\n" + OPEN_SQL})
    r = run(root, include_all=False)
    assert [f.rule_id for f in r.findings] == ["SB-RLS-OFF"] and len(r.hidden) == 1


def test_same_rule_same_file_is_grouped(project):
    code = f'const a = "{fake_key("stripe")}";\nconst b = 1;\nconst c = "{fake_key("stripe")}x";\n'
    [f] = ids(run(project({"src/pay.ts": code})), "SECRET-KNOWN")
    assert f.lines == [1, 3]


# ---------------------------------------------------------------- outputs

@pytest.fixture
def vuln_report(project):
    root = project({"supabase/migrations/1.sql": OPEN_SQL,
                    "src/x.ts": f'createClient(URL, "{fake_jwt("service_role")}");\n'})
    return run(root, include_all=False)


def test_json_contract(vuln_report):
    d = json.loads(render(vuln_report, "json"))
    assert d["schema_version"] == "1" and d["tool"]["name"] == "delstrike-check" and d["network"] == "none"
    f = d["findings"][0]
    assert set(f) >= {"id", "severity", "confidence", "file", "lines", "message", "fix", "cwe", "owasp", "docs",
                      "fingerprint"}
    assert d["summary"]["critical"] == 2 and len(f["fingerprint"]) == 32


def test_fingerprint_ignores_line_moves(project):
    a = run(project({"supabase/migrations/1.sql": OPEN_SQL})).findings[0].fingerprint()
    b = run(project({"supabase/migrations/1.sql": "\n\n\n" + OPEN_SQL})).findings[0].fingerprint()
    assert a == b


def test_sarif(vuln_report):
    s = json.loads(render(vuln_report, "sarif"))
    run0 = s["runs"][0]
    assert s["version"] == "2.1.0" and len(run0["tool"]["driver"]["rules"]) == len(vuln_report.rules)
    res = run0["results"][0]
    assert res["level"] == "error" and res["partialFingerprints"]["delstrikeFingerprint/v1"]
    assert run0["tool"]["driver"]["rules"][res["ruleIndex"]]["id"] == res["ruleId"]


def test_markdown_and_text_never_contain_secrets(vuln_report):
    secret = fake_jwt("service_role")
    for fmt in ("md", "text", "json", "sarif"):
        out = render(vuln_report, fmt)
        assert secret not in out and secret.split(".")[1] not in out
    md = render(vuln_report, "md")
    assert "Generated by delstrike-check" in md and "utm_source=md" in md


def test_text_wording(project):
    out = render(run(project({"src/a.ts": "export const a = 1;\n"}, supabase=False), include_all=False), "text")
    assert "No issues found by these 14 checks." in out and "can't see" in out
    assert "secure" not in out.lower().replace("security", "") and "safe" not in out.lower()
    quiet = render(run(project({"src/a.ts": "x\n"}, supabase=False)), "text", quiet=True)
    assert "can't see" not in quiet


# ---------------------------------------------------------------- CLI

def test_cli_exit_codes(project, capsys):
    root = project({"supabase/migrations/1.sql": OPEN_SQL})
    assert cli.main([str(root), "--format", "json"]) == 0
    assert cli.main([str(root), "--format", "json", "--fail-on", "high"]) == 1
    assert cli.main([str(root), "--format", "json", "--fail-on", "critical"]) == 1
    assert cli.main([str(root / "nope")]) == 2
    with pytest.raises(SystemExit) as e:
        cli.main([str(root), "--format", "xml"])
    assert e.value.code == 2
    capsys.readouterr()


def test_cli_internal_error_is_3_without_traceback(project, capsys, monkeypatch):
    monkeypatch.setattr(cli, "scan", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert cli.main([str(project({}))]) == 3
    err = capsys.readouterr().err
    assert "Internal error (RuntimeError)" in err and "Traceback" not in err


def test_cli_output_file_infers_format(project, tmp_path, capsys):
    root = project({"supabase/migrations/1.sql": OPEN_SQL})
    out = tmp_path / "report.sarif"
    assert cli.main([str(root), "-o", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["version"] == "2.1.0"
    capsys.readouterr()


def test_cli_explain_and_rules(capsys):
    assert cli.main(["explain", "fb-auth-anon"]) == 0
    out = capsys.readouterr().out
    assert "AUTH-CONFIG" in out and "enable_anonymous_sign_ins = false" in out
    assert cli.main(["explain", "SB-RPC-DEFINER"]) == 0
    assert "manual review verifies it" in capsys.readouterr().out
    assert cli.main(["explain", "NOPE"]) == 2
    assert cli.main(["rules"]) == 0
    out = capsys.readouterr().out
    assert all(r.id in out for r in RULES) and "15 rules" in out


def test_cli_max_file_size(project, capsys):
    root = project({"supabase/migrations/1.sql": OPEN_SQL + "-- " + "x" * 3000 + "\n"})
    assert cli.main([str(root), "--format", "json", "--max-file-size", "1KB"]) == 0
    d = json.loads(capsys.readouterr().out)
    assert not d["findings"] or all(f["id"] != "SB-RLS-OFF" for f in d["findings"])
    assert any("skipped" in w for w in d["warnings"])


# ---------------------------------------------------------------- --deps (mocked)

LOCK = json.dumps({"lockfileVersion": 3, "packages": {
    "": {"name": "app"},
    "node_modules/next": {"version": "14.0.0"},
    "node_modules/vite": {"version": "5.0.0", "dev": True},
    "node_modules/react": {"version": "18.3.1"}}}, indent=2)


def test_deps_osv_mocked(project, monkeypatch):
    sent = []

    def post(url, body):
        sent.append(body)
        return {"results": [{"vulns": [{"id": "GHSA-1"}]} if q["package"]["name"] in ("next", "vite") else {}
                            for q in body["queries"]]}

    def get(url):
        vid = url.rsplit("/", 1)[-1]
        return {"id": vid, "aliases": ["CVE-2025-1"], "database_specific": {"severity": "CRITICAL"},
                "affected": [{"package": {"name": "next"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "14.2.25"}]}]}]}

    monkeypatch.setattr(deps, "_post", post)
    monkeypatch.setattr(deps, "_get", get)
    r = run(project({"package-lock.json": LOCK}), deps=True)
    found = ids(r, "DEPS-OSV")
    runtime = next(f for f in found if not f.extra["dev"])
    assert runtime.severity == "critical" and "Fixed in 14.2.25" in runtime.message and runtime.lines[0] > 1
    dev = next(f for f in found if f.extra["dev"])
    assert dev.severity == "low" and "vite@5.0.0" in dev.message
    q = sent[0]["queries"][0]
    assert set(q) == {"package", "version"} and set(q["package"]) == {"name", "ecosystem"}


def test_deps_network_error_is_a_warning_not_zero(project, monkeypatch):
    def post(url, body):
        raise OSError("offline")
    monkeypatch.setattr(deps, "_post", post)
    r = run(project({"package-lock.json": LOCK}), deps=True)
    assert not ids(r, "DEPS-OSV") and any("NOT checked" in w for w in r.warnings)


def test_deps_not_run_without_flag(project, monkeypatch):
    monkeypatch.setattr(deps, "_post", lambda *a: pytest.fail("network used without --deps"))
    r = run(project({"package-lock.json": LOCK}))
    assert "DEPS-OSV" not in [x.id for x in r.rules]


def test_cvss3():
    assert deps.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert deps.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1


# ---------------------------------------------------------------- robustness

def test_binary_weird_encoding_huge_and_symlink(project, tmp_path):
    root = project({"img.png": b"\x89PNG\x00\x00" * 100, "blob.dat": b"abc\x00def",
                    "latin1.ts": "const s = 'caf\xe9';\n".encode("latin-1"),
                    "big.sql": "create table public.big (id int);\n" + "-- filler\n" * 200_000})
    r = run(root)
    assert any("skipped" in w for w in r.warnings)
    assert not any(f.file == "big.sql" for f in r.findings)


def test_failing_rule_does_not_stop_the_scan(project, monkeypatch):
    from delstrike_check.checks import supabase
    monkeypatch.setattr(supabase, "_policy_scan", lambda ctx: 1 / 0)
    r = run(project({"supabase/migrations/1.sql": OPEN_SQL}))
    assert ids(r, "SB-RLS-OFF") and any("SB-POLICY-OPEN failed" in e for e in r.errors)


def test_performance_20k_lines(project):
    files = {f"src/mod{i}/file{j}.ts": "export function f(x: number) {\n  return x + 1;\n}\n" * 33
             for i in range(20) for j in range(10)}
    files["supabase/migrations/1.sql"] = "".join(f"create table t{i} (id int);\nalter table t{i} enable row level "
                                                 f"security;\n" for i in range(300))
    root = project(files)
    t0 = time.monotonic()
    r = run(root)
    assert r.loc_own >= 19_000 and time.monotonic() - t0 < 10


# ---------------------------------------------------------------- docs

def test_docs_and_readme(tmp_path):
    assert docs.main(["--out", str(tmp_path / "out")]) == 0
    data = json.loads((tmp_path / "out" / "rules.json").read_text(encoding="utf-8"))
    assert len(data) == 15 and data[11]["aliases"] == ["FB-AUTH-ANON"]
    assert (tmp_path / "out" / "SB-EDGE-NOAUTH.md").read_text(encoding="utf-8").startswith("# SB-EDGE-NOAUTH")
    readme = write(tmp_path, {"README.md": "x\n<!-- rules:start -->\nold\n<!-- rules:end -->\ny\n"}) / "README.md"
    docs.update_readme(readme)
    assert "SB-POLICY-OVERLAP" in readme.read_text(encoding="utf-8")


def test_every_rule_has_texts():
    from delstrike_check.i18n import Translator
    t = Translator("en")
    for r in RULES:
        for field in ("title", "detects", "why", "fix", "fix_short"):
            assert t.rule(r.id, field) != f"rules.{r.id}.{field}", (r.id, field)
        assert t.rule(r.id, "code")["text"]
