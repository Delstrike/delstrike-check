"""Command line: `delstrike-check [PATH]`, `delstrike-check explain <RULE_ID>`, `delstrike-check rules`.

Exit codes: 0 nothing at or above --fail-on · 1 findings at or above --fail-on · 2 usage error · 3 internal error.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import textwrap
import traceback
from pathlib import Path

from . import __version__
from .checks import RULES, find_rule
from .i18n import AVAILABLE, Translator, system_lang
from .model import SEV_RANK, SEVERITIES
from .output import FORMATS, render
from .scan import DEFAULT_MAX_FILE_SIZE, Options, scan

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE, EXIT_INTERNAL = 0, 1, 2, 3
EXT_FORMAT = {".json": "json", ".sarif": "sarif", ".md": "md", ".markdown": "md", ".txt": "text"}
MIX = {"mediumHigh": "medium–high", "criticalHigh": "high–critical", "infoCritical": "info–critical",
       "perOsv": "per advisory"}


def parse_size(value: str) -> int:
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([kKmMgG]?)[bB]?\s*", value)
    if not m:
        raise argparse.ArgumentTypeError(f"invalid size: {value!r} (examples: 500KB, 1MB, 2000000)")
    mult = {"": 1, "k": 1_000, "m": 1_000_000, "g": 1_000_000_000}[m.group(2).lower()]
    return int(float(m.group(1)) * mult)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="delstrike-check",
        description="Local security checks for vibecoded apps (Supabase, Firebase, AI proxies). Reads files only; "
                    "nothing leaves your machine unless you pass --deps.",
        epilog="Also: `delstrike-check explain <RULE_ID>` and `delstrike-check rules`. "
               "Exit codes: 0 ok · 1 findings at or above --fail-on · 2 usage error · 3 internal error.")
    p.add_argument("path", nargs="?", default=".", help="folder to scan (default: current folder)")
    p.add_argument("--format", choices=FORMATS, help="output format (default: text in a terminal, json otherwise)")
    p.add_argument("--output", "-o", metavar="FILE", help="write the report to FILE")
    p.add_argument("--all", action="store_true", dest="include_all", help="also show medium and low confidence findings")
    p.add_argument("--fail-on", choices=[*SEVERITIES, "none"], default="none",
                   help="exit with 1 if a finding is at or above this severity (default: none)")
    p.add_argument("--deps", action="store_true",
                   help="check lockfiles against osv.dev (sends only package names, ecosystems and versions)")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="extra path glob to skip (repeatable)")
    p.add_argument("--lang", choices=AVAILABLE, help="language (default: system language, else en)")
    p.add_argument("--no-color", action="store_true", help="no colours (NO_COLOR is also honoured)")
    p.add_argument("--max-file-size", type=parse_size, default=DEFAULT_MAX_FILE_SIZE, metavar="SIZE",
                   help="skip files larger than SIZE (default: 1MB)")
    p.add_argument("--quiet", "-q", action="store_true", help="omit the closing 'what this tool can't see' lines")
    p.add_argument("--debug", action="store_true", help="show tracebacks")
    p.add_argument("--version", action="version", version=f"delstrike-check {__version__}")
    return p


def _setup_stdout() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            if not stream.isatty():
                stream.reconfigure(encoding="utf-8", errors="replace")
            else:
                stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
    if os.name == "nt":
        os.system("")  # enables ANSI escape sequences in the Windows console  # noqa: S605,S607


def _use_color(args, to_file: bool) -> bool:
    if args.no_color or os.environ.get("NO_COLOR") or to_file:
        return False
    return sys.stdout.isatty() and os.environ.get("TERM") != "dumb"


def cmd_explain(rule_id: str, lang: str) -> int:
    t = Translator(lang)
    rule = find_rule(rule_id)
    if not rule:
        print(t("ui.unknown_rule", rule=rule_id), file=sys.stderr)
        return EXIT_USAGE
    w = 88
    sev = MIX.get(rule.severity_mix or "", t(f"ui.severity.{rule.severity}"))
    out = ["", f"  {rule.id}{' ★' if rule.star else ''} — {t.rule(rule.id, 'title')}",
           "  " + t("ui.explain_meta", severity=sev, confidence=t(f"ui.confidence.{rule.confidence}"), stack=rule.stack,
                    cwe=", ".join(str(c) for c in rule.cwe), owasp=rule.owasp)]
    if rule.aliases:
        out.append(f"  Also known as: {', '.join(rule.aliases)}")
    if rule.opt_in:
        out.append("  " + t("ui.explain_opt_in"))
    for label, field in (("ui.explain_detects", "detects"), ("ui.explain_why", "why"), ("ui.explain_fix", "fix")):
        out += ["", "  " + t(label)]
        out += textwrap.wrap(t.rule(rule.id, field), width=w, initial_indent="    ", subsequent_indent="    ")
    code = t.rule(rule.id, "code") or {}
    if code.get("text"):
        out += ["", "  " + t("ui.explain_example") + f" ({code.get('lang', '')})", ""]
        out += ["    " + ln for ln in code["text"].splitlines()]
    refs = t.raw(f"rules.{rule.id}.references") or []
    out += ["", "  " + t("ui.explain_refs"), f"    {rule.docs}"] + [f"    {r}" for r in refs]
    if rule.confidence != "high":
        out += ["", "  " + t("ui.explain_hook")]
    out.append("")
    print("\n".join(out))
    return EXIT_OK


def cmd_rules(lang: str) -> int:
    t = Translator(lang)
    print()
    print("  " + t("ui.rules_header", count=len(RULES)))
    print()
    for r in RULES:
        sev = MIX.get(r.severity_mix or "", t(f"ui.severity.{r.severity}"))
        flag = " (--deps)" if r.opt_in else ""
        star = "★" if r.star else " "
        print(f"  {star} {r.id:<20} {sev:<14} {t('ui.confidence.' + r.confidence):<7} {r.stack:<12} "
              f"{t.rule(r.id, 'title')}{flag}")
    print()
    print("  delstrike-check explain <RULE_ID>  ·  https://www.delstrike.com/checkpoint/rules")
    print()
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    _setup_stdout()
    argv = list(sys.argv[1:] if argv is None else argv)
    lang = system_lang()
    if argv and argv[0] in ("explain", "rules") and not Path(argv[0]).is_dir():
        sub = argparse.ArgumentParser(prog=f"delstrike-check {argv[0]}")
        if argv[0] == "explain":
            sub.add_argument("rule")
        sub.add_argument("--lang", choices=AVAILABLE, default=lang)
        a = sub.parse_args(argv[1:])
        return cmd_explain(a.rule, a.lang) if argv[0] == "explain" else cmd_rules(a.lang)

    args = build_parser().parse_args(argv)
    lang = args.lang or lang
    t = Translator(lang)
    if not Path(args.path).is_dir():
        print(t("ui.not_a_dir", path=args.path), file=sys.stderr)
        return EXIT_USAGE
    fmt = args.format or (EXT_FORMAT.get(Path(args.output).suffix.lower(), "text") if args.output
                          else ("text" if sys.stdout.isatty() else "json"))
    try:
        report = scan(args.path, Options(include_all=args.include_all, deps=args.deps, exclude=args.exclude, lang=lang,
                                         max_file_size=args.max_file_size, debug=args.debug))
        text = render(report, fmt, color=_use_color(args, bool(args.output)), quiet=args.quiet)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
            if sys.stdout.isatty() and fmt != "text":
                s = report.summary()
                print(f"delstrike-check: {sum(s.values())} finding(s) written to {args.output}")
        else:
            sys.stdout.write(text)
            sys.stdout.flush()
    except KeyboardInterrupt:
        return 130
    except Exception as e:  # never a raw traceback unless --debug
        print(t("ui.internal_error", error=type(e).__name__), file=sys.stderr)
        if args.debug:
            traceback.print_exc()
        return EXIT_INTERNAL
    if args.fail_on != "none":
        threshold = SEV_RANK[args.fail_on]
        if any(SEV_RANK[f.severity] >= threshold for f in report.findings):
            return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
