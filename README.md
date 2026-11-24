# delstrike-check

Free, local security checks for vibecoded apps on **Supabase** and **Firebase**, by [DELSTRIKE](https://www.delstrike.com).

```bash
uvx delstrike-check .
# or
pipx run delstrike-check .
```

```
  delstrike-check 0.1.0 · Supabase + React + Vite · 4,210 own lines · nothing left your machine

  HIGH  SB-EDGE-NOAUTH       supabase/functions/payment-callback/index.ts:5
        Uses the service_role key and never checks who is calling.
        Anyone with your public anon key can call it.
        Fix: verify the caller with supabase.auth.getUser() or a shared secret header.
        → delstrike-check explain SB-EDGE-NOAUTH

  HIGH  SB-POLICY-OVERLAP    supabase/migrations/20260101000000_invoices.sql:7
        On invoices, policy "Enable read access for all users" (select) lets anyone, without
        signing in, read every row, and it is combined with OR with "Users read own
        invoices", which checks the owner.
        Permissive policies add up, so the open one wins.
        Fix: drop policy "Enable read access for all users" on public.invoices;
        → delstrike-check explain SB-POLICY-OVERLAP

  2 high
```

*(Example app, made up for this page.)*

## What it does, and what it doesn't

**It does:** walk a local folder without running anything, detect the stack, rebuild the final state of your Supabase
migrations (tables, RLS, every `CREATE`/`ALTER`/`DROP POLICY`), read your edge functions, API routes, Firebase rules,
`config.toml` and `.env` files, and tell you the file, the line, why it matters and how to fix it.

**It doesn't:** run your code or install your dependencies, connect to your database or your deployed app, send
telemetry, or check for updates on its own. **Nothing leaves your machine**, unless you pass `--deps`, which sends
only package names, ecosystems and versions to [osv.dev](https://osv.dev).

**It never prints a secret.** Findings name the key or the provider, never the value.

**It never says "secure".** With no findings it says *No issues found by these checks*, and lists what it can't
see: broken access logic (IDOR), business rules, n8n/Make workflows and production configuration.

## Rules

High-confidence findings are shown by default. `--all` adds the ones that depend on your design ("to verify").
★ = the checks that found the serious issues in our reviews of open-source vibecoded apps.

<!-- rules:start -->
| Rule | Severity | Confidence | Stack | What it catches |
|---|---|---|---|---|
| [`SB-EDGE-NOAUTH`](https://www.delstrike.com/checkpoint/rules/SB-EDGE-NOAUTH) ★ | High | High | Supabase | Edge function uses service_role without checking the caller |
| [`SB-EDGE-JWT-OFF`](https://www.delstrike.com/checkpoint/rules/SB-EDGE-JWT-OFF) ★ | Medium–High | High | Supabase | JWT verification disabled for an edge function |
| [`SB-SERVICE-ROLE-KEY`](https://www.delstrike.com/checkpoint/rules/SB-SERVICE-ROLE-KEY) | Critical | High | Supabase | service_role or secret key exposed to the client |
| [`SB-POLICY-OPEN`](https://www.delstrike.com/checkpoint/rules/SB-POLICY-OPEN) | High | High | Supabase | Row Level Security policy open to everyone |
| [`SB-RLS-OFF`](https://www.delstrike.com/checkpoint/rules/SB-RLS-OFF) | Critical | High | Supabase | Table in the public schema without Row Level Security |
| [`SB-POLICY-OVERLAP`](https://www.delstrike.com/checkpoint/rules/SB-POLICY-OVERLAP) ★ | High | High | Supabase | Open policy overrides an owner-only policy |
| [`SB-RPC-DEFINER`](https://www.delstrike.com/checkpoint/rules/SB-RPC-DEFINER) | Medium | Medium | Supabase | SECURITY DEFINER function callable by anyone |
| [`AI-PROXY-OPEN`](https://www.delstrike.com/checkpoint/rules/AI-PROXY-OPEN) ★ | High | High | AI | Open AI proxy (denial of wallet) |
| [`FB-RULES-OPEN`](https://www.delstrike.com/checkpoint/rules/FB-RULES-OPEN) | High–Critical | High | Firebase | Firebase security rules open to everyone |
| [`SB-BUCKET-PUBLIC`](https://www.delstrike.com/checkpoint/rules/SB-BUCKET-PUBLIC) | Medium | Medium | Supabase | Public storage bucket holding user content |
| [`SB-NO-SCHEMA`](https://www.delstrike.com/checkpoint/rules/SB-NO-SCHEMA) | Info | High | Supabase | Supabase is used, but the schema is not in the repository |
| [`AUTH-CONFIG`](https://www.delstrike.com/checkpoint/rules/AUTH-CONFIG) | Low | High | Supabase | Anonymous sign-in on, or email confirmation off |
| [`ENV-COMMITTED`](https://www.delstrike.com/checkpoint/rules/ENV-COMMITTED) | Info–Critical | High | Secrets | .env file committed to the repository |
| [`SECRET-KNOWN`](https://www.delstrike.com/checkpoint/rules/SECRET-KNOWN) | Critical | High | Secrets | API key with a known prefix in the code |
| [`DEPS-OSV`](https://www.delstrike.com/checkpoint/rules/DEPS-OSV) | Per advisory | High | Dependencies | Dependency with a known vulnerability (`--deps`) |
<!-- rules:end -->

`delstrike-check rules` lists them, and `delstrike-check explain <RULE_ID>` prints the full explanation and a fix
ready to paste, offline.

## Usage

```
delstrike-check [PATH] [options]
delstrike-check explain <RULE_ID>
delstrike-check rules
```

| Option | What it does |
|---|---|
| `--format text\|json\|sarif\|md` | Output format. Default: `text` in a terminal, `json` otherwise, or from the `--output` extension |
| `--output FILE`, `-o` | Write the report to a file |
| `--all` | Include medium and low confidence findings |
| `--fail-on critical\|high\|medium\|low\|info\|none` | Exit with 1 if a finding is at or above this severity (default `none`) |
| `--deps` | Check lockfiles against osv.dev (the only option that uses the network) |
| `--exclude GLOB` | Extra path to skip, repeatable. `node_modules`, `dist`, `.next`, `build`, `vendor`, `coverage` and `*.min.js` are always skipped, and so is anything in `.gitignore` |
| `--max-file-size SIZE` | Skip larger files and say so (default `1MB`) |
| `--quiet`, `-q` | Omit the closing "what this tool can't see" lines |
| `--no-color` | No colours (`NO_COLOR` is honoured too) |
| `--debug` | Show tracebacks |

**Exit codes:** `0` nothing at or above `--fail-on` · `1` findings at or above `--fail-on` · `2` usage error ·
`3` internal error.

## Suppressions

Every suppression needs a reason. Without one it isn't applied, and the scan tells you.

`.delstrike.toml` at the root of the scanned folder:

```toml
exclude = ["scripts/**"]

[[ignore]]
rule = "SB-POLICY-OPEN"
reason = "Board data is shared by design"

[[ignore]]
rule = "SB-EDGE-JWT-OFF"
path = "supabase/config.toml"
reason = "stripe-webhook verifies the signature"
```

Inline, on the line or the line above:

```ts
// delstrike-ignore SB-EDGE-NOAUTH: called only by pg_cron with a shared secret
```

```sql
-- delstrike-ignore SB-RLS-OFF: lookup table without user data
```

A `.delstrike.toml` with a syntax error never hides findings: the scan warns and runs without suppressions.

## Output formats

- **text** for the terminal.
- **json** is a stable contract (`schema_version`). Each finding has a `fingerprint` (rule + file + normalized
  snippet, without line numbers), so you can track it across commits even when lines move.
- **sarif** 2.1.0 for GitHub code scanning: findings appear in the repository's *Security* tab.
- **md** to paste in an issue or a PR, or to send to your agency.

## In CI: GitHub Action

```yaml
name: security
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  delstrike-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: delstrike/delstrike-check@v0.1.0
        with:
          fail-on: high      # critical, high, medium, low, info or none
          # all: "true"      # also findings to verify
          # deps: "true"     # also osv.dev
```

The code is scanned inside your own CI runner and never sent to us. The job summary shows the Markdown report.

## pre-commit

```yaml
repos:
  - repo: https://github.com/delstrike/delstrike-check
    rev: v0.1.0
    hooks:
      - id: delstrike-check
```

## As a library

```python
from delstrike_check import Options, scan

report = scan("path/to/app", Options(include_all=True))
for f in report.findings:
    print(f.rule_id, f.severity, f.file, f.lines, f.fingerprint())
```

## Use it on your own code

delstrike-check is a read-only linter. Run it on code you own or are authorised to review. If you find an issue in
someone else's open-source project, report it privately through their security policy.

## Need a human?

A tool finds patterns. It can't tell whether a user can read another user's invoices through your business logic,
or whether that open policy is on purpose. **CHECKPOINT** is a manual review of your app, with every finding
verified by hand and fixes ready to paste: [delstrike.com/checkpoint](https://www.delstrike.com/checkpoint?utm_source=readme).

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m delstrike_check.docs --readme README.md      # refresh the rules table
python -m delstrike_check.docs --out ../site/rules     # rules.json + one page per rule for the website
```

Zero runtime dependencies, Python 3.11 or later. Each rule has positive and negative fixtures in `tests/`.

## Licence

[Apache-2.0](LICENSE). See [NOTICE](NOTICE). Security reports: [SECURITY.md](SECURITY.md).
