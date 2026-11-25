# Changelog

All notable changes are listed here. The project follows [Semantic Versioning](https://semver.org): a new rule is a
minor version; a change to the JSON output format (`schema_version`) is a major version.

## 0.1.0 — 2026-11-25

First public version.

- 15 rules for vibecoded apps on Supabase and Firebase: `SB-EDGE-NOAUTH`, `SB-EDGE-JWT-OFF`, `SB-SERVICE-ROLE-KEY`,
  `SB-POLICY-OPEN`, `SB-RLS-OFF`, `SB-POLICY-OVERLAP`, `SB-RPC-DEFINER`, `AI-PROXY-OPEN`, `FB-RULES-OPEN`,
  `SB-BUCKET-PUBLIC`, `SB-NO-SCHEMA`, `AUTH-CONFIG` (alias `FB-AUTH-ANON`), `ENV-COMMITTED`, `SECRET-KNOWN` and
  `DEPS-OSV` (opt-in with `--deps`).
- Policies are evaluated in their final state, after every `CREATE`, `ALTER` and `DROP POLICY` in the migrations.
- Edge-function caller checks follow imported helpers (for example `_shared/auth.ts`) one level deep.
- Uses the git index to tell committed `.env` files from local, git-ignored ones.
- Output as text, JSON (`schema_version` 1, with fingerprints), SARIF 2.1.0 and Markdown.
- Suppressions in `.delstrike.toml` or inline with `delstrike-ignore RULE: reason` (a reason is required).
- `explain <RULE_ID>`, `rules`, `--fail-on`, `--all`, `--exclude`, `--max-file-size`, `--quiet`.
- GitHub Action and pre-commit hook.
