# Security policy

## Reporting a vulnerability in delstrike-check

Please report it privately: use **Report a vulnerability** on the repository's *Security* tab (GitHub private
vulnerability reporting), or email **info@delstrike.com** with the subject `delstrike-check security`.

We acknowledge reports within 3 working days and aim to ship a fix within 30 days. We credit reporters in the
release notes unless they prefer otherwise.

In scope: anything that makes delstrike-check execute code from the scanned folder, send data anywhere other than
`api.osv.dev` with `--deps`, print a secret value, or crash in a way that hides findings.

## Supported versions

Only the latest release receives fixes.

## How releases are protected

- Zero runtime dependencies.
- Releases are published to PyPI with Trusted Publishing (OIDC, no long-lived tokens) and carry build provenance
  attestations.
- `main` is protected and every maintainer uses MFA.

## A false negative is not a vulnerability

delstrike-check runs a fixed set of deterministic checks. "No issues found by these checks" does not mean an app is
secure. Missing detections are welcome as normal issues.
