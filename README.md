# TrustGraph

[![CI](https://github.com/karkiram05/trustgraph/actions/workflows/ci.yml/badge.svg)](https://github.com/karkiram05/trustgraph/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

Attack-path analysis for CI/CD identity and cloud trust. It reads GitHub
Actions workflows (and, optionally, AWS IAM trust policies), builds a
directed graph of who can act as whom and what they can reach, and reports
concrete attack paths -- not "this permission looks broad" in isolation,
but "this permission is broad AND reachable from a compromised CI step AND
leads to this specific cloud resource."

```
workflow permissions + OIDC federation + IAM trust policy
                    ↓
            trust graph (networkx)
                    ↓
   attack-path detection + severity by reachability
                    ↓
        findings, explanations, remediation
```

## Why this exists

The failure mode this targets is specific and well-documented: a GitHub
Actions job requests an OIDC cloud credential (`id-token: write`) while
also holding broad `GITHUB_TOKEN` permissions, or trusts that OIDC token
with a wildcard IAM condition, or runs a third-party action pinned to a
mutable tag instead of a commit SHA -- any one of which turns "a dependency
got compromised" into "our AWS account got compromised." These are real,
recurring incident patterns, not hypothetical ones. TrustGraph statically
finds them and, where the data is available, traces the actual path to a
named cloud resource rather than just flagging the permission in isolation.

## What's here (and what isn't, on purpose)

| | |
|---|---|
| ✅ | GitHub Actions workflow parser (permissions, OIDC requests, action pinning) |
| ✅ | AWS IAM trust policy parser (OIDC federation, audience/subject conditions) |
| ✅ | A real trust graph (networkx) modeling repo → workflow → action / OIDC → role → resource |
| ✅ | 4 detection rules, each tied to a documented real-world anti-pattern (`docs/detection-rules.md`) |
| ✅ | Severity that depends on actual graph reachability, not a static per-rule score |
| ✅ | Full attack-path explanations and concrete remediation (`trustgraph explain`, `trustgraph fix`) |
| ✅ | Evaluated against real public GitHub Actions workflows, not just hand-built fixtures (`docs/results.md`) |
| ✅ | 31 pytest tests across parsers, rules, graph building, the detection engine, and the CLI |
| ✅ | GitHub Actions CI: tests + Bandit + pip-audit |
| ✅ | Threat model of the tool itself (`docs/threat-model.md`) |
| ⛔ | Live validation of a finding against a real environment -- this is Phase 1: static analysis only, zero credentials, zero API calls, zero side effects. Phase 2 (TrustLab, a disposable local lab that actually attempts a finding end-to-end) is planned but not built yet -- see the roadmap in `docs/architecture.md` |
| ⛔ | Automatic discovery of which cloud resources a role can reach -- that requires parsing IAM *permission* policies and simulating evaluation, not just trust policies; Phase 1 takes it as a small supplied `resources.json` instead of a simplified (and likely wrong) permission-policy parser |

## Try it with zero local setup (GitHub Codespaces)

This repo has a `.devcontainer/` config. Click **Code → Codespaces → Create
codespace on main** on GitHub, or open the repo in a devcontainer-compatible
editor. It automatically creates a venv, installs dependencies, installs the
package, and runs a first scan against the bundled vulnerable example as a
smoke test -- no manual steps.

## Quickstart

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e .

# Scan the deliberately-vulnerable example
trustgraph scan examples/vulnerable-project --repo-name my-org/vulnerable-project
trustgraph explain TG-001 --in examples/vulnerable-project
trustgraph fix TG-001 --in examples/vulnerable-project

# Compare against the corrected version -- same shape, hardened
trustgraph scan examples/hardened-project --repo-name my-org/hardened-project
```

Or, equivalently, run `./setup.sh` from the repo root (also what the
Codespaces devcontainer runs automatically).

`scan` looks for `.github/workflows/*.yml` and `trust-policies/*.json`
under the target directory, plus an optional `resources.json` mapping IAM
role names to the cloud resources they can reach. Point it at any repo
checkout:

```bash
trustgraph scan /path/to/some/repo --repo-name org/repo
```

## Example: before / after

`examples/vulnerable-project` has a deploy workflow with `id-token: write`
alongside `contents: write` and `actions: write`, a trust policy scoped to
`repo:my-org/*:*` with no audience restriction, and two unpinned action
references. Scanning it:

```
Scanned 1 workflow(s), 1 trust policy.

SECURITY OVERVIEW

  CRITICAL   4
  MEDIUM     1

[CRITICAL] TG-001  Overpowered GitHub Actions token
[CRITICAL] TG-002  Overly broad OIDC trust condition
[CRITICAL] TG-004  Unpinned third-party action: some-random-org/build-action
[CRITICAL] TG-005  Unpinned third-party action: aws-actions/configure-aws-credentials
[MEDIUM]   TG-003  OIDC audience not pinned in trust policy
```

`trustgraph explain TG-001` prints the full attack path:

```
repo:my-org/vulnerable-project
      ↓
workflow:.../deploy.yml
      ↓
oidc:token.actions.githubusercontent.com
      ↓
role:production-deploy-role
      ↓
resource:prod-customer-data-s3-bucket
      ↓
resource:prod-rds-database
```

`examples/hardened-project` is the same workflow shape with scoped job-level
permissions, SHA-pinned actions, and a trust policy scoped to a specific
branch with a pinned audience. Scanning it: `No findings. ✓`

## Real-world evaluation

Unit tests prove the rules fire correctly on fixtures built to trigger
them. That's necessary but not sufficient -- so TrustGraph was also run
against 12 real, live-fetched GitHub Actions workflows from 9 public
repositories it had never seen, including major projects (Django, Flask,
pip, React, Next.js) and smaller ones. 11 scanned clean -- independently
verified, not just accepted at face value, by hand-inspecting each parsed
workflow's permissions and action references. The 12th
(`hashicorp/terraform-provider-aws`) produced 3 genuine MEDIUM findings for
unpinned third-party actions, with a full working `explain` output. Full
writeup, including what this kind of evaluation can and can't cover, in
`docs/results.md`.

## Documentation

- `docs/architecture.md` -- module map, design decisions, and what Phase 1
  deliberately doesn't do (with the reasoning, not just a list)
- `docs/detection-rules.md` -- each rule, why it matters, its severity
  model, and its input requirements
- `docs/threat-model.md` -- STRIDE analysis of TrustGraph itself
- `docs/results.md` -- the real-world evaluation, including honest limits

## Roadmap

Phase 1 (this) is the static analysis engine. Deliberately deferred:

- **Phase 2 -- TrustLab**: a disposable local lab (Kali container + mock CI
  runner + mock OIDC/STS) that actually attempts one specific finding
  end-to-end with a harmless "prove it" flag-capture, turning "this looks
  exploitable on paper" into "this was demonstrated."
- **Phase 3**: a Kubernetes profile (`kind`), a graph visualization
  dashboard (React Flow), and a single `make demo` tying scan → lab
  validation → visualization together.

See `docs/architecture.md` for the full reasoning behind the phased
sequencing and the specific gaps each phase closes.

## Development

```bash
python -m pytest          # 31 tests
bandit -r trustgraph -q   # static security analysis
pip-audit -r requirements.txt   # dependency CVE scan (scoped to this project)
```

## License

MIT -- see `LICENSE`.
