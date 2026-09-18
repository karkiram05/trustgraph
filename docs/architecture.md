# Architecture

## What this is

TrustGraph answers one question: if a GitHub Actions workflow in this repo
is compromised, what can the attacker actually reach? It statically parses
workflow YAML and (optionally) AWS IAM trust policy JSON, builds a directed
graph of identity/trust relationships, and walks that graph to find and
rank concrete attack paths -- not just "this permission is broad" in
isolation, but "this permission is broad AND it's reachable from a
compromised CI step AND it leads to a specific cloud resource."

Everything in Phase 1 is static analysis against files already sitting in a
repo checkout. Nothing executes, nothing calls the GitHub or AWS APIs,
nothing needs credentials. That's a deliberate scope boundary, not a
missing feature -- see "What Phase 1 deliberately does not do" below.

## Module map

```
trustgraph/
  parsers/
    github_actions.py   YAML -> Workflow/Job/ActionUse
    iam_trust.py         IAM trust policy JSON -> TrustPolicy
  graph/
    model.py             TrustGraph: thin typed wrapper over networkx.DiGraph
    builder.py            Workflow/TrustPolicy/resource map -> TrustGraph
  detections/
    base.py               Severity, Finding
    rules.py               4 rule functions, each (inputs) -> raw dict findings
    engine.py               orchestrates rules, assigns TG-NNN ids, builds
                             plain-English explanations and attack paths
  remediation/
    suggest.py             rule_id -> remediation text / before-after patch
  cli/
    main.py                 scan / explain / fix commands
```

The rule functions in `rules.py` are intentionally dumb -- each one takes
already-parsed objects and yields plain dicts describing what it found, with
no narrative text. `engine.py` is where a raw finding becomes a `Finding`
with severity, an entry point, a plain-English "problem / cloud trust /
result" narrative, and (when the graph supports it) an attack path. This
split exists so the detection logic can be unit-tested against exact
structured output (`{"rule_id": ..., "extra_scopes": [...]}`) without
also having to pin down prose wording in the same tests.

## Why networkx instead of a bespoke graph

The graph's value is the domain modeling -- what counts as a node (a repo,
a workflow, a third-party action, the OIDC provider, an IAM role, a cloud
resource), what counts as an edge (`defines`, `uses_action`,
`requests_token`, `trusts`, `can_access`), and which paths through that
graph are dangerous. Path-finding itself (`all_simple_paths`,
`descendants`) is a solved, well-tested problem; reimplementing it would
just be a place for new bugs with no offsetting benefit.

## Severity model

Severity is not a static property of a rule -- it depends on what's
actually reachable in the graph:

- `overpermissioned-token` and `unpinned-action` (when the workflow also
  requests an OIDC token) start at HIGH. If the graph can also trace a
  concrete path to a cloud resource (via a trust policy that this repo's
  OIDC subject would satisfy, plus a resource-access entry for that role),
  severity is raised to CRITICAL and the specific reachable resource is
  named in the finding.
- `unpinned-action` outside an OIDC-elevated job is MEDIUM: still a
  supply-chain risk (arbitrary code in CI), but without a demonstrated
  path to cloud credentials.
- `wildcard-oidc-trust` is HIGH by default, CRITICAL if a resource is
  reachable through it.
- `missing-audience-restriction` is MEDIUM unconditionally -- it's a
  defense-in-depth gap, not independently exploitable.

This is why the graph exists at all rather than four independent linters:
the same "unpinned action" fact means something very different in a job
with no cloud credentials versus one that can mint an AWS session.

## Trust condition evaluation

`roles_reachable_from_repo()` builds plausible OIDC subject claims for a
repo (`repo:org/repo:ref:refs/heads/main`, `repo:org/repo:ref:refs/heads/master`,
`repo:org/repo:pull_request`) and checks them against each trust policy's
`sub` condition with `fnmatch` -- which is how AWS's `StringLike` condition
operator actually behaves (shell-style `*` wildcards, not regex). This is
real evaluation of the trust condition's shape, not a guess dressed up as
one. Its known limitation: it only tries conventional branch names and the
`pull_request` context. A repo using unconventional branch names or GitHub
Environments in unusual ways may have a role that's actually reachable but
that this heuristic doesn't surface -- see the roadmap below.

## What Phase 1 deliberately does not do

- **Doesn't discover the role -> resource mapping automatically.** Knowing
  that an IAM role can reach a specific S3 bucket or RDS instance requires
  parsing that role's *permission* policies (not just its trust policy) and
  simulating policy evaluation against real AWS semantics -- a genuinely
  hard problem (`iam-policy-simulator`-grade). Phase 1 takes this as a
  small supplied JSON file (`resources.json`) instead of inventing a
  simplified, and likely wrong, permission-policy parser. This is the
  single largest simplification in the current design.
- **Doesn't know a repo's actual default token permissions.** GitHub Actions'
  default `GITHUB_TOKEN` permissions depend on an org/repo setting that
  isn't visible in the workflow YAML at all. When a workflow specifies no
  `permissions:` block, TrustGraph reports the effective permission as
  `unspecified` rather than guessing broad or narrow -- see
  `github_actions.py`'s `UNSPECIFIED` constant.
- **Doesn't call any live API.** No GitHub API, no AWS API, no live IAM
  policy simulation. Everything is derived from files already in the
  checkout. This is what makes Phase 1 safe to run against arbitrary repos
  with zero credentials and zero side effects -- and it's also why Phase 2
  (TrustLab) exists: static analysis can tell you a path *should* work
  given the configuration on paper; it can't prove a step in that path
  actually succeeds against the real GitHub Actions / AWS STS runtime
  semantics.
- **Doesn't validate exploitability.** A CRITICAL finding here means "the
  static configuration, read literally, describes a path from a compromised
  CI step to a named cloud resource" -- not "this was proven exploitable
  against a live environment." That gap is exactly what Phase 2 closes.

## Roadmap (explicitly deferred, not forgotten)

- **Phase 2 -- TrustLab**: a disposable local lab (a Kali container plus a
  mock CI runner and mock OIDC/STS endpoints) that takes one specific
  static finding and actually attempts the described path end-to-end, with
  a harmless "prove it" flag-capture rather than real cloud access. This is
  what turns "this looks exploitable on paper" into "this was demonstrated."
- **Phase 3 -- if Phase 1 and 2 land solid**: a Kubernetes-based profile
  (via `kind`) for modeling cluster-adjacent trust paths, a graph
  visualization dashboard (React Flow), and a single `make demo` that ties
  scan -> lab validation -> visualization together.
- Automatic role -> resource discovery from real IAM permission policies
  (not just trust policies) is the biggest open gap in Phase 1's model and
  would need to land before the resource-reachability severity boost could
  be trusted without a hand-supplied `resources.json`.
- Broader OIDC subject-claim heuristics (custom branch naming conventions,
  GitHub Environments beyond the two conventional ones tried today) to
  reduce `roles_reachable_from_repo()`'s false-negative rate.
