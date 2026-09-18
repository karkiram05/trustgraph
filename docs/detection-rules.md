# Detection rules

Four rules, each corresponding to a documented, real-world CI/CD
supply-chain anti-pattern rather than an invented one. Sources: GitHub's
own OIDC hardening documentation, and public writeups on overpermissioned
Actions tokens and unpinned third-party actions.

## TG rule: `overpermissioned-token`

**What it checks:** a job with `id-token: write` (requesting an OIDC cloud
credential) that *also* holds `contents: write` or `actions: write` on the
`GITHUB_TOKEN`.

**Why it matters:** the OIDC token exchange itself only needs
`id-token: write`. Everything else should be minted narrowly by the
assumed cloud role afterward, not sitting in the GitHub-side token too. A
job with both means a single compromised step can pivot from repo/workflow
write access straight into a cloud credential exchange, in one job, with no
extra hop.

**Severity:** HIGH by default; CRITICAL if the graph can trace this repo's
OIDC subject to a trust policy whose role has a known reachable resource
(via `resources.json`).

**Input required:** workflow YAML only (a trust policy and resource map
sharpen severity but aren't required to fire).

## TG rule: `wildcard-oidc-trust`

**What it checks:** an IAM trust policy that trusts GitHub's OIDC provider
(`token.actions.githubusercontent.com`) with a subject (`sub`) condition
that either contains a `*` wildcard, or isn't scoped down to a specific
`ref` or `environment` segment at all.

**Why it matters:** a trust policy scoped only to `repo:org/*:*` (or
similar) means *any* workflow run in *any* matching repo -- potentially a
feature branch, a fork's pull-request build, or an unrelated repo the
wildcard happens to cover -- can assume the role, not just the specific
deploy workflow the policy was meant for.

**Severity:** HIGH by default; CRITICAL if a resource is reachable from
that role in `resources.json`.

**Input required:** an IAM trust policy JSON file (`trust-policies/*.json`).
Does not require workflow YAML to fire, since the misconfiguration is
entirely on the AWS side.

## TG rule: `missing-audience-restriction`

**What it checks:** a GitHub-OIDC-trusting IAM policy whose `Condition`
doesn't pin `token.actions.githubusercontent.com:aud` to exactly
`sts.amazonaws.com`.

**Why it matters:** GitHub's own OIDC hardening guidance recommends pinning
both the audience *and* the subject as independent conditions. This isn't
independently exploitable -- it's a defense-in-depth gap that matters most
if the subject condition is ever loosened or misconfigured later.

**Severity:** MEDIUM, unconditionally (not resource-reachability-adjusted;
its risk isn't really about reachability, it's about the trust policy
having one fewer independent guard).

**Input required:** IAM trust policy JSON only.

## TG rule: `unpinned-action`

**What it checks:** any third-party action (`owner/action`, where `owner`
isn't `actions` or `github`) referenced by a mutable ref -- a tag or branch
name -- instead of a full 40-character commit SHA.

**Why it matters:** whoever controls that ref can change what code runs in
your CI at any time, with whatever permissions the job holds. This is the
supply-chain attack class behind several real GitHub Actions incidents:
compromise the action's repo (or its release/tag process), and every
downstream workflow pulling `@v2` starts running the attacker's code on its
next run with no changes needed on the victim's side.

**Severity:** MEDIUM if the job doesn't request an OIDC token. HIGH if it
does (the action's code runs with that job's full permission set,
including the ability to mint the cloud credential). CRITICAL if, in
addition, a resource is reachable from a role this repo's OIDC subject
would satisfy.

**Input required:** workflow YAML only. This is the only rule of the four
whose entire input is a single public file, which is why it's the only one
validated against real-world data in `docs/results.md` -- trust policies
and resource maps aren't published alongside a repo's workflows, so there's
no public corpus to test the other three rules against the way NSL-KDD
served SentinelFlow. They're covered by unit tests and the hand-crafted
`examples/vulnerable-project` walkthrough instead.

## What's intentionally not a rule (yet)

- **Self-hosted runner exposure on public repos** (a well-known real
  attack: a self-hosted runner accepting `pull_request` triggers from
  forks). Not implemented in Phase 1 because it requires knowing the
  runner's actual hosting/network context, not just the YAML -- workflow
  YAML alone can't distinguish a properly network-isolated self-hosted
  runner from an exposed one.
- **Script injection via untrusted `${{ }}` expression interpolation**
  (e.g. `run: echo "${{ github.event.issue.title }}"`) -- a real and
  common GitHub Actions vulnerability class, deliberately deferred rather
  than shipped half-built; it needs its own tainted-expression tracker, not
  a bolt-on to the existing four rules.
- **Third-party action *permission requests* beyond pinning** (an action
  could be pinned to a SHA and still be malicious at that SHA) -- out of
  scope for static analysis of the calling workflow; this is closer to
  supply-chain provenance verification (Sigstore/SLSA-style) than to
  anything TrustGraph's current model addresses.
