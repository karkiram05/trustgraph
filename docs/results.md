# Real-world evaluation

TrustGraph's unit tests use hand-crafted fixtures (deliberately vulnerable
and deliberately hardened examples) to pin down exact rule behavior. That
proves the rules fire correctly on cases built to trigger them. It doesn't
prove the rules behave sensibly on workflows nobody wrote to test a scanner.

So, following the same discipline used for SentinelFlow (evaluated against
real NSL-KDD traffic, not just synthetic attacks), TrustGraph was pointed at
public GitHub Actions workflows it had never seen, pulled live from GitHub at
evaluation time.

## What was scanned

12 real workflow files from 9 public repositories, fetched directly from
`raw.githubusercontent.com`:

| Repository | Workflow | Result |
|---|---|---|
| actions/checkout | (dogfooded example) | No findings |
| actions/upload-artifact | (dogfooded example) | No findings |
| pallets/flask | CI | No findings |
| pypa/pip | CI | No findings |
| django/django | CI | No findings |
| facebook/react | CI | No findings |
| vercel/next.js | CI | No findings |
| sindresorhus/awesome | lint | No findings |
| tiangolo/fastapi | test | No findings |
| tiangolo/typer | test | No findings |
| EbookFoundation/free-programming-books | fpb-lint | No findings |
| hashicorp/terraform-provider-aws | build | **3 MEDIUM findings** |

## Reading the negatives honestly

11 of 12 workflows scanned clean. That is not "the tool found nothing" in
the bad sense (a parser silently failing open) -- it was checked directly:
for every clean file, the workflow was independently parsed and every job's
effective permissions, every `id-token` request, and every action reference
(pinned or not, first- or third-party) were printed and inspected by hand.
The pattern holds: these are large, actively maintained projects, and their
CI workflows are in fact mostly first-party actions (`actions/*`), pinned
where they do use third-party actions, and none of them mix `id-token:
write` with broad `contents`/`actions` write permissions in a way that
would be flagged. That is a genuine true-negative result, not a bug.

It also means the sample undersells recall: mature, high-visibility OSS
projects are exactly the population least likely to have sloppy CI. That's
why the sample was deliberately widened to a 9th, less centrally-maintained
repository rather than stopping at "large projects look clean."

## The one real true positive

`hashicorp/terraform-provider-aws`'s build workflow references three
HashiCorp-owned actions (`actions-set-product-version`,
`actions-generate-metadata`, `actions-go-build`) by mutable tag (`v2`, `v1`)
rather than commit SHA. TrustGraph correctly flagged all three as MEDIUM
(third-party, unpinned, not in an OIDC-elevated job -- which is exactly the
severity band the rule is supposed to assign to this pattern; see
`docs/detection-rules.md`). `trustgraph explain TG-001` produces a full
attack path and concrete remediation for a finding on a workflow nobody
wrote for this project. That's the evidence this tool needed: not just "it
fires on my fixture," but "it fires correctly on something real."

## What this evaluation does not cover

No real-world example in this sample combines `id-token: write` with an
actual cloud IAM trust policy (`overpermissioned-token`,
`wildcard-oidc-trust`, `missing-audience-restriction` all require a trust
policy document as input, which isn't published alongside a repo's
workflow files -- see `docs/architecture.md` for why that's an inherent
input-availability limit, not a rule-design gap). Those three rules are
covered by the unit tests and the hand-crafted `examples/vulnerable-project`
walkthrough, but not by a real-world positive here, because the required
input simply isn't public for any repository. The `unpinned-action` rule is
the only one of the four for which "the whole input is one public YAML
file" is even possible, so it's the only one this kind of evaluation could
validate against real-world data. Anyone using TrustGraph against their own
repo also has their own IAM trust policy on hand, which is a different (and
better) evaluation position than a public scan like this one.
