# Threat model

This is a STRIDE-style pass over TrustGraph itself (the tool), not over the
CI/CD misconfigurations it detects (those are covered in
`docs/detection-rules.md`).

## Scope

TrustGraph Phase 1 is a local static-analysis CLI. It reads files from a
directory the user points it at, writes results to a `.trustgraph/` state
directory inside that same target, and makes no network calls. The trust
boundary is narrow: local filesystem in, local filesystem out, run by
whoever invokes the CLI with whatever permissions they already have.

## Assets

- The workflow YAML and trust-policy JSON files being scanned (inputs).
- The `resources.json` role-to-resource mapping, and the `permission-policies/`
  and `known-resources.json` files, if supplied (inputs, and potentially
  sensitive -- they name real roles, permissions and cloud resources).
- `.trustgraph/findings.json` and `.trustgraph/graph.json` (outputs, which
  echo back everything in the inputs plus TrustGraph's own analysis).

## Spoofing

Not applicable in the current scope -- there's no authentication surface.
TrustGraph doesn't identify "who" is running it and doesn't need to; it has
no notion of a user identity distinct from the OS user invoking the CLI.

## Tampering

TrustGraph trusts its inputs completely: it reads and parses whatever YAML
and JSON files are in the target directory. This is intentional and safe
*for the CLI itself* under the same "you're already running arbitrary code
against files you control" logic as any local linter -- but two things
follow from it directly:

1. TrustGraph's findings are only as trustworthy as the files it read. If
   someone hands you a `.trustgraph/findings.json` from a scan you didn't
   run yourself, treat it as any other unverified report -- it doesn't
   prove anything about the actual repo unless you can re-run the scan.
2. YAML parsing uses `yaml.safe_load` (not `yaml.load`), specifically to
   avoid the classic PyYAML arbitrary-object-deserialization risk when
   parsing untrusted workflow files pulled from a third party (this
   matters concretely, since Phase 1's own evaluation deliberately scans
   public GitHub repos' workflow files -- see `docs/results.md`).

## Repudiation

Not a design goal for a local CLI with no shared state or audit trail
requirement. `.trustgraph/findings.json` is the record of what a given scan
found; there's no tamper-evidence on it and none is claimed.

## Information disclosure

This is the main real risk surface. `resources.json`, the permission policies and the resource catalog, and any supplied trust
policy JSON can describe real infrastructure (role names, resource names,
which roles reach which resources). `.trustgraph/findings.json` and
`graph.json` will echo that information back, verbatim, into a directory
inside the scanned repo. Two concrete implications, both called out in the
generated `README.md`:

- **Don't commit `.trustgraph/` to version control** if the scanned repo's
  workflows or trust policies contain anything sensitive beyond what's
  already in the repo. It's scan output, not source, and its purpose is
  local/CI-ephemeral inspection.
- **Don't scan a target with a `resources.json` you don't want echoed**
  into `findings.json`'s `evidence` and `path` fields verbatim.

Neither of these is unique to TrustGraph -- any SAST-style tool that reads
config and writes a report has the same shape of risk -- but it's worth
stating plainly rather than leaving it implicit.

## Scanning a repository you don't trust

The point of a scanner like this is to run it on repositories you didn't
write (the real-world evaluation scans 12 of them). A hostile repo
controls every file TrustGraph reads, so the CLI treats the target as
untrusted (`trustgraph/cli/main.py`, `trustgraph/parsers/_io.py`, tests in
`tests/test_hardening.py`):

| Threat | Control |
|---|---|
| Repo ships `.trustgraph` (or `.trustgraph/findings.json`) as a symlink, so writing scan output overwrites a file elsewhere, e.g. `~/.bashrc` | Output is refused if the state directory or either output file is a symlink |
| A workflow or trust-policy file is a symlink to a file outside the repo (`/etc/...`, `~/.aws/credentials`), so its contents get parsed and echoed into findings or errors | Inputs whose resolved path is outside the target are skipped with a warning; an auto-discovered `resources.json` outside the target is an error |
| Action names, step names or job ids containing ANSI escape sequences that rewrite the terminal (hide findings, fake output) | Every line the CLI prints has C0/C1 control characters replaced with `?` |
| Multi-gigabyte input files | Each input is size-checked before reading (1 MB cap) |
| Malformed YAML/JSON, or valid YAML of the wrong shape | Parse errors become a one-line error, not a traceback; non-mapping steps are skipped; `resources.json` is schema-checked |

## Denial of service

Graph traversal is narrow (`descendants` and short, explicit path
constructions built by the detection engine, never an all-paths search).
Graph size scales with the number of input files, each capped at 1 MB.
`yaml.safe_load` keeps YAML aliases as shared references rather than
expanding them, and the parser only walks `jobs` and `steps`, so a
"billion laughs" alias bomb doesn't multiply work here.

## Elevation of privilege

TrustGraph itself requests no privileges beyond ordinary filesystem read/
write in the target directory. It never authenticates to GitHub, AWS, or
any other service, and Phase 1 has no code path that could execute an
attacker-controlled action even in principle -- workflow YAML is data to
TrustGraph, never something it runs. (This is exactly the property Phase 2
deliberately gives up, in a separate, explicitly disposable environment --
see `docs/architecture.md`'s roadmap section for why that's handled as its
own isolated system rather than folded into Phase 1's trust boundary.)

## Supply chain (of TrustGraph itself)

Same discipline as SentinelFlow: dependencies pinned in `requirements.txt`,
`pip-audit -r requirements.txt` run against exactly this project's own
dependency set (not the ambient environment) as part of CI, and `bandit`
run over the source tree. See `.github/workflows/ci.yml`.
