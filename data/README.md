# Data

The real-world evaluation's inputs and every table derived from them.
Nothing here is hand-edited; see `docs/results.md` for what the numbers
mean.

```
raw/real_workflows/                    every .github/workflows/*.yml of 12 public repos
  manifest.json                        repo, default branch, pinned commit, per-file URL + SHA-256
  <owner>__<repo>/.github/workflows/   the files, byte-for-byte as served by GitHub
clean/
  action_references.csv                one row per `uses:` (868)
  job_permissions.csv                  one row per job (402)
  parse_errors.csv                     files the parser rejected (none)
processed/
  findings.csv                         every finding (20)
  summary_by_repo.csv                  per-repo counts
  summary.json                         totals
```

Rebuild:

```bash
python scripts/fetch_real_workflows.py      # re-download pinned files, verify SHA-256
python scripts/evaluate_real_workflows.py   # writes clean/ and processed/
python scripts/verify_findings.py           # re-checks findings with plain PyYAML
```

`fetch_real_workflows.py --refresh` re-pins every repo to its current
default-branch HEAD (via `git ls-remote` and a blobless depth-1 clone; no
GitHub API token needed). The numbers in the docs then need regenerating.

## Columns

**`clean/action_references.csv`**

| Column | Meaning |
|---|---|
| `kind` | `action` (a step's `uses:`), `reusable-workflow` (a job's `uses:`) or `docker` (`docker://`) |
| `uses`, `ref` | what is referenced, and at which tag / branch / SHA / digest |
| `pinned` | 1 if `ref` is a 40-character commit SHA (or a `sha256:` digest for docker) |
| `third_party` | 1 unless owned by `actions/` or `github/`, or a reference back into the scanned repo itself. This is the same definition the `unpinned-action` rule uses |
| `same_repo` | 1 if the reference points into the scanned repository |
| `job_requests_id_token` | 1 if the job holds `id-token: write` (job-level permissions, else the workflow's) |

**`clean/job_permissions.csv`**

| Column | Meaning |
|---|---|
| `permission_source` | `job`, `workflow` (inherited), or `unspecified` (no `permissions:` anywhere; the repo/org default applies and isn't visible in the YAML) |
| `write_scopes` | `;`-separated token scopes the job can write |
| `write_all` | 1 if the effective permissions are `write-all` |

## Licensing

The workflow files belong to their repositories and are kept here, unmodified,
as research data under each repository's own licence. All 12 are public
open-source projects; `manifest.json` links every file to its source at the
pinned commit.
