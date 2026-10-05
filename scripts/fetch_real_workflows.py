#!/usr/bin/env python3
"""Download every GitHub Actions workflow file from a fixed list of public
repositories, pinned to a commit SHA, into data/raw/real_workflows/.

Two modes:

    python scripts/fetch_real_workflows.py            # re-download exactly what
                                                      # manifest.json pins (reproducible)
    python scripts/fetch_real_workflows.py --refresh  # resolve each repo's current
                                                      # default-branch HEAD and re-pin

Every file is checked against the SHA-256 recorded in the manifest, so the
committed raw data can be verified against GitHub at any time.

Network access: github.com over git (only with --refresh, to resolve the
default branch's HEAD and list .github/workflows/ via a blobless depth-1
clone) and raw.githubusercontent.com (file contents). No GitHub API calls
and no token: anyone can rerun this.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
# Only ever runs git with a fixed argument list and no shell.
import subprocess  # nosec B404
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = REPO_ROOT / "data" / "raw" / "real_workflows"
MANIFEST = RAW_DIR / "manifest.json"

# The same 12 repositories as the original evaluation, which scanned one
# hand-picked workflow from each. This version scans every workflow file in
# .github/workflows/ so the sample isn't chosen by the person grading it.
REPOS = [
    "actions/checkout",
    "actions/upload-artifact",
    "pallets/flask",
    "pypa/pip",
    "django/django",
    # facebook/react now redirects here (same HEAD commit). The canonical
    # name matters: React's workflows call `react/react/...@main`, which is
    # a reference into the repo itself, not a third-party one.
    "react/react",
    "vercel/next.js",
    "sindresorhus/awesome",
    "fastapi/fastapi",
    "fastapi/typer",
    "EbookFoundation/free-programming-books",
    "hashicorp/terraform-provider-aws",
]

MAX_FILE_BYTES = 1_000_000


def _get(url: str) -> bytes:
    headers = {"User-Agent": "trustgraph-evaluation"}
    host = urllib.parse.urlparse(url).hostname
    if host != "raw.githubusercontent.com":
        raise ValueError(f"refusing to fetch from unexpected host {host!r}")
    request = urllib.request.Request(url, headers=headers)
    # B310: the URL is https and its host was allow-listed just above.
    with urllib.request.urlopen(request, timeout=60) as response:  # nosec B310
        data = response.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f"{url}: response larger than {MAX_FILE_BYTES} bytes")
    return data


def _git(*args: str, cwd: Path | None = None) -> str:
    # B603/B607: fixed argv, no shell; "git" resolved from PATH on purpose.
    result = subprocess.run(  # nosec B603 B607
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True, timeout=300,
    )
    return result.stdout


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _local_dir(repo: str) -> Path:
    return RAW_DIR / repo.replace("/", "__")


def resolve(repo: str) -> dict:
    """Pin REPO to its default branch's current HEAD and list its workflows."""
    url = f"https://github.com/{repo}.git"
    # "ref: refs/heads/main\tHEAD" then "<sha>\tHEAD"
    lines = _git("ls-remote", "--symref", url, "HEAD").splitlines()
    branch = lines[0].split()[1].removeprefix("refs/heads/")
    with tempfile.TemporaryDirectory() as tmp:
        _git("clone", "--quiet", "--depth", "1", "--filter=blob:none", "--no-checkout",
             "--branch", branch, url, tmp)
        commit = _git("rev-parse", "HEAD", cwd=Path(tmp)).strip()
        listing = _git("ls-tree", "--name-only", "HEAD", ".github/workflows/", cwd=Path(tmp))
    files = sorted(p for p in listing.splitlines() if p.endswith((".yml", ".yaml")))
    return {"repo": repo, "default_branch": branch, "commit": commit,
            "files": [{"path": p} for p in files]}


def download(entry: dict) -> None:
    repo, commit = entry["repo"], entry["commit"]
    for item in entry["files"]:
        url = f"https://raw.githubusercontent.com/{repo}/{commit}/{urllib.parse.quote(item['path'])}"
        data = _get(url)
        digest = _sha256(data)
        if "sha256" in item and item["sha256"] != digest:
            raise SystemExit(f"{repo}/{item['path']}@{commit[:12]}: checksum mismatch "
                             f"({digest} != {item['sha256']})")
        item["sha256"] = digest
        item["bytes"] = len(data)
        item["url"] = url
        dest = _local_dir(repo) / item["path"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--refresh", action="store_true",
                        help="re-resolve each repo's current HEAD instead of using manifest.json")
    args = parser.parse_args()

    if args.refresh or not MANIFEST.exists():
        entries = []
        for repo in REPOS:
            entry = resolve(repo)
            print(f"{repo}: {entry['default_branch']} @ {entry['commit'][:12]}, "
                  f"{len(entry['files'])} workflow file(s)")
            entries.append(entry)
        manifest = {
            "fetched_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
            "note": "Every workflow file under .github/workflows/ at the pinned commit.",
            "repositories": entries,
        }
    else:
        manifest = json.loads(MANIFEST.read_text())
        print(f"Re-downloading the files pinned in {MANIFEST.relative_to(REPO_ROOT)} "
              f"(fetched {manifest['fetched_at']})")

    for entry in manifest["repositories"]:
        download(entry)
    total = sum(len(e["files"]) for e in manifest["repositories"])
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"{total} workflow files from {len(manifest['repositories'])} repositories, "
          f"all checksums recorded/verified in {MANIFEST.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
