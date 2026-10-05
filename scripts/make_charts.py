#!/usr/bin/env python3
"""Draw docs/figures/*.png from the real-world evaluation tables and from a
live scan of examples/vulnerable-project. Reads only files the other
scripts write, so a chart can't disagree with the data behind it.

Usage:
    python scripts/evaluate_real_workflows.py
    python scripts/make_charts.py
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from trustgraph.detections.engine import run_detections  # noqa: E402
from trustgraph.graph.builder import build_graph, load_resource_access  # noqa: E402
from trustgraph.parsers.github_actions import parse_workflow  # noqa: E402
from trustgraph.parsers.iam_trust import parse_trust_policy  # noqa: E402

PROCESSED = REPO_ROOT / "data" / "processed"
CLEAN = REPO_ROOT / "data" / "clean"
FIGURES = REPO_ROOT / "docs" / "figures"

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
BASELINE = "#c3c2b7"
BLUE, ORANGE, AQUA, VIOLET = "#2a78d6", "#eb6834", "#1baf7a", "#4a3aa7"
SEVERITY = {"CRITICAL": "#d03b3b", "HIGH": "#ec835a", "MEDIUM": "#fab219", "LOW": "#0ca30c"}


def style():
    plt.rcParams.update({
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
        "axes.edgecolor": BASELINE, "axes.labelcolor": INK_2, "text.color": INK,
        "xtick.color": MUTED, "ytick.color": INK_2, "axes.grid": True, "grid.color": GRID,
        "grid.linewidth": 0.8, "axes.axisbelow": True, "axes.spines.top": False,
        "axes.spines.right": False, "font.family": "DejaVu Sans", "font.size": 10,
        "axes.titlesize": 12, "axes.titleweight": "bold", "axes.titlelocation": "left",
    })


def read_csv(path: Path) -> list[dict]:
    with path.open() as handle:
        return list(csv.DictReader(handle))


def save(fig, name: str):
    FIGURES.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURES / name, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Wrote docs/figures/{name}")


def stacked_barh(ax, labels, series, colors, names):
    left = [0] * len(labels)
    for values, color, name in zip(series, colors, names):
        ax.barh(labels, values, left=left, color=color, edgecolor=SURFACE, linewidth=1.5,
                height=0.65, label=name)
        left = [a + b for a, b in zip(left, values)]
    return left


def pinning_by_repo(rows):
    rows = sorted(rows, key=lambda r: int(r["third_party_references"]))
    labels = [r["repo"] for r in rows]
    pinned = [int(r["third_party_pinned"]) for r in rows]
    unpinned = [int(r["third_party_unpinned"]) for r in rows]
    fig, ax = plt.subplots(figsize=(8, 5.2))
    ax.grid(axis="y", visible=False)
    totals = stacked_barh(ax, labels, [pinned, unpinned], [BLUE, ORANGE],
                          ["Pinned to a commit SHA / digest", "Mutable tag or branch"])
    for i, (total, bad) in enumerate(zip(totals, unpinned)):
        text = f"{bad} of {total} unpinned" if total else "no third-party refs"
        ax.text(total + 0.6, i, text, va="center", fontsize=8, color=INK_2)
    ax.set_xlim(0, max(totals) * 1.3)
    ax.set_xlabel("Third-party action / reusable workflow / image references")
    ax.set_title("Third-party references by repository (all workflows, pinned commits)")
    ax.legend(loc="lower right", frameon=True, facecolor=SURFACE, edgecolor=GRID)
    save(fig, "pinning_by_repo.png")


def findings_by_repo(rows):
    rows = sorted(rows, key=lambda r: int(r["findings"]))
    labels = [r["repo"] for r in rows]
    bands = [b for b in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
             if any(int(r[f"findings_{b.lower()}"]) for r in rows)]
    fig, ax = plt.subplots(figsize=(8, 5.2))
    ax.grid(axis="y", visible=False)
    totals = stacked_barh(ax, labels, [[int(r[f"findings_{b.lower()}"]) for r in rows] for b in bands],
                          [SEVERITY[b] for b in bands], bands)
    for i, total in enumerate(totals):
        ax.text(total + 0.15, i, str(total) if total else "clean", va="center", fontsize=8, color=INK_2)
    ax.set_xlim(0, max(totals) * 1.25 + 1)
    ax.set_xlabel("Findings")
    ax.set_title(f"TrustGraph findings on 12 public repositories ({sum(totals)} total)")
    ax.legend(loc="lower right", frameon=True, facecolor=SURFACE, edgecolor=GRID, title="Severity")
    save(fig, "findings_by_repo.png")


def permission_sources(jobs):
    repos = sorted({j["repo"] for j in jobs})
    sources = [("job", "Set on the job", BLUE), ("workflow", "Inherited from the workflow", AQUA),
               ("unspecified", "Not declared (repo/org default applies)", ORANGE)]
    counts = {s: [sum(1 for j in jobs if j["repo"] == r and j["permission_source"] == s)
                  for r in repos] for s, _, _ in sources}
    totals = [sum(counts[s][i] for s, _, _ in sources) for i in range(len(repos))]
    order = sorted(range(len(repos)), key=lambda i: totals[i])
    fig, ax = plt.subplots(figsize=(8, 5.2))
    ax.grid(axis="y", visible=False)
    stacked_barh(ax, [repos[i] for i in order], [[counts[s][i] for i in order] for s, _, _ in sources],
                 [c for _, _, c in sources], [n for _, n, _ in sources])
    unspecified = sum(counts["unspecified"])
    ax.set_xlabel("Jobs")
    ax.set_title(f"Where each job's GITHUB_TOKEN permissions come from ({len(jobs)} jobs)")
    ax.text(0, -0.13, f"{unspecified} jobs declare no permissions at all, so their token scope depends on a "
            "repo/org setting the YAML doesn't show.", transform=ax.transAxes, fontsize=8, color=INK_2)
    ax.legend(loc="lower right", frameon=True, facecolor=SURFACE, edgecolor=GRID)
    save(fig, "permission_sources.png")


def attack_path_example():
    """Draw the trust graph of examples/vulnerable-project from a live scan."""
    target = REPO_ROOT / "examples" / "vulnerable-project"
    workflows = [parse_workflow(p) for p in sorted((target / ".github" / "workflows").glob("*.yml"))]
    for wf in workflows:
        wf.path = str(Path(wf.path).relative_to(target))
    policies = [parse_trust_policy(p) for p in sorted((target / "trust-policies").glob("*.json"))]
    resources = load_resource_access(target / "resources.json")
    repo = "my-org/vulnerable-project"
    graph = build_graph(workflows, policies, resources, repo_name=repo)
    findings = run_detections(workflows, policies, graph, repo_name=repo)
    path = next(f.path for f in findings if f.rule_id == "overpermissioned-token")

    layer_of = {"repo": 0, "workflow": 1, "action": 2, "oidc": 2, "role": 3, "resource": 4}
    color_of = {"repo": INK_2, "workflow": BLUE, "action": ORANGE, "oidc": VIOLET,
                "role": "#d03b3b", "resource": "#d03b3b"}
    nodes = [n.id for n in graph.nodes()]
    layers: dict[int, list[str]] = {}
    for node in nodes:
        layers.setdefault(layer_of[node.split(":", 1)[0]], []).append(node)
    pos = {}
    for x, members in layers.items():
        members.sort(key=lambda n: (n.split(":")[0] != "oidc", n))
        for k, node in enumerate(members):
            pos[node] = (x * 2.6, (len(members) - 1) / 2 - k)

    on_path = set(path)
    fig, ax = plt.subplots(figsize=(12, 4.6))
    ax.axis("off")
    boxes = {}
    for node, (x, y) in pos.items():
        kind, name = node.split(":", 1)
        name = Path(name).name if kind == "workflow" else name
        boxes[node] = ax.text(
            x, y, f"{kind}\n{name}", ha="center", va="center", fontsize=8, color=INK, zorder=3,
            bbox=dict(boxstyle="round,pad=0.45", facecolor=SURFACE,
                      edgecolor=color_of[kind], linewidth=2 if node in on_path else 1))
    for edge in graph.edges():
        hot = edge.source in on_path and edge.target in on_path
        # Anchor to the boxes themselves so arrowheads stop at the box edge.
        ax.annotate("", xy=(0, 0.5), xycoords=boxes[edge.target],
                    xytext=(1, 0.5), textcoords=boxes[edge.source], zorder=2,
                    arrowprops=dict(arrowstyle="-|>", color="#d03b3b" if hot else BASELINE,
                                    lw=2.2 if hot else 1.2, shrinkA=4, shrinkB=4))
    xs = [p[0] for p in pos.values()]
    ys = [p[1] for p in pos.values()]
    ax.set_xlim(min(xs) - 1.2, max(xs) + 1.2)
    ax.set_ylim(min(ys) - 0.8, max(ys) + 0.8)
    ax.set_title("examples/vulnerable-project: trust graph, attack path for "
                 "\"Overpowered GitHub Actions token\" in red")
    save(fig, "attack_path_example.png")


def main():
    style()
    repos = read_csv(PROCESSED / "summary_by_repo.csv")
    summary = json.loads((PROCESSED / "summary.json").read_text())
    if sum(int(r["findings"]) for r in repos) != summary["findings"]:
        raise SystemExit("summary_by_repo.csv and summary.json disagree; rerun the evaluation")
    pinning_by_repo(repos)
    findings_by_repo(repos)
    permission_sources(read_csv(CLEAN / "job_permissions.csv"))
    attack_path_example()


if __name__ == "__main__":
    main()
