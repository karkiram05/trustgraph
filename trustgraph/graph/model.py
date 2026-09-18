"""The trust graph: nodes are identities/resources, edges are trust or
capability relationships between them ("X can act as Y", "X can reach Y").

This is deliberately a thin wrapper over networkx rather than a bespoke
graph implementation -- the value in this project is the domain modeling
(what counts as a node, what counts as an edge, which paths are dangerous),
not reimplementing graph traversal that a well-tested library already does
correctly.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterator

import networkx as nx


class NodeType(str, Enum):
    REPOSITORY = "repository"
    WORKFLOW = "workflow"
    THIRD_PARTY_ACTION = "third_party_action"
    OIDC_PROVIDER = "oidc_provider"
    IAM_ROLE = "iam_role"
    CLOUD_RESOURCE = "cloud_resource"


class EdgeType(str, Enum):
    DEFINES = "defines"                # repository -> workflow
    USES_ACTION = "uses_action"        # workflow -> third_party_action
    REQUESTS_TOKEN = "requests_token"  # workflow -> oidc_provider  # nosec B105 (enum value, not a credential)
    TRUSTS = "trusts"                  # oidc_provider -> iam_role (per trust policy)
    CAN_ACCESS = "can_access"          # iam_role -> cloud_resource


@dataclass
class Node:
    id: str
    type: NodeType
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    source: str
    target: str
    type: EdgeType
    attrs: dict[str, Any] = field(default_factory=dict)


class TrustGraph:
    def __init__(self) -> None:
        self._g = nx.DiGraph()

    def add_node(self, node: Node) -> None:
        self._g.add_node(node.id, type=node.type, attrs=node.attrs)

    def add_edge(self, edge: Edge) -> None:
        self._g.add_edge(edge.source, edge.target, type=edge.type, attrs=edge.attrs)

    def node(self, node_id: str) -> Node:
        data = self._g.nodes[node_id]
        return Node(id=node_id, type=data["type"], attrs=data["attrs"])

    def nodes(self, of_type: NodeType | None = None) -> Iterator[Node]:
        for node_id, data in self._g.nodes(data=True):
            if of_type is None or data["type"] == of_type:
                yield Node(id=node_id, type=data["type"], attrs=data["attrs"])

    def edges(self) -> Iterator[Edge]:
        for u, v, data in self._g.edges(data=True):
            yield Edge(source=u, target=v, type=data["type"], attrs=data["attrs"])

    def out_edges(self, node_id: str) -> Iterator[Edge]:
        for u, v, data in self._g.out_edges(node_id, data=True):
            yield Edge(source=u, target=v, type=data["type"], attrs=data["attrs"])

    def all_paths(self, source: str, target: str) -> list[list[str]]:
        """All simple paths from source to target -- the raw material for
        an attack path. Empty list if target isn't reachable."""
        if source not in self._g or target not in self._g:
            return []
        return list(nx.all_simple_paths(self._g, source, target))

    def reachable_from(self, source: str) -> set[str]:
        if source not in self._g:
            return set()
        return nx.descendants(self._g, source)

    def __len__(self) -> int:
        return self._g.number_of_nodes()

    def to_dict(self) -> dict:
        return {
            "nodes": [
                {"id": n.id, "type": n.type.value, "attrs": n.attrs}
                for n in self.nodes()
            ],
            "edges": [
                {"source": e.source, "target": e.target, "type": e.type.value, "attrs": e.attrs}
                for e in self.edges()
            ],
        }
