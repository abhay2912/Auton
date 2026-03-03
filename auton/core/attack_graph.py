"""
Attack Graph Model for Auton v2.

Models the target environment as a directed graph where:
- Nodes represent assets, entry points, vulnerabilities, and privileges
- Edges represent relationships and attack transitions
- The graph evolves as agents discover and test the target

This is the shared state that all agents read/write through graph tools.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum
import uuid
import json
from datetime import datetime


# ─── Enums ──────────────────────────────────────────────────────────

class NodeType(Enum):
    ASSET = "asset"                 # A target system/service (e.g., web-app:443)
    ENTRY_POINT = "entry_point"     # An input vector (form field, URL param, header)
    VULNERABILITY = "vulnerability" # A potential or confirmed vuln (XSS, SQLi, etc.)
    PRIVILEGE = "privilege"         # An access level (anonymous, authenticated, admin)


class NodeStatus(Enum):
    DISCOVERED = "discovered"     # Found during recon
    HYPOTHESIS = "hypothesis"     # Theorized by hypothesis engine
    TESTING = "testing"           # Currently being tested by a worker
    CONFIRMED = "confirmed"       # Verified by the verifier agent
    FAILED = "failed"             # Tested but not exploitable
    MITIGATED = "mitigated"       # Was confirmed but has been patched


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EdgeRelation(Enum):
    HAS_ENTRY_POINT = "has_entry_point"     # asset -> entry_point
    LEADS_TO = "leads_to"                   # entry_point -> vulnerability
    EXPLOITS = "exploits"                   # vulnerability -> privilege
    ESCALATES_TO = "escalates_to"           # privilege -> privilege
    DEPENDS_ON = "depends_on"              # vulnerability -> vulnerability (chained)
    SAME_ORIGIN = "same_origin"            # asset -> asset (same host)


# ─── Data Classes ───────────────────────────────────────────────────

@dataclass
class AttackNode:
    """A node in the attack graph."""
    id: str
    type: NodeType
    label: str
    status: NodeStatus = NodeStatus.DISCOVERED
    severity: Optional[Severity] = None
    metadata: Dict = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type.value,
            "label": self.label,
            "status": self.status.value,
            "severity": self.severity.value if self.severity else None,
            "metadata": self.metadata,
            "evidence": self.evidence,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class AttackEdge:
    """A directed edge in the attack graph."""
    source_id: str
    target_id: str
    relation: EdgeRelation
    confidence: float = 0.5     # 0.0 = speculative, 1.0 = proven
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "source": self.source_id,
            "target": self.target_id,
            "relation": self.relation.value,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


# ─── Attack Graph ───────────────────────────────────────────────────

class AttackGraph:
    """
    Directed graph representing the target's attack surface.
    
    Thread-safe shared state accessed by all agents via graph tools.
    Supports querying, path-finding, and serialization for LLM context.
    """
    
    def __init__(self):
        self.nodes: Dict[str, AttackNode] = {}
        self.edges: List[AttackEdge] = []
        self._adjacency: Dict[str, List[str]] = {}  # node_id -> [neighbor_ids]
    
    # ─── Node Operations ────────────────────────────────────────────
    
    def add_node(self, node_type: NodeType, label: str, 
                 status: NodeStatus = NodeStatus.DISCOVERED,
                 severity: Optional[Severity] = None,
                 metadata: Optional[Dict] = None) -> str:
        """Add a node to the graph. Returns the generated node ID."""
        node_id = f"{node_type.value}-{uuid.uuid4().hex[:8]}"
        node = AttackNode(
            id=node_id,
            type=node_type,
            label=label,
            status=status,
            severity=severity,
            metadata=metadata or {},
        )
        self.nodes[node_id] = node
        self._adjacency.setdefault(node_id, [])
        return node_id
    
    def add_asset(self, label: str, **metadata) -> str:
        """Convenience: add an asset node."""
        return self.add_node(NodeType.ASSET, label, metadata=metadata)
    
    def add_entry_point(self, label: str, **metadata) -> str:
        """Convenience: add an entry point node."""
        return self.add_node(NodeType.ENTRY_POINT, label, metadata=metadata)
    
    def add_hypothesis(self, label: str, severity: Severity = Severity.MEDIUM, 
                       **metadata) -> str:
        """Convenience: add a vulnerability hypothesis."""
        return self.add_node(
            NodeType.VULNERABILITY, label,
            status=NodeStatus.HYPOTHESIS,
            severity=severity,
            metadata=metadata,
        )
    
    def add_privilege(self, label: str, **metadata) -> str:
        """Convenience: add a privilege level node."""
        return self.add_node(NodeType.PRIVILEGE, label, metadata=metadata)
    
    def get_node(self, node_id: str) -> Optional[AttackNode]:
        """Get a node by ID."""
        return self.nodes.get(node_id)
    
    def update_status(self, node_id: str, status: NodeStatus, 
                      evidence: Optional[str] = None) -> bool:
        """Update a node's status. Optionally append evidence."""
        node = self.nodes.get(node_id)
        if not node:
            return False
        node.status = status
        node.updated_at = datetime.utcnow().isoformat()
        if evidence:
            node.evidence.append(evidence)
        return True
    
    def mark_confirmed(self, node_id: str, evidence: str) -> bool:
        """Mark a vulnerability as confirmed with evidence."""
        return self.update_status(node_id, NodeStatus.CONFIRMED, evidence)
    
    def mark_failed(self, node_id: str, reason: str) -> bool:
        """Mark a hypothesis as failed."""
        return self.update_status(node_id, NodeStatus.FAILED, reason)
    
    def mark_testing(self, node_id: str) -> bool:
        """Mark a node as currently being tested."""
        return self.update_status(node_id, NodeStatus.TESTING)
    
    # ─── Edge Operations ────────────────────────────────────────────
    
    def add_edge(self, source_id: str, target_id: str, 
                 relation: EdgeRelation, confidence: float = 0.5,
                 metadata: Optional[Dict] = None) -> bool:
        """Add a directed edge between two nodes."""
        if source_id not in self.nodes or target_id not in self.nodes:
            return False
        edge = AttackEdge(
            source_id=source_id,
            target_id=target_id,
            relation=relation,
            confidence=confidence,
            metadata=metadata or {},
        )
        self.edges.append(edge)
        self._adjacency.setdefault(source_id, []).append(target_id)
        return True
    
    # ─── Query Operations ───────────────────────────────────────────
    
    def get_nodes_by_type(self, node_type: NodeType) -> List[AttackNode]:
        """Get all nodes of a specific type."""
        return [n for n in self.nodes.values() if n.type == node_type]
    
    def get_nodes_by_status(self, status: NodeStatus) -> List[AttackNode]:
        """Get all nodes with a specific status."""
        return [n for n in self.nodes.values() if n.status == status]
    
    def get_untested_hypotheses(self) -> List[AttackNode]:
        """Get all vulnerability hypotheses that haven't been tested yet."""
        return [
            n for n in self.nodes.values()
            if n.type == NodeType.VULNERABILITY and n.status == NodeStatus.HYPOTHESIS
        ]
    
    def get_confirmed_vulnerabilities(self) -> List[AttackNode]:
        """Get all confirmed vulnerabilities."""
        return [
            n for n in self.nodes.values()
            if n.type == NodeType.VULNERABILITY and n.status == NodeStatus.CONFIRMED
        ]
    
    def get_neighbors(self, node_id: str) -> List[AttackNode]:
        """Get all nodes directly connected from this node."""
        neighbor_ids = self._adjacency.get(node_id, [])
        return [self.nodes[nid] for nid in neighbor_ids if nid in self.nodes]
    
    def get_edges_from(self, node_id: str) -> List[AttackEdge]:
        """Get all edges originating from a node."""
        return [e for e in self.edges if e.source_id == node_id]
    
    def get_edges_to(self, node_id: str) -> List[AttackEdge]:
        """Get all edges pointing to a node."""
        return [e for e in self.edges if e.target_id == node_id]
    
    # ─── Path Finding ───────────────────────────────────────────────
    
    def get_attack_paths(self, from_id: str, to_id: str, 
                         max_depth: int = 10) -> List[List[str]]:
        """
        Find all attack paths from source to target (BFS/DFS).
        Returns list of paths, where each path is a list of node IDs.
        """
        if from_id not in self.nodes or to_id not in self.nodes:
            return []
        
        paths = []
        stack = [(from_id, [from_id])]
        
        while stack:
            current, path = stack.pop()
            if current == to_id:
                paths.append(path)
                continue
            if len(path) >= max_depth:
                continue
            for neighbor_id in self._adjacency.get(current, []):
                if neighbor_id not in path:  # Avoid cycles
                    stack.append((neighbor_id, path + [neighbor_id]))
        
        return paths
    
    # ─── Serialization ──────────────────────────────────────────────
    
    def to_dict(self) -> dict:
        """Full graph serialization."""
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "stats": self.stats(),
        }
    
    def stats(self) -> dict:
        """Quick statistics about the graph state."""
        return {
            "total_nodes": len(self.nodes),
            "assets": len(self.get_nodes_by_type(NodeType.ASSET)),
            "entry_points": len(self.get_nodes_by_type(NodeType.ENTRY_POINT)),
            "hypotheses": len(self.get_untested_hypotheses()),
            "confirmed": len(self.get_confirmed_vulnerabilities()),
            "failed": len(self.get_nodes_by_status(NodeStatus.FAILED)),
            "total_edges": len(self.edges),
        }
    
    def summary(self) -> str:
        """
        Compact text summary for embedding in LLM prompts.
        Designed to be token-efficient while preserving key information.
        """
        s = self.stats()
        lines = [
            f"=== Attack Graph Summary ===",
            f"Assets: {s['assets']} | Entry Points: {s['entry_points']} | "
            f"Hypotheses: {s['hypotheses']} | Confirmed: {s['confirmed']} | "
            f"Failed: {s['failed']}",
        ]
        
        # List confirmed vulns
        confirmed = self.get_confirmed_vulnerabilities()
        if confirmed:
            lines.append("\nConfirmed Vulnerabilities:")
            for v in confirmed:
                sev = v.severity.value.upper() if v.severity else "?"
                lines.append(f"  [{sev}] {v.label} (evidence: {len(v.evidence)} items)")
        
        # List untested hypotheses
        untested = self.get_untested_hypotheses()
        if untested:
            lines.append(f"\nUntested Hypotheses ({len(untested)}):")
            for h in untested[:10]:  # Cap to avoid prompt bloat
                sev = h.severity.value if h.severity else "?"
                lines.append(f"  [{sev}] {h.label}")
            if len(untested) > 10:
                lines.append(f"  ... and {len(untested) - 10} more")
        
        # List assets
        assets = self.get_nodes_by_type(NodeType.ASSET)
        if assets:
            lines.append(f"\nAssets ({len(assets)}):")
            for a in assets:
                ep_count = len([e for e in self.edges 
                               if e.source_id == a.id 
                               and e.relation == EdgeRelation.HAS_ENTRY_POINT])
                lines.append(f"  {a.label} ({ep_count} entry points)")
        
        return "\n".join(lines)
    
    def to_json(self, indent: int = 2) -> str:
        """JSON serialization."""
        return json.dumps(self.to_dict(), indent=indent)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'AttackGraph':
        """Deserialize from dict."""
        graph = cls()
        for nd in data.get("nodes", []):
            node = AttackNode(
                id=nd["id"],
                type=NodeType(nd["type"]),
                label=nd["label"],
                status=NodeStatus(nd["status"]),
                severity=Severity(nd["severity"]) if nd.get("severity") else None,
                metadata=nd.get("metadata", {}),
                evidence=nd.get("evidence", []),
                created_at=nd.get("created_at", ""),
                updated_at=nd.get("updated_at", ""),
            )
            graph.nodes[node.id] = node
            graph._adjacency.setdefault(node.id, [])
        
        for ed in data.get("edges", []):
            edge = AttackEdge(
                source_id=ed["source"],
                target_id=ed["target"],
                relation=EdgeRelation(ed["relation"]),
                confidence=ed.get("confidence", 0.5),
                metadata=ed.get("metadata", {}),
            )
            graph.edges.append(edge)
            graph._adjacency.setdefault(edge.source_id, []).append(edge.target_id)
        
        return graph
