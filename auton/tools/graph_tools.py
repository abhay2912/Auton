"""
Attack Graph tools for Auton v2.

These tools allow agents to interact with the shared Attack Graph.
Agents call these tools to:
- Add discovered assets, entry points, hypotheses
- Update node status (confirmed/failed)
- Query the graph for attack paths and summaries
"""

from typing import Optional
from auton.tools.registry import registry


# The shared graph instance is set by the runtime/orchestrator at startup.
# Tools access it via this module-level reference.
_shared_graph = None


def set_shared_graph(graph):
    """Called by the runtime to inject the shared Attack Graph."""
    global _shared_graph
    _shared_graph = graph


def _get_graph():
    if _shared_graph is None:
        raise RuntimeError("Attack Graph not initialized. Runtime must call set_shared_graph() first.")
    return _shared_graph


@registry.register
def add_asset(name: str, tech: str = "") -> str:
    """
    Register a discovered asset in the Attack Graph.
    Use when you identify a service, endpoint, or technology.
    
    Args:
        name: Asset identifier (e.g., 'web-app:443', 'api:8080/v1').
        tech: Technology stack (e.g., 'Flask', 'Express', 'Apache').
    """
    try:
        from auton.core.attack_graph import Severity
        graph = _get_graph()
        node_id = graph.add_asset(name, tech=tech)
        return f"Asset '{name}' added to graph (id: {node_id}, tech: {tech}). Graph now has {graph.stats()['total_nodes']} nodes."
    except Exception as e:
        return f"Error adding asset: {e}"


@registry.register
def add_entry_point(name: str, input_type: str = "text", parent_asset: str = "") -> str:
    """
    Register a discovered entry point (input vector) in the graph.
    Use when you find a form, URL parameter, header, or API input.
    
    Args:
        name: Entry point identifier (e.g., 'login-form-username', 'search-query-param').
        input_type: Type of input (text, url_param, header, cookie, file_upload, api_param).
        parent_asset: Optional asset node ID to link this entry point to.
    """
    try:
        from auton.core.attack_graph import EdgeRelation
        graph = _get_graph()
        node_id = graph.add_entry_point(name, input_type=input_type)
        
        if parent_asset:
            try:
                graph.add_edge(parent_asset, node_id, EdgeRelation.HAS_ENTRY_POINT)
            except Exception:
                pass  # Parent might not exist yet
        
        return f"Entry point '{name}' ({input_type}) added. {graph.stats()['total_nodes']} total nodes."
    except Exception as e:
        return f"Error adding entry point: {e}"


@registry.register
def add_hypothesis(name: str, severity: str = "medium", entry_point: str = "") -> str:
    """
    Register a vulnerability hypothesis to test.
    Use when you theorize a potential vulnerability.
    
    Args:
        name: Hypothesis description (e.g., 'Reflected XSS via search param').
        severity: Expected severity (low, medium, high, critical).
        entry_point: Optional entry point node ID this hypothesis targets.
    """
    try:
        from auton.core.attack_graph import Severity, EdgeRelation
        
        sev_map = {
            "low": Severity.LOW, "medium": Severity.MEDIUM,
            "high": Severity.HIGH, "critical": Severity.CRITICAL,
        }
        sev = sev_map.get(severity.lower(), Severity.MEDIUM)
        
        graph = _get_graph()
        node_id = graph.add_hypothesis(name, sev)
        
        if entry_point:
            try:
                graph.add_edge(entry_point, node_id, EdgeRelation.LEADS_TO)
            except Exception:
                pass
        
        return f"Hypothesis added: '{name}' [{severity.upper()}] (id: {node_id})"
    except Exception as e:
        return f"Error adding hypothesis: {e}"


@registry.register
def confirm_vulnerability(node_id: str, evidence: str) -> str:
    """
    Mark a hypothesis as CONFIRMED with evidence.
    Use when a vulnerability test succeeds and is verified.
    
    Args:
        node_id: The hypothesis node ID to confirm.
        evidence: Proof of exploitation (e.g., 'alert(1) fired', 'admin data returned').
    """
    try:
        graph = _get_graph()
        graph.mark_confirmed(node_id, evidence)
        node = graph.get_node(node_id)
        return f"CONFIRMED: '{node.name}' — Evidence: {evidence}"
    except Exception as e:
        return f"Error confirming vulnerability: {e}"


@registry.register  
def mark_failed(node_id: str, reason: str = "") -> str:
    """
    Mark a hypothesis as FAILED (not vulnerable).
    Use when a vulnerability test definitively fails.
    
    Args:
        node_id: The hypothesis node ID to mark as failed.
        reason: Why the test failed (e.g., 'input is HTML-encoded').
    """
    try:
        graph = _get_graph()
        graph.mark_failed(node_id, reason)
        return f"Marked '{node_id}' as FAILED: {reason}"
    except Exception as e:
        return f"Error marking as failed: {e}"


@registry.register
def get_graph_summary() -> str:
    """
    Get a compact summary of the current Attack Graph.
    Use to understand the overall attack surface and progress.
    """
    try:
        graph = _get_graph()
        return graph.summary()
    except Exception as e:
        return f"Error getting graph summary: {e}"


@registry.register
def find_attack_paths(from_node: str, to_node: str) -> str:
    """
    Find all attack paths between two nodes in the graph.
    Use to plan attack chains.
    
    Args:
        from_node: Starting node ID (usually an asset).
        to_node: Target node ID (usually a privilege).
    """
    try:
        graph = _get_graph()
        paths = graph.get_attack_paths(from_node, to_node)
        if not paths:
            return f"No paths found from '{from_node}' to '{to_node}'."
        
        result = f"Found {len(paths)} attack path(s):\n"
        for i, path in enumerate(paths):
            nodes = [graph.get_node(n).name for n in path]
            result += f"  Path {i+1}: {' → '.join(nodes)}\n"
        return result
    except Exception as e:
        return f"Error finding paths: {e}"
