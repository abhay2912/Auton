"""
Agent coordination tools for Auton v2.

These tools allow agents to communicate via the shared message board
and interact with the knowledge base.
"""

from typing import Optional
from auton.tools.registry import registry


# Shared memory reference (injected by runtime)
_shared_memory = None
_knowledge_base = None


def set_shared_memory(memory):
    """Called by the runtime to inject SharedMemory."""
    global _shared_memory
    _shared_memory = memory


def set_knowledge_base(kb):
    """Called by the runtime to inject KnowledgeBase."""
    global _knowledge_base
    _knowledge_base = kb


@registry.register
def post_message(to_agent: str, msg_type: str, content: str, 
                 from_agent: str = "unknown") -> str:
    """
    Post a message to the shared message board for other agents.
    
    Args:
        to_agent: Target agent name, or '*' for broadcast.
        msg_type: Message type: 'discovery', 'hypothesis', 'result', 'request'.
        content: Message content (plain text or JSON string).
        from_agent: Your agent name (auto-set by runtime if available).
    """
    try:
        if _shared_memory is None:
            return "Error: Shared memory not initialized."
        
        import json
        try:
            parsed_content = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            parsed_content = {"text": content}
        
        _shared_memory.post_message(from_agent, to_agent, msg_type, parsed_content)
        return f"Message posted: [{msg_type}] to '{to_agent}'"
    except Exception as e:
        return f"Error posting message: {e}"


@registry.register
def read_messages(agent_name: str, msg_type: str = "") -> str:
    """
    Read messages from the shared board addressed to you.
    
    Args:
        agent_name: Your agent name.
        msg_type: Optional filter by type (discovery/hypothesis/result/request).
    """
    try:
        if _shared_memory is None:
            return "Error: Shared memory not initialized."
        
        msgs = _shared_memory.get_messages_for(
            agent_name, 
            msg_type=msg_type if msg_type else None
        )
        
        if not msgs:
            return f"No messages for '{agent_name}'"
        
        lines = [f"Messages for '{agent_name}' ({len(msgs)}):"]
        for m in msgs[-10:]:  # Last 10
            lines.append(f"  [{m.msg_type}] from {m.from_agent}: {str(m.content)[:100]}")
        
        if len(msgs) > 10:
            lines.append(f"  ... and {len(msgs) - 10} older messages")
        
        return "\n".join(lines)
    except Exception as e:
        return f"Error reading messages: {e}"


@registry.register
def query_knowledge(category: str, top_n: str = "5") -> str:
    """
    Query the knowledge base for known attack patterns.
    Use this before testing — it tells you what patterns are most effective.
    
    Args:
        category: Pattern category (xss_patterns, injection_patterns, auth_patterns, recon_patterns, business_logic_patterns).
        top_n: Number of top patterns to return (default: 5).
    """
    try:
        if _knowledge_base is None:
            return "Error: Knowledge base not initialized."
        
        n = int(top_n) if top_n.isdigit() else 5
        return _knowledge_base.get_context_for_category(category, n)
    except Exception as e:
        return f"Error querying knowledge: {e}"


@registry.register
def record_pattern_outcome(key: str, success: str) -> str:
    """
    Record whether a known pattern succeeded or failed.
    This helps the knowledge base learn over time.
    
    Args:
        key: The pattern key from the knowledge base.
        success: 'true' if the pattern worked, 'false' if not.
    """
    try:
        if _knowledge_base is None:
            return "Error: Knowledge base not initialized."
        
        did_succeed = success.lower() in ("true", "yes", "1")
        _knowledge_base.record_outcome(key, did_succeed)
        
        entry = _knowledge_base.get(key)
        if entry:
            return f"Recorded outcome for '{key}': {'success' if did_succeed else 'failure'} (effectiveness: {entry.effectiveness:.0%})"
        else:
            return f"Pattern '{key}' not found in knowledge base."
    except Exception as e:
        return f"Error recording outcome: {e}"


@registry.register
def report_vulnerability(name: str, severity: str, description: str) -> str:
    """
    Reports a confirmed vulnerability and adds a Finding to shared memory.
    MANDATORY: You must call this tool whenever you confirm a security issue.
    
    Args:
        name: Name of the vulnerability (e.g., 'Reflected XSS', 'SQL Injection').
        severity: Severity level (Low, Medium, High, Critical).
        description: Detailed description of the finding and how to reproduce it.
    """
    print(f"[Tool] report_vulnerability: [{severity}] {name}")
    
    try:
        from auton.core.evidence import Finding, Severity as EvSeverity
        
        sev_map = {
            "low": EvSeverity.LOW, "medium": EvSeverity.MEDIUM,
            "high": EvSeverity.HIGH, "critical": EvSeverity.CRITICAL,
        }
        sev = sev_map.get(severity.lower(), EvSeverity.MEDIUM)
        
        finding = Finding(
            id=f"V-{len(_shared_memory.findings) + 1:03d}" if _shared_memory else "V-000",
            title=name,
            severity=sev,
            description=description,
            impact="See description",
            reproduction_steps=[description],
            remediation="To be determined",
        )
        
        if _shared_memory:
            _shared_memory.add_finding(finding)
        
        return f"Vulnerability reported: [{severity.upper()}] {name} (ID: {finding.id})"
    except Exception as e:
        return f"Vulnerability logged: [{severity}] {name} - {description}"


@registry.register
def finish_scan(summary: str) -> str:
    """
    Finishes the scan and provides a summary.
    
    Args:
        summary: A brief summary of the findings and actions taken.
    """
    print(f"[Tool] finish_scan: {summary}")
    
    finding_count = len(_shared_memory.findings) if _shared_memory else 0
    return f"Scan finished. {finding_count} findings recorded. Summary: {summary}"
