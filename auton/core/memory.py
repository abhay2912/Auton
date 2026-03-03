"""
Memory Architecture for Auton v2.

Four-layer memory system:
  Layer 1: WorkingMemory  — Per-agent rolling context window
  Layer 2: SharedMemory   — Attack Graph + message board (blackboard)
  Layer 3: EngagementMemory — Serializable session state (save/resume)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
import json
import os

from auton.core.attack_graph import AttackGraph
from auton.core.evidence import Finding


# ─── Messages ───────────────────────────────────────────────────────

@dataclass
class Message:
    """A single message in an agent's conversation history."""
    role: str           # "system", "user", "assistant", "tool"
    content: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict = field(default_factory=dict)  # e.g. tool_name, tool_args
    
    def to_dict(self) -> dict:
        return {
            "role": self.role,
            "content": self.content,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, d: dict) -> 'Message':
        return cls(
            role=d["role"],
            content=d["content"],
            timestamp=d.get("timestamp", ""),
            metadata=d.get("metadata", {}),
        )


@dataclass
class AgentMessage:
    """Structured inter-agent communication on the shared message board."""
    from_agent: str         # "recon-scout"
    to_agent: str           # "hypothesis-engine" or "*" (broadcast)
    msg_type: str           # "discovery", "hypothesis", "result", "request"
    content: dict           # Structured payload
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> dict:
        return {
            "from": self.from_agent,
            "to": self.to_agent,
            "type": self.msg_type,
            "content": self.content,
            "timestamp": self.timestamp,
        }
    
    @classmethod
    def from_dict(cls, d: dict) -> 'AgentMessage':
        return cls(
            from_agent=d["from"],
            to_agent=d["to"],
            msg_type=d["type"],
            content=d["content"],
            timestamp=d.get("timestamp", ""),
        )


# ─── Layer 1: Working Memory (Per-Agent) ────────────────────────────

# Role-based window sizes
WINDOW_SIZES = {
    "manager": 30,
    "recon": 15,
    "hypothesis": 15,
    "worker": 5,
    "verifier": 5,
    "reporter": 10,
}


class WorkingMemory:
    """
    Per-agent rolling context window.
    
    Each agent has its own WorkingMemory that caps history
    based on role-specific cognitive load limits.
    """
    
    def __init__(self, role: str, system_prompt: str, goal: str,
                 max_turns: Optional[int] = None):
        self.role = role
        self.system_prompt = system_prompt
        self.goal = goal
        self.max_turns = max_turns or WINDOW_SIZES.get(role, 15)
        self.history: List[Message] = []
        self.injected_context: str = ""  # Compact shared state summary
        self._summary_block: str = ""    # Compressed old turns
    
    def add_message(self, role: str, content: str, **metadata) -> None:
        """Add a message and prune if over window."""
        self.history.append(Message(role=role, content=content, metadata=metadata))
        self._prune_if_needed()
    
    def _prune_if_needed(self) -> None:
        """Hybrid consolidation: heuristic pruning when history exceeds window."""
        if len(self.history) <= self.max_turns:
            return
        
        # Step 1: Heuristic pruning
        # Keep: tool results, HTTP responses, verified evidence, structured hypotheses
        # Drop: internal reasoning chatter, intermediate planning, repeated retries
        keep = []
        drop_count = 0
        
        for msg in self.history:
            if msg.role == "tool":
                # Always keep tool results
                keep.append(msg)
            elif msg.role == "assistant":
                # Keep if it contains a tool call (action), drop pure reasoning
                if "<function=" in msg.content:
                    keep.append(msg)
                else:
                    # Compress reasoning into summary
                    drop_count += 1
            else:
                keep.append(msg)
        
        # If heuristic pruning brought us under the limit, done
        if len(keep) <= self.max_turns:
            if drop_count > 0:
                self._summary_block += f"\n[Pruned {drop_count} reasoning turns]"
            self.history = keep
            return
        
        # Step 2: Sliding window — keep most recent turns
        overflow = len(keep) - self.max_turns
        dropped = keep[:overflow]
        self.history = keep[overflow:]
        
        # Build summary of dropped content
        summary_parts = []
        for msg in dropped:
            if msg.role == "tool":
                tool_name = msg.metadata.get("tool_name", "unknown")
                # Keep just a one-line summary of the result
                result_preview = msg.content[:100]
                summary_parts.append(f"[{tool_name}] {result_preview}")
        
        if summary_parts:
            self._summary_block += "\n" + "\n".join(summary_parts)
    
    def build_messages(self) -> List[Dict[str, str]]:
        """
        Build the message list to send to the LLM.
        Includes system prompt, injected context, summary of old turns, and recent history.
        """
        messages = []
        
        # System prompt with injected context
        sys_content = self.system_prompt
        if self.injected_context:
            sys_content += f"\n\n--- CURRENT STATE ---\n{self.injected_context}"
        if self._summary_block:
            sys_content += f"\n\n--- PREVIOUS WORK SUMMARY ---\n{self._summary_block}"
        
        messages.append({"role": "system", "content": sys_content})
        
        # Goal as first user message (Foundational context)
        # Always include this so the conversation starts with User -> Assistant
        messages.append({"role": "user", "content": f"Goal: {self.goal}"})
        
        # Recent history
        for msg in self.history:
            messages.append({"role": msg.role, "content": msg.content})
        
        return messages
    
    def inject_context(self, context: str) -> None:
        """Update the injected shared state context."""
        self.injected_context = context
    
    def clear(self) -> None:
        """Reset working memory (used when agent is discarded)."""
        self.history.clear()
        self._summary_block = ""
        self.injected_context = ""


# ─── Layer 2: Shared Memory (Blackboard) ────────────────────────────

class SharedMemory:
    """
    Shared state across all agents.
    Contains the Attack Graph (single source of truth) and a message board.
    Agents interact via graph tools — they never access this object directly.
    """
    
    def __init__(self):
        self.attack_graph: AttackGraph = AttackGraph()
        self.message_board: List[AgentMessage] = []
        self.findings: List[Finding] = []
    
    def post_message(self, from_agent: str, to_agent: str,
                     msg_type: str, content: dict) -> None:
        """Post a message to the board."""
        self.message_board.append(AgentMessage(
            from_agent=from_agent,
            to_agent=to_agent,
            msg_type=msg_type,
            content=content,
        ))
    
    def get_messages_for(self, agent_name: str, 
                         msg_type: Optional[str] = None) -> List[AgentMessage]:
        """Get messages addressed to a specific agent (or broadcast)."""
        results = []
        for msg in self.message_board:
            if msg.to_agent in (agent_name, "*"):
                if msg_type is None or msg.msg_type == msg_type:
                    results.append(msg)
        return results
    
    def get_recent_messages(self, n: int = 10) -> List[AgentMessage]:
        """Get the N most recent messages."""
        return self.message_board[-n:]
    
    def add_finding(self, finding: Finding) -> None:
        """Register a confirmed finding."""
        self.findings.append(finding)
    
    def get_context_summary(self) -> str:
        """
        Build a compact context string for injecting into agent Working Memory.
        Designed to be token-efficient.
        """
        parts = [self.attack_graph.summary()]
        
        if self.findings:
            parts.append(f"\nConfirmed Findings: {len(self.findings)}")
            for f in self.findings[-5:]:  # Last 5 only
                parts.append(f"  [{f.severity.value.upper()}] {f.title}")
        
        recent = self.get_recent_messages(5)
        if recent:
            parts.append(f"\nRecent Agent Activity:")
            for msg in recent:
                parts.append(f"  [{msg.from_agent}→{msg.to_agent}] {msg.msg_type}: {str(msg.content)[:80]}")
        
        return "\n".join(parts)
    
    def to_dict(self) -> dict:
        return {
            "attack_graph": self.attack_graph.to_dict(),
            "message_board": [m.to_dict() for m in self.message_board],
            "findings": [f.to_dict() for f in self.findings],
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'SharedMemory':
        sm = cls()
        sm.attack_graph = AttackGraph.from_dict(data.get("attack_graph", {}))
        sm.message_board = [
            AgentMessage.from_dict(m) for m in data.get("message_board", [])
        ]
        # Findings deserialization would need Finding.from_dict — keep simple for now
        return sm


# ─── Layer 3: Engagement Memory (Session State) ─────────────────────

@dataclass
class AgentState:
    """Checkpoint of a single agent's state."""
    name: str
    role: str
    goal: str
    step_count: int = 0
    is_finished: bool = False
    
    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "role": self.role,
            "goal": self.goal,
            "step_count": self.step_count,
            "is_finished": self.is_finished,
        }


class EngagementMemory:
    """
    Serializable snapshot of the entire engagement.
    Supports save/resume for long-running pentests.
    """
    
    def __init__(self, engagement_name: str = "unnamed"):
        self.engagement_name = engagement_name
        self.shared_memory: SharedMemory = SharedMemory()
        self.phase: str = "init"  # "recon", "hypothesis", "testing", "verify", "report"
        self.agent_states: Dict[str, AgentState] = {}
        self.step_count: int = 0
        self.created_at: str = datetime.utcnow().isoformat()
        self.updated_at: str = datetime.utcnow().isoformat()
    
    def register_agent(self, name: str, role: str, goal: str) -> None:
        """Register an agent state for checkpointing."""
        self.agent_states[name] = AgentState(name=name, role=role, goal=goal)
    
    def increment_step(self) -> None:
        """Track total steps across all agents."""
        self.step_count += 1
        self.updated_at = datetime.utcnow().isoformat()
    
    def set_phase(self, phase: str) -> None:
        """Update the current engagement phase."""
        self.phase = phase
        self.updated_at = datetime.utcnow().isoformat()
    
    def save(self, path: str) -> None:
        """Serialize engagement state to JSON file."""
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        data = {
            "engagement_name": self.engagement_name,
            "phase": self.phase,
            "step_count": self.step_count,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "shared_memory": self.shared_memory.to_dict(),
            "agent_states": {k: v.to_dict() for k, v in self.agent_states.items()},
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[Memory] Engagement saved to {path}")
    
    @classmethod
    def load(cls, path: str) -> 'EngagementMemory':
        """Load engagement state from JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        em = cls(engagement_name=data.get("engagement_name", "unnamed"))
        em.phase = data.get("phase", "init")
        em.step_count = data.get("step_count", 0)
        em.created_at = data.get("created_at", "")
        em.updated_at = data.get("updated_at", "")
        em.shared_memory = SharedMemory.from_dict(data.get("shared_memory", {}))
        
        for name, state_data in data.get("agent_states", {}).items():
            em.agent_states[name] = AgentState(
                name=state_data["name"],
                role=state_data["role"],
                goal=state_data["goal"],
                step_count=state_data.get("step_count", 0),
                is_finished=state_data.get("is_finished", False),
            )
        
        print(f"[Memory] Engagement loaded from {path} (phase: {em.phase}, steps: {em.step_count})")
        return em
