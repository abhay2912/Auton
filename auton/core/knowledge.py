"""
Knowledge Base for Auton v2 (Long-Term Memory — Layer 4).

Persistent knowledge that survives across engagements.
Stores curated attack patterns, technique effectiveness, and learned insights.

Storage: JSON on disk (~/.auton/knowledge/)
Retrieval: Deterministic category + key lookup (no embeddings in v1)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from datetime import datetime
import json
import os


DEFAULT_KNOWLEDGE_DIR = os.path.expanduser("~/.auton/knowledge")


@dataclass
class KnowledgeEntry:
    """A single piece of persistent knowledge."""
    category: str           # "xss_patterns", "recon_patterns", "bypass_techniques"
    key: str                # "img_onerror_bypass", "stored_xss_via_profile"
    content: str            # The actual knowledge (pattern description, not raw payload)
    context: str = ""       # When/where to use this pattern
    effectiveness: float = 0.5  # 0.0-1.0 (updated over time)
    times_used: int = 0
    times_succeeded: int = 0
    source: str = "seed"    # "seed" or engagement name that discovered this
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "key": self.key,
            "content": self.content,
            "context": self.context,
            "effectiveness": self.effectiveness,
            "times_used": self.times_used,
            "times_succeeded": self.times_succeeded,
            "source": self.source,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
    
    @classmethod
    def from_dict(cls, d: dict) -> 'KnowledgeEntry':
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


class KnowledgeBase:
    """
    Persistent knowledge store for cross-engagement learning.
    
    The system reasons in patterns, not payload lists.
    Entries are curated descriptions of attack techniques,
    not raw exploit code.
    """
    
    def __init__(self, storage_dir: str = DEFAULT_KNOWLEDGE_DIR):
        self.storage_dir = storage_dir
        self.entries: Dict[str, KnowledgeEntry] = {}  # key -> entry
        self._ensure_dir()
    
    def _ensure_dir(self) -> None:
        os.makedirs(self.storage_dir, exist_ok=True)
    
    def _db_path(self) -> str:
        return os.path.join(self.storage_dir, "knowledge.json")
    
    # ─── CRUD ────────────────────────────────────────────────────────
    
    def add(self, entry: KnowledgeEntry) -> None:
        """Add or update a knowledge entry."""
        self.entries[entry.key] = entry
    
    def get(self, key: str) -> Optional[KnowledgeEntry]:
        """Get a specific entry by key."""
        return self.entries.get(key)
    
    def query(self, category: str, min_effectiveness: float = 0.0) -> List[KnowledgeEntry]:
        """Get all entries in a category, sorted by effectiveness."""
        results = [
            e for e in self.entries.values()
            if e.category == category and e.effectiveness >= min_effectiveness
        ]
        return sorted(results, key=lambda e: e.effectiveness, reverse=True)
    
    def get_top_patterns(self, category: str, n: int = 5) -> List[KnowledgeEntry]:
        """Get the top-N most effective patterns in a category."""
        return self.query(category)[:n]
    
    def get_categories(self) -> List[str]:
        """List all categories in the knowledge base."""
        return list(set(e.category for e in self.entries.values()))
    
    # ─── Learning ────────────────────────────────────────────────────
    
    def record_outcome(self, key: str, success: bool) -> None:
        """Update effectiveness based on real test results."""
        entry = self.entries.get(key)
        if not entry:
            return
        
        entry.times_used += 1
        if success:
            entry.times_succeeded += 1
        
        # Recalculate effectiveness (simple ratio with smoothing)
        if entry.times_used > 0:
            entry.effectiveness = entry.times_succeeded / entry.times_used
        
        entry.updated_at = datetime.utcnow().isoformat()
    
    def learn_from_engagement(self, engagement_name: str, 
                              patterns: List[Dict]) -> None:
        """
        Extract new knowledge from a completed engagement.
        
        Args:
            engagement_name: Name of the completed engagement
            patterns: List of dicts with keys: category, key, content, context, success
        """
        for p in patterns:
            existing = self.entries.get(p["key"])
            if existing:
                self.record_outcome(p["key"], p.get("success", False))
            else:
                self.add(KnowledgeEntry(
                    category=p["category"],
                    key=p["key"],
                    content=p["content"],
                    context=p.get("context", ""),
                    effectiveness=1.0 if p.get("success") else 0.0,
                    times_used=1,
                    times_succeeded=1 if p.get("success") else 0,
                    source=engagement_name,
                ))
    
    # ─── Persistence ─────────────────────────────────────────────────
    
    def save(self) -> None:
        """Save knowledge base to disk."""
        self._ensure_dir()
        data = {k: v.to_dict() for k, v in self.entries.items()}
        with open(self._db_path(), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[Knowledge] Saved {len(self.entries)} entries to {self._db_path()}")
    
    def load(self) -> None:
        """Load knowledge base from disk."""
        path = self._db_path()
        if not os.path.exists(path):
            print(f"[Knowledge] No existing knowledge base at {path}")
            return
        
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        self.entries = {k: KnowledgeEntry.from_dict(v) for k, v in data.items()}
        print(f"[Knowledge] Loaded {len(self.entries)} entries from {path}")
    
    # ─── Context for LLM ────────────────────────────────────────────
    
    def get_context_for_category(self, category: str, n: int = 5) -> str:
        """Build a compact text block for injecting into agent prompts."""
        entries = self.get_top_patterns(category, n)
        if not entries:
            return f"No known patterns for '{category}'."
        
        lines = [f"Known patterns for '{category}' (top {len(entries)}):"]
        for e in entries:
            eff = f"{e.effectiveness:.0%}" if e.times_used > 0 else "untested"
            lines.append(f"  [{eff}] {e.key}: {e.content}")
            if e.context:
                lines.append(f"         Context: {e.context}")
        return "\n".join(lines)
    
    def stats(self) -> dict:
        """Quick statistics."""
        categories = {}
        for e in self.entries.values():
            categories[e.category] = categories.get(e.category, 0) + 1
        return {
            "total_entries": len(self.entries),
            "categories": categories,
        }


# ─── Seed Knowledge ─────────────────────────────────────────────────

def create_seed_knowledge() -> KnowledgeBase:
    """
    Create initial knowledge base with curated OWASP-informed patterns.
    These are reasoning patterns, not raw payloads.
    """
    kb = KnowledgeBase()
    
    # === XSS Patterns ===
    kb.add(KnowledgeEntry(
        category="xss_patterns",
        key="reflected_xss_basic",
        content="Input reflected directly in HTML without encoding. Test by injecting benign markers first, then script tags.",
        context="Forms, search bars, URL parameters that reflect user input in the response page.",
    ))
    kb.add(KnowledgeEntry(
        category="xss_patterns",
        key="stored_xss_profile",
        content="User-supplied data stored and rendered to other users. Check profile fields, comments, messages for persistent injection.",
        context="Any field that persists and is displayed to other users (usernames, bios, comments).",
    ))
    kb.add(KnowledgeEntry(
        category="xss_patterns",
        key="dom_xss_fragment",
        content="Client-side JS reads from URL fragment or DOM sources and writes to innerHTML/document.write without sanitization.",
        context="Single-page applications, JavaScript-heavy pages that manipulate DOM based on URL parameters.",
    ))
    kb.add(KnowledgeEntry(
        category="xss_patterns",
        key="filter_bypass_event_handlers",
        content="When <script> is filtered, try event handler attributes: onerror, onload, onfocus, onmouseover on elements like img, svg, input.",
        context="Applications that strip <script> tags but allow other HTML elements.",
    ))
    kb.add(KnowledgeEntry(
        category="xss_patterns",
        key="filter_bypass_encoding",
        content="Use HTML entity encoding, URL encoding, or unicode escapes to bypass naive string-matching filters.",
        context="WAFs or input filters that match exact strings like 'script' or 'alert'.",
    ))
    
    # === Injection Patterns ===
    kb.add(KnowledgeEntry(
        category="injection_patterns",
        key="sqli_error_based",
        content="Inject single quotes or SQL syntax to trigger database errors. Error messages reveal DB type and query structure.",
        context="Login forms, search fields, any input that likely queries a database.",
    ))
    kb.add(KnowledgeEntry(
        category="injection_patterns",
        key="sqli_boolean_blind",
        content="When no errors are shown, use boolean conditions (AND 1=1 vs AND 1=2) and observe response differences.",
        context="Applications that suppress error messages but produce different pages for true/false conditions.",
    ))
    kb.add(KnowledgeEntry(
        category="injection_patterns",
        key="command_injection_basic",
        content="If user input is passed to system commands, inject command separators (;, |, &&, ||, `backticks`, $(...)). ",
        context="File upload processors, ping utilities, DNS lookup tools, any feature that shells out.",
    ))
    
    # === Auth Patterns ===
    kb.add(KnowledgeEntry(
        category="auth_patterns",
        key="broken_auth_session_fixation",
        content="Check if session token changes after login. If not, attacker can set a known session ID before victim authenticates.",
        context="Login flows where session cookies exist before authentication.",
    ))
    kb.add(KnowledgeEntry(
        category="auth_patterns",
        key="idor_direct_reference",
        content="Change numeric/sequential IDs in URLs or API params to access other users' data. Test with two different authenticated sessions.",
        context="URLs like /user/123/profile, /api/orders/456, any endpoint with user-specific resource IDs.",
    ))
    kb.add(KnowledgeEntry(
        category="auth_patterns",
        key="privilege_escalation_role_param",
        content="Check if role/privilege level is sent as a client-side parameter (hidden field, cookie, JWT claim) that can be modified.",
        context="Admin panels, role-based access systems, APIs that accept role parameters.",
    ))
    
    # === Recon Patterns ===
    kb.add(KnowledgeEntry(
        category="recon_patterns",
        key="tech_fingerprinting",
        content="Identify technology stack from HTTP headers (Server, X-Powered-By), HTML comments, JavaScript library URLs, error page formats.",
        context="Initial reconnaissance phase — understanding what the target runs helps select relevant attack patterns.",
    ))
    kb.add(KnowledgeEntry(
        category="recon_patterns",
        key="entry_point_enumeration",
        content="Systematically catalog all input vectors: forms, URL params, headers (cookies, auth), file uploads, API endpoints, WebSocket messages.",
        context="After identifying pages/routes, map every point where user input enters the application.",
    ))
    kb.add(KnowledgeEntry(
        category="recon_patterns",
        key="hidden_endpoint_discovery",
        content="Check robots.txt, sitemap.xml, common admin paths (/admin, /dashboard), JavaScript source for API routes, and directory brute-forcing.",
        context="Initial surface mapping — finding pages and endpoints not linked from the main UI.",
    ))
    
    # === Business Logic Patterns ===
    kb.add(KnowledgeEntry(
        category="business_logic_patterns",
        key="race_condition",
        content="Send concurrent requests for state-changing operations (transfers, purchases, votes) to exploit TOCTOU bugs.",
        context="Financial operations, voting systems, inventory management — any operation that should be atomic.",
    ))
    kb.add(KnowledgeEntry(
        category="business_logic_patterns",
        key="price_manipulation",
        content="Check if prices, quantities, or discount codes are sent as client-side parameters that can be modified.",
        context="E-commerce checkout flows, payment processing, subscription upgrades.",
    ))
    
    return kb
