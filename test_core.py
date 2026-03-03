"""Verification of all Auton v2 core modules."""
import sys

print("=" * 60)
print("AUTON v2 — Core Module Verification")
print("=" * 60)

# ─── Phase A: Data Models ────────────────────────────────────
print("\n--- Phase A: Core Data Models ---")

# Attack Graph
from auton.core.attack_graph import (
    AttackGraph, NodeType, NodeStatus, Severity, EdgeRelation
)
g = AttackGraph()
web = g.add_asset("web-app:443", tech="Flask")
form = g.add_entry_point("login-form-username", input_type="text")
xss = g.add_hypothesis("Reflected XSS via username", Severity.HIGH)
auth = g.add_privilege("authenticated-user")
g.add_edge(web, form, EdgeRelation.HAS_ENTRY_POINT)
g.add_edge(form, xss, EdgeRelation.LEADS_TO)
g.add_edge(xss, auth, EdgeRelation.EXPLOITS, confidence=0.7)
paths = g.get_attack_paths(web, auth)
assert len(paths) == 1, f"Expected 1 attack path, got {len(paths)}"
g.mark_confirmed(xss, "alert(1) fired")
assert g.get_node(xss).status == NodeStatus.CONFIRMED
print(f"  AttackGraph: OK ({g.stats()['total_nodes']} nodes, {len(paths)} path)")

# Serialization round-trip
data = g.to_dict()
g2 = AttackGraph.from_dict(data)
assert g2.stats() == g.stats()
print(f"  Serialization round-trip: OK")

# Engagement
from auton.core.engagement import Engagement, Scope
eng = Engagement(
    name="Test",
    scope=Scope(target_urls=["https://xss-game.appspot.com"]),
    primary_llm="gemini",
    fallback_llm="local",
)
assert eng.scope.is_in_scope("https://xss-game.appspot.com/level1")
assert not eng.scope.is_in_scope("https://google.com")
print(f"  Engagement: OK (scope check works)")

# Evidence
from auton.core.evidence import Finding, Evidence, EvidenceType, PentestReport
from auton.core.evidence import Severity as EvSeverity
finding = Finding(
    id="V-001", title="XSS in Login", severity=EvSeverity.HIGH,
    description="Reflected XSS", impact="Session hijack",
    reproduction_steps=["Step 1", "Step 2"], remediation="Encode output",
)
report = PentestReport(engagement_name="Test", target="example.com")
report.add_finding(finding)
md = report.to_markdown()
assert "XSS in Login" in md
print(f"  Evidence/Report: OK ({len(md)} chars)")


# ─── Phase A+: Memory Architecture ──────────────────────────
print("\n--- Phase A+: Memory Architecture ---")

# Working Memory
from auton.core.memory import WorkingMemory, SharedMemory, EngagementMemory, Message
wm = WorkingMemory(role="worker", system_prompt="You are a test worker.", goal="Test XSS")
assert wm.max_turns == 5, f"Worker window should be 5, got {wm.max_turns}"

wm_mgr = WorkingMemory(role="manager", system_prompt="You are the manager.", goal="Manage engagement")
assert wm_mgr.max_turns == 30, f"Manager window should be 30, got {wm_mgr.max_turns}"

# Test pruning
for i in range(10):
    wm.add_message("assistant", f"Reasoning step {i}")
    wm.add_message("tool", f"Result {i}", tool_name=f"tool_{i}")
assert len(wm.history) <= wm.max_turns, f"History should be pruned to {wm.max_turns}, got {len(wm.history)}"
print(f"  WorkingMemory: OK (window={wm.max_turns}, after 20 msgs: {len(wm.history)} kept)")

# Build messages
msgs = wm.build_messages()
assert msgs[0]["role"] == "system"
print(f"  build_messages: OK ({len(msgs)} messages)")

# Shared Memory
sm = SharedMemory()
sm.post_message("recon", "*", "discovery", {"found": "login form"})
sm.post_message("hypothesis", "worker-1", "hypothesis", {"vuln": "XSS"})
board_msgs = sm.get_messages_for("worker-1")
assert len(board_msgs) == 2  # broadcast + direct
print(f"  SharedMemory: OK ({len(sm.message_board)} board msgs)")

context = sm.get_context_summary()
assert "Recent Agent Activity" in context
print(f"  Context summary: OK ({len(context)} chars)")

# Engagement Memory (save/resume)
import tempfile, os
em = EngagementMemory("test-engagement")
em.shared_memory = sm
em.set_phase("recon")
em.register_agent("recon-1", "recon", "Map the surface")
em.increment_step()

save_path = os.path.join(tempfile.gettempdir(), "auton_test_engagement.json")
em.save(save_path)
em2 = EngagementMemory.load(save_path)
assert em2.phase == "recon"
assert em2.step_count == 1
assert "recon-1" in em2.agent_states
os.remove(save_path)
print(f"  EngagementMemory: OK (save/resume verified)")


# ─── Phase A+: Knowledge Base ───────────────────────────────
print("\n--- Phase A+: Knowledge Base ---")

from auton.core.knowledge import KnowledgeBase, KnowledgeEntry, create_seed_knowledge

kb = create_seed_knowledge()
stats = kb.stats()
print(f"  Seed knowledge: {stats['total_entries']} entries across {len(stats['categories'])} categories")
assert stats["total_entries"] >= 15, f"Expected >= 15 seed entries, got {stats['total_entries']}"

# Query
xss_patterns = kb.query("xss_patterns")
assert len(xss_patterns) > 0
print(f"  XSS patterns: {len(xss_patterns)}")

# Learning
kb.record_outcome("reflected_xss_basic", success=True)
kb.record_outcome("reflected_xss_basic", success=True)
kb.record_outcome("reflected_xss_basic", success=False)
entry = kb.get("reflected_xss_basic")
assert entry.times_used == 3
assert abs(entry.effectiveness - 2/3) < 0.01
print(f"  Learning: OK (effectiveness={entry.effectiveness:.2f} after 3 uses)")

# Context for LLM
ctx = kb.get_context_for_category("xss_patterns")
assert "Known patterns" in ctx
print(f"  LLM context: OK ({len(ctx)} chars)")

# Persistence
save_dir = os.path.join(tempfile.gettempdir(), "auton_test_kb")
kb_save = KnowledgeBase(storage_dir=save_dir)
kb_save.add(KnowledgeEntry(category="test", key="test_key", content="test content"))
kb_save.save()
kb_load = KnowledgeBase(storage_dir=save_dir)
kb_load.load()
assert "test_key" in kb_load.entries
import shutil
shutil.rmtree(save_dir)
print(f"  Persistence: OK (save/load verified)")


# ─── Phase A++: LLM Client Layer ────────────────────────────
print("\n--- Phase A++: LLM Client Layer ---")

# Base types
from auton.llm.base import BaseLLMClient, LLMResponse, ToolCall
tc = ToolCall(name="visit_page", args={"url": "https://example.com"})
resp = LLMResponse(text="test", tool_calls=[tc])
assert resp.has_tool_calls
assert resp.first_tool_call.name == "visit_page"
print(f"  Base types: OK (LLMResponse, ToolCall)")

# Local client (parse test only — no server needed)
from auton.llm.local_client import LocalClient
lc = LocalClient(base_url="http://localhost:9999")  # Dummy URL
xml_text = '<function=visit_page><parameter=url>https://example.com</parameter></function>'
parsed = lc._parse_tool_calls(xml_text)
assert len(parsed) == 1
assert parsed[0].name == "visit_page"
assert parsed[0].args["url"] == "https://example.com"

# Multi-tool parsing
multi_xml = (
    '<function=visit_page><parameter=url>https://a.com</parameter></function>'
    '<function=execute_js><parameter=script>alert(1)</parameter></function>'
)
parsed_multi = lc._parse_tool_calls(multi_xml)
assert len(parsed_multi) == 2
assert parsed_multi[0].name == "visit_page"
assert parsed_multi[1].name == "execute_js"
print(f"  LocalClient XML parsing: OK (single + multi)")

# Message building
msgs = lc._build_messages([
    {"role": "system", "content": "You are a pentester."},
    {"role": "user", "content": "Test this site."},
    {"role": "assistant", "content": "I will visit the page."},
    {"role": "tool", "content": "Page loaded successfully."},
])
assert msgs[3]["role"] == "user"  # tool -> user
assert "[Tool Result]" in msgs[3]["content"]
print(f"  LocalClient message building: OK")

# Switcher
from auton.llm.switcher import LLMClientSwitcher
print(f"  Switcher: OK (imported)")

# Gemini client import check (may not have SDK installed)
try:
    from auton.llm.gemini_client import GeminiClient
    print(f"  GeminiClient: OK (imported, SDK available)")
except ImportError:
    print(f"  GeminiClient: SKIP (google-generativeai not installed)")


# ─── Summary ─────────────────────────────────────────────────
print("\n" + "=" * 60)
print("ALL TESTS PASSED ✓")
print("=" * 60)
