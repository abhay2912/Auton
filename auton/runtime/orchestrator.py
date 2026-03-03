"""
Orchestrator Runtime for Auton v2.

The orchestrator manages the full engagement lifecycle:
1. Initializes shared state (Attack Graph, Memory, Knowledge)
2. Injects shared resources into tool modules
3. Builds agents with proper role-specific prompts + tool subsets
4. Runs the agent loop using the unified LLM interface
5. Manages the phase pipeline
"""

import time
import collections
from typing import List, Dict, Any, Optional

from auton.core.attack_graph import AttackGraph
from auton.core.memory import WorkingMemory, SharedMemory, EngagementMemory
from auton.core.knowledge import KnowledgeBase, create_seed_knowledge
from auton.core.evidence import PentestReport

from auton.llm.base import BaseLLMClient, LLMResponse
from auton.prompts.system_prompts import build_prompt, format_tool_descriptions

from auton.tools.registry import registry
from auton.tools import graph_tools, agent_tools


class Orchestrator:
    """
    Main runtime that wires everything together and runs the engagement.
    
    Usage:
        from auton.llm.local_client import LocalClient
        
        llm = LocalClient()
        orch = Orchestrator(
            llm=llm,
            target_url="https://xss-game.appspot.com/level1/frame",
            engagement_name="xss-game-level1"
        )
        orch.run()
    """
    
    def __init__(self, llm: BaseLLMClient, target_url: str,
                 engagement_name: str = "unnamed",
                 max_steps: int = 30,
                 backend: str = "local"):
        self.llm = llm
        self.target_url = target_url
        self.engagement_name = engagement_name
        self.max_steps = max_steps
        self.backend = backend  # "gemini" or "local"
        
        # Tool deduplication buffer to prevent loops
        self._deduplication_buffer = collections.deque(maxlen=10)
        
        # Initialize shared state
        self.shared_memory = SharedMemory()
        self.knowledge_base = create_seed_knowledge()
        self.engagement = EngagementMemory(engagement_name)
        self.engagement.shared_memory = self.shared_memory
        
        # Inject into tool modules
        graph_tools.set_shared_graph(self.shared_memory.attack_graph)
        agent_tools.set_shared_memory(self.shared_memory)
        agent_tools.set_knowledge_base(self.knowledge_base)
        
        # Collect tools
        self._tools = self._collect_tools()
        
        print(f"[Orchestrator] Initialized: {engagement_name}")
        print(f"[Orchestrator] Target: {target_url}")
        print(f"[Orchestrator] LLM backend: {backend}")
        print(f"[Orchestrator] Tools: {len(self._tools)}")
    
    def _collect_tools(self) -> List:
        """Get all registered tools."""
        return registry.get_tools()
    
    def _get_tool_subset(self, role: str) -> List:
        """
        Get role-appropriate tool subset.
        Workers don't need graph management tools, etc.
        """
        all_tools = self._tools
        tool_names_map = {t.__name__: t for t in all_tools}
        
        # All roles get these basics
        base_tools = [
            "visit_page", "get_computed_dom", "execute_js", 
            "click_element", "fill_form_input",
            "http_get", "http_post", "http_request",
            "finish_scan",
        ]
        
        role_extras = {
            "manager": [
                "add_asset", "add_entry_point", "add_hypothesis",
                "confirm_vulnerability", "mark_failed",
                "get_graph_summary", "find_attack_paths",
                "post_message", "read_messages",
                "query_knowledge", "record_pattern_outcome",
                "report_vulnerability",
                "manage_session",
            ],
            "recon": [
                "add_asset", "add_entry_point",
                "get_graph_summary",
                "post_message",
            ],
            "hypothesis": [
                "add_hypothesis", "get_graph_summary",
                "query_knowledge", "post_message",
            ],
            "worker": [
                "confirm_vulnerability", "mark_failed",
                "record_pattern_outcome",
                "post_message", "report_vulnerability",
                "manage_session",
            ],
            "verifier": [
                "confirm_vulnerability", "mark_failed",
                "post_message", "report_vulnerability",
                "manage_session",
            ],
            "reporter": [
                "get_graph_summary", "report_vulnerability",
            ],
        }
        
        needed = set(base_tools + role_extras.get(role, []))
        return [t for t in all_tools if t.__name__ in needed]
    
    def run(self):
        """
        Run the full engagement as a single Manager agent.
        
        The Manager handles all phases itself, using its large context window
        and strategic prompt. In the future, this will be expanded to 
        spawn specialized child agents.
        """
        print(f"\n{'='*60}")
        print(f"AUTON v2 — Engagement: {self.engagement_name}")
        print(f"Target: {self.target_url}")
        print(f"{'='*60}\n")
        
        # Build the Manager agent
        role = "manager"
        tools = self._get_tool_subset(role)
        tool_desc = format_tool_descriptions(tools)
        
        goal = (
            f"Perform a security assessment of {self.target_url}.\n"
            f"Find and verify all vulnerabilities.\n"
            f"Report confirmed findings with evidence.\n"
            f"Focus on XSS, injection, and auth vulnerabilities."
        )
        
        context = self.shared_memory.get_context_summary()
        system_prompt = build_prompt(role, goal, tool_desc, context, self.backend)
        
        # Create WorkingMemory for the Manager
        working_memory = WorkingMemory(
            role=role,
            system_prompt=system_prompt,
            goal=goal,
        )
        
        self.engagement.register_agent("manager", role, goal)
        self.engagement.set_phase("active")
        
        # Agent loop
        step = 0
        is_finished = False
        
        while not is_finished and step < self.max_steps:
            step += 1
            self.engagement.increment_step()
            
            print(f"\n--- Step {step}/{self.max_steps} ---")
            
            # Update context every few steps
            if step % 3 == 0 or step == 1:
                context = self.shared_memory.get_context_summary()
                working_memory.inject_context(context)
            
            # Build messages from working memory
            messages = working_memory.build_messages()
            
            # Call LLM
            response = self.llm.chat(messages, tools=tools)
            
            if response.error:
                print(f"[Orchestrator] LLM error: {response.error}")
                # Add error to history so agent can adapt
                working_memory.add_message("user", 
                    f"[System Error] LLM call failed: {response.error}. Please try again.")
                time.sleep(2)
                continue
            
            # Log the assistant's response
            if response.text:
                print(f"[Agent] {response.text[:300]}")
                working_memory.add_message("assistant", response.text)
            
            # Execute tool calls
            if response.has_tool_calls:
                for tc in response.tool_calls:
                    # Check for duplicates to prevent loops
                    call_sig = (tc.name, str(sorted(tc.args.items())))
                    if call_sig in self._deduplication_buffer:
                        print(f"[Runtime] Skipping duplicate tool call: {tc.name}")
                        working_memory.add_message("tool", f"Tool call skipped: You just executed {tc.name} with these exact arguments. Do not repeat actions.", tool_name=tc.name)
                        continue
                    
                    self._deduplication_buffer.append(call_sig)
                    
                    print(f"[Runtime] Executing: {tc.name}({tc.args})")
                    
                    tool_func = registry.get_tool(tc.name)
                    if tool_func:
                        try:
                            # IMPORTANT: We handle missing args gracefully-ish by letting Python raise TypeError
                            # which falls into the except block
                            result = tool_func(**tc.args)
                        except Exception as e:
                            print(f"[Runtime] Error executing {tc.name}: {e}")
                            result = f"Error executing {tc.name}: {e}. Check your arguments."
                    else:
                        result = f"Tool '{tc.name}' not found. Available: {[t.__name__ for t in tools]}"
                    
                    print(f"[Runtime] Result (truncated): {str(result)[:100]}...")
                    
                    # Add tool result to working memory
                    working_memory.add_message("tool", str(result), tool_name=tc.name)
                    
                    # Check for finish
                    if tc.name == "finish_scan":
                        is_finished = True
                        break
            else:
                # No tool calls — give the agent feedback
                working_memory.add_message("user", 
                    "[System] No tool call detected in your response. "
                    "You MUST call a tool. Use visit_page to start reconnaissance, "
                    "or finish_scan if done.")
            
            # Small delay to avoid rate limiting
            time.sleep(0.5)
        
        # Wrap up
        self.engagement.set_phase("complete")
        self._print_summary()
    
    def _print_summary(self):
        """Print engagement summary."""
        print(f"\n{'='*60}")
        print(f"ENGAGEMENT COMPLETE: {self.engagement_name}")
        print(f"{'='*60}")
        print(f"Steps: {self.engagement.step_count}")
        print(f"Findings: {len(self.shared_memory.findings)}")
        
        graph_stats = self.shared_memory.attack_graph.stats()
        print(f"Graph: {graph_stats['total_nodes']} nodes, {graph_stats['total_edges']} edges")
        
        if self.shared_memory.findings:
            print(f"\nConfirmed Vulnerabilities:")
            for f in self.shared_memory.findings:
                print(f"  [{f.severity.value.upper()}] {f.title}")
        else:
            print(f"\nNo vulnerabilities confirmed.")
        
        # Generate report
        if self.shared_memory.findings:
            report = PentestReport(
                engagement_name=self.engagement_name,
                target=self.target_url,
            )
            for f in self.shared_memory.findings:
                report.add_finding(f)
            
            md = report.to_markdown()
            report_path = f"{self.engagement_name}_report.md"
            with open(report_path, "w", encoding="utf-8") as fp:
                fp.write(md)
            print(f"\nReport saved: {report_path}")
        
        print(f"{'='*60}")
