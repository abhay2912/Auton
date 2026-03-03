"""
Auton v2 — Test Runner

Launch script for the orchestrated architecture.
Target: https://xss-game.appspot.com/level5/frame
"""

import sys

# Import tools to trigger registration
from auton.tools.browser import (
    visit_page, get_computed_dom, execute_js, 
    click_element, fill_form_input, manage_session, close_browser
)
from auton.tools.web import http_get, http_post, http_request
from auton.tools.graph_tools import (
    add_asset, add_entry_point, add_hypothesis,
    confirm_vulnerability, mark_failed,
    get_graph_summary, find_attack_paths
)
from auton.tools.agent_tools import (
    post_message, read_messages, 
    query_knowledge, record_pattern_outcome,
    report_vulnerability, finish_scan
)
from auton.tools.terminal import run_terminal_command

# LLM and Orchestrator
from auton.llm.local_client import LocalClient
from auton.runtime.orchestrator import Orchestrator


def main():
    target = "https://xss-game.appspot.com/level5/frame"
    
    print("=" * 60)
    print("AUTON v2 — XSS Game Level 1 Assessment")
    print("=" * 60)
    
    # Initialize LLM client (Mistral via local server)
    print("\n[Setup] Connecting to local LLM...")
    llm = LocalClient(
        base_url="http://172.17.9.88:8000",
        model="llm",
        temperature=0.0,
    )
    
    # Create and run orchestrator
    orch = Orchestrator(
        llm=llm,
        target_url=target,
        engagement_name="xss-game-level5",
        max_steps=25,
        backend="local",
    )
    
    try:
        orch.run()
    except KeyboardInterrupt:
        print("\n[Stopped by user]")
    except Exception as e:
        print(f"\n[Runtime Error] {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
