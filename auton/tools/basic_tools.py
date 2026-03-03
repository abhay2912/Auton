"""
Basic tools for Auton v2.

Agent spawning and lifecycle tools.
Note: report_vulnerability and finish_scan have moved to agent_tools.py.
"""

from auton.tools.registry import registry
import uuid


@registry.register
def create_child_agent(goal: str, parent_id: str = "root", agent_type: str = "general") -> str:
    """
    Creates a new child agent to handle a specific sub-task.
    
    Args:
        goal: The specific goal for the child agent.
        parent_id: The ID of the parent agent.
        agent_type: The type of agent to spawn. Options: 'general', 'verifier', 'recon', 'worker'.
    """
    print(f"[Tool] create_child_agent ({agent_type}) called with goal='{goal}'")
    
    child_id = f"agent-{agent_type}-{uuid.uuid4().hex[:8]}"
    
    import threading
    from auton.agents.auton_agent import AutonAgent
    from auton.llm.local_client import LocalClient
    from auton.runtime.local_runtime import LocalRuntime
    
    def run_child():
        print(f"[System] Starting child agent {child_id}...")
        try:
            llm = LocalClient()
            agent = AutonAgent(name=child_id, goal=goal, llm=llm, parent_id=parent_id)
            runtime = LocalRuntime(root_agent=agent)
            runtime.run()
            print(f"[System] Child agent {child_id} finished.")
        except Exception as e:
            print(f"[System] Child agent {child_id} failed: {e}")

    thread = threading.Thread(target=run_child, daemon=True)
    thread.start()
    
    return f"Child agent {child_id} started in background."
