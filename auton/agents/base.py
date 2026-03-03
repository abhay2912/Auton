from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class AgentState:
    goal: str
    history: List[Dict[str, str]] = field(default_factory=list)
    memory: Dict[str, Any] = field(default_factory=dict)
    is_finished: bool = False

class BaseAgent:
    def __init__(self, name: str, goal: str):
        self.name = name
        self.state = AgentState(goal=goal)

    def step(self) -> Optional[str]:
        """
        Executes one step of the agent loop.
        Returns the output of the step.
        """
        raise NotImplementedError
