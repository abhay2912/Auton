from typing import Dict, List, Optional
from dataclasses import dataclass, field

@dataclass
class GraphNode:
    agent_id: str
    parent_id: Optional[str]
    children_ids: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)

class AgentGraph:
    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}

    def add_node(self, agent_id: str, parent_id: Optional[str] = None, metadata: Dict = None):
        node = GraphNode(agent_id=agent_id, parent_id=parent_id, metadata=metadata or {})
        self.nodes[agent_id] = node
        
        if parent_id:
            if parent_id in self.nodes:
                self.nodes[parent_id].children_ids.append(agent_id)
            else:
                # In a real system we might handle this differently, but for now just warn
                print(f"Warning: Parent {parent_id} not found for {agent_id}")

    def get_children(self, agent_id: str) -> List[str]:
        if agent_id in self.nodes:
            return self.nodes[agent_id].children_ids
        return []

    def get_parent(self, agent_id: str) -> Optional[str]:
        if agent_id in self.nodes:
            return self.nodes[agent_id].parent_id
        return None

# Global graph instance
graph = AgentGraph()
