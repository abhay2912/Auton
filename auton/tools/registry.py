from typing import Callable, Dict, List, Any

class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, Callable] = {}
        self._schemas: List[Any] = []

    def register(self, func: Callable):
        """Decorator to register a tool."""
        self._tools[func.__name__] = func
        # In a real implementation, we would generate the schema here or require it.
        # For Gemini SDK, passing the function directly often works as it auto-generates schema.
        self._schemas.append(func)
        return func

    def get_tools(self) -> List[Any]:
        return self._schemas

    def get_tool(self, name: str) -> Callable:
        return self._tools.get(name)

# Global registry instance
registry = ToolRegistry()
