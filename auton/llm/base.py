"""
Base LLM Client interface for Auton v2.

Defines the unified interface that both GeminiClient and LocalClient implement.
The runtime only ever sees LLMResponse and ToolCall objects — never SDK-specific types.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional


@dataclass
class ToolCall:
    """A parsed tool call, normalized from either Gemini native or XML format."""
    name: str
    args: Dict[str, str]


@dataclass
class LLMResponse:
    """
    Unified response from any LLM backend.
    
    The runtime consumes this — never SDK-specific response objects.
    """
    text: str                                   # Raw LLM output text
    tool_calls: List[ToolCall] = field(default_factory=list)
    raw: Any = None                             # Original SDK response (debug only)
    error: Optional[str] = None                 # Error message if call failed
    
    @property
    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0
    
    @property
    def first_tool_call(self) -> Optional[ToolCall]:
        return self.tool_calls[0] if self.tool_calls else None


class BaseLLMClient(ABC):
    """
    Abstract base class for LLM clients.
    
    Both GeminiClient and LocalClient implement this interface.
    The `chat` method takes a list of message dicts and returns an LLMResponse.
    """
    
    @abstractmethod
    def chat(self, messages: List[Dict[str, str]], 
             tools: Optional[List[Any]] = None) -> LLMResponse:
        """
        Send messages to the LLM and return a unified response.
        
        Args:
            messages: List of dicts with 'role' and 'content' keys.
                      Roles: "system", "user", "assistant", "tool"
            tools: Optional list of tool functions (used by Gemini for native 
                   function calling; ignored by LocalClient which uses XML).
        
        Returns:
            LLMResponse with text and parsed tool calls.
        """
        ...
