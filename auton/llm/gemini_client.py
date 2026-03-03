"""
Gemini LLM Client for Auton v2.

Primary LLM backend using Google's Gemini API.
- Uses generate_content() directly — NO start_chat()
- Native function calling via FunctionDeclaration
- We manage conversation history ourselves (tiered memory system)
"""

import os
import json
import inspect
from typing import List, Dict, Any, Optional

from auton.llm.base import BaseLLMClient, LLMResponse, ToolCall

try:
    import google.generativeai as genai
    from google.generativeai.types import content_types
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False


class GeminiClient(BaseLLMClient):
    """
    Gemini LLM client using native function calling.
    
    Key design:
    - generate_content() with manually constructed Content objects
    - Tool functions converted to FunctionDeclaration for native calling
    - System prompt set via system_instruction parameter
    - Responses normalized to LLMResponse
    """
    
    def __init__(self, model_name: str = "models/gemini-2.0-flash-lite",
                 api_key: Optional[str] = None):
        if not GEMINI_AVAILABLE:
            raise ImportError("google-generativeai package not installed. "
                              "Install with: pip install google-generativeai")
        
        api_key = api_key or os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY environment variable not set.")
        
        genai.configure(api_key=api_key)
        self.model_name = model_name
        self._model = None
        self._current_system_instruction = None
    
    def _get_model(self, system_instruction: Optional[str] = None):
        """Get or create model, updating system instruction if changed."""
        if (self._model is None or 
            system_instruction != self._current_system_instruction):
            self._model = genai.GenerativeModel(
                self.model_name,
                system_instruction=system_instruction,
            )
            self._current_system_instruction = system_instruction
        return self._model
    
    def _build_tool_declarations(self, tools: List[Any]) -> Optional[List]:
        """Convert our tool functions into Gemini FunctionDeclaration objects."""
        if not tools:
            return None
        
        declarations = []
        for tool in tools:
            name = getattr(tool, "__name__", str(tool))
            doc = getattr(tool, "__doc__", "") or ""
            
            # Parse function signature for parameter info
            params = {}
            try:
                sig = inspect.signature(tool)
                for param_name, param in sig.parameters.items():
                    # Simple type mapping
                    param_type = "STRING"
                    if param.annotation == int:
                        param_type = "INTEGER"
                    elif param.annotation == float:
                        param_type = "NUMBER"
                    elif param.annotation == bool:
                        param_type = "BOOLEAN"
                    
                    params[param_name] = {
                        "type": param_type,
                        "description": f"Parameter: {param_name}",
                    }
            except (ValueError, TypeError):
                pass
            
            # Build the declaration
            declaration = {
                "name": name,
                "description": doc.strip().split("\n")[0] if doc else name,
            }
            if params:
                declaration["parameters"] = {
                    "type": "OBJECT",
                    "properties": params,
                    "required": list(params.keys()),
                }
            
            declarations.append(declaration)
        
        return [genai.protos.Tool(function_declarations=[
            genai.protos.FunctionDeclaration(**d) for d in declarations
        ])]
    
    def _build_contents(self, messages: List[Dict[str, str]]) -> tuple:
        """
        Convert our message format to Gemini Content objects.
        
        Returns: (system_instruction, contents_list)
        """
        system_instruction = None
        contents = []
        
        for msg in messages:
            role = msg["role"]
            content = msg["content"]
            
            if role == "system":
                system_instruction = content
            elif role == "user":
                contents.append({"role": "user", "parts": [content]})
            elif role == "assistant":
                contents.append({"role": "model", "parts": [content]})
            elif role == "tool":
                # Tool results go as user messages with a prefix
                # This is because Gemini expects user/model alternation
                # For native function calling, we'd use FunctionResponse parts,
                # but since we parse XML tool calls, treat as user observation
                contents.append({
                    "role": "user", 
                    "parts": [f"[Tool Result] {content}"]
                })
        
        # Gemini requires alternating user/model roles
        # Merge consecutive same-role messages
        merged = []
        for c in contents:
            if merged and merged[-1]["role"] == c["role"]:
                merged[-1]["parts"].extend(c["parts"])
            else:
                merged.append(c)
        
        return system_instruction, merged
    
    def _extract_tool_calls(self, response) -> List[ToolCall]:
        """Extract tool calls from Gemini response — native function_call parts."""
        tool_calls = []
        
        try:
            if not response.candidates:
                return tool_calls
            
            for part in response.candidates[0].content.parts:
                if hasattr(part, 'function_call') and part.function_call:
                    fc = part.function_call
                    args = dict(fc.args) if fc.args else {}
                    tool_calls.append(ToolCall(name=fc.name, args=args))
        except (AttributeError, IndexError):
            pass
        
        return tool_calls
    
    def _extract_text(self, response) -> str:
        """Extract text from Gemini response."""
        try:
            if response.candidates:
                parts = response.candidates[0].content.parts
                text_parts = [p.text for p in parts if hasattr(p, 'text') and p.text]
                return "\n".join(text_parts)
        except (AttributeError, IndexError):
            pass
        return ""
    
    def chat(self, messages: List[Dict[str, str]], 
             tools: Optional[List[Any]] = None) -> LLMResponse:
        """
        Send messages to Gemini using generate_content().
        
        Uses native function calling when tools are provided.
        Returns unified LLMResponse.
        """
        try:
            # Build contents and extract system instruction
            system_instruction, contents = self._build_contents(messages)
            
            # Get model with current system instruction
            model = self._get_model(system_instruction)
            
            # Build tool declarations
            tool_defs = self._build_tool_declarations(tools) if tools else None
            
            # Call generate_content — NOT start_chat
            response = model.generate_content(
                contents,
                tools=tool_defs,
            )
            
            # Extract text and tool calls
            text = self._extract_text(response)
            tool_calls = self._extract_tool_calls(response)
            
            self._log_debug({
                "type": "gemini_response",
                "text": text[:200],
                "tool_calls": [{"name": tc.name, "args": tc.args} for tc in tool_calls],
            })
            
            return LLMResponse(
                text=text,
                tool_calls=tool_calls,
                raw=response,
            )
        
        except Exception as e:
            error_msg = f"Gemini API error: {e}"
            print(f"[Gemini] {error_msg}")
            self._log_debug({"type": "gemini_error", "error": str(e)})
            return LLMResponse(text="", error=error_msg)
    
    def _log_debug(self, data: dict) -> None:
        try:
            with open("llm_debug.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(data, default=str) + "\n")
        except Exception:
            pass
