"""
Local/Mistral LLM Client for Auton v2.

Fallback LLM backend using OpenAI-compatible API (Mistral hosted locally).
- Endpoint: /v1/chat/completions (configurable)
- No native tool calling — uses strict XML format + application-side parsing
- Full message history sent each call (our memory system handles context)
- temperature: 0 for deterministic outputs
"""

import requests
import json
import re
from typing import List, Dict, Any, Optional

from auton.llm.base import BaseLLMClient, LLMResponse, ToolCall


class LocalClient(BaseLLMClient):
    """
    Local LLM client using OpenAI-compatible chat completions API.
    
    Key design:
    - Sends full message history each call (no session_id)
    - Tool descriptions injected into system prompt
    - Model responds with XML tool calls: <function=name><parameter=k>v</parameter></function>
    - Application-side parsing via regex
    """
    
    def __init__(self, base_url: str = "http://172.17.9.88:8000",
                 model: str = "llm", temperature: float = 0.0,
                 timeout: int = 120):
        self.base_url = base_url.rstrip("/")
        self.api_url = f"{self.base_url}/v1/chat/completions"
        self.model = model
        self.temperature = temperature
        self.timeout = timeout
    
    def chat(self, messages: List[Dict[str, str]], 
             tools: Optional[List[Any]] = None) -> LLMResponse:
        """
        Send messages to the local LLM using OpenAI-compatible format.
        
        Tool calls are parsed from XML in the response text.
        """
        try:
            # Build the request payload
            api_messages = self._build_messages(messages)
            
            payload = {
                "model": self.model,
                "temperature": self.temperature,
                "messages": api_messages,
            }
            
            self._log_debug({
                "type": "local_request",
                "url": self.api_url,
                "message_count": len(api_messages),
                "last_role": api_messages[-1]["role"] if api_messages else "none",
            })
            
            # Make the API call
            response = requests.post(
                self.api_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()
            
            # Extract the assistant's response text
            text = self._extract_text(data)
            
            # Client-side stop sequence enforcement
            # Truncate after the LAST </function> to prevent hallucinated observations
            if "</function>" in text:
                last_idx = text.rfind("</function>")
                text = text[:last_idx + len("</function>")]
            
            # Parse tool calls from XML
            tool_calls = self._parse_tool_calls(text)
            
            self._log_debug({
                "type": "local_response",
                "text": text[:200],
                "tool_calls": [{"name": tc.name, "args": tc.args} for tc in tool_calls],
            })
            
            print(f"\n[Local LLM] Response ({len(text)} chars, {len(tool_calls)} tool calls)")
            
            return LLMResponse(
                text=text,
                tool_calls=tool_calls,
                raw=data,
            )
        
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Cannot connect to local LLM at {self.api_url}: {e}"
            print(f"[Local LLM] {error_msg}")
            return LLMResponse(text="", error=error_msg)
        
        except requests.exceptions.Timeout:
            error_msg = f"Local LLM request timed out after {self.timeout}s"
            print(f"[Local LLM] {error_msg}")
            return LLMResponse(text="", error=error_msg)
        
        except Exception as e:
            error_msg = f"Local LLM error: {e}"
            print(f"[Local LLM] {error_msg}")
            self._log_debug({"type": "local_error", "error": str(e)})
            return LLMResponse(text="", error=error_msg)
    
    def _build_messages(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Convert our message format to OpenAI-compatible format.
        Coalesce consecutive messages from the same role to avoid 400 errors.
        """
        api_messages = []
        
        for msg in messages:
            role = msg["role"]
            content = msg["content"]
            
            # Map roles
            if role == "tool":
                api_role = "user"
                api_content = f"[Tool Result] {content}"
            else:
                api_role = role
                api_content = content
            
            # Coalesce with previous if same role
            if api_messages and api_messages[-1]["role"] == api_role:
                api_messages[-1]["content"] += f"\n\n{api_content}"
            else:
                api_messages.append({
                    "role": api_role,
                    "content": api_content,
                })
        
        return api_messages
    
    def _extract_text(self, data: dict) -> str:
        """Extract the response text from OpenAI-compatible response."""
        try:
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "")
        except (KeyError, IndexError):
            pass
        return data.get("response", "") or data.get("text", "")
    
    def _parse_tool_calls(self, text: str) -> List[ToolCall]:
        """
        Parse all Strix-style XML tool calls from the response text.
        
        Supports formats:
        - <function=name><parameter=key>value</parameter></function>
        - <function name="name"><parameter name="key">value</parameter></function>
        """
        tool_calls = []
        
        try:
            # 1. Find function blocks
            # Regex handles: <function=NAME> or <function name="NAME">
            func_pattern = re.compile(
                r'<function(?:=| name=["\']?)(\w+)(?:["\']?)>(.*?)</function>', 
                re.DOTALL | re.IGNORECASE
            )
            
            for func_match in func_pattern.finditer(text):
                tool_name = func_match.group(1)
                inner_content = func_match.group(2)
                
                args = {}
                # 2. Find parameters inside function block
                # Regex handles: <parameter=KEY>, <parameter name="KEY">, <param name="KEY">
                param_pattern = re.compile(
                    r'<(?:parameter|param)(?:(?:\s+name=["\']?)|(?:=))(\w+)(?:["\']?)>(.*?)</(?:parameter|param)>',
                    re.DOTALL | re.IGNORECASE
                )
                
                for pm in param_pattern.finditer(inner_content):
                    param_name = pm.group(1)
                    param_value = pm.group(2).strip()
                    args[param_name] = param_value
                
                tool_calls.append(ToolCall(name=tool_name, args=args))
        
        except Exception as e:
            print(f"[Local LLM] Error parsing tool calls: {e}")
        
        return tool_calls
    
    def _log_debug(self, data: dict) -> None:
        try:
            with open("llm_debug.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(data, default=str) + "\n")
        except Exception:
            pass
