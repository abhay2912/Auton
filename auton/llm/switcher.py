"""
LLM Client Switcher for Auton v2.

Automatic failover: tries primary (Gemini) first, falls back to local (Mistral)
when rate-limited or on error.
"""

from typing import List, Dict, Any, Optional

from auton.llm.base import BaseLLMClient, LLMResponse


class LLMClientSwitcher(BaseLLMClient):
    """
    Transparent failover between primary and fallback LLM clients.
    
    Usage:
        gemini = GeminiClient()
        local = LocalClient()
        llm = LLMClientSwitcher(primary=gemini, fallback=local)
        
        response = llm.chat(messages, tools=tools)  # Tries Gemini first
    """
    
    def __init__(self, primary: BaseLLMClient, fallback: BaseLLMClient):
        self.primary = primary
        self.fallback = fallback
        self._using_fallback = False
        self._primary_failures = 0
        self._max_primary_failures = 3  # Switch to fallback after N failures
    
    def chat(self, messages: List[Dict[str, str]], 
             tools: Optional[List[Any]] = None) -> LLMResponse:
        """
        Try primary client first. On failure, fall back.
        
        After max_primary_failures consecutive failures, stops trying primary
        until reset_primary() is called.
        """
        # Try primary unless it's been failing too much
        if self._primary_failures < self._max_primary_failures:
            response = self.primary.chat(messages, tools=tools)
            
            if response.error:
                self._primary_failures += 1
                print(f"[Switcher] Primary failed ({self._primary_failures}/{self._max_primary_failures}): {response.error}")
                
                if self._is_rate_limit_error(response.error):
                    print("[Switcher] Rate limit detected, switching to fallback")
                
                # Fall through to fallback
            else:
                # Primary succeeded, reset failure counter
                self._primary_failures = 0
                self._using_fallback = False
                return response
        else:
            if not self._using_fallback:
                print(f"[Switcher] Primary disabled after {self._max_primary_failures} failures. Using fallback.")
                self._using_fallback = True
        
        # Use fallback
        fallback_response = self.fallback.chat(messages, tools=tools)
        
        if fallback_response.error:
            print(f"[Switcher] Fallback also failed: {fallback_response.error}")
        
        return fallback_response
    
    def _is_rate_limit_error(self, error: str) -> bool:
        """Check if the error is a rate limit."""
        rate_limit_indicators = [
            "429", "rate limit", "quota", "too many requests",
            "resource exhausted", "RESOURCE_EXHAUSTED",
        ]
        error_lower = error.lower()
        return any(indicator.lower() in error_lower for indicator in rate_limit_indicators)
    
    def reset_primary(self) -> None:
        """Reset primary failure counter (e.g., after a cooldown period)."""
        self._primary_failures = 0
        self._using_fallback = False
        print("[Switcher] Primary client re-enabled")
    
    @property
    def active_backend(self) -> str:
        """Which backend is currently active."""
        return "fallback" if self._using_fallback else "primary"
