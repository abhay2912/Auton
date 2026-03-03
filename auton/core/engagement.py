"""
Engagement configuration for Auton v2.

Defines the scope, rules, and constraints for a penetration test engagement.
This ensures all agents operate within approved boundaries.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict
from enum import Enum


class EngagementType(Enum):
    WEB_APP = "web_app"
    API = "api"
    NETWORK = "network"
    FULL = "full"


class TestingMode(Enum):
    PASSIVE = "passive"       # Recon only, no active exploitation
    ACTIVE = "active"         # Full testing including exploitation attempts
    SAFE = "safe"             # Active but avoids destructive actions (DoS, data deletion)


@dataclass
class Scope:
    """Defines what is in and out of scope."""
    
    # In-scope targets
    target_urls: List[str] = field(default_factory=list)
    target_hosts: List[str] = field(default_factory=list)
    target_ports: List[int] = field(default_factory=list)
    
    # Explicitly excluded
    excluded_urls: List[str] = field(default_factory=list)
    excluded_paths: List[str] = field(default_factory=list)
    excluded_hosts: List[str] = field(default_factory=list)
    
    def is_in_scope(self, url: str) -> bool:
        """Check if a URL is within the approved scope."""
        # Check exclusions first
        for excl in self.excluded_urls:
            if excl in url:
                return False
        for excl in self.excluded_paths:
            if excl in url:
                return False
        for excl in self.excluded_hosts:
            if excl in url:
                return False
        
        # Check inclusions
        for target in self.target_urls:
            if target in url:
                return True
        for target in self.target_hosts:
            if target in url:
                return True
        
        return False


@dataclass
class Engagement:
    """
    Full engagement configuration.
    
    Created at the start of a pentest run and shared with all agents.
    The Engagement Manager enforces these rules throughout the test.
    """
    
    name: str = "Unnamed Engagement"
    engagement_type: EngagementType = EngagementType.WEB_APP
    testing_mode: TestingMode = TestingMode.SAFE
    scope: Scope = field(default_factory=Scope)
    
    # Credentials (if provided for authenticated testing)
    credentials: List[Dict[str, str]] = field(default_factory=list)
    
    # Rate limiting
    max_requests_per_second: int = 10
    max_concurrent_workers: int = 3
    
    # Safety constraints
    max_steps_per_agent: int = 50
    max_total_steps: int = 500
    
    # LLM config
    primary_llm: str = "gemini"       # "gemini" or "local"
    fallback_llm: str = "local"       # Used when primary hits rate limits
    
    # Output
    output_dir: str = "./reports"
    
    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.engagement_type.value,
            "mode": self.testing_mode.value,
            "scope": {
                "targets": self.scope.target_urls + self.scope.target_hosts,
                "excluded": self.scope.excluded_urls + self.scope.excluded_paths,
            },
            "limits": {
                "max_requests_per_sec": self.max_requests_per_second,
                "max_workers": self.max_concurrent_workers,
                "max_steps_per_agent": self.max_steps_per_agent,
                "max_total_steps": self.max_total_steps,
            },
            "llm": {
                "primary": self.primary_llm,
                "fallback": self.fallback_llm,
            },
        }
    
    def summary(self) -> str:
        """Compact text for LLM prompts."""
        targets = ", ".join(self.scope.target_urls[:5])
        return (
            f"Engagement: {self.name}\n"
            f"Type: {self.engagement_type.value} | Mode: {self.testing_mode.value}\n"
            f"Targets: {targets}\n"
            f"Limits: {self.max_steps_per_agent} steps/agent, "
            f"{self.max_concurrent_workers} workers"
        )
