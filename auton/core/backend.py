"""Framework-agnostic agent backend protocol and Claude Code implementation.

Adapted from PentestGPT's backend.py with Auton-specific modifications.
The AgentBackend ABC enables future backends (OpenAI, local LLM, etc.).
"""

import logging
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class MessageType(Enum):
    """Framework-agnostic message types from agent backends."""

    TEXT = "text"
    TOOL_START = "tool_start"
    TOOL_RESULT = "tool_result"
    RESULT = "result"
    ERROR = "error"


@dataclass
class AgentMessage:
    """Framework-agnostic message from any agent backend."""

    type: MessageType
    content: Any
    tool_name: str | None = None
    tool_args: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class AgentBackend(ABC):
    """Abstract interface for agent backends.

    Implement this to support different frameworks:
    - ClaudeCodeBackend (current)
    - OpenAI Agents Backend (future)
    - Local LLM Backend (future)
    """

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to the agent."""
        ...

    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection."""
        ...

    @abstractmethod
    async def query(self, prompt: str) -> None:
        """Send a query/instruction to the agent."""
        ...

    @abstractmethod
    def receive_messages(self) -> AsyncIterator[AgentMessage]:
        """Async iterator yielding messages from agent."""
        ...

    @property
    @abstractmethod
    def session_id(self) -> str | None:
        """Current session ID (if backend supports sessions)."""
        ...

    @property
    def supports_resume(self) -> bool:
        """Whether this backend supports session resume."""
        return False

    @abstractmethod
    async def resume(self, session_id: str) -> bool:
        """Resume a previous session. Returns success."""
        ...


class ClaudeCodeBackend(AgentBackend):
    """Claude Code SDK implementation of AgentBackend.

    Uses the claude_agent_sdk to connect to Claude Code CLI.
    Requires: npm install -g @anthropic-ai/claude-code
    Authentication: Uses Claude Pro subscription via OAuth (no API key needed).
    """

    def __init__(
        self,
        working_directory: str,
        system_prompt: str,
        model: str,
        permission_mode: str = "bypassPermissions",
        env_overrides: dict[str, str] | None = None,
    ) -> None:
        self._cwd = working_directory
        self._system_prompt = system_prompt
        self._model = model
        self._permission_mode = permission_mode
        self._env_overrides = env_overrides or {}
        self._client: Any = None  # ClaudeSDKClient
        self._session_id: str | None = None

    async def connect(self) -> None:
        """Connect to Claude Code CLI."""
        from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient

        options = ClaudeAgentOptions(
            cwd=self._cwd,
            permission_mode=self._permission_mode,
            system_prompt=self._system_prompt,
            model=self._model,
            env=self._env_overrides if self._env_overrides else None,
        )

        logger.info(f"Connecting to Claude Code CLI (model={self._model})...")
        self._client = ClaudeSDKClient(options=options)

        result = self._client.connect()
        if result is not None:
            await result

        logger.info("Connected to Claude Code CLI.")

    async def disconnect(self) -> None:
        """Disconnect from Claude Code CLI."""
        if self._client:
            result = self._client.disconnect()
            if result is not None:
                await result
            self._client = None
            logger.info("Disconnected from Claude Code CLI.")

    async def query(self, prompt: str) -> None:
        """Send a query to Claude Code."""
        if not self._client:
            raise RuntimeError("Backend not connected")

        result = self._client.query(prompt)
        if result is not None:
            await result

    async def receive_messages(self) -> AsyncIterator[AgentMessage]:
        """Convert Claude SDK messages to framework-agnostic AgentMessage."""
        from claude_agent_sdk import (
            AssistantMessage,
            ResultMessage,
            TextBlock,
            ToolUseBlock,
        )

        if not self._client:
            raise RuntimeError("Backend not connected")

        async for msg in self._client.receive_response():
            if isinstance(msg, AssistantMessage):
                for block in msg.content:
                    if isinstance(block, TextBlock):
                        yield AgentMessage(
                            type=MessageType.TEXT,
                            content=block.text,
                        )
                    elif isinstance(block, ToolUseBlock):
                        yield AgentMessage(
                            type=MessageType.TOOL_START,
                            content=None,
                            tool_name=block.name,
                            tool_args=block.input,
                        )

            elif isinstance(msg, ResultMessage):
                yield AgentMessage(
                    type=MessageType.RESULT,
                    content=None,
                    metadata={
                        "cost_usd": getattr(msg, "total_cost_usd", 0),
                    },
                )

    @property
    def session_id(self) -> str | None:
        """Get current session ID."""
        return self._session_id

    @property
    def supports_resume(self) -> bool:
        """Claude Code supports session resume."""
        return True

    async def resume(self, session_id: str) -> bool:
        """Resume a previous Claude Code session."""
        from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient

        # Disconnect existing client
        if self._client:
            await self.disconnect()

        options = ClaudeAgentOptions(
            cwd=self._cwd,
            permission_mode=self._permission_mode,
            system_prompt=self._system_prompt,
            model=self._model,
            resume=session_id,
            env=self._env_overrides if self._env_overrides else None,
        )

        self._client = ClaudeSDKClient(options=options)
        result = self._client.connect()
        if result is not None:
            await result

        self._session_id = session_id
        logger.info(f"Resumed session {session_id}")
        return True
