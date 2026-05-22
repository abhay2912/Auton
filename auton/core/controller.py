"""Agent controller with lifecycle management and vulnerability detection.

Orchestrates the scan lifecycle: connect → query → process messages → report.
Handles pause/resume/stop, extracts findings, and manages session persistence.
"""

import asyncio
import logging
import re
from enum import Enum
from typing import Any, ClassVar

from auton.core.backend import (
    AgentBackend,
    AgentMessage,
    ClaudeCodeBackend,
    MessageType,
)
from auton.core.session import (
    Finding,
    SessionStatus,
    SessionStore,
)

logger = logging.getLogger(__name__)


class AgentState(Enum):
    """Agent lifecycle states."""

    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"


class AgentController:
    """Central orchestrator with lifecycle management.

    Features:
    - Framework-agnostic via AgentBackend
    - Pause/resume/stop control
    - Vulnerability finding detection from Claude's output
    - Session persistence
    """

    # Patterns that suggest Claude found a vulnerability
    VULN_INDICATORS: ClassVar[list[str]] = [
        r"(?i)vulnerability\s+(?:found|confirmed|detected|verified)",
        r"(?i)successfully\s+(?:exploited|injected|executed)",
        r"(?i)XSS\s+(?:payload|attack)\s+(?:worked|successful|executed)",
        r"(?i)SQL\s+injection\s+(?:confirmed|found|successful)",
        r"(?i)alert\s*\(\s*['\"]?(?:XSS|1|document\.)",
        r"(?i)proof\s+of\s+concept",
        r"(?i)CRITICAL|HIGH|MEDIUM\s+severity",
    ]

    def __init__(
        self,
        config: Any,
        backend: AgentBackend | None = None,
        session_store: SessionStore | None = None,
    ) -> None:
        self.config = config
        self.backend = backend
        self.sessions = session_store or SessionStore(
            sessions_dir=config.working_directory / ".sessions"
        )

        # State management
        self._state = AgentState.IDLE
        self._stop_requested = False
        self._pause_requested = False
        self._resume_event = asyncio.Event()
        self._pending_instruction: str | None = None

    @property
    def state(self) -> AgentState:
        """Get current agent state."""
        return self._state

    # === Control Methods ===

    def pause(self) -> bool:
        """Request pause at next safe point."""
        if self._state == AgentState.RUNNING:
            self._pause_requested = True
            return True
        return False

    def resume(self, instruction: str | None = None) -> bool:
        """Resume from paused state."""
        if self._state == AgentState.PAUSED:
            self._pending_instruction = instruction
            self._pause_requested = False
            self._resume_event.set()
            return True
        return False

    def stop(self) -> bool:
        """Request stop."""
        self._stop_requested = True
        self._resume_event.set()  # Unblock if paused
        return True

    # === Main Execution ===

    async def run(
        self,
        task: str,
        resume_session_id: str | None = None,
    ) -> dict[str, Any]:
        """Run agent with full lifecycle management.

        Args:
            task: Task/instructions for the agent
            resume_session_id: Optional session ID to resume

        Returns:
            Result dict with success, output, findings, cost, session_id
        """
        # Reset state
        self._stop_requested = False
        self._pause_requested = False
        self._resume_event.clear()

        # Create or resume session
        if resume_session_id:
            session = self.sessions.load(resume_session_id)
            if not session:
                return {
                    "success": False,
                    "error": f"Session {resume_session_id} not found",
                }
            if not task:
                task = session.task
        else:
            session = self.sessions.create(
                target=self.config.target,
                task=task,
                model=self.config.llm_model,
            )

        # Create backend if needed
        if self.backend is None:
            from auton.prompts.pentesting import get_system_prompt

            # Build environment overrides (proxy, etc.)
            env_overrides: dict[str, str] = {}
            if self.config.proxy:
                env_overrides["HTTP_PROXY"] = self.config.proxy
                env_overrides["HTTPS_PROXY"] = self.config.proxy
                env_overrides["http_proxy"] = self.config.proxy
                env_overrides["https_proxy"] = self.config.proxy
                # Burp Suite intercepts TLS with its own cert —
                # Claude Code SDK (Node.js) must accept it
                env_overrides["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
                # CRITICAL: Exclude Anthropic API from proxy so the SDK's
                # own connection doesn't get routed through Burp (which
                # breaks the WebSocket/streaming connection silently).
                # Only curl/browser/python spawned by Claude go through proxy.
                env_overrides["NO_PROXY"] = (
                    "api.anthropic.com,"
                    "anthropic.com,"
                    "claude.ai,"
                    "*.anthropic.com,"
                    "*.claude.ai,"
                    "sentry.io,"          # SDK telemetry
                    "statsigapi.net"      # SDK feature flags
                )
                env_overrides["no_proxy"] = env_overrides["NO_PROXY"]
                self._print_status(f"🔀 Proxy: {self.config.proxy} (TLS verification disabled)")

            self.backend = ClaudeCodeBackend(
                working_directory=str(self.config.working_directory),
                system_prompt=get_system_prompt(
                    custom_instruction=self.config.custom_instruction,
                    proxy_url=self.config.proxy,
                    browser_mode=self.config.browser_mode,
                ),
                model=self.config.llm_model,
                permission_mode=self.config.permission_mode,
                env_overrides=env_overrides if env_overrides else None,
            )

        try:
            self._state = AgentState.RUNNING
            self._print_status("Connecting to Claude Code...")

            # Connect or resume
            if resume_session_id and self.backend.supports_resume:
                backend_sid = session.backend_session_id or resume_session_id
                await self.backend.resume(backend_sid)
                self._print_status(f"Resumed session {resume_session_id}")
            else:
                await self.backend.connect()

            # Store backend session ID for future resume
            if self.backend.session_id:
                self.sessions.set_backend_session_id(self.backend.session_id)

            # Send initial query
            self._print_status(f"Starting scan: {task[:80]}...")
            await self.backend.query(task)
            self.sessions.update_status(SessionStatus.RUNNING)

            # Process message stream
            output_parts: list[str] = []
            findings_detected: list[dict[str, Any]] = []

            async for msg in self.backend.receive_messages():
                # Check stop request
                if self._stop_requested:
                    self._state = AgentState.IDLE
                    self.sessions.update_status(SessionStatus.PAUSED)
                    self._print_status("Stopped by user.")
                    break

                # Check pause request
                if self._pause_requested:
                    self._pause_requested = False
                    self._state = AgentState.PAUSED
                    self.sessions.update_status(SessionStatus.PAUSED)
                    self._print_status("Paused — waiting for input...")

                    await self._resume_event.wait()
                    self._resume_event.clear()

                    if self._stop_requested:
                        break

                    self._state = AgentState.RUNNING
                    self.sessions.update_status(SessionStatus.RUNNING)

                    if self._pending_instruction:
                        self._print_status(
                            f"Injecting: {self._pending_instruction[:60]}..."
                        )
                        await self.backend.query(self._pending_instruction)
                        self._pending_instruction = None

                # Process the message
                self._process_message(msg, output_parts, findings_detected)

            # Mark completed
            if not self._stop_requested:
                self._state = AgentState.COMPLETED
                self.sessions.update_status(SessionStatus.COMPLETED)

            # Save final output
            for text in output_parts:
                self.sessions.add_output(text)

            result = {
                "success": True,
                "output": "\n".join(output_parts),
                "findings": findings_detected,
                "session_id": session.session_id,
                "cost_usd": session.total_cost_usd,
                "tool_calls": session.tool_calls,
            }

            # Generate report
            self._generate_report(result)

            return result

        except Exception as e:
            self._state = AgentState.ERROR
            self.sessions.set_error(str(e))
            self.sessions.update_status(SessionStatus.ERROR)
            logger.exception("Scan failed")
            return {"success": False, "error": str(e)}

        finally:
            if self.backend:
                await self.backend.disconnect()

    # === Message Processing ===

    def _process_message(
        self,
        msg: AgentMessage,
        output_parts: list[str],
        findings: list[dict[str, Any]],
    ) -> None:
        """Process a single agent message."""

        if msg.type == MessageType.TEXT:
            output_parts.append(msg.content)
            self._print_output(msg.content)

            # Detect vulnerability indicators
            detected = self._detect_findings(msg.content)
            for finding_text in detected:
                if finding_text not in [f.get("raw_text") for f in findings]:
                    finding_entry = {"raw_text": finding_text}
                    findings.append(finding_entry)
                    self._print_finding(finding_text)

        elif msg.type == MessageType.TOOL_START:
            self.sessions.increment_tool_calls()
            tool_display = msg.tool_name or "unknown"
            args_preview = ""
            if msg.tool_args:
                args_preview = str(msg.tool_args)[:80]
            self._print_status(f"🔧 {tool_display} {args_preview}")

        elif msg.type == MessageType.TOOL_RESULT:
            pass  # Tool results are handled by Claude internally

        elif msg.type == MessageType.RESULT:
            cost = msg.metadata.get("cost_usd", 0)
            if cost > 0:
                self.sessions.add_cost(cost)
                self._print_status(f"💰 Cost so far: ${cost:.4f}")

    def _detect_findings(self, text: str) -> list[str]:
        """Detect potential vulnerability findings in text."""
        findings = []
        for pattern in self.VULN_INDICATORS:
            for match in re.finditer(pattern, text):
                # Extract surrounding context (the sentence containing the match)
                start = max(0, text.rfind(".", 0, match.start()) + 1)
                end = text.find(".", match.end())
                if end == -1:
                    end = min(len(text), match.end() + 200)
                context = text[start:end].strip()
                if context:
                    findings.append(context)
        return findings

    # === Report Generation ===

    def _generate_report(self, result: dict[str, Any]) -> None:
        """Generate a markdown report from scan results."""
        if not result.get("success"):
            return

        from auton.reporting.generator import generate_report

        report_path = self.config.working_directory / "report.md"
        generate_report(
            target=self.config.target,
            output=result.get("output", ""),
            findings=result.get("findings", []),
            session_id=result.get("session_id", ""),
            cost_usd=result.get("cost_usd", 0),
            tool_calls=result.get("tool_calls", 0),
            output_path=report_path,
        )
        self._print_status(f"📄 Report saved: {report_path}")

    # === Output Helpers ===

    def _print_status(self, msg: str) -> None:
        """Print a status update."""
        print(f"\033[36m[auton]\033[0m {msg}")

    def _print_output(self, text: str) -> None:
        """Print agent output."""
        # Only print substantial output, skip small fragments
        if len(text.strip()) > 10:
            print(f"\033[37m{text}\033[0m")

    def _print_finding(self, text: str) -> None:
        """Print a finding detection."""
        print(f"\n\033[91m🚨 [FINDING DETECTED]\033[0m {text[:200]}\n")
