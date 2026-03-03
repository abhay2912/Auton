"""Session persistence — save and resume scans.

Each scan session is stored as a JSON file in the workspace directory
so it can be resumed later or used for reporting.
"""

import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class SessionStatus(Enum):
    """Session lifecycle states."""

    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass
class Finding:
    """A confirmed vulnerability finding.

    Every finding must include an actual payload and observed evidence.
    """

    title: str
    severity: str  # Critical / High / Medium / Low / Info
    description: str
    payload: str  # What was injected
    evidence: str  # What was observed (alert text, DOM change, error, etc.)
    url: str = ""
    reproduction_steps: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Session:
    """Represents a single scan session."""

    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    target: str = ""
    task: str = ""
    model: str = ""
    status: str = SessionStatus.CREATED.value
    backend_session_id: str | None = None

    # Timestamps
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = ""

    # Results
    findings: list[dict[str, Any]] = field(default_factory=list)
    output_log: list[str] = field(default_factory=list)
    total_cost_usd: float = 0.0
    tool_calls: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SessionStore:
    """Manages session persistence to disk."""

    def __init__(self, sessions_dir: Path | None = None) -> None:
        self._dir = sessions_dir or Path.cwd() / "workspace" / ".sessions"
        self._dir.mkdir(parents=True, exist_ok=True)
        self._current: Session | None = None

    def create(self, target: str, task: str, model: str) -> Session:
        """Create a new session."""
        session = Session(target=target, task=task, model=model)
        self._current = session
        self._save()
        logger.info(f"Created session {session.session_id}")
        return session

    def load(self, session_id: str) -> Session | None:
        """Load a session by ID."""
        path = self._dir / f"{session_id}.json"
        if not path.exists():
            logger.warning(f"Session {session_id} not found")
            return None

        with open(path) as f:
            data = json.load(f)

        session = Session(**data)
        self._current = session
        return session

    def list_sessions(self) -> list[dict[str, Any]]:
        """List all saved sessions."""
        sessions = []
        for path in sorted(self._dir.glob("*.json"), reverse=True):
            with open(path) as f:
                data = json.load(f)
            sessions.append({
                "session_id": data.get("session_id"),
                "target": data.get("target"),
                "status": data.get("status"),
                "created_at": data.get("created_at"),
                "findings_count": len(data.get("findings", [])),
            })
        return sessions

    def update_status(self, status: SessionStatus) -> None:
        """Update session status."""
        if self._current:
            self._current.status = status.value
            self._current.updated_at = datetime.now(timezone.utc).isoformat()
            self._save()

    def add_finding(self, finding: Finding) -> None:
        """Add a vulnerability finding."""
        if self._current:
            self._current.findings.append(finding.to_dict())
            self._save()
            logger.info(f"Finding added: {finding.title} [{finding.severity}]")

    def add_output(self, text: str) -> None:
        """Append to the output log."""
        if self._current:
            self._current.output_log.append(text)
            # Don't save on every output — too frequent
            if len(self._current.output_log) % 10 == 0:
                self._save()

    def add_cost(self, cost: float) -> None:
        """Add API cost."""
        if self._current:
            self._current.total_cost_usd += cost

    def increment_tool_calls(self) -> None:
        """Track tool usage."""
        if self._current:
            self._current.tool_calls += 1

    def set_backend_session_id(self, backend_id: str) -> None:
        """Store the backend-specific session ID for resume."""
        if self._current:
            self._current.backend_session_id = backend_id
            self._save()

    def set_error(self, error: str) -> None:
        """Record an error."""
        if self._current:
            self._current.error = error
            self._save()

    def _save(self) -> None:
        """Persist current session to disk."""
        if not self._current:
            return
        path = self._dir / f"{self._current.session_id}.json"
        with open(path, "w") as f:
            json.dump(self._current.to_dict(), f, indent=2)

    @property
    def current(self) -> Session | None:
        return self._current
