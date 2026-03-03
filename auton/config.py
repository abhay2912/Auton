"""Configuration management for Auton using Pydantic."""

from pathlib import Path
from typing import Any, Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AutonConfig(BaseSettings):
    """Main configuration for Auton.

    Configuration is loaded from environment variables and .env files.
    Claude Code manages its own authentication via OAuth — no API key needed.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="AUTON_",
        case_sensitive=False,
        extra="ignore",
    )

    # === Target ===
    target: str = Field(
        ...,  # Required
        description="Target URL for security testing",
    )

    # === LLM Configuration ===
    llm_model: str = Field(
        default="claude-sonnet-4-5-20250929",
        description="Claude model to use",
    )

    # === Agent Settings ===
    max_iterations: int = Field(
        default=200,
        description="Maximum agent iterations before forced stop",
    )

    permission_mode: Literal["ask", "bypassPermissions"] = Field(
        default="bypassPermissions",
        description="Permission mode for Claude Code SDK",
    )

    working_directory: Path = Field(
        default_factory=lambda: Path.cwd() / "workspace",
        description="Working directory for agent operations",
    )

    # === Scan Options ===
    custom_instruction: str | None = Field(
        default=None,
        description="Additional instructions to append to system prompt",
    )

    headless: bool = Field(
        default=False,
        description="Run in headless mode (no TUI, CLI output only)",
    )

    verbose: bool = Field(
        default=True,
        description="Enable verbose output",
    )

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        # Ensure working directory exists
        try:
            self.working_directory.mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError):
            if not self.working_directory.exists():
                raise


def load_config(**overrides: object) -> AutonConfig:
    """Load configuration from environment with optional overrides.

    Example:
        config = load_config(target="https://example.com")
    """
    return AutonConfig(**overrides)
