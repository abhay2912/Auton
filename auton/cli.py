"""Auton CLI — Entry point for running security scans.

Usage:
    python -m auton scan https://example.com
    python -m auton scan https://example.com --proxy http://127.0.0.1:8080
    python -m auton scan https://example.com --instruction "Focus on auth bypass"
    python -m auton scan https://example.com --no-browser
    python -m auton resume <session_id>
    python -m auton sessions
"""

import argparse
import asyncio
import logging
import sys

from auton import __version__


def setup_logging(verbose: bool = False) -> None:
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stderr),
        ],
    )


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="auton",
        description=f"Auton v{__version__} — Autonomous Web Security Tester",
    )
    parser.add_argument(
        "--version", action="version", version=f"auton {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # === scan ===
    scan_parser = subparsers.add_parser(
        "scan", help="Start a new security scan"
    )
    scan_parser.add_argument(
        "target",
        help="Target URL to scan (e.g., https://example.com)",
    )
    scan_parser.add_argument(
        "--instruction", "-i",
        help="Additional instructions for the scan",
    )
    scan_parser.add_argument(
        "--model", "-m",
        default="claude-sonnet-4-5-20250929",
        help="Claude model to use (default: claude-sonnet-4-5-20250929)",
    )
    scan_parser.add_argument(
        "--max-iterations",
        type=int,
        default=200,
        help="Maximum agent iterations (default: 200)",
    )
    scan_parser.add_argument(
        "--proxy", "-p",
        default=None,
        help="HTTP proxy URL (e.g., http://127.0.0.1:8080 for Burp Suite)",
    )
    scan_parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Disable browser (use curl only)",
    )
    scan_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug output",
    )

    # === resume ===
    resume_parser = subparsers.add_parser(
        "resume", help="Resume a previous scan session"
    )
    resume_parser.add_argument(
        "session_id",
        help="Session ID to resume",
    )
    resume_parser.add_argument(
        "--instruction", "-i",
        help="New instructions for the resumed session",
    )
    resume_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug output",
    )

    # === sessions ===
    subparsers.add_parser(
        "sessions", help="List saved scan sessions"
    )

    return parser


async def cmd_scan(args: argparse.Namespace) -> None:
    """Execute a new scan."""
    from auton.config import load_config
    from auton.core.controller import AgentController

    print(f"\033[36m{'═' * 60}\033[0m")
    print(f"\033[36m  Auton v{__version__} — Autonomous Web Security Tester\033[0m")
    print(f"\033[36m{'═' * 60}\033[0m")
    print(f"\033[36m  Target:\033[0m  {args.target}")
    print(f"\033[36m  Model:\033[0m   {args.model}")
    if args.proxy:
        print(f"\033[36m  Proxy:\033[0m   {args.proxy}")
    print(f"\033[36m  Browser:\033[0m {'Disabled' if args.no_browser else 'Enabled'}")
    if args.instruction:
        print(f"\033[36m  Note:\033[0m    {args.instruction}")
    print(f"\033[36m{'═' * 60}\033[0m")
    print()

    config = load_config(
        target=args.target,
        llm_model=args.model,
        max_iterations=args.max_iterations,
        custom_instruction=args.instruction,
        proxy=args.proxy,
        browser_mode=not args.no_browser,
    )

    controller = AgentController(config)

    # Build the task prompt
    task = f"Perform a comprehensive security assessment of: {args.target}"
    if args.instruction:
        task += f"\n\nAdditional context: {args.instruction}"

    result = await controller.run(task)

    # Print summary
    print()
    print(f"\033[36m{'═' * 60}\033[0m")
    if result.get("success"):
        findings = result.get("findings", [])
        print(f"\033[32m  ✓ Scan completed successfully\033[0m")
        print(f"  Findings: {len(findings)}")
        print(f"  Cost: ${result.get('cost_usd', 0):.4f}")
        print(f"  Session: {result.get('session_id', 'N/A')}")
    else:
        print(f"\033[31m  ✗ Scan failed: {result.get('error', 'Unknown')}\033[0m")
    print(f"\033[36m{'═' * 60}\033[0m")


async def cmd_resume(args: argparse.Namespace) -> None:
    """Resume a previous scan."""
    from auton.config import load_config
    from auton.core.controller import AgentController

    config = load_config(target="(resumed)")

    controller = AgentController(config)
    task = args.instruction or "Continue the security assessment from where you left off."

    result = await controller.run(task, resume_session_id=args.session_id)

    if result.get("success"):
        print(f"\033[32m  ✓ Resumed scan completed\033[0m")
    else:
        print(f"\033[31m  ✗ Resume failed: {result.get('error')}\033[0m")


def cmd_sessions() -> None:
    """List saved sessions."""
    from auton.core.session import SessionStore

    store = SessionStore()
    sessions = store.list_sessions()

    if not sessions:
        print("No saved sessions found.")
        return

    print(f"\n{'ID':<10} {'Target':<35} {'Status':<12} {'Findings':<10} {'Created'}")
    print(f"{'─' * 10} {'─' * 35} {'─' * 12} {'─' * 10} {'─' * 20}")
    for s in sessions:
        print(
            f"{s['session_id']:<10} "
            f"{s['target'][:33]:<35} "
            f"{s['status']:<12} "
            f"{s['findings_count']:<10} "
            f"{s['created_at'][:19]}"
        )
    print()


def main() -> None:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    setup_logging(getattr(args, "verbose", False))

    if args.command == "scan":
        asyncio.run(cmd_scan(args))
    elif args.command == "resume":
        asyncio.run(cmd_resume(args))
    elif args.command == "sessions":
        cmd_sessions()


if __name__ == "__main__":
    main()
