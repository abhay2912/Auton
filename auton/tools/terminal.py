import subprocess
from auton.tools.registry import registry

@registry.register
def run_terminal_command(command: str) -> str:
    """
    Executes a shell command inside the secure sandbox (Kali Linux).
    Use this to run tools like nmap, curl, whois, etc.
    
    Args:
        command: The shell command to execute.
    """
    print(f"[Tool] run_terminal_command called: {command}")
    
    # Lazy import to avoid circular dependencies if any, though sandbox is standalone
    from auton.runtime.sandbox import sandbox
    
    # Ensure sandbox is running (it should be started by CLI, but good to check/start if needed)
    # sandbox.start() # Avoiding auto-start here to prevent delays on every call if not running
    
    return sandbox.exec(command)
