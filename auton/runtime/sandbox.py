import subprocess
import time
import sys

class SandboxManager:
    def __init__(self, image: str = "kalilinux/kali-rolling", container_name: str = "auton-sandbox"):
        self.image = image
        self.container_name = container_name

    def start(self):
        """Starts the sandbox container if not already running."""
        print(f"[Sandbox] Checking for container '{self.container_name}'...")
        
        # Check if running
        if self._is_running():
            print(f"[Sandbox] Container '{self.container_name}' is already running.")
            return

        # Check if exists but stopped
        if self._exists():
            print(f"[Sandbox] Container '{self.container_name}' exists but stopped. Starting...")
            subprocess.run(["docker", "start", self.container_name], check=True)
            return

        # Create and run
        print(f"[Sandbox] Creating and starting container '{self.container_name}' from image '{self.image}'...")
        print("[Sandbox] This might take a while if the image needs to be pulled.")
        try:
            # Run detached, keep alive with tail -f /dev/null
            subprocess.run(
                ["docker", "run", "-d", "--name", self.container_name, self.image, "tail", "-f", "/dev/null"],
                check=True
            )
            print(f"[Sandbox] Container started successfully.")
            
            # Optional: Install basic tools if needed (Kali usually has them, but 'rolling' might be minimal)
            # self.exec("apt-get update && apt-get install -y nmap curl whois")
            
        except subprocess.CalledProcessError as e:
            print(f"[Sandbox] Error starting container: {e}")
            sys.exit(1)

    def stop(self):
        """Stops the sandbox container."""
        print(f"[Sandbox] Stopping container '{self.container_name}'...")
        subprocess.run(["docker", "stop", self.container_name], check=False)

    def exec(self, command: str) -> str:
        """Executes a command inside the sandbox."""
        # print(f"[Sandbox] Executing: {command}")
        try:
            # docker exec container_name sh -c "command"
            result = subprocess.run(
                ["docker", "exec", self.container_name, "sh", "-c", command],
                capture_output=True,
                text=True,
                timeout=60
            )
            output = result.stdout
            if result.stderr:
                output += f"\nSTDERR:\n{result.stderr}"
            return output
        except Exception as e:
            return f"Error executing command in sandbox: {e}"

    def _is_running(self) -> bool:
        result = subprocess.run(
            ["docker", "ps", "--filter", f"name={self.container_name}", "--format", "{{.Names}}"],
            capture_output=True,
            text=True
        )
        return self.container_name in result.stdout.strip()

    def _exists(self) -> bool:
        result = subprocess.run(
            ["docker", "ps", "-a", "--filter", f"name={self.container_name}", "--format", "{{.Names}}"],
            capture_output=True,
            text=True
        )
        return self.container_name in result.stdout.strip()

# Global instance
sandbox = SandboxManager()
