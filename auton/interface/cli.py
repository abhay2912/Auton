import argparse
import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from auton.llm.gemini_client import GeminiLLMClient
from auton.agents.auton_agent import AutonAgent
from auton.runtime.local_runtime import LocalRuntime
# Import tools to register them
import auton.tools.basic_tools
import auton.tools.terminal
import auton.tools.web

def load_env():
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".env")
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ[key] = value

from auton.runtime.sandbox import sandbox

from auton.llm.local_client import LocalLLMClient

def main():
    load_env()
    parser = argparse.ArgumentParser(description="Auton Security Tool")
    parser.add_argument("--goal", type=str, default="Perform a basic security scan of example.com", help="The goal for the agent")
    parser.add_argument("--local", action="store_true", help="Use local LLM at localhost:5000")
    args = parser.parse_args()

    print(f"Auton starting with goal: {args.goal}")
    
    # Start Sandbox
    sandbox.start()

    try:
        if args.local:
            print("Using Local LLM Client...")
            llm = LocalLLMClient()
        else:
            print("Using Gemini LLM Client...")
            llm = GeminiLLMClient()
    except ValueError as e:
        print(f"Error: {e}")
        return

    root_agent = AutonAgent(name="Root", goal=args.goal, llm=llm)
    runtime = LocalRuntime(root_agent=root_agent)
    
    runtime.run()

if __name__ == "__main__":
    main()
