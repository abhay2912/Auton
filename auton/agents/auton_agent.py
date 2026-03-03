from typing import List, Dict, Any
from auton.agents.base import BaseAgent
from auton.llm.gemini_client import GeminiLLMClient
from auton.tools.registry import registry
from auton.agents.graph import graph

from auton.prompts.system_prompts import ROOT_AGENT_PROMPT, CHILD_AGENT_PROMPT, STRIX_SYSTEM_PROMPT
from auton.llm.local_client import LocalLLMClient

class AutonAgent(BaseAgent):
    def __init__(self, name: str, goal: str, llm: Any, parent_id: str = None, tools: List[Any] = None, system_prompt: str = None):
        super().__init__(name, goal)
        self.llm = llm
        self.tools = tools if tools is not None else registry.get_tools()
        self.parent_id = parent_id
        self.system_prompt = system_prompt
        
        # Register in graph
        graph.add_node(agent_id=name, parent_id=parent_id, metadata={"goal": goal})

    def _get_tool_descriptions(self) -> str:
        desc = ""
        for tool in self.tools:
            # Assuming tool is a callable with a __name__ and __doc__
            # If it's a LangChain tool or similar, adjust accordingly.
            # For this POC, our tools are functions.
            name = getattr(tool, "__name__", str(tool))
            doc = getattr(tool, "__doc__", "No description.")
            desc += f"- {name}: {doc}\n"
        return desc

    def step(self) -> Any:
        if self.state.is_finished:
            return "Agent is finished."

        # Construct messages
        messages = []
        
        # Select prompt
        if isinstance(self.llm, LocalLLMClient):
            # Prompt Optimization:
            # If session exists, we check if we can send just the incremental update.
            # LocalLLMClient manages the session_id.
            if self.llm.session_id and self.state.history:
                # Incremental Update
                last_msg = self.state.history[-1]
                content = last_msg["content"]
                role = last_msg["role"]
                
                # We only need to feed the new observation to the model.
                # The model's context on the server already has the previous turns.
                if role == "tool" or role == "user":
                    full_prompt = f"Observation: {content}"
                else:
                    # Fallback for weird states
                    full_prompt = f"Observation: {content}"
            else:
                # Full Context Initialization
                tool_desc = self._get_tool_descriptions()
                # Use custom system prompt if provided, else Strix default
                base_prompt = self.system_prompt if self.system_prompt else STRIX_SYSTEM_PROMPT
                sys_prompt = base_prompt.format(goal=self.state.goal, tool_descriptions=tool_desc)
                full_prompt = sys_prompt + "\n\n"
                
                for msg in self.state.history:
                    role = msg["role"]
                    content = msg["content"]
                    if role == "assistant":
                        full_prompt += f"{content}\n"
                    elif role == "tool":
                        full_prompt += f"Observation: {content}\n"
                    elif role == "user":
                        # Treat user messages as observations or directives
                        full_prompt += f"Observation: {content}\n"
            
            print(f"[DEBUG] Sending ReAct Prompt to LLM (Length: {len(full_prompt)})")
            
            # Send as a single message to LocalLLMClient
            # We wrap it in a list of dicts because the client expects it, but the client will just take the last content.
            messages = [{"role": "user", "content": full_prompt}]
            
        elif self.parent_id:
            sys_prompt = CHILD_AGENT_PROMPT.format(goal=self.state.goal)
            messages.append({"role": "system", "content": sys_prompt})
            messages.extend(self.state.history)
            if not self.state.history:
                 messages.append({"role": "user", "content": f"Start working on: {self.state.goal}"})
        else:
            sys_prompt = ROOT_AGENT_PROMPT
            messages.append({"role": "system", "content": sys_prompt})
            messages.extend(self.state.history)
            if not self.state.history:
                 messages.append({"role": "user", "content": f"Start working on: {self.state.goal}"})

        # Call LLM with Retry & Correction Logic
        max_retries = 3
        current_messages = messages # Start with the constructed messages

        for attempt in range(max_retries):
            try:
                if isinstance(self.llm, LocalLLMClient):
                    response = self.llm.chat(current_messages, tools=self.tools)
                else:
                    response = self.llm.chat(current_messages, tools=self.tools)
                
                text_resp = getattr(response, 'text', '')
                
                # Check for transient errors
                if any(err in text_resp for err in ["Error: Input box not found", "Error: Send button not found", "Error: Timeout"]):
                     print(f"[Agent] Transient error detected: '{text_resp}'. Retrying ({attempt+1}/{max_retries})...")
                     import time
                     time.sleep(2)
                     continue 
                
                # Check for Format Error (Missing XML)
                # We skip this check if the agent says "Agent is finished" or some valid text? 
                # No, strict XML means ALWAYS XML.
                if "<function" not in text_resp:
                    print(f"[Agent] Format Error: No XML tool call found in '{text_resp[:50]}...'. Retrying with correction ({attempt+1}/{max_retries})...")
                    # Send feedback to LLM to correct itself
                    # If session exists, we can just send the error message as the next turn.
                    if self.llm.session_id:
                        current_messages = [{"role": "user", "content": "Error: No tool call found. You MUST output a tool call in XML format like <function=...>."}]
                    else:
                        # If stateless (rare now), append to history? 
                        # Or just retry the same prompt? 
                        # Let's retry same prompt for now or append to the list.
                        current_messages.append({"role": "user", "content": "Error: No tool call found. You MUST output a tool call in XML format."})
                    
                    import time
                    time.sleep(1)
                    continue

                break # Success

            except Exception as e:
                print(f"[DEBUG] LLM Chat Error: {e}")
                if attempt == max_retries - 1:
                    return f"Error: {e}"
                import time
                time.sleep(2)

        print(f"[DEBUG] LLM Response Object: {response}")
        if hasattr(response, 'text'):
            print(f"[DEBUG] LLM Response Text: {response.text}")
            
        return response
