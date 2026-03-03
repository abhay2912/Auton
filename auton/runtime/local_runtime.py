from typing import Any
from auton.agents.auton_agent import AutonAgent
from auton.tools.registry import registry

class LocalRuntime:
    def __init__(self, root_agent: AutonAgent):
        self.root_agent = root_agent

    def run(self):
        print(f"Starting runtime with agent: {self.root_agent.name}")
        
        while not self.root_agent.state.is_finished:
            # 1. Agent Step
            response = self.root_agent.step()
            
            # 2. Process Response
            # The response from Gemini SDK might be a GenerateContentResponse object
            # We need to check for function calls.
            
            # Note: This part depends heavily on the exact structure of the Gemini SDK response object.
            # For this POC, we'll try to handle it generically or assume a certain structure.
            
            # If response has candidates and parts
            if hasattr(response, 'candidates') and response.candidates:
                candidate = response.candidates[0]
                if hasattr(candidate, 'content') and hasattr(candidate.content, 'parts'):
                    part = candidate.content.parts[0]
                    
                    # 1. Capture the full LLM response (Thought + Action) and add to history
                    # This ensures the "Thought" is preserved.
                    llm_text = getattr(part, 'text', '')
                    if llm_text:
                        print(f"[Agent] {llm_text}")
                        self.root_agent.state.history.append({
                            "role": "assistant",
                            "content": llm_text
                        })

                    # 2. Check for tool calls (Action)
                    # Support multiple tool calls
                    tool_calls = getattr(part, 'function_calls', [])
                    
                    # Fallback for single call property if list is empty but single exists
                    if not tool_calls and hasattr(part, 'function_call') and part.function_call:
                        tool_calls = [part.function_call]
                    
                    if tool_calls:
                        for fc in tool_calls:
                            tool_name = fc.name
                            tool_args = dict(fc.args)
                            
                            print(f"[Runtime] Executing tool: {tool_name} with args: {tool_args}")
                            
                            tool_func = registry.get_tool(tool_name)
                            if tool_func:
                                try:
                                    result = tool_func(**tool_args)
                                except Exception as e:
                                    result = f"Error executing tool: {e}"
                            else:
                                result = f"Tool {tool_name} not found."
                                
                            print(f"[Runtime] Tool result: {result}")
                            
                            # 3. Add Observation to history
                            self.root_agent.state.history.append({
                                "role": "tool",
                                "content": str(result)
                            })
                            
                            if tool_name == "finish_scan":
                                self.root_agent.state.is_finished = True
                                return
            else:
                print("No response from agent.")
                break
