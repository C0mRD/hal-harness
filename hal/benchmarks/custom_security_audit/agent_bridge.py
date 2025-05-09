import os
import sys
from typing import Dict, Any, Optional

from inspect_ai.solver import solver
from inspect_ai.solver import TaskState, Generate
from inspect_ai.model import ChatMessageAssistant, ModelOutput

# Ensure proper importing of the security audit agent module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from agents.security_audit_agent.main import run as security_audit_run

@solver
def security_audit_solver(
    model_name: Optional[str] = None,
    temperature: float = 0.2,
):
    """Creates a solver that uses the security audit agent"""
    
    # Default to Google's Gemini model if none specified
    model_name = model_name or "google/gemini-1.5-flash"
    
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        """Run the security audit agent on the input"""
        
        # Create input in the format expected by the security audit agent
        # We're processing one sample at a time through the solver
        input_dict = {
            "task_0": {"code": state.input_text}
        }
        
        # Run the security audit agent
        kwargs = {
            "model_name": model_name,
            "temperature": temperature,
        }
        
        # Call the security audit agent
        results = security_audit_run(input_dict, **kwargs)
        
        # Extract the report
        if "task_0" in results:
            report = results["task_0"]
            
            # Determine the vulnerability type based on the report content
            if "SQL Injection" in report:
                completion = "SQL Injection"
            elif "Cross-Site Scripting" in report or "XSS" in report:
                completion = "Cross-Site Scripting"
            elif "Sensitive Data" in report or "credentials" in report.lower():
                completion = "Sensitive Data Exposure"
            else:
                completion = "Unknown Vulnerability"
            
            # Add completion as an assistant message
            state.messages.append(
                ChatMessageAssistant(content=completion)
            )
            
            # Set the model output (will be used by scorer)
            if state.output is None:
                state.output = ModelOutput(completion=completion)
            else:
                state.output.completion = completion
            
            # Save full report as metadata
            if state.metadata is None:
                state.metadata = {}
            state.metadata["full_report"] = report
        
        return state

    return solve 