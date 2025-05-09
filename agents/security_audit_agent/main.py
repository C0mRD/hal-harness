import os
import json
from typing import Dict, Any

from smolagents import CodeAgent, InferenceClientModel, OpenAIServerModel, LiteLLMModel, tool

from dotenv import load_dotenv

load_dotenv()

# Import security-related tools
from tools import (
    ScanForSQLInjectionTool,
    ScanForXSSTool, 
    ScanForCSRFTool,
    ScanForSensitiveDataTool,
    CheckSecureConfigTool
)

from code_parser import extract_code_context, identify_language

# Initialize the tools
scan_sql_injection_tool = ScanForSQLInjectionTool()
scan_xss_tool = ScanForXSSTool()
scan_csrf_tool = ScanForCSRFTool()
scan_sensitive_data_tool = ScanForSensitiveDataTool()
check_secure_config_tool = CheckSecureConfigTool()

@tool
def generate_vulnerability_report(scanner_findings: str, code_context: str) -> str:
    prompt = f"""
    As a security report specialist, create a comprehensive vulnerability report based on the 
    scanner findings below. For each vulnerability:
    
    1. Assign it to the correct OWASP Top 10 category
    2. Provide a severity rating (Critical, High, Medium, Low)
    3. Include the exact location in the code
    4. Describe the vulnerability and its implications
    5. Suggest detailed remediation steps with example code
    
    Format the report in Markdown with clear sections, code snippets, and actionable recommendations.
    
    Scanner Findings:
    {scanner_findings}
    
    Code Context:
    ```
    {code_context[:5000]}  # Limiting to first 5000 chars for context
    ```
    
    Ensure you correctly categorize each vulnerability according to OWASP Top 10 standards and avoid 
    misclassifications (e.g., don't label plaintext credentials as SQL injection).
    """
    
    # Get response from report agent
    response = report_agent.run(prompt)
    return response

def run(input: dict[str, Any], **kwargs) -> dict[str, str]:
    global report_agent  # Make it accessible to the tool function
    
    # Validate required arguments
    if 'model_name' not in kwargs:
        raise ValueError("model_name is required. Please provide it with -A model_name=<n>")
    
    # Parse model configuration
    model_name = kwargs.get('model_name')
    temperature = float(kwargs.get('temperature', 0.2))
    use_ollama = kwargs.get('use_ollama')
    
    # print(use_ollama)
    # # Setup the model to use
    # if use_ollama:
    #     model = OpenAIServerModel(
    #         model_id=model_name,
    #         api_base="http://localhost:11434/v1",
    #         api_key="ollama"
    #     )
    # else:
    #     model = OpenAIServerModel(
    #         model_id="meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8",
    #         api_base="https://api.together.xyz/v1/",
    #         api_key=os.getenv("TOGETHER_API_KEY"),
    #     )

    model = LiteLLMModel(
        model_id="gemini/gemini-1.5-flash",
        api_key=os.getenv("GEMINI_API_KEY")
    )
    
    # Create the scanner agent with specialized tools
    scanner_agent = CodeAgent(
        model=model,
        tools=[
            scan_sql_injection_tool,
            scan_xss_tool,
            scan_csrf_tool,
            scan_sensitive_data_tool,
            check_secure_config_tool
        ],
        name="SecurityScannerAgent",
        description="A specialized agent for detecting security vulnerabilities in code.",
        additional_authorized_imports=[
            "re", "json", "os", "pathlib", 
            "bandit", "semgrep", "pydantic"
        ],
        max_steps=2
    )
    
    # Create the report generation agent
    report_agent = CodeAgent(
        model=model,
        tools=[],
        name="SecurityReportAgent",
        description="A specialized agent for generating comprehensive security vulnerability reports.",
        add_base_tools=False,
        max_steps=2
    )
    
    results = {}
    
    for task_id, task in input.items():
        # Extract code to audit from the task
        code_to_audit = extract_code_context(task)
        
        # Identify the programming language
        language = identify_language(code_to_audit)
        
        # Define the security scan task
        security_scan_prompt = f"""
        Conduct a comprehensive security scan of the following code written in {language}:
        
        ```{language}
        {code_to_audit}
        ```
        
        Use the provided security scanning tools to identify potential security vulnerabilities.
        Focus on identifying:
        
        1. SQL Injection vulnerabilities
        2. Cross-Site Scripting (XSS) vulnerabilities
        3. Cross-Site Request Forgery (CSRF) vulnerabilities
        4. Sensitive data exposure (hardcoded credentials, tokens, API keys)
        5. Security misconfigurations
        
        For each finding, precisely indicate:
        - The exact line number and code where the vulnerability exists
        - The type of vulnerability according to OWASP Top 10 categories
        - A detailed explanation of why it's vulnerable
        - The potential impact if exploited
        
        Be meticulous in categorizing vulnerabilities correctly - for example, plaintext credentials 
        should be categorized as Sensitive Data Exposure, not SQL Injection.
        """
        
        # Run the security scan
        scan_result = scanner_agent.run(security_scan_prompt)
        
        # Generate detailed report using the report agent
        final_report = generate_vulnerability_report(scan_result, code_to_audit)
        
        # Add to results
        results[task_id] = final_report
    
    return results 