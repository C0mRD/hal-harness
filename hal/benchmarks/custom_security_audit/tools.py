import re
import os
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional, Union

from smolagents import Tool

class ScanForSQLInjectionTool(Tool):
    name = "scan_for_sql_injection"
    description = "Scan code for SQL injection vulnerabilities."
    inputs = {
        "code_snippet": {
            "type": "string",
            "description": "The code to analyze"
        },
        "language": {
            "type": "string",
            "description": "The programming language (python, javascript, php, etc.)"
        }
    }
    output_type = "object"
    
    def forward(self, code_snippet: str, language: str) -> Dict[str, Any]:
        """
        Scan code for SQL injection vulnerabilities.
        
        Args:
            code_snippet: The code to analyze
            language: The programming language (python, javascript, php, etc.)
            
        Returns:
            Dictionary with vulnerability findings
        """
        # Patterns for common SQL injection vulnerabilities
        sql_injection_patterns = {
            "python": [
                r"cursor\.execute\([^,]+%[^,]*\)",  # String formatting with %
                r"cursor\.execute\([\"\']\s*.*?\+\s*.*?[\"\']",  # String concatenation
                r"cursor\.execute\(f[\"\''].*?{.*?}.*?[\"\'']",  # f-strings without parameters
                r"cursor\.executemany\([^,]+%[^,]*\)",
                r"cursor\.executescript\([^,)]*\)",  # Dangerous executescript
                r"raw_input\(.*?\)",  # raw_input without sanitization
                r"input\(.*?\)"  # input without sanitization
            ],
            "javascript": [
                r"db\.query\([\"\']\s*.*?\+\s*.*?[\"\']",  # String concatenation in queries
                r"`SELECT.*?\\${.*?}`",  # Template literals in SQL
                r"connection\.query\([\"\']\s*.*?\+\s*.*?[\"\']",
                r"sequelize\.query\([\"\']\s*.*?\+\s*.*?[\"\']"
            ],
            "php": [
                r"mysql_query\([\"\']\s*.*?\.\s*.*?[\"\']",  # String concatenation
                r"mysqli_query\([^,]+,\s*[\"\']\s*.*?\.\s*.*?[\"\']", 
                r"PDO.*?->query\([\"\']\s*.*?\.\s*.*?[\"\']",
                r"\$_GET\[.*?\]",  # Direct use of GET parameters
                r"\$_POST\[.*?\]"  # Direct use of POST parameters
            ]
        }
        
        findings = []
        patterns = sql_injection_patterns.get(language.lower(), sql_injection_patterns["python"])
        
        for pattern in patterns:
            matches = re.finditer(pattern, code_snippet, re.MULTILINE)
            for match in matches:
                findings.append({
                    "line": code_snippet.count('\n', 0, match.start()) + 1,
                    "code": match.group(0),
                    "vulnerability": "SQL Injection",
                    "description": "Potential SQL injection vulnerability. User input should be properly sanitized or parameterized queries should be used.",
                    "severity": "High",
                    "recommendation": "Use parameterized queries or ORM libraries to prevent SQL injection attacks."
                })
        
        return {
            "vulnerability_type": "SQL Injection",
            "findings": findings,
            "total_findings": len(findings)
        }

class ScanForXSSTool(Tool):
    name = "scan_for_xss"
    description = "Scan code for Cross-Site Scripting (XSS) vulnerabilities."
    inputs = {
        "code_snippet": {
            "type": "string",
            "description": "The code to analyze"
        },
        "language": {
            "type": "string",
            "description": "The programming language (python, javascript, php, etc.)"
        }
    }
    output_type = "object"
    
    def forward(self, code_snippet: str, language: str) -> Dict[str, Any]:
        """
        Scan code for XSS vulnerabilities.
        
        Args:
            code_snippet: The code to analyze
            language: The programming language (python, javascript, php, etc.)
            
        Returns:
            Dictionary with vulnerability findings
        """
        # Patterns for common XSS vulnerabilities
        xss_patterns = {
            "python": [
                r"render_template\(.*?[\"\'](.*?)[\"\'].*?,.*?\)",  # Template rendering without escaping
                r"request\.args\.get\([^,)]+\)",  # GET parameters without escaping
                r"request\.form\.get\([^,)]+\)",  # POST parameters without escaping 
                r"\.format\(.*?request\.",  # String formatting with request data
                r"f[\"\''].*?{.*?request\..*?}.*?[\"\'']"  # f-strings with request data
            ],
            "javascript": [
                r"document\.write\(.*?\)",  # Direct document.write
                r"innerHTML\s*=\s*.*?",  # Setting innerHTML
                r"outerHTML\s*=\s*.*?",  # Setting outerHTML
                r"\$\(.*?\)\.html\(",  # jQuery html method
                r"eval\(",  # eval usage
                r"location\.href\s*=",  # Setting location from potentially unsanitized input
                r"element\.insertAdjacentHTML"  # insertAdjacentHTML method
            ],
            "php": [
                r"echo\s*\$_GET",  # Echo GET parameters
                r"echo\s*\$_POST",  # Echo POST parameters
                r"echo\s*\$_REQUEST",  # Echo REQUEST parameters
                r"print\s*\$_GET",  # Print GET parameters
                r"print\s*\$_POST",  # Print POST parameters
                r"print\s*\$_REQUEST",  # Print REQUEST parameters
                r"<\?=.*?\$_GET",  # Short tags with GET
                r"<\?=.*?\$_POST"  # Short tags with POST
            ]
        }
        
        findings = []
        patterns = xss_patterns.get(language.lower(), xss_patterns["python"])
        
        for pattern in patterns:
            matches = re.finditer(pattern, code_snippet, re.MULTILINE)
            for match in matches:
                findings.append({
                    "line": code_snippet.count('\n', 0, match.start()) + 1,
                    "code": match.group(0),
                    "vulnerability": "Cross-Site Scripting (XSS)",
                    "description": "Potential XSS vulnerability. User input should be properly sanitized before being rendered in HTML.",
                    "severity": "High",
                    "recommendation": "Use context-aware escaping or sanitization libraries before rendering user input."
                })
        
        return {
            "vulnerability_type": "Cross-Site Scripting (XSS)",
            "findings": findings,
            "total_findings": len(findings)
        }

class ScanForCSRFTool(Tool):
    name = "scan_for_csrf"
    description = "Scan code for Cross-Site Request Forgery (CSRF) vulnerabilities."
    inputs = {
        "code_snippet": {
            "type": "string",
            "description": "The code to analyze"
        },
        "language": {
            "type": "string",
            "description": "The programming language (python, javascript, php, etc.)"
        }
    }
    output_type = "object"
    
    def forward(self, code_snippet: str, language: str) -> Dict[str, Any]:
        """
        Scan code for CSRF vulnerabilities.
        
        Args:
            code_snippet: The code to analyze
            language: The programming language (python, javascript, php, etc.)
            
        Returns:
            Dictionary with vulnerability findings
        """
        # Patterns for missing CSRF protections
        csrf_patterns = {
            "python": [
                r"@app\.route\([^)]+, methods=\[[^\]]*[\"']POST[\"'][^\]]*\]",  # Flask POST routes
                r"@csrf_exempt",  # Django CSRF exempt
                r"csrf_exempt",  # Django CSRF exempt function
                r"CSRF_COOKIE_SECURE\s*=\s*False",  # Insecure CSRF cookie settings
                r"CSRF_USE_SESSIONS\s*=\s*False"  # Insecure CSRF session settings
            ],
            "javascript": [
                r"fetch\([^)]+,\s*\{\s*method:\s*[\"']POST[\"']",  # Fetch POST without CSRF token
                r"\.post\([^)]+\)",  # jQuery/Axios POST without visible token
                r"xmlHttpRequest\.open\([\"']POST[\"']"  # XHR request without visible token
            ],
            "php": [
                r"<form[^>]*method=[\"']post[\"'][^>]*>(?:(?!csrf).)*?<\/form>",  # Form without CSRF token
                r"\$_SERVER\[[\"']REQUEST_METHOD[\"']\]\s*===?\s*[\"']POST[\"']",  # POST handling without token check
                r"csrf_token\s*=\s*false"  # Disabled CSRF protection
            ]
        }
        
        findings = []
        patterns = csrf_patterns.get(language.lower(), csrf_patterns["python"])
        
        for pattern in patterns:
            matches = re.finditer(pattern, code_snippet, re.MULTILINE | re.DOTALL)
            for match in matches:
                # Check for CSRF token patterns near the match
                surrounding_code = code_snippet[max(0, match.start() - 200):min(len(code_snippet), match.end() + 200)]
                has_csrf_token = re.search(r"csrf_token|CSRFToken|CSRF|_token|X-CSRF-TOKEN", surrounding_code, re.IGNORECASE)
                
                if not has_csrf_token:
                    findings.append({
                        "line": code_snippet.count('\n', 0, match.start()) + 1,
                        "code": match.group(0),
                        "vulnerability": "Cross-Site Request Forgery (CSRF)",
                        "description": "Potential CSRF vulnerability. State-changing operations should include CSRF protection.",
                        "severity": "Medium",
                        "recommendation": "Implement CSRF tokens for all state-changing operations and validate them on the server."
                    })
        
        return {
            "vulnerability_type": "Cross-Site Request Forgery (CSRF)",
            "findings": findings,
            "total_findings": len(findings)
        }

class ScanForSensitiveDataTool(Tool):
    name = "scan_for_sensitive_data"
    description = "Scan code for sensitive data exposure vulnerabilities."
    inputs = {
        "code_snippet": {
            "type": "string",
            "description": "The code to analyze"
        },
        "language": {
            "type": "string",
            "description": "The programming language (python, javascript, php, etc.)"
        }
    }
    output_type = "object"
    
    def forward(self, code_snippet: str, language: str) -> Dict[str, Any]:
        """
        Scan code for sensitive data exposure.
        
        Args:
            code_snippet: The code to analyze
            language: The programming language (python, javascript, php, etc.)
            
        Returns:
            Dictionary with vulnerability findings
        """
        # Patterns for sensitive data exposure
        sensitive_data_patterns = {
            "common": [
                r"password\s*=\s*['\"][^'\"]+['\"]",  # Hardcoded passwords
                r"secret\s*=\s*['\"][^'\"]+['\"]",  # Hardcoded secrets
                r"api[_-]?key\s*=\s*['\"][^'\"]+['\"]",  # API keys
                r"access[_-]?token\s*=\s*['\"][^'\"]+['\"]",  # Access tokens
                r"auth[_-]?token\s*=\s*['\"][^'\"]+['\"]",  # Auth tokens
                r"private[_-]?key\s*=\s*['\"][^'\"]+['\"]",  # Private keys
                r"ssh[_-]?key\s*=\s*['\"][^'\"]+['\"]",  # SSH keys
                r"aws[_-]?key\s*=\s*['\"][^'\"]+['\"]",  # AWS keys
                r"hash\s*=\s*['\"][a-f0-9]{32,}['\"]",  # MD5 or other hashes
                r"bearer\s+[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",  # JWT tokens
                r"[0-9]{13,16}",  # Potential credit card numbers
                r"[0-9]{3,4}-[0-9]{4}-[0-9]{4}-[0-9]{4}",  # Credit card with dashes
                r"[0-9]{9}",  # SSN pattern
                r"[0-9]{3}-[0-9]{2}-[0-9]{4}"  # SSN with dashes
            ],
            "python": [
                r"os\.environ\.get\(['\"].*?[pP][aA][sS][sS].*?['\"].*?\)",  # Environment variables for passwords
                r"os\.environ\.get\(['\"].*?[tT][oO][kK][eE][nN].*?['\"].*?\)",  # Environment variables for tokens
                r"os\.environ\.get\(['\"].*?[sS][eE][cC][rR][eE][tT].*?['\"].*?\)",  # Environment variables for secrets
                r"os\.environ\.get\(['\"].*?[kK][eE][yY].*?['\"].*?\)"  # Environment variables for keys
            ],
            "javascript": [
                r"process\.env\.[A-Z_]*(?:PASS|SECRET|KEY|TOKEN)[A-Z_]*",  # Environment variables in Node.js
                r"localStorage\.setItem\(['\"](?:token|auth|password|secret|key)['\"]",  # Sensitive data in localStorage
                r"sessionStorage\.setItem\(['\"](?:token|auth|password|secret|key)['\"]"  # Sensitive data in sessionStorage
            ],
            "php": [
                r"\$_ENV\[['\"].*?(?:PASS|SECRET|KEY|TOKEN).*?['\"]\]",  # Environment variables in PHP
                r"\$_SERVER\[['\"].*?(?:PASS|SECRET|KEY|TOKEN).*?['\"]\]"  # Server variables in PHP
            ]
        }
        
        findings = []
        
        # Check common patterns for all languages
        for pattern in sensitive_data_patterns["common"]:
            matches = re.finditer(pattern, code_snippet, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                # Skip if it looks like a variable assignment to an empty string or environment variable
                if re.search(r"=\s*['\"]['\"]", match.group(0)) or re.search(r"=\s*os\.environ", match.group(0)):
                    continue
                    
                findings.append({
                    "line": code_snippet.count('\n', 0, match.start()) + 1,
                    "code": match.group(0),
                    "vulnerability": "Sensitive Data Exposure",
                    "description": "Potential hardcoded sensitive information found in code.",
                    "severity": "High",
                    "recommendation": "Store sensitive information in environment variables or secure vaults, not in code."
                })
        
        # Check language-specific patterns
        language_patterns = sensitive_data_patterns.get(language.lower(), [])
        for pattern in language_patterns:
            matches = re.finditer(pattern, code_snippet, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                findings.append({
                    "line": code_snippet.count('\n', 0, match.start()) + 1,
                    "code": match.group(0),
                    "vulnerability": "Sensitive Data Exposure",
                    "description": "Potential sensitive information handling detected.",
                    "severity": "Medium",
                    "recommendation": "Ensure sensitive data is properly managed with secure storage and access controls."
                })
        
        return {
            "vulnerability_type": "Sensitive Data Exposure",
            "findings": findings,
            "total_findings": len(findings)
        }

class CheckSecureConfigTool(Tool):
    name = "check_secure_config"
    description = "Check for security misconfigurations in code and configuration files."
    inputs = {
        "code_snippet": {
            "type": "string",
            "description": "The code to analyze"
        },
        "language": {
            "type": "string",
            "description": "The programming language (python, javascript, php, etc.)"
        }
    }
    output_type = "object"
    
    def forward(self, code_snippet: str, language: str) -> Dict[str, Any]:
        """
        Check for security misconfigurations.
        
        Args:
            code_snippet: The code to analyze
            language: The programming language (python, javascript, php, etc.)
            
        Returns:
            Dictionary with vulnerability findings
        """
        # Patterns for security misconfigurations
        security_config_patterns = {
            "python": [
                r"DEBUG\s*=\s*True",  # Debug mode enabled
                r"ALLOWED_HOSTS\s*=\s*\[\s*['\"][*]['\"]",  # Allow all hosts in Django
                r"SECRET_KEY\s*=\s*['\"][^'\"]+['\"]",  # Hardcoded secret key
                r"CSRF_ENABLED\s*=\s*False",  # CSRF protection disabled
                r"SESSION_COOKIE_SECURE\s*=\s*False",  # Insecure session cookie
                r"SESSION_COOKIE_HTTPONLY\s*=\s*False",  # HttpOnly flag not set for cookies
                r"X_FRAME_OPTIONS\s*=\s*['\"](ALLOW|ALLOWALL)['\"]",  # Unsafe X-Frame-Options
                r"SECURE_SSL_REDIRECT\s*=\s*False",  # SSL redirect disabled
                r"SECURE_CONTENT_TYPE_NOSNIFF\s*=\s*False",  # Content type sniffing allowed
                r"SECURE_BROWSER_XSS_FILTER\s*=\s*False"  # XSS filter disabled
            ],
            "javascript": [
                r"app\.use\(helmet\(\{.+content[sS]ecurityPolicy:\s*false",  # CSP disabled
                r"app\.use\(cors\(\{\s*origin\s*:\s*['\"][*]['\"]",  # CORS allow all origins
                r"app\.use\(cors\(\{\s*credentials\s*:\s*true",  # Unsafe CORS with credentials
                r"require\(['\"]express-session['\"]\)\(\{\s*.*?cookie\s*:\s*\{\s*.*?secure\s*:\s*false",  # Insecure cookies
                r"cookie-parser[^;]*;\s*app\.use\(cookieParser\(\)\)",  # Cookie parser without signed option
                r"eval\(",  # Unsafe eval
                r"app\.use\(bodyParser\.json\(\{\s*verify\s*:\s*false",  # Request verification disabled
                r"NODE_ENV\s*=\s*['\"]development['\"]"  # Development mode enabled
            ],
            "php": [
                r"display_errors\s*=\s*On",  # Display errors enabled
                r"expose_php\s*=\s*On",  # PHP version exposed
                r"allow_url_fopen\s*=\s*On",  # Allow URL fopen enabled
                r"allow_url_include\s*=\s*On",  # Allow URL include enabled
                r"session\.cookie_httponly\s*=\s*0",  # HttpOnly flag not set for session cookies
                r"session\.cookie_secure\s*=\s*0",  # Secure flag not set for session cookies
                r"session\.use_cookies\s*=\s*0",  # Session cookies not used
                r"session\.use_only_cookies\s*=\s*0",  # Not using only cookies for session ID
                r"open_basedir\s*=\s*",  # open_basedir not set
                r"disable_functions\s*=\s*"  # No functions disabled
            ]
        }
        
        findings = []
        patterns = security_config_patterns.get(language.lower(), security_config_patterns["python"])
        
        for pattern in patterns:
            matches = re.finditer(pattern, code_snippet, re.MULTILINE)
            for match in matches:
                findings.append({
                    "line": code_snippet.count('\n', 0, match.start()) + 1,
                    "code": match.group(0),
                    "vulnerability": "Security Misconfiguration",
                    "description": "Potential security misconfiguration detected.",
                    "severity": "Medium",
                    "recommendation": "Review and secure the configuration to follow security best practices."
                })
        
        return {
            "vulnerability_type": "Security Misconfiguration",
            "findings": findings,
            "total_findings": len(findings)
        } 