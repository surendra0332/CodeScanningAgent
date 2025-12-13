import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()

class LLMAnalyzer:
    def __init__(self):
        self.enabled = False
        self.api_key = os.getenv('GROQ_API_KEY')
        self.api_url = os.getenv('GROQ_API_URL')
        self.model = os.getenv('LLM_MODEL', 'llama-3.1-8b-instant')  # Configurable via .env
        
        # Performance/Cost constraints (configurable via env)
        max_tokens_str = os.getenv('LLM_MAX_TOKENS', '1000')
        self.max_tokens = int(max_tokens_str) if max_tokens_str.isdigit() else 1000
        
        temp_str = os.getenv('LLM_TEMPERATURE', '0.1')
        try:
            self.temperature = float(temp_str)
        except ValueError:
            self.temperature = 0.1
            
        timeout_str = os.getenv('LLM_TIMEOUT', '30')
        self.timeout = int(timeout_str) if timeout_str.isdigit() else 30
        
        # Check explicit enablement
        llm_enabled = os.getenv('LLM_ENABLED', 'false').lower() == 'true'
        
        if llm_enabled and self.api_key:
            self.enabled = True
            print("LLM integration enabled with Groq API")
        else:
            print("LLM integration disabled or API key missing")
    
    def analyze_code_files(self, file_contents, repo_url, prd_content=None):
        """Use LLM to analyze actual code files for issues"""
        if not self.enabled or not file_contents:
            return []
        
        try:
            # Create code analysis prompt
            code_summary = f"Repository: {repo_url}\n\nCode files to analyze:\n"
            for file_path, content in file_contents.items():
                # Limit content size for API (configurable)
                content_limit = int(os.getenv('FILE_READ_LIMIT', '1000'))
                truncated_content = content[:content_limit] + '...' if len(content) > content_limit else content
                code_summary += f"\n=== {file_path} ===\n{truncated_content}\n"
            prd_section = ""
            if prd_content:
                prd_section = f"""
PRODUCT REQUIREMENTS DOCUMENT (PRD) - CONTEXT ASSESSMENT:
The user has provided a PRD document. You must first validate its relevance.

STEP 1: RELEVANCE CHECK
Compare this PRD content with the Codebase Summary below.
- DOES IT MATCH? (Are the project names, features, or technologies similar?)
- IF NO MATCH: Ignore the PRD content completely. Proceed with a standard Security & Quality scan.
- IF MATCH FOUND: Enforce the PRD's constraints as strict "Scanning Boundaries".

STEP 2: ANALYSIS EXECUTION
- If PRD is ignored: Report standard issues only.
- If PRD is active: Report violations of the PRD as '[PRD BOUNDARY VIOLATION]' (High Severity).

{prd_content}
---------------------------------------------------
"""

            prompt = f"""Analyze this code repository for security vulnerabilities and code quality issues.
{prd_section}

{code_summary}

IMPORTANT INSTRUCTIONS:
1. ONLY report issues that you can ACTUALLY SEE in the code above
2. You MUST specify the EXACT file name and line number where the issue exists
3. DO NOT give generic recommendations or suggestions
4. DO NOT report hypothetical issues that might exist
5. If you don't find any real issues in a category, DON'T report anything for that category

Look for REAL issues in these categories:
- Security: 
    - SQL Injection, Cross-Site Scripting (XSS), Command Injection
    - Path Traversal, Insecure Deserialization
    - Authentication Flaws, Access Control Failures
    - SSRF, CSRF, Insecure JWT Usage, Sensitive Data Exposure
    - Secrets: Hardcoded Passwords, API Keys, Tokens, Private Keys, OAuth Secrets, Cloud Credentials (AWS/Azure/GCP)
- Quality: 
    - Dead Code, Unused Variables, Duplicate Code
    - Long Methods, Large Classes, Too Many Parameters
    - Naming Violations, Poor Readability
- Performance: 
    - Unoptimized Loops, Inefficient Memory Usage
    - Inefficient Queries, N+1 Query Problems
- Reliability:
    - Null Pointer Risks, Uncaught Exceptions
    - Resource Leaks (File Handles, Streams)
    - Unreachable Code
- Bug-Prone Patterns:
    - Wrong Comparisons, Misused APIs
    - Incorrect Boolean Logic
    - Race Conditions, Off-by-One Errors
- Dependency Vulnerabilities (SCA):
    - Vulnerable Libraries, Out-of-Date Packages
    - CVE Matches
    - Risky Transitive Dependencies
- Maintainability: 
    - High Cyclomatic Complexity, Deeply Nested Logic (>3-4 levels)
    - Long Functions, Hard-coded Values (Magic Numbers)
    - Bad Architectural Patterns
- Documentation: Missing docstrings, unclear comments
- Accessibility: Missing ARIA labels, poor contrast, semantic HTML issues
- Testability: Hard-to-test code, tight coupling, lack of dependency injection

Return ONLY ACTUAL issues found in the code in this JSON format:
{{
  "issues": [
    {{
      "file": "exact_filename_from_code_above",
      "line": actual_line_number,
      "type": "security" | "quality" | "performance" | "best_practice" | "maintainability" | "documentation" | "accessibility" | "testability",
      "severity": "HIGH/MEDIUM/LOW",
      "issue": "specific description with code reference"
    }}
  ]
}}

If no real issues found, return: {{"issues": []}}"""
            
            # Use Groq REST API with configurable values
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": self.model,
                "messages": [{
                    "role": "user",
                    "content": prompt
                }],
                "max_tokens": self.max_tokens,
                "temperature": self.temperature
            }
            
            response = requests.post(self.api_url, json=payload, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                result = response.json()
                analysis_text = result.get('choices', [{}])[0].get('message', {}).get('content', '')
                
                # Try to parse JSON response
                try:
                    # Extract JSON from response
                    json_start = analysis_text.find('{')
                    json_end = analysis_text.rfind('}') + 1
                    if json_start >= 0 and json_end > json_start:
                        json_str = analysis_text[json_start:json_end]
                        parsed = json.loads(json_str)
                        return parsed.get('issues', [])
                except:
                    pass
                
                # Fallback: parse text response
                return self._parse_text_issues(analysis_text)
            else:
                print(f"Groq API error: {response.status_code} - {response.text}")
                return []
                
        except Exception as e:
            print(f"LLM analysis failed: {e}")
            return []
    
    def _parse_text_issues(self, text):
        """Parse issues from text response"""
        issues = []
        lines = text.split('\n')
        
        for line in lines:
            # Check for keywords in the line
            line_lower = line.lower()
            
            if any(keyword in line_lower for keyword in ['security', 'vulnerability', 'issue', 'problem', 'performance', 'practice', 'maintainability', 'documentation', 'accessibility', 'testability', 'aria', 'coupling', 'docstring', 'dead', 'duplicate', 'unused', 'naming', 'readability', 'parameters', 'class', 'method', 'complexity', 'nested', 'long', 'magic', 'hard-coded', 'architectural', 'global', 'loop', 'query', 'memory', 'n+1', 'null', 'exception', 'leak', 'unreachable', 'pointer', 'comparison', 'boolean', 'race', 'off-by-one', 'api', 'dependency', 'cve', 'vulnerable', 'outdated', 'package', 'library', 'transitive']):
                # Extract basic issue info
                if 'security' in line_lower or 'vulnerability' in line_lower:
                    issue_type = 'security'
                    severity = 'HIGH'
                elif any(k in line_lower for k in ['cve', 'vulnerable', 'outdated', 'dependency', 'package', 'library', 'transitive']):
                    issue_type = 'security'
                    severity = 'HIGH'
                elif any(k in line_lower for k in ['performance', 'slow', 'loop', 'query', 'memory', 'n+1']):
                    issue_type = 'performance'
                    severity = 'MEDIUM'
                elif any(k in line_lower for k in ['reliability', 'null', 'exception', 'leak', 'unreachable', 'pointer']):
                    issue_type = 'quality'
                    severity = 'HIGH'
                elif any(k in line_lower for k in ['comparison', 'boolean', 'race', 'off-by-one', 'misused api']):
                    issue_type = 'quality'
                    severity = 'HIGH'
                elif 'practice' in line_lower or 'convention' in line_lower:
                    issue_type = 'best_practice'
                    severity = 'LOW'
                elif any(k in line_lower for k in ['maintainability', 'complexity', 'nested', 'long', 'magic', 'hard-coded', 'architectural', 'global']):
                    issue_type = 'maintainability'
                    severity = 'LOW'
                elif 'documentation' in line_lower or 'docstring' in line_lower or 'comment' in line_lower:
                    issue_type = 'documentation'
                    severity = 'LOW'
                elif 'accessibility' in line_lower or 'aria' in line_lower or 'alt text' in line_lower or 'contrast' in line_lower:
                    issue_type = 'accessibility'
                    severity = 'MEDIUM'
                elif 'testability' in line_lower or 'coupling' in line_lower or 'dependency' in line_lower or 'hard to test' in line_lower:
                    issue_type = 'testability'
                    severity = 'MEDIUM'
                elif any(k in line_lower for k in ['dead', 'duplicate', 'unused', 'naming', 'readability', 'parameters', 'class', 'method']):
                    issue_type = 'quality'
                    severity = 'MEDIUM'
                else:
                    issue_type = 'quality'
                    severity = 'MEDIUM'
                
                issues.append({
                    'file': 'detected_file',
                    'line': 1,
                    'type': issue_type,
                    'severity': severity,
                    'issue': line.strip()[:100]
                })
        
        return issues[:20]  # Limit to 20 issues
    
