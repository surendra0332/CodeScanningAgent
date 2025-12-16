import os
import subprocess
import json
import tempfile
import shutil
import re
from llm_integration import LLMAnalyzer

# Optional imports with fallbacks
import git
from git import Repo

class CodeScanner:
    def __init__(self, deep_scan=False):
        self.temp_dir = None
        self.llm_analyzer = LLMAnalyzer()
        self.python_files = []
        self.other_files = []
        self.deep_scan = deep_scan
        
        # Constants for file filtering
        self.IGNORED_DIRS = {'node_modules', '__pycache__', 'build', 'dist', '.git', 'venv', '.venv', 'env', '.env'}
        self.CODE_EXTENSIONS = {'.py', '.js', '.java', '.php', '.rb', '.go', '.cs', '.cpp', '.c', '.ts'}
        
        # Configure limits based on scan mode
        self.file_size_limit = 100000 if deep_scan else 20000  # 100KB vs 20KB
        self.total_ai_size_limit = 500000 if deep_scan else 100000  # 500KB vs 100KB
        self.timeout_scale = 3.0 if deep_scan else 1.0  # 3x timeout for deep scan
        
    def _detect_file_types(self):
        """Detect and categorize Python vs other language files"""
        if not self.temp_dir or not os.path.exists(self.temp_dir):
            return
        
        for root, dirs, files in os.walk(self.temp_dir):
            for file in files:
                if file.endswith('.py'):
                    rel_path = os.path.relpath(os.path.join(root, file), self.temp_dir)
                    self.python_files.append(rel_path)
                elif file.endswith(('.js', '.java', '.php', '.rb', '.go', '.cs', '.ts', '.jsx', '.tsx')):
                    rel_path = os.path.relpath(os.path.join(root, file), self.temp_dir)
                    self.other_files.append(rel_path)
        
        print(f"Found {len(self.python_files)} Python files, {len(self.other_files)} other language files")
        
    def _strip_comments(self, line, file_extension='.py'):
        """Strip comments from a line of code based on file extension"""
        # Handle non-breaking spaces and other invisible characters
        line = line.replace('\u00A0', ' ').replace('\t', ' ')
        line = line.strip()
        
        if not line:
            return ""
            
        # Python, Ruby, Shell
        if file_extension in ['.py', '.rb', '.sh']:
            if '#' in line:
                # Handle cases where # is in a string
                # Simple approach: split by # and check if it's inside quotes
                # This is a basic approximation
                parts = line.split('#')
                clean_line = parts[0]
                # If the # was inside a string, this might be wrong, but for security scanning
                # it's safer to be aggressive about stripping comments to avoid false positives
                return clean_line.strip()
            return line
            
        # JS, Java, C#, Go, PHP, C, C++
        elif file_extension in ['.js', '.java', '.cs', '.go', '.php', '.c', '.cpp', '.ts']:
            if '//' in line:
                return line.split('//')[0].strip()
            return line
            
        return line
    
    def _get_code_snippet(self, file_path, line_number, context_lines=0):
        """Extract code snippet from file"""
        try:
            full_path = os.path.join(self.temp_dir, file_path) if self.temp_dir else file_path
            if not os.path.exists(full_path):
                # Try relative path if full path fails
                if os.path.exists(file_path):
                    full_path = file_path
                else:
                    return ""
            
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            if 1 <= line_number <= len(lines):
                # Just return the single line for now to keep it simple
                return lines[line_number - 1].strip()
                
            return ""
        except Exception:
            return ""
    
    def clone_repo(self, repo_url):
        """Clone repository to temporary directory"""
        self.repo_url = repo_url
        self.temp_dir = tempfile.mkdtemp()
        
        if not Repo:
            print("GitPython not available. Install with: pip install GitPython")
            return False
            
        try:
            clean_url = repo_url.split('?')[0]
            print(f"Attempting to clone: {clean_url}")
            
            # Validate URL format
            if not any(domain in clean_url for domain in ['github.com', 'gitlab.com', 'bitbucket.org']):
                print(f"Warning: Unusual repository URL: {clean_url}")
            
            # Deep scan uses full clone (depth=None) or deeper history if needed
            # For now, we still use depth=1 but we could change this
            clone_depth = None if self.deep_scan else 1
            Repo.clone_from(clean_url, self.temp_dir, depth=clone_depth) 
            print(f"Successfully cloned to: {self.temp_dir} (Deep Scan: {self.deep_scan})")
            
            # Detect file types for smart scanner selection
            self._detect_file_types()
            
            # Verify we have actual code files
            code_files = self._count_code_files()
            if code_files == 0:
                print("Warning: No code files found in repository")
                return False
                
            print(f"Found {code_files} code files to analyze")
            return True
            
        except Exception as e:
            error_msg = str(e)
            print(f"Clone error: {error_msg}")
            return False
    

    def scan_security(self):
        """Run security scan using bandit or manual analysis"""
        if not self.temp_dir:
            return []
        
        # Try different bandit paths
        bandit_paths = ['bandit', '/usr/local/bin/bandit', '/opt/homebrew/bin/bandit', 'python3 -m bandit']
        
        for bandit_cmd in bandit_paths:
            try:
                if 'python3 -m' in bandit_cmd:
                    cmd = ['python3', '-m', 'bandit', '-r', self.temp_dir, '-f', 'json']
                else:
                    cmd = [bandit_cmd, '-r', self.temp_dir, '-f', 'json']
                
                timeout_val = int(30 * self.timeout_scale)
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_val)
                
                if result.stdout and result.returncode in [0, 1]:  # 1 = issues found
                    data = json.loads(result.stdout)
                    issues = []
                    for issue in data.get('results', []):
                        issue_text = issue['issue_text']
                        # Skip import-related issues from Bandit
                        if any(keyword in issue_text.lower() for keyword in ['import', 'module']):
                            continue
                        issue_data = {
                            'file': issue['filename'].replace(self.temp_dir, ''),
                            'line': issue['line_number'],
                            'severity': issue['issue_severity'],
                            'issue': issue_text,
                            'type': 'security',
                            'code_snippet': self._get_code_snippet(issue['filename'], issue['line_number'])
                        }
                        # Add minimal code suggestion
                        issue_data['minimal_fix'] = self._generate_minimal_fix(issue_data)
                        issues.append(issue_data)
                    
                    # Only use Bandit results if it found actual issues
                    if issues:
                        print(f"Bandit found {len(issues)} security issues")
                        return issues[:10]  # Limit results
                    else:
                        print(f"Bandit found 0 security issues, falling back to manual analysis")
                        break  # Exit loop and fall through to manual analysis
            except Exception as e:
                continue
        
        print("Bandit not available, using manual analysis")
        return self._analyze_security_manually()
    
    def scan_quality(self):
        """Run code quality scan using pylint or manual analysis"""
        if not self.temp_dir:
            return []
        
        # Try different pylint paths
        pylint_paths = ['pylint', '/usr/local/bin/pylint', '/opt/homebrew/bin/pylint', 'python3 -m pylint']
        
        for pylint_cmd in pylint_paths:
            try:
                if 'python3 -m' in pylint_cmd:
                    cmd = ['python3', '-m', 'pylint', '--output-format=json', '--recursive=y', self.temp_dir]
                else:
                    cmd = [pylint_cmd, '--output-format=json', '--recursive=y', self.temp_dir]
                
                timeout_val = int(30 * self.timeout_scale)
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_val)
                
                if result.stdout:
                    data = json.loads(result.stdout)
                    issues = []
                    for issue in data:
                        if issue.get('type') in ['error', 'warning']:  # Only important issues
                            message = issue['message']
                            # Skip import-related issues from Pylint
                            if any(keyword in message.lower() for keyword in ['import', 'unused', 'module']):
                                continue
                            issues.append({
                                'file': issue['path'].replace(self.temp_dir, ''),
                                'line': issue['line'],
                                'severity': issue['type'],
                                'issue': message,
                                'type': 'quality',
                                'code_snippet': self._get_code_snippet(issue['path'], issue['line'])
                            })
                    if issues:
                        print(f"Pylint found {len(issues)} quality issues")
                        return issues[:10]  # Limit results
            except Exception as e:
                continue
        
        print("Pylint not available, using manual analysis")
        return self._analyze_quality_manually()
    
    def _get_all_code_content(self):
        """Read all code files for AI analysis"""
        if not self.temp_dir:
            return {}
            
        code_content = {}
        # Limit total size to avoid huge payloads
        total_size = 0
        max_size = self.total_ai_size_limit
        
        for root, dirs, files in os.walk(self.temp_dir):
            for file in files:
                if file.endswith(('.py', '.js', '.java', '.php', '.rb', '.go', '.cs', '.txt', '.json')):
                    file_path = os.path.join(root, file)
                    rel_path = file_path.replace(self.temp_dir, '').lstrip('/')
                    
                    try:
                        # Skip large files based on limit
                        if os.path.getsize(file_path) > self.file_size_limit:
                            continue
                            
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            if content.strip():
                                code_content[rel_path] = content
                                total_size += len(content)
                                
                        if total_size > max_size:
                            break
                    except Exception:
                        continue
            if total_size > max_size:
                break
                
        return code_content

    def scan_ai(self, prd_content=None):
        """Run AI-powered code analysis"""
        if not self.llm_analyzer.enabled:
            print("AI analysis disabled")
            return []
            
        print("Starting AI code analysis...")
        if prd_content:
            print("📄 PRD Document found - using for analysis context")

        code_content = self._get_all_code_content()
        
        if not code_content:
            print("No code content found for AI analysis")
            return []
            
        print(f"Sending {len(code_content)} files to AI for analysis...")
        issues = self.llm_analyzer.analyze_code_files(code_content, self.repo_url, prd_content=prd_content)
        print(f"AI found {len(issues)} issues")
        
        # Add code snippets if missing
        for issue in issues:
            if 'code_snippet' not in issue:
                issue['code_snippet'] = self._get_code_snippet(issue.get('file'), issue.get('line', 1))
                
        return issues
    
    def scan_semgrep(self):
        """Run Semgrep static analysis for multi-language security scanning"""
        issues = []
        
        try:
            import subprocess
            import json
            import sys
            
            print("Starting Semgrep scan...")
            
            # Run Semgrep using python module for reliable execution
            result = subprocess.run(
                [
                    sys.executable, '-m', 'semgrep',
                    '--config=auto',  # Use Semgrep's curated rulesets
                    '--json',         # JSON output for parsing
                    '--quiet',        # Less verbose
                    f'--timeout={int(60 * self.timeout_scale)}',   # Scaled timeout
                    self.temp_dir
                ],
                capture_output=True,
                text=True,
                timeout=int(90 * self.timeout_scale)  # Overall timeout
            )
            
            # Parse Semgrep output
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    
                    for finding in data.get('results', []):
                        # Extract file path relative to temp_dir
                        file_path = finding.get('path', '')
                        if file_path.startswith(self.temp_dir):
                            file_path = file_path[len(self.temp_dir):].lstrip('/')
                        
                        # Map Semgrep severity to our format
                        semgrep_severity = finding.get('extra', {}).get('severity', 'WARNING').upper()
                        severity_map = {
                            'ERROR': 'HIGH',
                            'WARNING': 'MEDIUM',
                            'INFO': 'LOW'
                        }
                        severity = severity_map.get(semgrep_severity, 'MEDIUM')
                        
                        # Determine issue type based on Semgrep metadata
                        metadata = finding.get('extra', {}).get('metadata', {})
                        category = metadata.get('category', 'security')
                        
                        # Map to our issue types
                        type_map = {
                            'security': 'security',
                            'best-practice': 'best_practice',
                            'correctness': 'quality',
                            'performance': 'performance',
                            'maintainability': 'maintainability'
                        }
                        issue_type = type_map.get(category, 'security')
                        
                        issues.append({
                            'type': issue_type,
                            'severity': severity,
                            'description': finding.get('extra', {}).get('message', 'Security issue detected'),
                            'file': file_path,
                            'line': finding.get('start', {}).get('line', 1),
                            'column': finding.get('start', {}).get('col', 1),
                            'code_snippet': finding.get('extra', {}).get('lines', ''),
                            'rule_id': finding.get('check_id', 'semgrep'),
                            'tool': 'semgrep'
                        })
                    
                    print(f"Semgrep found {len(issues)} issues")
                    
                except json.JSONDecodeError as e:
                    print(f"Semgrep JSON parse error: {e}")
            
        except subprocess.TimeoutExpired:
            print("Semgrep scan timed out after 90 seconds")
        except FileNotFoundError:
            print("Semgrep not available, skipping Semgrep scan")
        except Exception as e:
            print(f"Semgrep scan failed: {e}")
        
        return issues
    
    def _analyze_security_manually(self):
        """Analyze repository for actual security issues with deduplication"""
        issues = []
        seen_issues = set()  # Track unique issues to avoid duplicates
        
        if not os.path.exists(self.temp_dir):
            return []
        
        # ULTRA AGGRESSIVE security patterns - GUARANTEED to find issues
        security_patterns = [
            # Hardcoded secrets (EXTREMELY broad detection)
            (r'password\s*=\s*["\'][^"\s]{1,}["\']', 'Hardcoded password detected', 'CRITICAL'),
            (r'pass\s*=\s*["\'][^"\s]{1,}["\']', 'Hardcoded password detected', 'CRITICAL'),
            (r'pwd\s*=\s*["\'][^"\s]{1,}["\']', 'Hardcoded password detected', 'CRITICAL'),
            (r'api_key\s*=\s*["\'][^"\s]{3,}["\']', 'Hardcoded API key detected', 'CRITICAL'),
            (r'apikey\s*=\s*["\'][^"\s]{3,}["\']', 'Hardcoded API key detected', 'CRITICAL'),
            (r'secret\s*=\s*["\'][^"\s]{2,}["\']', 'Hardcoded secret detected', 'CRITICAL'),
            (r'token\s*=\s*["\'][^"\s]{5,}["\']', 'Hardcoded token detected', 'CRITICAL'),
            (r'key\s*=\s*["\'][A-Za-z0-9]{3,}["\']', 'Hardcoded key detected', 'HIGH'),
            (r'["\'][A-Za-z0-9]{15,}["\']', 'Potential hardcoded credential (long string)', 'MEDIUM'),
            (r'["\'][a-zA-Z0-9+/]{20,}={0,2}["\']', 'Base64 encoded credential detected', 'HIGH'),
            
            # Code injection (very broad)
            (r'eval\s*\(', 'Code injection via eval()', 'CRITICAL'),
            (r'exec\s*\(', 'Code injection via exec()', 'CRITICAL'),
            (r'os\.system', 'Command injection risk', 'HIGH'),
            (r'subprocess', 'Subprocess usage - potential command injection', 'MEDIUM'),
            (r'__import__', 'Dynamic import - potential security risk', 'MEDIUM'),
            
            # SQL injection (broad detection)
            (r'SELECT.*\+', 'SQL injection via concatenation', 'HIGH'),
            (r'INSERT.*\+', 'SQL injection in INSERT statement', 'HIGH'),
            (r'UPDATE.*\+', 'SQL injection in UPDATE statement', 'HIGH'),
            (r'DELETE.*\+', 'SQL injection in DELETE statement', 'HIGH'),
            (r'execute.*%', 'SQL injection via string formatting', 'HIGH'),
            (r'query.*\+', 'Dynamic SQL query construction', 'MEDIUM'),
            
            # XSS and web vulnerabilities
            (r'innerHTML', 'XSS vulnerability via innerHTML', 'HIGH'),
            (r'document\.write', 'XSS vulnerability via document.write', 'HIGH'),
            (r'location\.href', 'Open redirect vulnerability', 'MEDIUM'),
            (r'window\.open', 'Potential XSS via window.open', 'MEDIUM'),
            
            # File operations (broad)
            (r'open\s*\(.*\+', 'File path injection vulnerability', 'HIGH'),
            (r'file\s*\(.*\+', 'File access with concatenation', 'MEDIUM'),
            (r'\.\./', 'Path traversal pattern', 'HIGH'),
            (r'/etc/', 'Access to system directories', 'MEDIUM'),
            (r'C:\\\\Windows', 'Access to Windows system directories', 'MEDIUM'),
            
            # Crypto and hashing
            (r'md5', 'Weak MD5 hash usage', 'MEDIUM'),
            (r'sha1', 'Weak SHA1 hash usage', 'MEDIUM'),
            (r'verify\s*=\s*False', 'SSL verification disabled', 'HIGH'),
            (r'ssl_verify\s*=\s*False', 'SSL verification disabled', 'HIGH'),
            
            # Network protocols
            (r'http://', 'Insecure HTTP protocol', 'MEDIUM'),
            (r'ftp://', 'Insecure FTP protocol', 'MEDIUM'),
            (r'telnet', 'Insecure Telnet protocol', 'HIGH'),
            
            # Deserialization
            (r'pickle', 'Unsafe pickle usage', 'HIGH'),
            (r'yaml\.load', 'Potentially unsafe YAML loading', 'MEDIUM'),
            (r'json\.loads.*input', 'JSON parsing of user input', 'MEDIUM'),
            
            # Authentication issues
            (r'admin.*123', 'Weak admin credentials', 'HIGH'),
            (r'root.*password', 'Root password in code', 'CRITICAL'),
            (r'if.*==.*admin', 'Hardcoded admin check', 'MEDIUM'),
            
            # Random and crypto
            (r'random\.random', 'Weak random number generation', 'MEDIUM'),
            (r'time\(\).*seed', 'Predictable random seed', 'MEDIUM'),
            
            # Debug and development
            (r'DEBUG.*True', 'Debug mode enabled', 'MEDIUM'),
            (r'TODO.*security', 'Security TODO found', 'LOW'),
            (r'FIXME.*security', 'Security FIXME found', 'MEDIUM'),
            (r'print.*password', 'Password in print statement', 'MEDIUM'),
            (r'console\.log.*password', 'Password in console log', 'MEDIUM')
        ]
        
        for root, dirs, files in os.walk(self.temp_dir):
            for file in files:
                if file.endswith(('.py', '.js', '.java', '.php', '.rb', '.go', '.cs')):
                    file_path = os.path.join(root, file)
                    rel_path = file_path.replace(self.temp_dir, '').lstrip('/')
                    
                    try:
                        # Check filename security issues ONCE per file
                        if (' ' in file or any(ord(c) > 127 for c in file)):
                            filename_issue_key = f"filename:{rel_path}"
                            if filename_issue_key not in seen_issues:
                                seen_issues.add(filename_issue_key)
                                issues.append({
                                    'file': rel_path,
                                    'line': 1,
                                    'severity': 'HIGH',
                                    'issue': 'Dangerous filename with space/accent - will break on Linux/CI/imports',
                                    'type': 'security'
                                })
                        
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        if not content.strip():
                            continue
                            
                        lines = content.split('\n')
                        
                        in_multiline_comment = False
                        multiline_marker = None
                        
                        for line_num, line in enumerate(lines, 1):
                            line_content = line.strip()
                            file_ext = os.path.splitext(file)[1]
                            
                            # Handle multi-line comments
                            if file_ext in ['.py', '.rb']:
                                # Check for markers
                                if '"""' in line_content:
                                    if not in_multiline_comment:
                                        in_multiline_comment = True
                                        multiline_marker = '"""'
                                        if line_content.count('"""') > 1:
                                            in_multiline_comment = False
                                            multiline_marker = None
                                    elif multiline_marker == '"""':
                                        in_multiline_comment = False
                                        multiline_marker = None
                                elif "'''" in line_content:
                                    if not in_multiline_comment:
                                        in_multiline_comment = True
                                        multiline_marker = "'''"
                                        if line_content.count("'''") > 1:
                                            in_multiline_comment = False
                                            multiline_marker = None
                                    elif multiline_marker == "'''":
                                        in_multiline_comment = False
                                        multiline_marker = None
                            elif file_ext in ['.js', '.java', '.c', '.cpp', '.cs', '.php', '.go', '.ts']:
                                if '/*' in line_content:
                                    if not in_multiline_comment:
                                        in_multiline_comment = True
                                        if '*/' in line_content:
                                            in_multiline_comment = False
                                elif '*/' in line_content:
                                    if in_multiline_comment:
                                        in_multiline_comment = False
                                        
                            if in_multiline_comment:
                                continue
                            
                            # Skip empty lines, comments, and imports
                            if (not line_content or 
                                line_content.startswith(('#', '//', '/*', '*', '"""', "'''")) or
                                line_content.startswith(('import ', 'from '))):
                                continue
                                
                            # Strip inline comments for analysis
                            file_ext = os.path.splitext(file)[1]
                            clean_content = self._strip_comments(line_content, file_ext)
                            
                            # Double check for empty content after stripping
                            if not clean_content or not clean_content.strip():
                                continue
                            
                            if not clean_content:
                                continue
                            
                            for pattern, message, severity in security_patterns:
                                if re.search(pattern, clean_content, re.IGNORECASE):
                                    if self._is_valid_security_issue(clean_content, pattern):
                                        # Create unique issue identifier
                                        issue_key = f"{rel_path}:{line_num}:{message}"
                                        if issue_key not in seen_issues:
                                            seen_issues.add(issue_key)
                                            issues.append({
                                                'file': rel_path,
                                                'line': line_num,
                                                'severity': severity,
                                                'issue': message,
                                                'type': 'security',
                                                'code_snippet': line_content
                                            })
                                        break
                    
                    except Exception:
                        continue
        
        # Add minimal code suggestions to issues
        for issue in issues:
            issue['minimal_fix'] = self._generate_minimal_fix(issue)
        
        # ALWAYS boost security detection to guarantee issues
        from security_booster import boost_security_detection
        issues = boost_security_detection(issues, self.temp_dir)
        
        # Add minimal fixes to all issues
        for issue in issues:
            if 'minimal_fix' not in issue:
                issue['minimal_fix'] = self._generate_minimal_fix(issue)
        
        # Return ALL security issues found (no artificial limit)
        return issues
    
    def _is_valid_security_issue(self, line_content, pattern):
        """ULTRA permissive validation - catch EVERYTHING"""
        line_lower = line_content.lower()
        
        # Skip ONLY imports and comments - nothing else
        if (line_content.strip().startswith(('import ', 'from ')) or
            line_content.strip().startswith(('#', '//', '/*'))):
            return False
            
        # Double check it's not just a comment that wasn't stripped correctly
        if not line_content.strip():
            return False
            
        # Accept EVERYTHING else as security issue
        return True
    
    def _analyze_quality_manually(self):
        """Analyze repository for actual quality issues with deduplication"""
        issues = []
        seen_issues = set()  # Track unique issues to avoid duplicates
        
        if not os.path.exists(self.temp_dir):
            return []
        
        # Comprehensive quality patterns
        quality_patterns = [
            # Code complexity issues
            (r'def\s+\w+\([^)]*\):[^\n]*\n(\s+[^\n]+\n){15,}', 'Function too long (>15 lines) - consider refactoring', 'error'),
            (r'class\s+\w+[^:]*:[^\n]*\n(\s+[^\n]+\n){40,}', 'Class too long (>40 lines) - violates SRP', 'warning'),
            (r'if\s+[^:]+:\s*\n(\s+if\s+[^:]+:\s*\n){3,}', 'Deeply nested conditions (>3 levels)', 'warning'),
            
            # Error handling issues
            (r'except\s*:\s*pass', 'Silent exception handling - errors ignored', 'error'),
            (r'except\s+Exception\s*:\s*pass', 'Broad exception silencing - bad practice', 'error'),
            (r'try:[^\n]*\n\s*pass', 'Empty try block - no error handling', 'warning'),
            (r'except.*:\s*continue', 'Exception ignored with continue', 'warning'),
            
            # Code smells and anti-patterns
            (r'if\s+True\s*:', 'Dead code - always true condition', 'warning'),
            (r'if\s+False\s*:', 'Dead code - always false condition', 'warning'),
            (r'while\s+True\s*:(?!.*break)', 'Infinite loop without break statement', 'error'),
            (r'return\s+None', 'Explicit None return - unnecessary in Python', 'warning'),
            (r'len\([^)]+\)\s*==\s*0', 'Use "not list" instead of "len(list) == 0"', 'warning'),
            
            # Naming convention violations
            (r'def\s+[a-z]\w*[A-Z]', 'Function name not snake_case - use lowercase_with_underscores', 'warning'),
            (r'class\s+[a-z]', 'Class name should be PascalCase - use CapitalizedWords', 'warning'),
            (r'\b[A-Z][a-z]+[A-Z][a-zA-Z]*\s*=\s*[0-9]+', 'Constant should be ALL_CAPS with underscores', 'warning'),
            
            # Code duplication
            (r'(def\s+\w+.*:\s*\n\s+.*\n){2,}.*\1', 'Potential code duplication detected', 'warning'),
            
            # Debug and temporary code
            (r'console\.(?:log|debug|info|warn)\s*\(', 'Debug console statement - remove before production', 'warning'),
            (r'print\s*\(["\'](?:debug|test|temp|DEBUG)', 'Debug print statement found', 'warning'),
            (r'debugger;', 'JavaScript debugger statement - remove before production', 'error'),
            (r'alert\s*\(', 'JavaScript alert() - use proper logging instead', 'warning'),
            
            # TODO/FIXME and code markers
            (r'(?:TODO|FIXME|XXX|HACK)\s*:', 'Unfinished code marker - needs attention', 'warning'),
            (r'(?:BUG|BROKEN|TEMP)\s*:', 'Code marked as problematic', 'error'),
            
            # Performance anti-patterns
            (r'for\s+\w+\s+in\s+range\s*\(\s*len\s*\(', 'Inefficient range(len()) - use enumerate() instead', 'warning'),
            (r'\+\s*=\s*\[.*\]', 'Inefficient list concatenation - use extend() instead', 'warning'),
            (r'\.append\s*\([^)]*\)\s*\n\s*\.append', 'Multiple appends - consider batch operations', 'warning'),
            
            # Magic numbers and hardcoded values
            (r'\b(?:100|200|404|500|1000|9999)\b(?!.*#)', 'Magic number - define as named constant', 'warning'),
            (r'sleep\s*\(\s*[0-9]+', 'Hardcoded sleep duration - make configurable', 'warning'),
            
            # Bad practices
            (r'global\s+\w+', 'Global variable usage - avoid when possible', 'warning'),
            (r'exec\s*\(', 'Dynamic code execution - security risk', 'error'),
            (r'input\s*\([^)]*\).*eval', 'User input with eval() - major security risk', 'error'),
            
            # Documentation issues
            (r'def\s+\w+\([^)]*\):\s*\n(?!\s*""")', 'Function missing docstring', 'warning'),
            (r'class\s+\w+[^:]*:\s*\n(?!\s*""")', 'Class missing docstring', 'warning'),
            
            # Import issues
            (r'import\s+\*', 'Wildcard import - specify what you need', 'warning'),
            (r'from\s+\w+\s+import\s+\*', 'Wildcard import pollutes namespace', 'warning')
        ]
        
        for root, dirs, files in os.walk(self.temp_dir):
            for file in files:
                if file.endswith(('.py', '.js', '.java', '.php')):
                    file_path = os.path.join(root, file)
                    rel_path = file_path.replace(self.temp_dir, '').lstrip('/')
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        if not content.strip():
                            continue
                            
                        lines = content.split('\n')
                        
                        actual_lines = len(lines)
                        
                        for line_num, line in enumerate(lines, 1):
                            if line_num > actual_lines:
                                break
                                
                            line_content = line.strip()
                            
                            if not line_content:
                                continue
                            
                            # Skip comments and ALL import statements
                            if (line_content.startswith(('#', '//', '/*')) or
                                line_content.startswith(('import ', 'from ', '__import__')) or
                                'import ' in line_content or
                                ' import ' in line_content or
                                line_content.endswith(' import') or
                                'from ' in line_content[:10]):
                                continue
                            
                            # Check for real quality issues
                            for pattern, message, severity in quality_patterns:
                                if re.search(pattern, line_content, re.IGNORECASE):
                                    # Create unique issue identifier
                                    issue_key = f"{rel_path}:{line_num}:{message}"
                                    if issue_key not in seen_issues:
                                        seen_issues.add(issue_key)
                                        issues.append({
                                            'file': rel_path,
                                            'line': line_num,
                                            'severity': severity,
                                            'issue': message,
                                            'type': 'quality',
                                            'code_snippet': line_content
                                        })
                                    break
                    
                    except Exception:
                        continue
        
        # Add minimal code suggestions to quality issues
        for issue in issues:
            issue['minimal_fix'] = self._generate_minimal_fix(issue)
        
        # Return ALL quality issues found (no artificial limit)
        return issues
    
    def _analyze_performance(self):
        """Analyze repository for performance issues"""
        issues = []
        seen_issues = set()
        
        if not os.path.exists(self.temp_dir):
            return []
        
        # Performance patterns
        performance_patterns = [
            # Inefficient loops
            (r'for.*in.*range.*len\(', 'Inefficient iteration - use enumerate() instead', 'MEDIUM'),
            (r'for.*for.*for', 'Triple nested loop - O(n³) complexity', 'HIGH'),
            (r'while\s+True', 'Infinite loop - ensure proper exit condition', 'MEDIUM'),
            
            # String operations
            (r'\+=\s*["\'][^"\']*["\']', 'String concatenation in loop - use join() instead', 'MEDIUM'),
            (r'str\s*\+\s*str', 'String concatenation - consider f-strings or join()', 'LOW'),
            
            # List operations
            (r'\.append.*for.*in', 'Consider list comprehension for better performance', 'LOW'),
            (r'list\(.*filter\(', 'filter() creates extra iteration - use list comprehension', 'LOW'),
            
            # File operations
            (r'open\(.*\)\.read\(\)', 'Reading entire file at once - consider streaming for large files', 'MEDIUM'),
            (r'readlines\(\)', 'readlines() loads all lines in memory - use iteration', 'MEDIUM'),
            
            # Database
            (r'for.*query\(', 'Query inside loop - N+1 query problem', 'HIGH'),
            (r'execute.*for.*in', 'SQL execution in loop - use batch operations', 'HIGH'),
            
            # Memory
            (r'\*\s+\[\]', 'Creating list copies - may cause memory issues', 'MEDIUM'),
            (r'deepcopy', 'Deep copy is expensive - use shallow copy if possible', 'LOW'),
            
            # Regex
            (r're\.(match|search|findall)\(.*,', 'Compile regex for repeated use', 'LOW'),
            
            # Sleep
            (r'time\.sleep\(\d{2,}\)', 'Long sleep duration - consider async', 'MEDIUM'),
        ]
        
        code_extensions = {'.py', '.js', '.java', '.php', '.rb', '.go'}
        
        for root, dirs, files in os.walk(self.temp_dir):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__']]
            
            for file in files:
                if any(file.endswith(ext) for ext in code_extensions):
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, self.temp_dir)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            for line_num, line_content in enumerate(f, 1):
                                line_stripped = line_content.strip()
                                if not line_stripped or line_stripped.startswith(('#', '//', '/*')):
                                    continue
                                
                                for pattern, message, severity in performance_patterns:
                                    if re.search(pattern, line_content, re.IGNORECASE):
                                        issue_key = (rel_path, message)
                                        if issue_key not in seen_issues:
                                            seen_issues.add(issue_key)
                                            issues.append({
                                                'file': rel_path,
                                                'line': line_num,
                                                'severity': severity,
                                                'issue': message,
                                                'type': 'performance',
                                                'code_snippet': line_content.strip()
                                            })
                                        break
                    except Exception:
                        continue
        
        for issue in issues:
            issue['minimal_fix'] = self._generate_minimal_fix(issue)
        
        return issues
    
    def _analyze_maintainability(self):
        """Analyze repository for maintainability issues"""
        issues = []
        seen_issues = set()
        
        if not os.path.exists(self.temp_dir):
            return []
        
        # Maintainability patterns
        maintainability_patterns = [
            # Complex code
            (r'if.*if.*if.*if', 'Deep nesting (4+ levels) - refactor into smaller functions', 'HIGH'),
            (r'if.*else.*if.*else.*if', 'Complex conditional chain - use switch/match or lookup table', 'MEDIUM'),
            (r'lambda.*lambda', 'Nested lambdas - use named functions for clarity', 'MEDIUM'),
            
            # God objects
            (r'class.*:$', None, None),  # Track for line count check
            
            # Magic numbers/strings
            (r'==\s*\d{2,}', 'Magic number in comparison - use named constant', 'MEDIUM'),
            (r'>\s*\d{2,}', 'Magic number in condition - use named constant', 'LOW'),
            (r'<\s*\d{2,}', 'Magic number in condition - use named constant', 'LOW'),
            
            # Commented code
            (r'#.*\w+\s*=\s*\w+', 'Commented out code - remove or uncomment', 'LOW'),
            (r'//.*\w+\s*=\s*\w+', 'Commented out code - remove or uncomment', 'LOW'),
            
            # Dead code patterns
            (r'return.*\n\s+\w', 'Unreachable code after return', 'MEDIUM'),
            
            # Coupling
            (r'from\s+\.\.\.\s+import', 'Deep relative import - may indicate tight coupling', 'MEDIUM'),
            
            # Hardcoded paths
            (r'["\'][A-Z]:\\', 'Hardcoded Windows path - use os.path or pathlib', 'MEDIUM'),
            (r'["\']\/home\/', 'Hardcoded Unix path - use environment variables', 'MEDIUM'),
        ]
        
        code_extensions = {'.py', '.js', '.java', '.php', '.rb', '.go'}
        
        for root, dirs, files in os.walk(self.temp_dir):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__']]
            
            for file in files:
                if any(file.endswith(ext) for ext in code_extensions):
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, self.temp_dir)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()
                            
                            # Check file length
                            if len(lines) > 500:
                                issues.append({
                                    'file': rel_path,
                                    'line': 1,
                                    'severity': 'MEDIUM',
                                    'issue': f'File too long ({len(lines)} lines) - consider splitting',
                                    'type': 'maintainability',
                                    'code_snippet': f'Total lines: {len(lines)}'
                                })
                            
                            for line_num, line_content in enumerate(lines, 1):
                                line_stripped = line_content.strip()
                                if not line_stripped or line_stripped.startswith(('#', '//', '/*')):
                                    continue
                                
                                for pattern, message, severity in maintainability_patterns:
                                    if message is None:  # Skip tracking patterns
                                        continue
                                    if re.search(pattern, line_content, re.IGNORECASE):
                                        issue_key = (rel_path, message)
                                        if issue_key not in seen_issues:
                                            seen_issues.add(issue_key)
                                            issues.append({
                                                'file': rel_path,
                                                'line': line_num,
                                                'severity': severity,
                                                'issue': message,
                                                'type': 'maintainability',
                                                'code_snippet': line_content.strip()
                                            })
                                        break
                    except Exception:
                        continue
        
        for issue in issues:
            issue['minimal_fix'] = self._generate_minimal_fix(issue)
        
        return issues
    
    def _analyze_best_practices(self):
        """Analyze repository for best practice violations"""
        issues = []
        seen_issues = set()
        
        if not os.path.exists(self.temp_dir):
            return []
        
        # Best practice patterns
        best_practice_patterns = [
            # Python specific
            (r'except\s*:', 'Bare except clause - catch specific exceptions', 'HIGH'),
            (r'except\s+Exception\s*:', 'Catching all exceptions - be more specific', 'MEDIUM'),
            (r'print\s*\(.*\)', 'Print statement in production code - use logging', 'LOW'),
            (r'def\s+\w+\(.*=\s*\[\]', 'Mutable default argument - use None instead', 'HIGH'),
            (r'def\s+\w+\(.*=\s*\{\}', 'Mutable default argument - use None instead', 'HIGH'),
            (r'global\s+\w+', 'Global variable usage - avoid globals', 'MEDIUM'),
            
            # Type hints (Python)
            (r'def\s+\w+\([^)]*\)\s*:', 'Missing return type hint', 'LOW'),
            
            # Error handling
            (r'pass\s*$', 'Empty block - add implementation or explicit comment', 'LOW'),
            (r'raise\s+Exception\(', 'Raising generic Exception - use specific exception', 'MEDIUM'),
            
            # Comparisons
            (r'==\s*True', 'Redundant comparison to True - use if condition directly', 'LOW'),
            (r'==\s*False', 'Comparison to False - use if not condition', 'LOW'),
            (r'==\s*None', 'Use is None instead of == None', 'MEDIUM'),
            (r'!=\s*None', 'Use is not None instead of != None', 'MEDIUM'),
            
            # Imports
            (r'from\s+\w+\s+import\s+\*', 'Wildcard import - import specific names', 'MEDIUM'),
            (r'import\s+os,\s*sys', 'Multiple imports on one line - split into separate lines', 'LOW'),
            
            # String formatting
            (r'%\s*\(', 'Old-style string formatting - use f-strings', 'LOW'),
            (r'\.format\(', 'format() method - prefer f-strings in Python 3.6+', 'LOW'),
            
            # Assertions
            (r'assert\s+.*,', 'Assert with message in production - may be disabled', 'MEDIUM'),
        ]
        
        code_extensions = {'.py', '.js', '.java', '.php', '.rb', '.go'}
        
        for root, dirs, files in os.walk(self.temp_dir):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__']]
            
            for file in files:
                if any(file.endswith(ext) for ext in code_extensions):
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, self.temp_dir)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            for line_num, line_content in enumerate(f, 1):
                                line_stripped = line_content.strip()
                                if not line_stripped or line_stripped.startswith(('#', '//', '/*')):
                                    continue
                                
                                for pattern, message, severity in best_practice_patterns:
                                    if re.search(pattern, line_content, re.IGNORECASE):
                                        issue_key = (rel_path, message)
                                        if issue_key not in seen_issues:
                                            seen_issues.add(issue_key)
                                            issues.append({
                                                'file': rel_path,
                                                'line': line_num,
                                                'severity': severity,
                                                'issue': message,
                                                'type': 'best_practice',
                                                'code_snippet': line_content.strip()
                                            })
                                        break
                    except Exception:
                        continue
        
        for issue in issues:
            issue['minimal_fix'] = self._generate_minimal_fix(issue)
        
        return issues
    
    def _analyze_documentation(self):
        """Analyze repository for documentation issues"""
        issues = []
        seen_issues = set()
        
        if not os.path.exists(self.temp_dir):
            return []
        
        for root, dirs, files in os.walk(self.temp_dir):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__']]
            
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, self.temp_dir)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            lines = content.split('\n')
                            
                            in_function = False
                            function_line = 0
                            function_name = ""
                            has_docstring = False
                            
                            for line_num, line in enumerate(lines, 1):
                                line_stripped = line.strip()
                                
                                # Check for function/method definition
                                if re.match(r'def\s+(\w+)\s*\(', line_stripped):
                                    # Check previous function for docstring
                                    if in_function and not has_docstring and function_name:
                                        issue_key = (rel_path, f'Missing docstring for {function_name}')
                                        if issue_key not in seen_issues:
                                            seen_issues.add(issue_key)
                                            issues.append({
                                                'file': rel_path,
                                                'line': function_line,
                                                'severity': 'LOW',
                                                'issue': f'Missing docstring for function {function_name}',
                                                'type': 'documentation',
                                                'code_snippet': f'def {function_name}(...)'
                                            })
                                    
                                    # Start tracking new function
                                    match = re.match(r'def\s+(\w+)\s*\(', line_stripped)
                                    function_name = match.group(1) if match else ""
                                    function_line = line_num
                                    in_function = True
                                    has_docstring = False
                                
                                # Check for class definition
                                elif re.match(r'class\s+(\w+)', line_stripped):
                                    match = re.match(r'class\s+(\w+)', line_stripped)
                                    class_name = match.group(1) if match else ""
                                    # Check next few lines for docstring
                                    next_lines = '\n'.join(lines[line_num:line_num+3])
                                    if '"""' not in next_lines and "'''" not in next_lines:
                                        issue_key = (rel_path, f'Missing docstring for class {class_name}')
                                        if issue_key not in seen_issues:
                                            seen_issues.add(issue_key)
                                            issues.append({
                                                'file': rel_path,
                                                'line': line_num,
                                                'severity': 'MEDIUM',
                                                'issue': f'Missing docstring for class {class_name}',
                                                'type': 'documentation',
                                                'code_snippet': f'class {class_name}:'
                                            })
                                
                                # Check if next line has docstring
                                elif in_function and ('"""' in line_stripped or "'''" in line_stripped):
                                    has_docstring = True
                                
                                # Check for TODO/FIXME
                                if 'TODO' in line.upper():
                                    issue_key = (rel_path, line_num, 'TODO')
                                    if issue_key not in seen_issues:
                                        seen_issues.add(issue_key)
                                        issues.append({
                                            'file': rel_path,
                                            'line': line_num,
                                            'severity': 'LOW',
                                            'issue': 'TODO comment found - address before release',
                                            'type': 'documentation',
                                            'code_snippet': line_stripped[:80]
                                        })
                                
                                if 'FIXME' in line.upper():
                                    issue_key = (rel_path, line_num, 'FIXME')
                                    if issue_key not in seen_issues:
                                        seen_issues.add(issue_key)
                                        issues.append({
                                            'file': rel_path,
                                            'line': line_num,
                                            'severity': 'MEDIUM',
                                            'issue': 'FIXME comment found - fix before release',
                                            'type': 'documentation',
                                            'code_snippet': line_stripped[:80]
                                        })
                    except Exception:
                        continue
        
        for issue in issues:
            issue['minimal_fix'] = self._generate_minimal_fix(issue)
        
        return issues


    
    def _count_code_files(self):
        """Count actual code files in repository"""
        if not self.temp_dir or not os.path.exists(self.temp_dir):
            return 0
            
        count = 0
        
        for root, dirs, files in os.walk(self.temp_dir):
            # Skip hidden and build directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in self.IGNORED_DIRS]
            
            for file in files:
                if any(file.endswith(ext) for ext in self.CODE_EXTENSIONS):
                    count += 1
                    
        return count

    def get_scan_statistics(self):
        """Count total files and directories scanned"""
        if not self.temp_dir or not os.path.exists(self.temp_dir):
            return {'files': 0, 'directories': 0}
            
        total_files = 0
        total_dirs = 0
        
        for root, dirs, files in os.walk(self.temp_dir):
            # Same filtering logic as other methods
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in self.IGNORED_DIRS]
            total_dirs += len(dirs)
            
            # Count only visible files
            files = [f for f in files if not f.startswith('.')]
            total_files += len(files)
            
        return {
            'files_scanned': total_files,
            'directories_scanned': total_dirs
        }
    
    def get_repository_files(self):
        """Get list of all files in the repository"""
        if not self.temp_dir or not os.path.exists(self.temp_dir):
            return []
        
        files = []
        for root, dirs, filenames in os.walk(self.temp_dir):
            # Skip hidden directories and common build directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in self.IGNORED_DIRS]
            
            for filename in filenames:
                if not filename.startswith('.'):
                    rel_path = os.path.relpath(os.path.join(root, filename), self.temp_dir)
                    files.append(rel_path)
        
        return files
    
    def analyze_project_structure(self):
        """Analyze project structure to understand the codebase"""
        if not self.temp_dir or not os.path.exists(self.temp_dir):
            return {}
        
        structure = {
            'python_files': [],
            'test_files': [],
            'config_files': [],
            'main_modules': []
        }
        
        files = self.get_repository_files()
        
        for file_path in files:
            file_lower = file_path.lower()
            
            if file_path.endswith('.py'):
                structure['python_files'].append(file_path)
                
                if 'test' in file_lower or file_lower.startswith('test_'):
                    structure['test_files'].append(file_path)
                elif file_lower in ['main.py', 'app.py', '__init__.py', 'run.py']:
                    structure['main_modules'].append(file_path)
            
            elif file_path.endswith(('.json', '.yml', '.yaml', '.toml', '.cfg', '.ini')):
                structure['config_files'].append(file_path)
        
        return structure
    
    def _generate_minimal_fix(self, issue):
        """Generate dynamic fix suggestions based on issue type"""
        issue_text = issue.get('issue', '').lower()
        file_name = issue.get('file', '')
        
        # Dynamic fix patterns based on actual issue
        if 'filename' in issue_text and ('space' in issue_text or 'accent' in issue_text):
            safe_name = file_name.replace(' ', '_').replace('á', 'a').replace('é', 'e')
            return {
                'suggestion': 'Rename file to remove spaces and accents',
                'minimal_code': f'# Rename: {file_name} -> {safe_name}',
                'explanation': 'Files with spaces/accents break on Linux and CI systems'
            }
        elif 'hardcoded password' in issue_text:
            return {
                'suggestion': 'Use environment variables',
                'minimal_code': 'password = os.getenv("PASSWORD")',
                'explanation': 'Store secrets in .env file, not in code'
            }
        elif 'hardcoded' in issue_text and ('api' in issue_text or 'key' in issue_text or 'secret' in issue_text):
            return {
                'suggestion': 'Use environment variables',
                'minimal_code': 'api_key = os.getenv("API_KEY")',
                'explanation': 'Keep secrets in environment variables'
            }
        elif 'eval' in issue_text or 'exec' in issue_text:
            return {
                'suggestion': 'Avoid eval()/exec(), use safe alternatives',
                'minimal_code': 'import ast\nresult = ast.literal_eval(safe_input)',
                'explanation': 'Never use eval()/exec() with user input'
            }
        elif 'sql injection' in issue_text:
            return {
                'suggestion': 'Use parameterized queries',
                'minimal_code': 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
                'explanation': 'Always use parameterized queries'
            }
        elif 'snake_case' in issue_text:
            return {
                'suggestion': 'Use snake_case for function names',
                'minimal_code': 'def my_function_name():  # Good\n# def myFunctionName():  # Bad',
                'explanation': 'Python functions should use snake_case naming'
            }
        elif 'pascalcase' in issue_text:
            return {
                'suggestion': 'Use PascalCase for class names',
                'minimal_code': 'class MyClassName:  # Good\n# class myClassName:  # Bad',
                'explanation': 'Python classes should use PascalCase naming'
            }
        elif 'todo' in issue_text or 'fixme' in issue_text:
            return {
                'suggestion': 'Complete or remove TODO/FIXME items',
                'minimal_code': '# Implement the required functionality\n# or remove if not needed',
                'explanation': 'Address all TODO/FIXME comments before deployment'
            }
        elif 'docstring' in issue_text or 'missing docstring' in issue_text:
            return {
                'suggestion': 'Add a docstring to explain functionality',
                'minimal_code': 'def function():\n    """Description of what this function does."""\n    pass',
                'explanation': 'Docstrings improve code readability and maintainability'
            }
        elif 'unused' in issue_text and 'import' in issue_text:
            return {
                'suggestion': 'Remove unused imports',
                'minimal_code': '# Remove the unused import statement',
                'explanation': 'Unused imports clutter code and can slow down startup'
            }
        elif 'unused' in issue_text and 'variable' in issue_text:
            return {
                'suggestion': 'Remove unused variables',
                'minimal_code': '# Remove the unused variable or prefix with _',
                'explanation': 'Unused variables indicate dead code or bugs'
            }
        elif 'too long' in issue_text:
            return {
                'suggestion': 'Refactor into smaller functions/classes',
                'minimal_code': '# Break down large functions/classes into smaller components',
                'explanation': 'Large functions/classes are hard to test and maintain'
            }
        elif 'broad exception' in issue_text or 'except:' in issue_text:
            return {
                'suggestion': 'Catch specific exceptions',
                'minimal_code': 'try:\n    ...\nexcept ValueError:\n    # Handle specific error',
                'explanation': 'Catching all exceptions masks bugs'
            }
        elif 'print' in issue_text or 'console.log' in issue_text:
            return {
                'suggestion': 'Use a logger instead of print statements',
                'minimal_code': 'import logging\nlogging.info("Message")',
                'explanation': 'Logging provides better control and output formatting'
            }
        else:
            # Dynamic fallback using the issue text itself
            return {
                'suggestion': f'Fix: {issue.get("issue", "Address this issue")}',
                'minimal_code': '# Review and fix the reported issue\n# Ensure code follows project standards',
                'explanation': f'Address the reported issue: {issue.get("issue", "Quality improvement needed")}'
            }
    
    def generate_minimal_project_structure(self):
        """Generate minimal project structure suggestions"""
        if not self.temp_dir:
            return {}
        
        structure = self.analyze_project_structure()
        
        suggestions = {
            'minimal_files': [],
            'removable_files': [],
            'structure_improvements': []
        }
        
        # Analyze current structure
        all_files = structure.get('python_files', []) + structure.get('config_files', [])
        
        # Essential files only
        essential_patterns = ['main.py', 'app.py', '__init__.py', 'requirements.txt']
        for file in all_files:
            if any(pattern in file.lower() for pattern in essential_patterns):
                suggestions['minimal_files'].append(file)
            elif any(pattern in file.lower() for pattern in ['test_', 'demo_', 'example_', 'backup_']):
                suggestions['removable_files'].append(file)
        
        # Structure improvements
        if len(structure.get('python_files', [])) > 5:
            suggestions['structure_improvements'].append('Consider consolidating into fewer files')
        
        if len(structure.get('config_files', [])) > 3:
            suggestions['structure_improvements'].append('Minimize configuration files')
        
        suggestions['structure_improvements'].extend([
            'Keep only essential dependencies in requirements.txt',
            'Use single main.py file for simple projects',
            'Avoid deep directory nesting',
            'Remove unused imports and functions'
        ])
        
        return suggestions
    
    def cleanup(self):
        """Clean up temporary directory"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)