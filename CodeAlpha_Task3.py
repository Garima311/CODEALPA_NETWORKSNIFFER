

import re
import os
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Any

class SecurityVulnerability:
    """Represents a security vulnerability found in code"""
    
    def __init__(self, vuln_type: str, severity: str, line_number: int, 
                 code_snippet: str, description: str, remediation: str,
                 cwe_id: str = None, file_path: str = None):
        self.vuln_type = vuln_type
        self.severity = severity
        self.line_number = line_number
        self.code_snippet = code_snippet
        self.description = description
        self.remediation = remediation
        self.cwe_id = cwe_id
        self.file_path = file_path
        self.timestamp = datetime.now()

    def to_dict(self):
        return {
            'type': self.vuln_type,
            'severity': self.severity,
            'line_number': self.line_number,
            'code_snippet': self.code_snippet,
            'description': self.description,
            'remediation': self.remediation,
            'cwe_id': self.cwe_id,
            'file_path': self.file_path,
            'timestamp': self.timestamp.isoformat()
        }

class SecureCodeReviewer:
    """Main class for conducting secure code reviews"""
    
    def __init__(self):
        self.vulnerabilities = []
        self.supported_languages = ['python', 'javascript', 'java', 'php', 'c', 'cpp']
        self.severity_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        
        # Security patterns for different languages
        self.security_patterns = self._load_security_patterns()
    
    def _load_security_patterns(self) -> Dict:
        """Load security vulnerability patterns for different languages"""
        return {
            'python': {
                'sql_injection': [
                    r'execute\s*\(\s*["\'].*%.*["\']',
                    r'cursor\.execute\s*\(\s*["\'][^"\']*["\']\s*%',
                    r'\.format\s*\([^)]*\)\s*(?=.*execute)',
                    r'f["\'][^"\']*{[^}]*}[^"\']*["\'](?=.*execute)'
                ],
                'command_injection': [
                    r'os\.system\s*\(\s*["\'][^"\']*["\']\s*\+',
                    r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True',
                    r'eval\s*\(',
                    r'exec\s*\('
                ],
                'path_traversal': [
                    r'open\s*\([^)]*\+.*["\']\.\./',
                    r'file\s*\([^)]*\+.*["\']\.\./',
                    r'os\.path\.join\([^)]*user_input'
                ],
                'weak_crypto': [
                    r'md5\s*\(',
                    r'sha1\s*\(',
                    r'hashlib\.md5',
                    r'hashlib\.sha1'
                ],
                'hardcoded_secrets': [
                    r'password\s*=\s*["\'][^"\']{4,}["\']',
                    r'api_key\s*=\s*["\'][^"\']+["\']',
                    r'secret\s*=\s*["\'][^"\']+["\']',
                    r'token\s*=\s*["\'][^"\']+["\']'
                ]
            },
            'javascript': {
                'xss': [
                    r'innerHTML\s*=.*\+',
                    r'document\.write\s*\(',
                    r'\.html\s*\([^)]*\+',
                    r'eval\s*\('
                ],
                'sql_injection': [
                    r'query\s*\(["\'][^"\']*["\']\s*\+',
                    r'execute\s*\(["\'][^"\']*["\']\s*\+'
                ],
                'insecure_random': [
                    r'Math\.random\s*\(\)',
                    r'new Date\(\)\.getTime\(\)'
                ],
                'prototype_pollution': [
                    r'Object\.assign\s*\([^)]*req\.',
                    r'merge\s*\([^)]*req\.',
                    r'\[.*req\..*\]\s*='
                ]
            },
            'java': {
                'sql_injection': [
                    r'Statement.*execute.*\+',
                    r'prepareStatement.*["\'].*["\'].*\+',
                    r'createQuery.*["\'].*["\'].*\+'
                ],
                'command_injection': [
                    r'Runtime\.getRuntime\(\)\.exec',
                    r'ProcessBuilder.*\+',
                    r'new ProcessBuilder.*user'
                ],
                'path_traversal': [
                    r'new File\s*\([^)]*\+.*\.\.',
                    r'FileInputStream\s*\([^)]*\+.*\.\.'
                ],
                'deserialization': [
                    r'ObjectInputStream.*readObject',
                    r'XMLDecoder.*readObject',
                    r'\.deserialize\s*\('
                ]
            },
            'php': {
                'sql_injection': [
                    r'mysql_query\s*\(\s*["\'].*\$',
                    r'mysqli_query\s*\([^)]*["\'].*\$',
                    r'\$.*query.*["\'].*\$'
                ],
                'command_injection': [
                    r'exec\s*\(\s*\$',
                    r'system\s*\(\s*\$',
                    r'shell_exec\s*\(\s*\$',
                    r'passthru\s*\(\s*\$'
                ],
                'file_inclusion': [
                    r'include\s*\(\s*\$',
                    r'require\s*\(\s*\$',
                    r'include_once\s*\(\s*\$',
                    r'require_once\s*\(\s*\$'
                ],
                'xss': [
                    r'echo\s+\$_GET',
                    r'echo\s+\$_POST',
                    r'print\s+\$_REQUEST'
                ]
            }
        }
    
    def analyze_file(self, file_path: str) -> List[SecurityVulnerability]:
        """Analyze a single file for security vulnerabilities"""
        vulnerabilities = []
        
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            return vulnerabilities
        
        # Determine language from file extension
        language = self._detect_language(file_path)
        if language not in self.supported_languages:
            print(f"Unsupported language for file: {file_path}")
            return vulnerabilities
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                lines = file.readlines()
            
            # Analyze each line
            for line_num, line in enumerate(lines, 1):
                line_vulnerabilities = self._analyze_line(line, line_num, language, file_path)
                vulnerabilities.extend(line_vulnerabilities)
            
            # Perform file-level analysis
            file_content = ''.join(lines)
            file_vulnerabilities = self._analyze_file_content(file_content, language, file_path)
            vulnerabilities.extend(file_vulnerabilities)
            
        except Exception as e:
            print(f"Error analyzing file {file_path}: {e}")
        
        return vulnerabilities
    
    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension"""
        extension_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.java': 'java',
            '.php': 'php',
            '.c': 'c',
            '.cpp': 'cpp',
            '.cc': 'cpp',
            '.cxx': 'cpp'
        }
        
        ext = Path(file_path).suffix.lower()
        return extension_map.get(ext, 'unknown')
    
    def _analyze_line(self, line: str, line_num: int, language: str, file_path: str) -> List[SecurityVulnerability]:
        """Analyze a single line of code for vulnerabilities"""
        vulnerabilities = []
        
        if language not in self.security_patterns:
            return vulnerabilities
        
        patterns = self.security_patterns[language]
        
        for vuln_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, line, re.IGNORECASE):
                    vuln = self._create_vulnerability(
                        vuln_type, line.strip(), line_num, language, file_path
                    )
                    vulnerabilities.append(vuln)
                    break  # Only report one vulnerability per line per type
        
        return vulnerabilities
    
    def _analyze_file_content(self, content: str, language: str, file_path: str) -> List[SecurityVulnerability]:
        """Perform file-level security analysis"""
        vulnerabilities = []
        
        # Check for common security issues across the entire file
        if language == 'python':
            # Check for debug mode in production
            if re.search(r'debug\s*=\s*True', content, re.IGNORECASE):
                vuln = SecurityVulnerability(
                    'debug_mode',
                    'MEDIUM',
                    0,
                    'debug = True',
                    'Debug mode enabled in production',
                    'Set debug = False in production environments',
                    'CWE-489',
                    file_path
                )
                vulnerabilities.append(vuln)
        
        elif language == 'javascript':
            # Check for console.log statements
            console_logs = re.findall(r'console\.log\s*\([^)]*\)', content)
            if console_logs:
                vuln = SecurityVulnerability(
                    'information_disclosure',
                    'LOW',
                    0,
                    f'Found {len(console_logs)} console.log statements',
                    'Console logging may expose sensitive information',
                    'Remove console.log statements from production code',
                    'CWE-200',
                    file_path
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _create_vulnerability(self, vuln_type: str, code_snippet: str, 
                            line_num: int, language: str, file_path: str) -> SecurityVulnerability:
        """Create a vulnerability object with appropriate details"""
        
        vulnerability_info = {
            'sql_injection': {
                'severity': 'CRITICAL',
                'description': 'Potential SQL injection vulnerability detected',
                'remediation': 'Use parameterized queries or prepared statements',
                'cwe_id': 'CWE-89'
            },
            'command_injection': {
                'severity': 'CRITICAL',
                'description': 'Potential command injection vulnerability detected',
                'remediation': 'Avoid executing system commands with user input. Use safe APIs instead',
                'cwe_id': 'CWE-78'
            },
            'xss': {
                'severity': 'HIGH',
                'description': 'Potential cross-site scripting (XSS) vulnerability',
                'remediation': 'Sanitize and validate user input before output',
                'cwe_id': 'CWE-79'
            },
            'path_traversal': {
                'severity': 'HIGH',
                'description': 'Potential path traversal vulnerability',
                'remediation': 'Validate and sanitize file paths, use whitelisting',
                'cwe_id': 'CWE-22'
            },
            'weak_crypto': {
                'severity': 'MEDIUM',
                'description': 'Weak cryptographic algorithm detected',
                'remediation': 'Use strong cryptographic algorithms (SHA-256, SHA-3)',
                'cwe_id': 'CWE-327'
            },
            'hardcoded_secrets': {
                'severity': 'HIGH',
                'description': 'Hardcoded credentials detected',
                'remediation': 'Store credentials in environment variables or secure vaults',
                'cwe_id': 'CWE-798'
            },
            'insecure_random': {
                'severity': 'MEDIUM',
                'description': '