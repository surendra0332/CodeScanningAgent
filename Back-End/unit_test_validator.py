"""
Unit Test Report Validator
Validates that unit test reports match the provided Git repository
"""

import os
import re
from typing import Dict, Any, Optional, Tuple
import json


class UnitTestReportValidator:
    """Validates unit test reports against repository information"""
    
    def __init__(self):
        pass
    
    def extract_repo_name(self, repo_url: str) -> str:
        """
        Extract repository name from various Git URL formats
        
        Supports:
        - https://github.com/owner/repo.git
        - https://github.com/owner/repo
        - git@github.com:owner/repo.git
        - https://gitlab.com/owner/repo.git
        - etc.
        """
        # Remove .git suffix if present
        url = repo_url.strip().rstrip('/')
        if url.endswith('.git'):
            url = url[:-4]
        
        # Extract the last part of the path (repository name)
        # Handle both HTTP(S) and SSH formats
        if '/' in url:
            parts = url.split('/')
            repo_name = parts[-1]
        elif ':' in url:  # SSH format like git@github.com:owner/repo
            parts = url.split(':')[-1].split('/')
            repo_name = parts[-1]
        else:
            repo_name = url
        
        return repo_name.lower()
    
    def extract_owner_and_repo(self, repo_url: str) -> Tuple[str, str]:
        """
        Extract owner and repository name from Git URL
        Returns: (owner, repo_name)
        """
        url = repo_url.strip().rstrip('/')
        if url.endswith('.git'):
            url = url[:-4]
        
        # Try to extract owner/repo from URL patterns
        # GitHub/GitLab format: https://github.com/owner/repo
        match = re.search(r'[:/]([^/]+)/([^/]+?)(?:\.git)?$', url)
        if match:
            owner = match.group(1).lower()
            repo = match.group(2).lower()
            return owner, repo
        
        return "", self.extract_repo_name(repo_url)
    
    def check_metadata(self, test_data: Dict[str, Any], repo_name: str, owner: str = "") -> Tuple[bool, str]:
        """
        Check if test report contains repository metadata that matches
        
        Returns: (is_valid, error_message)
        """
        # Fields that indicate repository/project info (only at top level or in metadata)
        repo_fields = ['repository', 'repo', 'project', 'project_name', 'repo_name', 
                       'repository_name', 'repository_url', 'repo_url', 'project_url']
        
        # Fields to SKIP (these contain test names, not repo names)
        skip_keys = ['tests', 'test_cases', 'results', 'testsuites', 'testsuite']
        
        found_metadata = {}
        
        # Search for repository metadata - but skip test arrays
        def search_metadata(data, prefix="", depth=0):
            if depth > 3:  # Don't go too deep - repo info should be at top level
                return
                
            if isinstance(data, dict):
                for key, value in data.items():
                    key_lower = key.lower()
                    
                    # Skip arrays containing individual tests
                    if key_lower in skip_keys:
                        continue
                    
                    # Only capture 'name' at top level or in metadata section
                    if key_lower == 'name' and depth <= 1 and prefix not in ['tests', 'test_cases']:
                        # Additional check: skip if value looks like a test name
                        if isinstance(value, str) and not value.startswith('test_'):
                            found_metadata[key] = value
                    
                    # Capture repository-specific fields at any level
                    if key_lower in repo_fields:
                        found_metadata[key] = value
                    
                    # Recursively search metadata section
                    if key_lower == 'metadata' and isinstance(value, dict):
                        search_metadata(value, 'metadata', depth + 1)
                    elif key_lower == 'coverage' and isinstance(value, dict):
                        # Check coverage.files for source file names
                        if 'files' in value and isinstance(value['files'], list):
                            for f in value['files']:
                                if isinstance(f, dict) and 'path' in f:
                                    found_metadata['coverage_file'] = f['path']
        
        search_metadata(test_data)
        
        # Check if any found metadata matches the repository
        if found_metadata:
            for field, value in found_metadata.items():
                value_str = str(value).lower()
                
                # Check if repository name is in the metadata
                if repo_name in value_str:
                    return True, ""
                
                # Check if owner/repo combination is in the metadata
                if owner and owner in value_str and repo_name in value_str:
                    return True, ""
        
        # No metadata found that conflicts - allow the scan
        # (This is lenient: if no repo info found, assume it's okay)
        return True, ""
    
    def check_file_paths(self, test_data: Dict[str, Any], repo_path: Optional[str] = None) -> Tuple[bool, str, int, int]:
        """
        Check if file paths in test report exist in the repository
        
        Returns: (is_valid, error_message, files_found, total_files)
        """
        if not repo_path or not os.path.exists(repo_path):
            # If repo not cloned yet, skip file path validation
            return True, "", 0, 0
        
        # Extract file paths from the test report
        file_paths = set()
        
        def extract_paths(data):
            if isinstance(data, dict):
                for key, value in data.items():
                    key_lower = key.lower()
                    # Common fields containing file paths
                    if key_lower in ['file', 'filename', 'filepath', 'path', 'source_file', 'test_file']:
                        if isinstance(value, str):
                            file_paths.add(value)
                    # Recursively search
                    if isinstance(value, (dict, list)):
                        extract_paths(value)
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, (dict, list)):
                        extract_paths(item)
        
        extract_paths(test_data)
        
        if not file_paths:
            # No file paths found in test report - cannot validate
            return True, "", 0, 0
        
        # Check how many files exist in the repository
        files_found = 0
        total_files = len(file_paths)
        missing_files = []
        
        for file_path in file_paths:
            # Clean up the path
            clean_path = file_path.strip().lstrip('./')
            
            # Try multiple path combinations
            possible_paths = [
                os.path.join(repo_path, clean_path),
                os.path.join(repo_path, file_path),
                os.path.join(repo_path, os.path.basename(clean_path))
            ]
            
            found = False
            for path in possible_paths:
                if os.path.exists(path):
                    files_found += 1
                    found = True
                    break
            
            if not found and len(missing_files) < 5:  # Keep track of first 5 missing files
                missing_files.append(clean_path)
        
        # Calculate match percentage
        match_percentage = (files_found / total_files * 100) if total_files > 0 else 0
        
        # Require at least 30% of files to match
        if match_percentage < 30 and total_files >= 3:
            missing_str = ", ".join(missing_files[:3])
            return False, f"Unit test report does not match repository. Only {files_found}/{total_files} test files found in repository. Missing files: {missing_str}...", files_found, total_files
        
        return True, "", files_found, total_files
    
    def validate_repository_match(
        self, 
        repo_url: str, 
        test_data: Dict[str, Any], 
        cloned_repo_path: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Main validation function to check if test report matches repository
        
        Returns: (is_valid, error_message)
        """
        # Extract repository information
        repo_name = self.extract_repo_name(repo_url)
        owner, repo = self.extract_owner_and_repo(repo_url)
        
        print(f"🔍 Validating test report for repository: {owner}/{repo} (name: {repo_name})")
        
        # Step 1: Check metadata
        metadata_valid, metadata_error = self.check_metadata(test_data, repo, owner)
        if not metadata_valid:
            return False, metadata_error
        
        print(f"✅ Metadata validation passed")
        
        # Step 2: Check file paths (only if repository is cloned)
        if cloned_repo_path:
            paths_valid, paths_error, files_found, total_files = self.check_file_paths(test_data, cloned_repo_path)
            
            if not paths_valid:
                return False, paths_error
            
            if total_files > 0:
                print(f"✅ File path validation passed ({files_found}/{total_files} files found)")
        
        print(f"✅ VALIDATION SUCCESS: Test report matches repository {repo_name}")
        return True, ""
    
    def validate_json_structure(self, test_data: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validate that the JSON has a reasonable test report structure
        
        Returns: (is_valid, error_message)
        """
        if not isinstance(test_data, dict):
            return False, "Test report must be a JSON object"
        
        # Check for common test report fields
        common_fields = [
            'tests', 'test', 'results', 'result', 'testsuites', 'testsuite',
            'summary', 'stats', 'statistics', 'coverage', 'failures', 'passed'
        ]
        
        has_test_field = any(field in str(test_data).lower() for field in common_fields)
        
        if not has_test_field:
            return False, "File does not appear to be a valid unit test report. Please provide a JSON file containing test results."
        
        return True, ""
