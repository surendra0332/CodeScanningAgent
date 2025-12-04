import os
import json
import re
from llm_integration import LLMAnalyzer

class RepoValidator:
    def __init__(self):
        self.llm_analyzer = LLMAnalyzer()
    
    def validate_repo_test_match(self, repo_path, unit_test_data):
        """Validate that unit test report matches the actual repository"""
        
        # Get actual repo structure
        repo_files = self._get_repo_structure(repo_path)
        
        # Extract test file references from unit test report
        test_files = self._extract_test_files(unit_test_data)
        
        # Use LLM for intelligent validation
        validation_result = self._llm_validate_match(repo_files, test_files, unit_test_data)
        
        return validation_result
    
    def _get_repo_structure(self, repo_path):
        """Get complete repository file structure"""
        files = []
        
        for root, dirs, filenames in os.walk(repo_path):
            # Skip hidden and build directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', 'build', 'dist']]
            
            for filename in filenames:
                if not filename.startswith('.'):
                    rel_path = os.path.relpath(os.path.join(root, filename), repo_path)
                    files.append(rel_path)
        
        return files
    
    def _extract_test_files(self, unit_test_data):
        """Extract file references from unit test report"""
        test_files = set()
        
        # Convert to string for analysis
        test_str = json.dumps(unit_test_data) if isinstance(unit_test_data, dict) else str(unit_test_data)
        
        # Extract file patterns
        file_patterns = [
            r'["\']([^"\']*\.py)["\']',
            r'["\']([^"\']*\.js)["\']',
            r'["\']([^"\']*\.java)["\']',
            r'file["\']?\s*:\s*["\']([^"\']+)["\']',
            r'path["\']?\s*:\s*["\']([^"\']+)["\']',
            r'source["\']?\s*:\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in file_patterns:
            matches = re.findall(pattern, test_str, re.IGNORECASE)
            test_files.update(matches)
        
        return list(test_files)
    
    def _llm_validate_match(self, repo_files, test_files, unit_test_data):
        """Use LLM to validate repo-test correlation"""
        
        prompt = f"""
CRITICAL VALIDATION TASK: Determine if this unit test report belongs to this repository.

REPOSITORY FILES ({len(repo_files)} files):
{repo_files[:50]}  # First 50 files

UNIT TEST REPORT FILES MENTIONED:
{test_files}

UNIT TEST DATA SAMPLE:
{str(unit_test_data)[:1000]}

VALIDATION CRITERIA:
1. Do test files reference actual repository files?
2. Are programming languages consistent?
3. Do test names match repository structure?
4. Are framework patterns consistent?

RESPOND WITH JSON:
{{
    "is_valid": true/false,
    "confidence": 0-100,
    "reason": "detailed explanation",
    "matching_files": ["list of matching files"],
    "language_match": true/false,
    "framework_match": true/false
}}
"""
        
        try:
            response = self.llm_analyzer.analyze_with_groq(prompt)
            
            # Parse LLM response
            if response and '{' in response:
                json_start = response.find('{')
                json_end = response.rfind('}') + 1
                json_str = response[json_start:json_end]
                result = json.loads(json_str)
                
                # Additional validation checks
                result['file_overlap'] = self._calculate_file_overlap(repo_files, test_files)
                result['structure_similarity'] = self._check_structure_similarity(repo_files, test_files)
                
                return result
            
        except Exception as e:
            print(f"LLM validation error: {e}")
        
        # Fallback validation
        return self._fallback_validation(repo_files, test_files)
    
    def _calculate_file_overlap(self, repo_files, test_files):
        """Calculate percentage of test files that exist in repo"""
        if not test_files:
            return 0
        
        matches = 0
        for test_file in test_files:
            # Check exact match or similar names
            test_base = os.path.basename(test_file).lower()
            for repo_file in repo_files:
                repo_base = os.path.basename(repo_file).lower()
                if test_base == repo_base or test_base.replace('test_', '') == repo_base:
                    matches += 1
                    break
        
        return (matches / len(test_files)) * 100
    
    def _check_structure_similarity(self, repo_files, test_files):
        """Check if directory structures are similar"""
        repo_dirs = set()
        test_dirs = set()
        
        for file in repo_files:
            if '/' in file:
                repo_dirs.add(os.path.dirname(file))
        
        for file in test_files:
            if '/' in file:
                test_dirs.add(os.path.dirname(file))
        
        if not repo_dirs or not test_dirs:
            return 50  # Neutral score
        
        common_dirs = repo_dirs.intersection(test_dirs)
        return (len(common_dirs) / max(len(repo_dirs), len(test_dirs))) * 100
    
    def _fallback_validation(self, repo_files, test_files):
        """Fallback validation when LLM fails"""
        file_overlap = self._calculate_file_overlap(repo_files, test_files)
        structure_similarity = self._check_structure_similarity(repo_files, test_files)
        
        # Simple scoring
        score = (file_overlap + structure_similarity) / 2
        
        return {
            'is_valid': score > 15,
            'confidence': min(score + 20, 95),
            'reason': f'File overlap: {file_overlap:.1f}%, Structure similarity: {structure_similarity:.1f}%',
            'matching_files': [],
            'language_match': True,
            'framework_match': True,
            'file_overlap': file_overlap,
            'structure_similarity': structure_similarity
        }