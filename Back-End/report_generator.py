#!/usr/bin/env python3
"""
Dynamic Report Generator - Generates reports based on actual scan data
"""
import json
import os
from datetime import datetime
from typing import Dict, List, Any

class ReportGenerator:
    def __init__(self):
        self.report_templates = {
            'security': self._get_security_template(),
            'quality': self._get_quality_template(),
            'summary': self._get_summary_template()
        }
    
    def generate_dynamic_report(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate completely dynamic report based on actual scan results"""
        
        # Extract real data from scan
        repo_url = scan_data.get('repo_url', '')
        issues = scan_data.get('issues', [])
        unit_test_data = scan_data.get('unit_test_report', {})
        
        # Analyze repository characteristics
        repo_analysis = self._analyze_repository(repo_url, issues)
        
        # Generate dynamic metrics
        metrics = self._calculate_dynamic_metrics(issues, repo_analysis, unit_test_data)
        
        # Create comprehensive report
        report = {
            'scan_metadata': {
                'repository': repo_url,
                'scan_timestamp': datetime.now().isoformat(),
                'scan_id': scan_data.get('job_id', 'unknown'),
                'repository_type': repo_analysis['type'],
                'primary_language': repo_analysis['language']
            },
            'executive_summary': self._generate_executive_summary(metrics, issues),
            'detailed_analysis': self._generate_detailed_analysis(issues, metrics),
            'security_assessment': self._generate_security_assessment(issues, metrics),
            'quality_assessment': self._generate_quality_assessment(issues, metrics),
            'recommendations': self._generate_recommendations(issues, repo_analysis),
            'metrics': metrics,
            'raw_data': {
                'total_issues': len(issues),
                'security_issues': len([i for i in issues if i.get('type') == 'security']),
                'quality_issues': len([i for i in issues if i.get('type') == 'quality']),
                'critical_issues': len([i for i in issues if i.get('severity') == 'CRITICAL']),
                'high_issues': len([i for i in issues if i.get('severity') == 'HIGH'])
            }
        }
        
        return report
    
    def _analyze_repository(self, repo_url: str, issues: List[Dict]) -> Dict[str, Any]:
        """Analyze repository characteristics from URL and issues"""
        
        # Extract repo name and owner
        repo_parts = repo_url.replace('.git', '').split('/')
        repo_name = repo_parts[-1] if repo_parts else 'unknown'
        owner = repo_parts[-2] if len(repo_parts) > 1 else 'unknown'
        
        # Determine language from issues and repo name
        language = 'python'  # default
        if any('.js' in str(issue.get('file', '')) for issue in issues):
            language = 'javascript'
        elif any('.java' in str(issue.get('file', '')) for issue in issues):
            language = 'java'
        elif 'py' in repo_name.lower():
            language = 'python'
        
        # Determine project type
        project_type = 'application'
        if 'api' in repo_name.lower() or 'service' in repo_name.lower():
            project_type = 'api_service'
        elif 'web' in repo_name.lower() or 'frontend' in repo_name.lower():
            project_type = 'web_application'
        elif 'lib' in repo_name.lower() or 'package' in repo_name.lower():
            project_type = 'library'
        
        return {
            'name': repo_name,
            'owner': owner,
            'language': language,
            'type': project_type,
            'complexity': 'medium' if len(issues) < 10 else 'high'
        }
    
    def _calculate_dynamic_metrics(self, issues: List[Dict], repo_analysis: Dict, unit_test_data: Dict) -> Dict[str, Any]:
        """Calculate metrics based on actual scan results"""
        
        total_issues = len(issues)
        security_issues = len([i for i in issues if i.get('type') == 'security'])
        quality_issues = len([i for i in issues if i.get('type') == 'quality'])
        
        # Dynamic scoring based on actual findings
        security_score = max(0, 100 - (security_issues * 15))
        quality_score = max(0, 100 - (quality_issues * 10))
        overall_score = (security_score + quality_score) / 2
        
        # Risk assessment based on issue severity
        critical_count = len([i for i in issues if i.get('severity') == 'CRITICAL'])
        high_count = len([i for i in issues if i.get('severity') == 'HIGH'])
        
        risk_level = 'LOW'
        if critical_count > 0:
            risk_level = 'CRITICAL'
        elif high_count > 2:
            risk_level = 'HIGH'
        elif total_issues > 5:
            risk_level = 'MEDIUM'
        
        # Test coverage analysis
        test_coverage = unit_test_data.get('coverage_percent', 0)
        if isinstance(test_coverage, str):
            try:
                test_coverage = float(test_coverage.replace('%', ''))
            except:
                test_coverage = 0
        
        return {
            'overall_score': round(overall_score, 1),
            'security_score': round(security_score, 1),
            'quality_score': round(quality_score, 1),
            'risk_level': risk_level,
            'test_coverage': test_coverage,
            'issue_density': round(total_issues / max(1, test_coverage/10), 2),
            'remediation_effort': self._calculate_remediation_effort(issues),
            'compliance_status': 'PASS' if critical_count == 0 and high_count < 3 else 'FAIL'
        }
    
    def _calculate_remediation_effort(self, issues: List[Dict]) -> str:
        """Calculate estimated remediation effort"""
        
        effort_points = 0
        for issue in issues:
            severity = issue.get('severity', 'MEDIUM')
            if severity == 'CRITICAL':
                effort_points += 8
            elif severity == 'HIGH':
                effort_points += 5
            elif severity == 'MEDIUM':
                effort_points += 3
            else:
                effort_points += 1
        
        if effort_points < 10:
            return 'LOW (1-2 days)'
        elif effort_points < 25:
            return 'MEDIUM (3-5 days)'
        elif effort_points < 50:
            return 'HIGH (1-2 weeks)'
        else:
            return 'VERY HIGH (2+ weeks)'
    
    def _generate_executive_summary(self, metrics: Dict, issues: List[Dict]) -> str:
        """Generate dynamic executive summary"""
        
        risk_level = metrics['risk_level']
        total_issues = len(issues)
        security_issues = len([i for i in issues if i.get('type') == 'security'])
        
        if risk_level == 'CRITICAL':
            summary = f"CRITICAL SECURITY RISKS DETECTED: {security_issues} security vulnerabilities found requiring immediate attention."
        elif risk_level == 'HIGH':
            summary = f"HIGH RISK: {total_issues} issues identified with significant security and quality concerns."
        elif risk_level == 'MEDIUM':
            summary = f"MODERATE RISK: {total_issues} issues found with manageable security and quality improvements needed."
        else:
            summary = f"LOW RISK: {total_issues} minor issues identified. Overall code quality is acceptable."
        
        summary += f" Overall security score: {metrics['security_score']}/100. "
        summary += f"Estimated remediation effort: {metrics['remediation_effort']}."
        
        return summary
    
    def _generate_detailed_analysis(self, issues: List[Dict], metrics: Dict) -> Dict[str, Any]:
        """Generate detailed analysis section"""
        
        # Group issues by type and severity
        issue_breakdown = {
            'by_type': {},
            'by_severity': {},
            'by_file': {}
        }
        
        for issue in issues:
            issue_type = issue.get('type', 'unknown')
            severity = issue.get('severity', 'MEDIUM')
            file_path = issue.get('file', 'unknown')
            
            # Count by type
            issue_breakdown['by_type'][issue_type] = issue_breakdown['by_type'].get(issue_type, 0) + 1
            
            # Count by severity
            issue_breakdown['by_severity'][severity] = issue_breakdown['by_severity'].get(severity, 0) + 1
            
            # Count by file
            issue_breakdown['by_file'][file_path] = issue_breakdown['by_file'].get(file_path, 0) + 1
        
        # Find most problematic files
        problematic_files = sorted(issue_breakdown['by_file'].items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            'issue_distribution': issue_breakdown,
            'most_problematic_files': problematic_files,
            'trend_analysis': self._analyze_trends(issues),
            'impact_assessment': self._assess_impact(issues, metrics)
        }
    
    def _generate_security_assessment(self, issues: List[Dict], metrics: Dict) -> Dict[str, Any]:
        """Generate security-specific assessment"""
        
        security_issues = [i for i in issues if i.get('type') == 'security']
        
        # Categorize security issues
        categories = {
            'injection': [],
            'authentication': [],
            'encryption': [],
            'configuration': [],
            'other': []
        }
        
        for issue in security_issues:
            issue_text = issue.get('issue', '').lower()
            if any(keyword in issue_text for keyword in ['injection', 'sql', 'xss', 'eval', 'exec']):
                categories['injection'].append(issue)
            elif any(keyword in issue_text for keyword in ['password', 'auth', 'credential']):
                categories['authentication'].append(issue)
            elif any(keyword in issue_text for keyword in ['ssl', 'tls', 'crypto', 'hash']):
                categories['encryption'].append(issue)
            elif any(keyword in issue_text for keyword in ['config', 'debug', 'verify']):
                categories['configuration'].append(issue)
            else:
                categories['other'].append(issue)
        
        return {
            'total_security_issues': len(security_issues),
            'security_categories': {k: len(v) for k, v in categories.items()},
            'critical_vulnerabilities': [i for i in security_issues if i.get('severity') == 'CRITICAL'],
            'security_score': metrics['security_score'],
            'compliance_status': metrics['compliance_status']
        }
    
    def _generate_quality_assessment(self, issues: List[Dict], metrics: Dict) -> Dict[str, Any]:
        """Generate quality-specific assessment"""
        
        quality_issues = [i for i in issues if i.get('type') == 'quality']
        
        # Categorize quality issues
        categories = {
            'naming': [],
            'complexity': [],
            'maintainability': [],
            'performance': [],
            'other': []
        }
        
        for issue in quality_issues:
            issue_text = issue.get('issue', '').lower()
            if any(keyword in issue_text for keyword in ['name', 'snake_case', 'pascalcase']):
                categories['naming'].append(issue)
            elif any(keyword in issue_text for keyword in ['complex', 'long', 'nested']):
                categories['complexity'].append(issue)
            elif any(keyword in issue_text for keyword in ['todo', 'fixme', 'debug']):
                categories['maintainability'].append(issue)
            elif any(keyword in issue_text for keyword in ['performance', 'inefficient', 'slow']):
                categories['performance'].append(issue)
            else:
                categories['other'].append(issue)
        
        return {
            'total_quality_issues': len(quality_issues),
            'quality_categories': {k: len(v) for k, v in categories.items()},
            'quality_score': metrics['quality_score'],
            'maintainability_index': max(0, 100 - len(quality_issues) * 5)
        }
    
    def _generate_recommendations(self, issues: List[Dict], repo_analysis: Dict) -> List[Dict[str, str]]:
        """Generate dynamic recommendations based on findings"""
        
        recommendations = []
        
        # Security recommendations
        security_issues = [i for i in issues if i.get('type') == 'security']
        if security_issues:
            critical_security = [i for i in security_issues if i.get('severity') == 'CRITICAL']
            if critical_security:
                recommendations.append({
                    'priority': 'CRITICAL',
                    'category': 'Security',
                    'title': 'Address Critical Security Vulnerabilities',
                    'description': f'Fix {len(critical_security)} critical security issues immediately before deployment.',
                    'effort': 'HIGH'
                })
        
        # Quality recommendations
        quality_issues = [i for i in issues if i.get('type') == 'quality']
        if len(quality_issues) > 5:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Code Quality',
                'title': 'Improve Code Quality Standards',
                'description': f'Address {len(quality_issues)} quality issues to improve maintainability.',
                'effort': 'MEDIUM'
            })
        
        # File naming recommendations
        filename_issues = [i for i in issues if 'filename' in i.get('issue', '').lower()]
        if filename_issues:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Infrastructure',
                'title': 'Fix File Naming Issues',
                'description': 'Rename files with spaces/accents to prevent deployment issues on Linux systems.',
                'effort': 'LOW'
            })
        
        # Language-specific recommendations
        if repo_analysis['language'] == 'python':
            naming_issues = [i for i in issues if 'snake_case' in i.get('issue', '').lower()]
            if naming_issues:
                recommendations.append({
                    'priority': 'MEDIUM',
                    'category': 'Python Standards',
                    'title': 'Follow Python Naming Conventions',
                    'description': 'Use snake_case for functions and PascalCase for classes as per PEP 8.',
                    'effort': 'LOW'
                })
        
        return recommendations
    
    def _analyze_trends(self, issues: List[Dict]) -> Dict[str, Any]:
        """Analyze issue trends"""
        return {
            'most_common_issue_type': 'quality' if len([i for i in issues if i.get('type') == 'quality']) > len([i for i in issues if i.get('type') == 'security']) else 'security',
            'severity_distribution': {
                'critical': len([i for i in issues if i.get('severity') == 'CRITICAL']),
                'high': len([i for i in issues if i.get('severity') == 'HIGH']),
                'medium': len([i for i in issues if i.get('severity') == 'MEDIUM']),
                'low': len([i for i in issues if i.get('severity') == 'LOW'])
            }
        }
    
    def _assess_impact(self, issues: List[Dict], metrics: Dict) -> Dict[str, str]:
        """Assess business impact"""
        
        risk_level = metrics['risk_level']
        
        if risk_level == 'CRITICAL':
            return {
                'business_impact': 'HIGH - Potential security breaches and system failures',
                'deployment_recommendation': 'DO NOT DEPLOY - Fix critical issues first',
                'timeline': 'Immediate action required'
            }
        elif risk_level == 'HIGH':
            return {
                'business_impact': 'MEDIUM - Quality and security concerns may affect reliability',
                'deployment_recommendation': 'DEPLOY WITH CAUTION - Plan fixes in next sprint',
                'timeline': 'Address within 1 week'
            }
        else:
            return {
                'business_impact': 'LOW - Minor improvements needed',
                'deployment_recommendation': 'SAFE TO DEPLOY - Address issues in maintenance cycle',
                'timeline': 'Address within 1 month'
            }
    
    def _get_security_template(self) -> Dict:
        return {
            'critical_patterns': ['injection', 'authentication', 'encryption'],
            'severity_weights': {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 1}
        }
    
    def _get_quality_template(self) -> Dict:
        return {
            'categories': ['naming', 'complexity', 'maintainability', 'performance'],
            'thresholds': {'excellent': 90, 'good': 70, 'fair': 50, 'poor': 0}
        }
    
    def _get_summary_template(self) -> Dict:
        return {
            'risk_levels': ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
            'compliance_standards': ['security', 'quality', 'maintainability']
        }

def generate_report_for_scan(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """Main function to generate dynamic report"""
    generator = ReportGenerator()
    return generator.generate_dynamic_report(scan_data)