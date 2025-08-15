#!/usr/bin/env python3
"""
SPL to Datadog Detection Rule Converter

Converts Splunk Search Processing Language (SPL) queries into 
Datadog Security Monitoring detection rules.
"""

import re
import json
import argparse
import sys
import os
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
import uuid
try:
    import urllib.request
    import urllib.parse
    import urllib.error
except ImportError:
    print("Warning: urllib not available, validation feature disabled")


class SPLParser:
    """Parses SPL queries and extracts components."""
    
    def __init__(self):
        self.search_commands = {
            'search', 'where', 'eval', 'stats', 'table', 'sort', 'head', 'tail',
            'dedup', 'rename', 'fields', 'rex', 'lookup', 'join', 'append',
            'appendcols', 'union', 'map', 'foreach', 'streamstats', 'eventstats'
        }
        
        self.correlation_commands = {
            'join', 'append', 'appendcols', 'union', 'transaction', 'stats', 
            'streamstats', 'eventstats', 'correlate', 'set'
        }
        
        self.security_indicators = {
            'authentication': ['login', 'logon', 'auth', 'password', 'credential'],
            'network': ['ip', 'port', 'protocol', 'tcp', 'udp', 'http', 'https', 'dns'],
            'process': ['process', 'cmd', 'command', 'exec', 'spawn', 'pid'],
            'file': ['file', 'path', 'directory', 'write', 'read', 'delete', 'create'],
            'malware': ['malware', 'virus', 'trojan', 'backdoor', 'suspicious'],
            'intrusion': ['intrusion', 'attack', 'exploit', 'vulnerability', 'breach']
        }
    
    def parse_query(self, spl_query: str) -> Dict[str, Any]:
        """Parse SPL query and extract key components."""
        components = {
            'original_query': spl_query.strip(),
            'search_terms': [],
            'commands': [],
            'fields': [],
            'filters': [],
            'statistics': [],
            'security_category': None,
            'event_type': None,
            'correlation_info': {
                'is_correlated': False,
                'correlation_type': None,
                'correlation_commands': [],
                'subsearches': [],
                'join_fields': [],
                'transaction_fields': [],
                'correlation_id': None
            }
        }
        
        # Remove extra whitespace and normalize
        query = re.sub(r'\s+', ' ', spl_query.strip())
        
        # Extract search terms (initial search criteria)
        search_match = re.match(r'^([^|]*)', query)
        if search_match:
            search_part = search_match.group(1).strip()
            if search_part and not search_part.startswith('search'):
                components['search_terms'] = self._extract_search_terms(search_part)
        
        # Extract pipe commands
        pipe_commands = re.findall(r'\|\s*(\w+)([^|]*)', query)
        for cmd, args in pipe_commands:
            if cmd.lower() in self.search_commands:
                components['commands'].append({
                    'command': cmd.lower(),
                    'arguments': args.strip()
                })
        
        # Extract field names
        field_patterns = [
            r'\b(\w+)\s*=',  # field=value
            r'by\s+(\w+)',   # group by field
            r'fields?\s+([^|]+)',  # fields command
        ]
        for pattern in field_patterns:
            matches = re.findall(pattern, query, re.IGNORECASE)
            components['fields'].extend(matches)
        
        # Determine security category and event type
        components['security_category'] = self._determine_security_category(query)
        components['event_type'] = self._determine_event_type(query, components['security_category'])
        
        # Analyze correlation patterns
        components['correlation_info'] = self._analyze_correlation_patterns(query, components)
        
        return components
    
    def _extract_search_terms(self, search_part: str) -> List[str]:
        """Extract individual search terms from the search portion."""
        terms = []
        
        # Handle quoted terms
        quoted_terms = re.findall(r'"([^"]+)"', search_part)
        terms.extend(quoted_terms)
        
        # Remove quoted terms and extract remaining terms
        no_quotes = re.sub(r'"[^"]+"', '', search_part)
        word_terms = re.findall(r'\b\w+\b', no_quotes)
        terms.extend([term for term in word_terms if len(term) > 2])
        
        return list(set(terms))  # Remove duplicates
    
    def _determine_security_category(self, query: str) -> Optional[str]:
        """Determine the security category based on query content."""
        query_lower = query.lower()
        
        for category, indicators in self.security_indicators.items():
            if any(indicator in query_lower for indicator in indicators):
                return category
        
        return 'system_activity'  # Default category
    
    def _determine_event_type(self, query: str, category: Optional[str]) -> str:
        """Determine OCSF event type based on category and query content."""
        query_lower = query.lower()
        
        if category == 'authentication':
            if any(term in query_lower for term in ['fail', 'error', 'deny']):
                return 'authentication_failure'
            return 'authentication_success'
        elif category == 'network':
            if 'connection' in query_lower or 'connect' in query_lower:
                return 'network_connection'
            return 'network_activity'
        elif category == 'process':
            return 'process_activity'
        elif category == 'file':
            return 'file_system_activity'
        elif category == 'malware':
            return 'malware_detection'
        elif category == 'intrusion':
            return 'security_finding'
        
        return 'system_activity'
    
    def _analyze_correlation_patterns(self, query: str, components: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze SPL query for correlation patterns."""
        correlation_info = {
            'is_correlated': False,
            'correlation_type': None,
            'correlation_commands': [],
            'subsearches': [],
            'join_fields': [],
            'transaction_fields': [],
            'correlation_id': str(uuid.uuid4())
        }
        
        query_lower = query.lower()
        
        # Detect correlation commands
        for command in components.get('commands', []):
            cmd_name = command.get('command', '').lower()
            if cmd_name in self.correlation_commands:
                correlation_info['is_correlated'] = True
                correlation_info['correlation_commands'].append(command)
                
                # Determine correlation type
                if cmd_name == 'join':
                    correlation_info['correlation_type'] = 'join'
                    join_fields = self._extract_join_fields(command.get('arguments', ''))
                    correlation_info['join_fields'].extend(join_fields)
                elif cmd_name in ['append', 'appendcols', 'union']:
                    correlation_info['correlation_type'] = 'merge'
                elif cmd_name == 'transaction':
                    correlation_info['correlation_type'] = 'transaction'
                    transaction_fields = self._extract_transaction_fields(command.get('arguments', ''))
                    correlation_info['transaction_fields'].extend(transaction_fields)
                elif cmd_name in ['stats', 'streamstats', 'eventstats']:
                    correlation_info['correlation_type'] = 'aggregation'
        
        # Detect subsearches
        subsearch_pattern = r'\[\s*([^\]]+)\s*\]'
        subsearches = re.findall(subsearch_pattern, query)
        if subsearches:
            correlation_info['is_correlated'] = True
            correlation_info['subsearches'] = subsearches
            if not correlation_info['correlation_type']:
                correlation_info['correlation_type'] = 'subsearch'
        
        return correlation_info
    
    def _extract_join_fields(self, join_args: str) -> List[str]:
        """Extract join fields from join command arguments."""
        join_fields = []
        
        # Common join patterns
        patterns = [
            r'type=\w+\s+(\w+)',  # join type=inner fieldname
            r'(\w+)\s*=\s*\w+',   # fieldname=value
            r'on\s+(\w+)',        # on fieldname
            r'^(\w+)',            # first word as field
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, join_args, re.IGNORECASE)
            join_fields.extend(matches)
        
        return list(set(join_fields))
    
    def _extract_transaction_fields(self, transaction_args: str) -> List[str]:
        """Extract transaction fields from transaction command arguments."""
        transaction_fields = []
        
        # Transaction field patterns
        patterns = [
            r'(\w+)\s*=\s*',      # field=value
            r'by\s+(\w+)',        # by fieldname
            r'^(\w+)',            # first word as field
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, transaction_args, re.IGNORECASE)
            transaction_fields.extend(matches)
        
        return list(set(transaction_fields))


class DatadogAPIValidator:
    """Validates detection rules using Datadog API."""
    
    def __init__(self, api_key: str = None, app_key: str = None):
        self.api_key = api_key or os.getenv('DD_API_KEY')
        self.app_key = app_key or os.getenv('DD_APPLICATION_KEY')
        self.base_url = 'https://api.datadoghq.com/api/v2/security_monitoring'
    
    def validate_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a detection rule using Datadog's test API."""
        if not self.api_key or not self.app_key:
            return {
                'valid': False,
                'error': 'Missing API credentials. Set DD_API_KEY and DD_APPLICATION_KEY environment variables.'
            }
        
        # Prepare test payload
        test_payload = {
            'ruleQueryPayloads': self._generate_test_payloads(rule)
        }
        
        # Add the rule configuration
        test_payload.update(rule)
        
        try:
            return self._call_validation_api(test_payload)
        except Exception as e:
            return {
                'valid': False,
                'error': f'API validation failed: {str(e)}'
            }
    
    def _generate_test_payloads(self, rule: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate test payloads based on rule queries."""
        payloads = []
        
        for i, query in enumerate(rule.get('queries', [])):
            # Create mock log data for testing
            mock_logs = self._create_mock_logs(query)
            payloads.append({
                'index': i,
                'logs': mock_logs,
                'expected_result': True  # Expect the rule to trigger on mock data
            })
        
        return payloads
    
    def _create_mock_logs(self, query_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Create mock log entries for testing the query."""
        query = query_config.get('query', '')
        mock_logs = []
        
        # Generate mock log based on query content
        mock_log = {
            'timestamp': datetime.now(timezone.utc).isoformat() + 'Z',
            'message': 'Mock log entry for testing',
            'service': 'test-service',
            'source': 'security'
        }
        
        # Add fields based on query content
        if 'authentication' in query.lower() or 'auth' in query.lower():
            mock_log.update({
                '@auth.result': 'failed',
                '@user.name': 'test_user',
                '@evt.name': 'authentication'
            })
        elif 'network' in query.lower():
            mock_log.update({
                '@network.client.ip': '192.168.1.100',
                '@network.destination.port': '443',
                '@evt.name': 'network_connection'
            })
        elif 'process' in query.lower():
            mock_log.update({
                '@process.name': 'suspicious.exe',
                '@process.command_line': 'suspicious.exe --malicious',
                '@evt.name': 'process_execution'
            })
        
        mock_logs.append(mock_log)
        return mock_logs
    
    def _call_validation_api(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Call Datadog's rule validation API."""
        url = f'{self.base_url}/rules/test'
        
        # Prepare request
        data = json.dumps(payload).encode('utf-8')
        request = urllib.request.Request(url, data=data, method='POST')
        request.add_header('Content-Type', 'application/json')
        request.add_header('DD-API-KEY', self.api_key)
        request.add_header('DD-APPLICATION-KEY', self.app_key)
        
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                result = json.loads(response.read().decode('utf-8'))
                return {
                    'valid': True,
                    'result': result,
                    'status_code': response.getcode()
                }
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8')
            try:
                error_data = json.loads(error_body)
            except json.JSONDecodeError:
                error_data = {'error': error_body}
            
            return {
                'valid': False,
                'error': f'HTTP {e.code}: {error_data}',
                'status_code': e.code
            }
        except urllib.error.URLError as e:
            return {
                'valid': False,
                'error': f'Network error: {str(e)}'
            }


class DatadogDetectionRuleGenerator:
    """Generates Datadog Security Monitoring detection rules."""
    
    def __init__(self):
        self.severity_mapping = {
            'authentication': 'medium',
            'network': 'medium',
            'process': 'high',
            'file': 'medium',
            'malware': 'critical',
            'intrusion': 'critical',
            'system_activity': 'low'
        }
        
        self.rule_type_mapping = {
            'authentication': 'log_detection',
            'network': 'log_detection',
            'process': 'log_detection',
            'file': 'log_detection',
            'malware': 'log_detection',
            'intrusion': 'log_detection',
            'system_activity': 'log_detection'
        }
        
        self.datadog_log_source_mapping = {
            'authentication': ['auth', 'authentication', 'login'],
            'network': ['network', 'firewall', 'proxy'],
            'process': ['process', 'system', 'endpoint'],
            'file': ['filesystem', 'file', 'storage'],
            'malware': ['antivirus', 'endpoint', 'security'],
            'intrusion': ['ids', 'ips', 'security', 'network'],
            'system_activity': ['system', 'os']
        }
    
    def generate_detection_rule(self, spl_components: Dict[str, Any]) -> Dict[str, Any]:
        """Generate Datadog detection rule from parsed SPL components."""
        correlation_info = spl_components.get('correlation_info', {})
        
        if correlation_info.get('is_correlated'):
            return self._generate_correlated_rule(spl_components)
        else:
            return self._generate_regular_rule(spl_components)
    
    def _generate_regular_rule(self, spl_components: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a regular (non-correlated) Datadog detection rule."""
        category = spl_components.get('security_category', 'system_activity')
        rule_name = self._generate_rule_name(spl_components)
        
        return {
            'name': rule_name,
            'message': self._generate_rule_message(spl_components),
            'tags': self._generate_rule_tags(spl_components),
            'queries': [{
                'name': f'Query for {category}',
                'query': self._convert_spl_to_datadog_query(spl_components),
                'aggregation': {
                    'type': 'count',
                    'group_by_fields': self._extract_group_by_fields(spl_components),
                    'metric': 'logs'
                },
                'distinct_fields': [],
                'metric': 'logs'
            }],
            'filters': self._generate_suppression_filters(spl_components),
            'options': {
                'evaluation_window': self._get_evaluation_window(category),
                'keep_alive': 3600,
                'max_signal_duration': 7200,
                'decrease_criticality_based_on_env': False
            },
            'cases': [{
                'name': self._generate_case_name(category),
                'status': self.severity_mapping.get(category, 'medium'),
                'condition': self._generate_rule_condition(spl_components),
                'notifications': self._generate_default_notifications()
            }],
            'enabled': True,
            'creation_date': int(datetime.now(timezone.utc).timestamp() * 1000),
            'creator': {
                'name': 'SPL to Datadog Converter',
                'handle': 'spl-converter@local'
            },
            'type': self.rule_type_mapping.get(category, 'log_detection'),
            'is_default': False,
            'has_extended_title': True,
            'compliance_rule_id': self._generate_compliance_id(category)
        }
    
    def _convert_spl_to_datadog_query(self, spl_components: Dict[str, Any]) -> str:
        """Convert SPL query to optimized Datadog log query following best practices."""
        query_parts = []
        original_query = spl_components.get('original_query', '')
        category = spl_components.get('security_category', 'system_activity')
        
        # Add event name filtering for better performance
        event_name_mapping = {
            'authentication': '@evt.name:(authentication OR logon OR login)',
            'network': '@evt.name:(network_connection OR network_activity)',
            'process': '@evt.name:(process_execution OR process_creation)',
            'file': '@evt.name:(file_access OR file_creation OR file_modification)',
            'malware': '@evt.name:(malware_detection OR threat_detected)',
            'intrusion': '@evt.name:(security_detection OR intrusion_detected)'
        }
        
        if category in event_name_mapping:
            query_parts.append(event_name_mapping[category])
        
        # Convert index to source (more specific)
        index_match = re.search(r'index=([\w\-]+)', original_query)
        if index_match:
            index_name = index_match.group(1)
            # Map common Splunk indexes to Datadog sources
            source_mapping = {
                'security': 'security',
                'network': 'network',
                'windows': 'windows',
                'linux': 'linux',
                'auth': 'authentication',
                'firewall': 'firewall',
                'proxy': 'proxy'
            }
            source = source_mapping.get(index_name, index_name)
            query_parts.append(f'source:{source}')
        
        # Convert sourcetype to service with better mapping
        sourcetype_match = re.search(r'sourcetype=([\w\-:]+)', original_query)
        if sourcetype_match:
            sourcetype_name = sourcetype_match.group(1)
            query_parts.append(f'service:{sourcetype_name}')
        
        # Convert key-value pairs with proper attribute mapping
        kv_patterns = [
            (r'src_ip=([\d\.]+)', '@network.client.ip:{}'),
            (r'dest_ip=([\d\.]+)', '@network.destination.ip:{}'),
            (r'user(?:name)?=([\w\-\.]+)', '@user.name:{}'),
            (r'process(?:_name)?=([\w\-\.]+)', '@process.name:{}'),
            (r'file(?:_path|_name)?=([\w\-\./\\]+)', '@file.path:{}'),
            (r'src_port=(\d+)', '@network.client.port:{}'),
            (r'dest_port=(\d+)', '@network.destination.port:{}'),
            (r'protocol=(\w+)', '@network.protocol:{}'),
            (r'action=(\w+)', '@evt.outcome:{}'),
            (r'status=(\w+)', '@evt.outcome:{}')
        ]
        
        for pattern, template in kv_patterns:
            matches = re.findall(pattern, original_query, re.IGNORECASE)
            for match in matches:
                query_parts.append(template.format(match))
        
        # Convert search terms with better filtering
        for term in spl_components.get('search_terms', []):
            if term not in ['index', 'sourcetype', 'search'] and len(term) > 2:
                # Check if it's a common security term
                security_terms = {
                    'failed': '@evt.outcome:failure',
                    'success': '@evt.outcome:success',
                    'error': '@error.message:*',
                    'deny': '@evt.outcome:deny',
                    'allow': '@evt.outcome:allow',
                    'blocked': '@evt.outcome:block',
                    'malware': 'malware',
                    'virus': 'virus',
                    'suspicious': 'suspicious',
                    'attack': 'attack',
                    'breach': 'breach'
                }
                
                if term.lower() in security_terms:
                    query_parts.append(security_terms[term.lower()])
                elif ' ' in term:
                    query_parts.append(f'"{term}"')
                else:
                    query_parts.append(term)
        
        # Ensure we have at least one query component
        if not query_parts:
            if category in event_name_mapping:
                return event_name_mapping[category]
            else:
                return 'source:security'
        
        return ' AND '.join(query_parts)
    
    def _generate_rule_name(self, spl_components: Dict[str, Any]) -> str:
        """Generate a descriptive name for the detection rule following best practices."""
        category = spl_components.get('security_category', 'system_activity')
        search_terms = spl_components.get('search_terms', [])
        correlation_info = spl_components.get('correlation_info', {})
        
        # Follow Datadog naming convention: [Category] - [Action/Behavior]
        base_name = category.replace('_', ' ').title()
        
        if search_terms:
            # Use most relevant search term
            relevant_terms = [term for term in search_terms if len(term) > 3 and term not in ['index', 'search', 'sourcetype']]
            if relevant_terms:
                behavior = relevant_terms[0]
                if correlation_info.get('is_correlated'):
                    return f"{base_name} - Multiple {behavior} Events"
                else:
                    return f"{base_name} - {behavior.title()} Activity"
        
        # Default naming based on category
        if correlation_info.get('is_correlated'):
            correlation_type = correlation_info.get('correlation_type', 'correlated')
            return f"{base_name} - {correlation_type.title()} Pattern Detected"
        else:
            return f"{base_name} - Suspicious Activity Detected"
    
    def _generate_rule_message(self, spl_components: Dict[str, Any]) -> str:
        """Generate alert message following Datadog best practices."""
        category = spl_components.get('security_category', 'system_activity')
        correlation_info = spl_components.get('correlation_info', {})
        
        # Create informative message with context
        base_message = f"## Detection Goal\n{category.replace('_', ' ').title()} activity has been detected"
        
        if correlation_info.get('is_correlated'):
            correlation_type = correlation_info.get('correlation_type')
            base_message += f" using {correlation_type} correlation analysis"
        
        base_message += ".\n\n## Attack Detection\nThis rule monitors for:"
        
        search_terms = spl_components.get('search_terms', [])
        if search_terms:
            base_message += "\n" + "\n".join([f"- {term}" for term in search_terms[:3]])
        
        base_message += "\n\n## Next Steps\n1. Investigate the source and context of the activity\n2. Check for related events in the same timeframe\n3. Verify if this is expected behavior\n4. Take appropriate containment actions if confirmed malicious"
        
        # Add template variables for dynamic content
        base_message += "\n\n**Triggered by:** {{@user.name}} from {{@network.client.ip}}"
        
        return base_message
    
    def _generate_rule_tags(self, spl_components: Dict[str, Any]) -> List[str]:
        """Generate comprehensive tags following Datadog best practices."""
        tags = ['spl-converted', 'detection-rule']
        category = spl_components.get('security_category', 'system_activity')
        
        # Add category and security framework tags
        tags.append(f'security-rule-type:{category}')
        
        # Add MITRE ATT&CK mapping based on category
        mitre_mapping = {
            'authentication': ['mitre-attack:credential-access', 'mitre-attack:t1110'],
            'network': ['mitre-attack:command-and-control', 'mitre-attack:t1071'],
            'process': ['mitre-attack:execution', 'mitre-attack:t1059'],
            'file': ['mitre-attack:persistence', 'mitre-attack:t1105'],
            'malware': ['mitre-attack:malware', 'mitre-attack:t1204'],
            'intrusion': ['mitre-attack:initial-access', 'mitre-attack:t1190']
        }
        
        if category in mitre_mapping:
            tags.extend(mitre_mapping[category])
        
        # Add correlation tags
        correlation_info = spl_components.get('correlation_info', {})
        if correlation_info.get('is_correlated'):
            tags.append('correlation-enabled')
            correlation_type = correlation_info.get('correlation_type')
            if correlation_type:
                tags.append(f'correlation-type:{correlation_type}')
        
        # Add severity tags
        severity = self.severity_mapping.get(category, 'medium')
        tags.append(f'severity:{severity}')
        
        return tags
    
    def _extract_group_by_fields(self, spl_components: Dict[str, Any]) -> List[str]:
        """Extract group by fields from SPL commands."""
        group_by_fields = []
        
        for command in spl_components.get('commands', []):
            if command.get('command') == 'stats':
                # Extract 'by' clause from stats command
                args = command.get('arguments', '')
                by_match = re.search(r'by\s+([^|]+)', args)
                if by_match:
                    by_fields = by_match.group(1).strip().split(',')
                    group_by_fields.extend([f.strip() for f in by_fields])
        
        return [f'@{field}' for field in group_by_fields if field]
    
    def _generate_rule_condition(self, spl_components: Dict[str, Any]) -> str:
        """Generate optimized rule condition based on security category."""
        category = spl_components.get('security_category', 'system_activity')
        correlation_info = spl_components.get('correlation_info', {})
        
        # Set thresholds based on security category and best practices
        if correlation_info.get('is_correlated'):
            correlation_type = correlation_info.get('correlation_type')
            if correlation_type == 'join':
                return 'a > 0 && b > 0'  # Both queries must have results
            elif correlation_type in ['transaction', 'aggregation']:
                return 'a > 1'  # Multiple events in transaction
            else:
                return 'a > 0'
        else:
            # Threshold based on category criticality
            category_thresholds = {
                'malware': 'a > 0',      # Any malware detection is critical
                'intrusion': 'a > 0',    # Any intrusion attempt is critical
                'authentication': 'a > 2', # Multiple failed attempts
                'network': 'a > 4',      # Multiple network events
                'process': 'a > 0',      # Any suspicious process
                'file': 'a > 0'          # Any suspicious file activity
            }
            
            return category_thresholds.get(category, 'a > 0')
    
    def _generate_correlated_rule(self, spl_components: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a correlated Datadog detection rule."""
        category = spl_components.get('security_category', 'system_activity')
        correlation_info = spl_components.get('correlation_info', {})
        correlation_type = correlation_info.get('correlation_type')
        rule_name = self._generate_rule_name(spl_components)
        
        # Base rule structure
        rule = {
            'name': rule_name,
            'message': self._generate_rule_message(spl_components),
            'tags': self._generate_rule_tags(spl_components),
            'queries': [],
            'filters': self._generate_suppression_filters(spl_components),
            'options': {
                'evaluation_window': self._get_evaluation_window(category, correlation_type),
                'keep_alive': 7200,
                'max_signal_duration': 14400,
                'decrease_criticality_based_on_env': False
            },
            'cases': [{
                'name': self._generate_case_name(category, correlation_type),
                'status': self.severity_mapping.get(category, 'medium'),
                'condition': '',
                'notifications': self._generate_default_notifications()
            }],
            'enabled': True,
            'creation_date': int(datetime.now(timezone.utc).timestamp() * 1000),
            'creator': {
                'name': 'SPL to Datadog Converter',
                'handle': 'spl-converter@local'
            },
            'type': 'signal_correlation',
            'is_default': False,
            'has_extended_title': True
        }
        
        if correlation_type == 'join':
            rule['queries'] = self._generate_join_queries(spl_components)
            rule['cases'][0]['condition'] = 'a > 0 && b > 0'
        elif correlation_type == 'transaction':
            rule['queries'] = self._generate_transaction_queries(spl_components)
            rule['cases'][0]['condition'] = 'a > 0'
        elif correlation_type == 'subsearch':
            rule['queries'] = self._generate_subsearch_queries(spl_components)
            rule['cases'][0]['condition'] = 'a > 0'
        else:
            # Default aggregation-based correlation
            rule['queries'] = [{
                'query': self._convert_spl_to_datadog_query(spl_components),
                'aggregation': {
                    'type': 'count',
                    'group_by_fields': self._extract_group_by_fields(spl_components)
                },
                'distinct_fields': [],
                'metric': 'logs'
            }]
            rule['cases'][0]['condition'] = 'a > 1'  # Multiple events
        
        return rule
    
    def _generate_join_queries(self, spl_components: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate multiple queries for join-based correlation."""
        queries = []
        
        # Primary query
        queries.append({
            'query': self._convert_spl_to_datadog_query(spl_components),
            'aggregation': {
                'type': 'count',
                'group_by_fields': self._extract_correlation_fields(spl_components)
            },
            'distinct_fields': [],
            'metric': 'logs'
        })
        
        # Secondary query for join correlation
        queries.append({
            'query': self._generate_join_secondary_query(spl_components),
            'aggregation': {
                'type': 'count',
                'group_by_fields': self._extract_correlation_fields(spl_components)
            },
            'distinct_fields': [],
            'metric': 'logs'
        })
        
        return queries
    
    def _generate_transaction_queries(self, spl_components: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate queries for transaction-based correlation."""
        return [{
            'query': self._convert_spl_to_datadog_query(spl_components),
            'aggregation': {
                'type': 'cardinality',
                'group_by_fields': self._extract_transaction_fields(spl_components),
                'metric': 'transaction_id'
            },
            'distinct_fields': self._extract_transaction_fields(spl_components),
            'metric': 'logs'
        }]
    
    def _generate_subsearch_queries(self, spl_components: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate queries for subsearch-based correlation."""
        correlation_info = spl_components.get('correlation_info', {})
        subsearches = correlation_info.get('subsearches', [])
        
        queries = [{
            'query': self._convert_spl_to_datadog_query(spl_components),
            'aggregation': {
                'type': 'count',
                'group_by_fields': ['@source_ip', '@dest_ip']
            },
            'distinct_fields': [],
            'metric': 'logs'
        }]
        
        # Add queries for each subsearch
        for subsearch in subsearches[:2]:  # Limit to 2 subsearches
            queries.append({
                'query': subsearch.strip(),
                'aggregation': {
                    'type': 'count',
                    'group_by_fields': ['@source_ip', '@dest_ip']
                },
                'distinct_fields': [],
                'metric': 'logs'
            })
        
        return queries
    
    def _generate_join_secondary_query(self, spl_components: Dict[str, Any]) -> str:
        """Generate secondary query for join operations."""
        # Simplified secondary query based on original
        base_query = self._convert_spl_to_datadog_query(spl_components)
        return base_query  # In real implementation, this would be more sophisticated
    
    def _extract_correlation_fields(self, spl_components: Dict[str, Any]) -> List[str]:
        """Extract fields used for correlation."""
        correlation_info = spl_components.get('correlation_info', {})
        join_fields = correlation_info.get('join_fields', [])
        return [f'@{field}' for field in join_fields if field]
    
    def _extract_transaction_fields(self, spl_components: Dict[str, Any]) -> List[str]:
        """Extract fields used for transaction grouping."""
        correlation_info = spl_components.get('correlation_info', {})
        transaction_fields = correlation_info.get('transaction_fields', [])
        return [f'@{field}' for field in transaction_fields if field]
    
    def _generate_suppression_filters(self, spl_components: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate suppression filters to reduce false positives."""
        category = spl_components.get('security_category', 'system_activity')
        filters = []
        
        # Common suppression patterns based on category
        if category == 'authentication':
            filters.append({
                'query': '@user.name:(service-account* OR system OR root)'
            })
        elif category == 'network':
            filters.append({
                'query': '@network.client.ip:(10.0.0.0/8 OR 192.168.0.0/16 OR 172.16.0.0/12) AND @network.destination.port:53'
            })
        elif category == 'process':
            filters.append({
                'query': '@process.name:(svchost.exe OR explorer.exe OR chrome.exe OR firefox.exe)'
            })
        
        return filters
    
    def _get_evaluation_window(self, category: str, correlation_type: str = None) -> int:
        """Get optimal evaluation window based on category and correlation type."""
        if correlation_type:
            # Longer windows for correlation
            return 1800  # 30 minutes
        
        category_windows = {
            'malware': 300,        # 5 minutes - immediate response needed
            'intrusion': 600,      # 10 minutes - quick detection
            'authentication': 900,  # 15 minutes - account for retry patterns
            'network': 1200,       # 20 minutes - network patterns take time
            'process': 600,        # 10 minutes - process analysis
            'file': 900           # 15 minutes - file operation patterns
        }
        
        return category_windows.get(category, 900)
    
    def _generate_case_name(self, category: str, correlation_type: str = None) -> str:
        """Generate descriptive case names."""
        if correlation_type:
            return f"{category.title()} {correlation_type} Pattern"
        else:
            severity_levels = {
                'malware': 'Critical Threat',
                'intrusion': 'Security Incident',
                'authentication': 'Access Anomaly',
                'network': 'Network Anomaly',
                'process': 'Process Anomaly',
                'file': 'File System Anomaly'
            }
            return severity_levels.get(category, 'Security Event')
    
    def _generate_default_notifications(self) -> List[str]:
        """Generate default notification targets."""
        # Return empty list - users should configure their own notifications
        return []
    
    def _generate_compliance_id(self, category: str) -> str:
        """Generate compliance rule ID for frameworks like PCI DSS, SOX, etc."""
        compliance_mapping = {
            'authentication': 'AUTH_001',
            'network': 'NET_001',
            'process': 'PROC_001',
            'file': 'FILE_001',
            'malware': 'MAL_001',
            'intrusion': 'INT_001'
        }
        return compliance_mapping.get(category, 'GEN_001')
    
    


def main():
    """Main function to handle CLI interaction."""
    parser = argparse.ArgumentParser(
        description='Convert SPL queries to Datadog Security Monitoring detection rules'
    )
    parser.add_argument('query', help='SPL query to convert')
    parser.add_argument(
        '--output', '-o',
        help='Output file (default: stdout)'
    )
    parser.add_argument(
        '--pretty', '-p',
        action='store_true',
        help='Pretty print JSON output'
    )
    parser.add_argument(
        '--validate', '-v',
        action='store_true',
        help='Validate the generated rule using Datadog API (requires DD_API_KEY and DD_APPLICATION_KEY)'
    )
    
    args = parser.parse_args()
    
    try:
        # Parse SPL query
        parser_obj = SPLParser()
        components = parser_obj.parse_query(args.query)
        
        # Generate Datadog detection rule
        generator = DatadogDetectionRuleGenerator()
        datadog_output = generator.generate_detection_rule(components)
        
        # Validate rule if requested
        if args.validate:
            print("Validating rule with Datadog API...")
            validator = DatadogAPIValidator()
            validation_result = validator.validate_rule(datadog_output)
            
            if validation_result.get('valid'):
                print("✅ Rule validation successful!")
                if 'result' in validation_result:
                    print(f"Validation details: {json.dumps(validation_result['result'], indent=2)}")
            else:
                print(f"❌ Rule validation failed: {validation_result.get('error')}")
                if not args.output:  # Still output the rule even if validation fails
                    print("\nGenerated rule (despite validation failure):")
        
        # Format output
        if args.pretty:
            json_output = json.dumps(datadog_output, indent=2, default=str)
        else:
            json_output = json.dumps(datadog_output, default=str)
        
        # Write output
        if args.output:
            with open(args.output, 'w') as f:
                f.write(json_output)
            print(f"Rule written to {args.output}")
        else:
            print(json_output)
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.validate:
            print("Note: Validation requires DD_API_KEY and DD_APPLICATION_KEY environment variables", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()