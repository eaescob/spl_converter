#!/usr/bin/env python3
"""
SPL to OCSF Converter

Converts Splunk Search Processing Language (SPL) queries into 
Open Cybersecurity Schema Framework (OCSF) events or detection rules.
"""

import re
import json
import argparse
import sys
from typing import Dict, List, Any, Optional
from datetime import datetime
import uuid


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


class OCSFGenerator:
    """Generates OCSF events and detection rules."""
    
    def __init__(self):
        self.category_mapping = {
            'authentication': 3,
            'network': 4,
            'process': 1,
            'file': 1,
            'malware': 2,
            'intrusion': 2,
            'system_activity': 1
        }
        
        self.class_uid_mapping = {
            'authentication_failure': 3002,
            'authentication_success': 3001,
            'network_connection': 4001,
            'network_activity': 4000,
            'process_activity': 1007,
            'file_system_activity': 1001,
            'malware_detection': 2001,
            'security_finding': 2001,
            'system_activity': 1000
        }
    
    def generate_ocsf_event(self, spl_components: Dict[str, Any], output_format: str = 'event') -> Dict[str, Any]:
        """Generate OCSF event from parsed SPL components."""
        if output_format == 'rule':
            return self._generate_detection_rule(spl_components)
        
        event = self._create_base_event(spl_components)
        
        # Add category-specific attributes
        category = spl_components.get('security_category', 'system_activity')
        if category == 'authentication':
            event.update(self._add_authentication_attributes(spl_components))
        elif category == 'network':
            event.update(self._add_network_attributes(spl_components))
        elif category == 'process':
            event.update(self._add_process_attributes(spl_components))
        elif category == 'file':
            event.update(self._add_file_attributes(spl_components))
        
        # Add correlation attributes if present
        correlation_info = spl_components.get('correlation_info', {})
        if correlation_info.get('is_correlated'):
            event.update(self._add_correlation_attributes(correlation_info))
        
        return event
    
    def _create_base_event(self, spl_components: Dict[str, Any]) -> Dict[str, Any]:
        """Create base OCSF event structure."""
        category = spl_components.get('security_category', 'system_activity')
        event_type = spl_components.get('event_type', 'system_activity')
        
        return {
            'metadata': {
                'version': '1.0.0',
                'product': {
                    'name': 'SPL to OCSF Converter',
                    'vendor_name': 'Custom'
                },
                'uid': str(uuid.uuid4()),
                'original_time': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            },
            'category_uid': self.category_mapping.get(category, 1),
            'category_name': category.replace('_', ' ').title(),
            'class_uid': self.class_uid_mapping.get(event_type, 1000),
            'class_name': event_type.replace('_', ' ').title(),
            'activity_id': 1,
            'activity_name': 'Unknown',
            'severity_id': 1,
            'severity': 'Informational',
            'type_uid': self.class_uid_mapping.get(event_type, 1000) * 100 + 1,
            'time': int(datetime.utcnow().timestamp() * 1000),
            'message': f"Event generated from SPL query: {spl_components['original_query'][:100]}...",
            'raw_data': spl_components['original_query'],
            'observables': self._extract_observables(spl_components)
        }
    
    def _extract_observables(self, spl_components: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract observable indicators from SPL components."""
        observables = []
        
        for term in spl_components.get('search_terms', []):
            # Check if term looks like an IP address
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', term):
                observables.append({
                    'name': 'ip_address',
                    'type': 'IP Address',
                    'value': term
                })
            # Check if term looks like a domain
            elif '.' in term and len(term.split('.')) >= 2:
                observables.append({
                    'name': 'hostname',
                    'type': 'Hostname',
                    'value': term
                })
            # Check if term looks like a file path
            elif '/' in term or '\\' in term:
                observables.append({
                    'name': 'file_path',
                    'type': 'File Path',
                    'value': term
                })
        
        return observables
    
    def _add_authentication_attributes(self, spl_components: Dict[str, Any]) -> Dict[str, Any]:
        """Add authentication-specific attributes."""
        return {
            'auth_protocol': 'Unknown',
            'logon_type': 'Unknown',
            'is_mfa': False
        }
    
    def _add_network_attributes(self, spl_components: Dict[str, Any]) -> Dict[str, Any]:
        """Add network-specific attributes."""
        return {
            'connection_info': {
                'protocol_name': 'Unknown',
                'direction': 'Unknown'
            }
        }
    
    def _add_process_attributes(self, spl_components: Dict[str, Any]) -> Dict[str, Any]:
        """Add process-specific attributes."""
        return {
            'process': {
                'name': 'Unknown',
                'pid': 0,
                'command_line': ''
            }
        }
    
    def _add_file_attributes(self, spl_components: Dict[str, Any]) -> Dict[str, Any]:
        """Add file-specific attributes."""
        return {
            'file': {
                'name': 'Unknown',
                'path': '',
                'type': 'Unknown'
            }
        }
    
    def _add_correlation_attributes(self, correlation_info: Dict[str, Any]) -> Dict[str, Any]:
        """Add correlation-specific attributes to OCSF event."""
        correlation_attrs = {
            'correlation': {
                'correlation_id': correlation_info.get('correlation_id'),
                'correlation_type': correlation_info.get('correlation_type'),
                'is_correlated': correlation_info.get('is_correlated', False),
                'related_events': []
            }
        }
        
        # Add correlation-specific fields based on type
        correlation_type = correlation_info.get('correlation_type')
        
        if correlation_type == 'join':
            correlation_attrs['correlation']['join_fields'] = correlation_info.get('join_fields', [])
            correlation_attrs['correlation']['join_type'] = 'field_based'
        elif correlation_type == 'transaction':
            correlation_attrs['correlation']['transaction_fields'] = correlation_info.get('transaction_fields', [])
            correlation_attrs['correlation']['transaction_type'] = 'session_based'
        elif correlation_type == 'merge':
            correlation_attrs['correlation']['merge_type'] = 'data_union'
        elif correlation_type == 'aggregation':
            correlation_attrs['correlation']['aggregation_type'] = 'statistical'
        elif correlation_type == 'subsearch':
            correlation_attrs['correlation']['subsearch_count'] = len(correlation_info.get('subsearches', []))
        
        # Add enhanced observables for correlation tracking
        correlation_observables = []
        
        # Add join fields as observables
        for field in correlation_info.get('join_fields', []):
            correlation_observables.append({
                'name': f'join_field_{field}',
                'type': 'Correlation Field',
                'value': field,
                'reputation': {'score_id': 5}
            })
        
        # Add transaction fields as observables
        for field in correlation_info.get('transaction_fields', []):
            correlation_observables.append({
                'name': f'transaction_field_{field}',
                'type': 'Session Field',
                'value': field,
                'reputation': {'score_id': 5}
            })
        
        if correlation_observables:
            correlation_attrs['correlation_observables'] = correlation_observables
        
        # Add enrichment for correlation context
        correlation_attrs['enrichments'] = [
            {
                'name': 'spl_correlation_analysis',
                'provider': 'spl_to_ocsf_converter',
                'type': 'correlation_metadata',
                'data': {
                    'commands_used': [cmd.get('command') for cmd in correlation_info.get('correlation_commands', [])],
                    'subsearch_queries': correlation_info.get('subsearches', [])
                }
            }
        ]
        
        return correlation_attrs
    
    def _generate_detection_rule(self, spl_components: Dict[str, Any]) -> Dict[str, Any]:
        """Generate OCSF-based detection rule."""
        return {
            'rule_id': str(uuid.uuid4()),
            'name': f"Detection Rule from SPL Query",
            'description': f"Generated from SPL: {spl_components['original_query'][:200]}...",
            'severity': 'Medium',
            'category': spl_components.get('security_category', 'system_activity'),
            'query_logic': {
                'original_spl': spl_components['original_query'],
                'search_terms': spl_components['search_terms'],
                'commands': spl_components['commands'],
                'fields': spl_components['fields']
            },
            'ocsf_mapping': {
                'category_uid': self.category_mapping.get(spl_components.get('security_category'), 1),
                'class_uid': self.class_uid_mapping.get(spl_components.get('event_type'), 1000),
                'required_fields': spl_components['fields'],
                'observables': self._extract_observables(spl_components)
            },
            'created_time': datetime.utcnow().isoformat(),
            'updated_time': datetime.utcnow().isoformat(),
            'correlation_rule': self._generate_correlation_rule_metadata(spl_components)
        }
    
    def _generate_correlation_rule_metadata(self, spl_components: Dict[str, Any]) -> Dict[str, Any]:
        """Generate correlation-specific rule metadata."""
        correlation_info = spl_components.get('correlation_info', {})
        
        if not correlation_info.get('is_correlated'):
            return {'enabled': False}
        
        return {
            'enabled': True,
            'correlation_type': correlation_info.get('correlation_type'),
            'correlation_id': correlation_info.get('correlation_id'),
            'time_window': '24h',  # Default time window for correlation
            'event_threshold': 2,  # Minimum events to trigger correlation
            'correlation_fields': (
                correlation_info.get('join_fields', []) + 
                correlation_info.get('transaction_fields', [])
            ),
            'subsearch_dependencies': len(correlation_info.get('subsearches', [])),
            'complexity_score': self._calculate_correlation_complexity(correlation_info)
        }
    
    def _calculate_correlation_complexity(self, correlation_info: Dict[str, Any]) -> int:
        """Calculate complexity score for correlation rule."""
        score = 1
        
        # Add complexity based on correlation type
        correlation_type = correlation_info.get('correlation_type')
        if correlation_type == 'join':
            score += 2
        elif correlation_type == 'transaction':
            score += 3
        elif correlation_type == 'subsearch':
            score += len(correlation_info.get('subsearches', [])) * 2
        elif correlation_type == 'aggregation':
            score += 1
        
        # Add complexity for multiple correlation commands
        score += len(correlation_info.get('correlation_commands', []))
        
        return min(score, 10)  # Cap at 10


def main():
    """Main function to handle CLI interaction."""
    parser = argparse.ArgumentParser(
        description='Convert SPL queries to OCSF events or detection rules'
    )
    parser.add_argument('query', help='SPL query to convert')
    parser.add_argument(
        '--format', '-f',
        choices=['event', 'rule'],
        default='event',
        help='Output format: event or detection rule (default: event)'
    )
    parser.add_argument(
        '--output', '-o',
        help='Output file (default: stdout)'
    )
    parser.add_argument(
        '--pretty', '-p',
        action='store_true',
        help='Pretty print JSON output'
    )
    
    args = parser.parse_args()
    
    try:
        # Parse SPL query
        parser_obj = SPLParser()
        components = parser_obj.parse_query(args.query)
        
        # Generate OCSF output
        generator = OCSFGenerator()
        ocsf_output = generator.generate_ocsf_event(components, args.format)
        
        # Format output
        if args.pretty:
            json_output = json.dumps(ocsf_output, indent=2, default=str)
        else:
            json_output = json.dumps(ocsf_output, default=str)
        
        # Write output
        if args.output:
            with open(args.output, 'w') as f:
                f.write(json_output)
            print(f"Output written to {args.output}")
        else:
            print(json_output)
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()