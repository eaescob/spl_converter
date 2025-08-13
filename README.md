# SPL to OCSF Converter

A Python script that converts Splunk Search Processing Language (SPL) queries into Open Cybersecurity Schema Framework (OCSF) events or detection rules.

## Features

- Parse SPL queries and extract key components (search terms, commands, fields, filters)
- Automatically categorize security events based on query content
- Generate OCSF-compliant events with proper structure and metadata
- Create detection rules mapped to OCSF schema
- Support for multiple security categories: authentication, network, process, file, malware, intrusion
- Extract observables (IP addresses, hostnames, file paths) from queries

## Usage

### Basic Usage

```bash
# Convert SPL query to OCSF event
python3 spl_to_ocsf_converter.py 'index=security failed login' --format event --pretty

# Convert SPL query to OCSF detection rule
python3 spl_to_ocsf_converter.py 'index=network suspicious traffic' --format rule --pretty

# Save output to file
python3 spl_to_ocsf_converter.py 'sourcetype=process malware' --output malware_event.json
```

### Command Line Options

- `query`: SPL query to convert (required)
- `--format, -f`: Output format - 'event' or 'rule' (default: event)
- `--output, -o`: Output file path (default: stdout)
- `--pretty, -p`: Pretty print JSON output

### Examples

1. **Authentication Event**:
```bash
python3 spl_to_ocsf_converter.py 'index=security sourcetype=auth failed login | stats count by user' --format event --pretty
```

2. **Network Detection Rule**:
```bash
python3 spl_to_ocsf_converter.py 'index=network src_ip=192.168.1.100 dest_port=443 | where protocol="tcp"' --format rule --pretty
```

3. **Process Activity**:
```bash
python3 spl_to_ocsf_converter.py 'sourcetype=process process_name="malware.exe" | eval threat_level=if(process_name like "%malware%", "high", "low")' --format event --pretty
```

## Security Categories Supported

- **Authentication**: Login events, credential activities
- **Network**: Network connections, traffic analysis
- **Process**: Process execution, command line activities  
- **File**: File system operations, file access
- **Malware**: Malware detection, suspicious activities
- **Intrusion**: Security findings, attack detection
- **System Activity**: General system events (default)

## OCSF Mapping

The converter maps SPL queries to appropriate OCSF event classes:

| Security Category | OCSF Category UID | Example Event Classes |
|------------------|-------------------|----------------------|
| Authentication   | 3                 | Authentication (3001/3002) |
| Network         | 4                 | Network Activity (4000/4001) |
| Process         | 1                 | Process Activity (1007) |
| File            | 1                 | File System Activity (1001) |
| Malware         | 2                 | Malware Detection (2001) |
| Intrusion       | 2                 | Security Finding (2001) |

## Requirements

- Python 3.6+
- No external dependencies required

## Limitations

- Currently supports common SPL commands and patterns
- Observable extraction is pattern-based and may need refinement for complex queries
- Some advanced SPL features may not be fully supported
- Generated OCSF events use default/placeholder values for some fields that cannot be inferred from the query

## Contributing

This is a defensive security tool designed to help with:
- Security event normalization
- Detection rule development
- SIEM integration
- Security analytics

The tool focuses on converting detection queries and security events, not on creating malicious content.