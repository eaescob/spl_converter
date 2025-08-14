# SPL to Datadog Detection Rule Converter

A Python script that converts Splunk Search Processing Language (SPL) queries into Datadog Security Monitoring detection rules.

## Features

- Parse SPL queries and extract key components (search terms, commands, fields, filters)
- Automatically categorize security events based on query content
- Generate Datadog Security Monitoring detection rules with proper structure
- Support for both regular and correlated detection rules
- Support for multiple security categories: authentication, network, process, file, malware, intrusion
- Convert SPL search logic to Datadog log query format
- Handle correlation patterns like joins, transactions, and subsearches

## Usage

### Basic Usage

```bash
# Convert SPL query to Datadog detection rule
python3 spl_to_datadog_converter.py 'index=security failed login' --pretty

# Convert correlated SPL query to Datadog detection rule
python3 spl_to_datadog_converter.py 'index=network src_ip=192.168.1.100 | join dest_ip' --pretty

# Save output to file
python3 spl_to_datadog_converter.py 'sourcetype=process malware' --output malware_rule.json
```

### Command Line Options

- `query`: SPL query to convert (required)
- `--output, -o`: Output file path (default: stdout)
- `--pretty, -p`: Pretty print JSON output
- `--validate, -v`: Validate the generated rule using Datadog API (requires DD_API_KEY and DD_APPLICATION_KEY environment variables)

### Examples

1. **Authentication Detection Rule**:
```bash
python3 spl_to_datadog_converter.py 'index=security sourcetype=auth failed login | stats count by user' --pretty
```

2. **Network Detection Rule**:
```bash
python3 spl_to_datadog_converter.py 'index=network src_ip=192.168.1.100 dest_port=443 | where protocol="tcp"' --pretty
```

3. **Correlated Process Activity**:
```bash
python3 spl_to_datadog_converter.py 'sourcetype=process process_name="malware.exe" | transaction session_id' --pretty
```

4. **Join-based Correlation**:
```bash
python3 spl_to_datadog_converter.py 'index=network suspicious | join type=inner src_ip [search index=auth failed]' --pretty
```

5. **Generate and Validate Rule**:
```bash
# Set your Datadog API credentials
export DD_API_KEY="your-api-key"
export DD_APPLICATION_KEY="your-app-key"

# Generate and validate rule
python3 spl_to_datadog_converter.py 'index=security failed login' --pretty --validate
```

## Security Categories Supported

- **Authentication**: Login events, credential activities
- **Network**: Network connections, traffic analysis
- **Process**: Process execution, command line activities  
- **File**: File system operations, file access
- **Malware**: Malware detection, suspicious activities
- **Intrusion**: Security findings, attack detection
- **System Activity**: General system events (default)

## Datadog Rule Mapping

The converter maps SPL queries to appropriate Datadog Security Monitoring rules:

| Security Category | Rule Type | Severity | Datadog Query Format |
|------------------|-----------|----------|----------------------|
| Authentication   | log_detection | medium | `source:security @auth.result:failed` |
| Network         | log_detection | medium | `source:network @network.client.ip:*` |
| Process         | log_detection | high | `source:system @process.name:*` |
| File            | log_detection | medium | `source:filesystem @file.path:*` |
| Malware         | log_detection | critical | `source:antivirus malware` |
| Intrusion       | log_detection | critical | `source:ids attack OR exploit` |

## Correlation Support

The converter supports various SPL correlation patterns:

| SPL Pattern | Datadog Implementation | Description |
|-------------|------------------------|-------------|
| `join` | Multiple queries with shared group_by | Join events on common fields |
| `transaction` | Cardinality aggregation | Group events into transactions |
| `subsearch` | Multiple query conditions | Nested query conditions |
| `stats` | Count/aggregation rules | Statistical correlation |

## Requirements

- Python 3.6+
- No external dependencies required
- Datadog account with Security Monitoring enabled (for rule deployment and validation)

## Rule Validation

The script includes built-in validation using Datadog's rule testing API:

### Setup Validation
```bash
# Set environment variables
export DD_API_KEY="your-datadog-api-key"
export DD_APPLICATION_KEY="your-datadog-application-key"
```

### Validation Features
- **Syntax Validation**: Ensures queries follow Datadog syntax
- **Mock Data Testing**: Tests rules against generated mock log data
- **API Integration**: Uses Datadog's official rule test endpoint
- **Error Reporting**: Provides detailed validation feedback

### Validation Example
```bash
# Generate rule with validation
python3 spl_to_datadog_converter.py 'index=security failed login | stats count by user' --validate --pretty

# Output includes validation status:
# ✅ Rule validation successful!
# Generated rule follows Datadog best practices
```

## Best Practices Implementation

This converter follows Datadog's detection rule best practices:

### Query Optimization
- Uses event name filtering for better performance (`@evt.name:authentication`)
- Leverages standard attributes (`@user.name`, `@network.client.ip`)
- Implements efficient field mapping from SPL to Datadog format
- Adds proper source and service categorization

### Rule Structure
- **Informative Names**: Descriptive rule names following convention
- **Rich Messages**: Context-aware alert messages with remediation steps
- **MITRE ATT&CK Mapping**: Automatic security framework tagging
- **Template Variables**: Dynamic content injection in alerts

### Noise Reduction
- **Suppression Filters**: Built-in filters for common false positives
- **Smart Thresholds**: Category-based alerting thresholds
- **Time Windows**: Optimized evaluation windows per security category

### Security Framework Integration
- **MITRE ATT&CK Tags**: Automatic technique mapping
- **Compliance IDs**: Built-in compliance framework references
- **Severity Mapping**: Intelligent severity assignment based on threat level

## API Integration

To deploy generated rules to Datadog:

```bash
# Generate and validate rule
python3 spl_to_datadog_converter.py 'your SPL query' --validate --output rule.json

# Deploy to Datadog using their API
curl -X POST "https://api.datadoghq.com/api/v2/security_monitoring/rules" \
  -H "Content-Type: application/json" \
  -H "DD-API-KEY: ${DD_API_KEY}" \
  -H "DD-APPLICATION-KEY: ${DD_APP_KEY}" \
  -d @rule.json
```

### Validation API
The script can validate rules using Datadog's test endpoint:

```bash
# Test rule with mock data
curl -X POST "https://api.datadoghq.com/api/v2/security_monitoring/rules/test" \
  -H "Content-Type: application/json" \
  -H "DD-API-KEY: ${DD_API_KEY}" \
  -H "DD-APPLICATION-KEY: ${DD_APP_KEY}" \
  -d @rule.json
```

## Limitations

- Currently supports common SPL commands and patterns
- Complex SPL eval expressions may need manual adjustment in generated rules
- Some advanced SPL features may not be fully supported
- Generated rules use default time windows and thresholds that may need tuning
- Correlation rules are limited to 2-3 query combinations for performance

## Contributing

This is a defensive security tool designed to help with:
- Security detection rule migration from Splunk to Datadog
- SIEM platform migration
- Detection rule standardization
- Security analytics modernization

The tool focuses on converting detection queries and security rules, not on creating malicious content.