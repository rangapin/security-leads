# Security Lead Scorer

Analyze prospect domains for security vulnerabilities and generate lead scores for outreach.

## Installation

```bash
pip install -e .
```

## Usage

```bash
# Scan a single domain
security-leads scan example.com

# Scan with specific checks
security-leads scan example.com --checks ssl,headers

# Output as JSON
security-leads scan example.com --format json
```

## Available Checks

- `ssl` - SSL/TLS certificate analysis
- `headers` - HTTP security headers
- `redirects` - HTTPS redirect and mixed content

## Scoring

Domains are scored 0-100 based on security issues found:
- **A (0-15)**: Good security - cold lead
- **B (16-35)**: Minor issues - warm lead
- **C (36-55)**: Multiple issues - hot lead
- **D (56-75)**: Significant problems - hot lead
- **F (76-100)**: Critical issues - on fire

## License

MIT
