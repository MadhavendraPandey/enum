# Example Usage

## Basic scan
```bash
python run.py
```

Output:
## JSON output
See `results.json`:
```json
{
  "domain": "google.com",
  "subdomains": ["www.google.com", "api.google.com", ...],
  "total_subdomains": 318,
  "ports": {
    "google.com": [80, 443]
  },
  "security": {
    "findings": [
      {
        "host": "google.com",
        "port": 80,
        "service": "HTTP",
        "risk": "MEDIUM",
        "description": "Unencrypted web traffic",
        "recommendation": "Enforce HTTPS (port 443), redirect HTTP to HTTPS"
      }
    ],
    "summary": {"total": 1, "critical": 0, "high": 0, "medium": 1}
  }
}
```

## Docker
```bash
docker run asset-enum:latest
```

## Custom domain
Edit `run.py` to change domain, or:
```python
from src.scanner import AssetScanner
scanner = AssetScanner("your-domain.com")
subdomains = scanner.enumerate_subdomains()
ports = scanner.scan_ports(hosts=subdomains[:10])
security = scanner.analyze_security()
```
