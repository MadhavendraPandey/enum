# Architecture

## Overview
Asset Enumeration Tool automates subdomain discovery, port scanning, and security vulnerability analysis.

## Components

### src/scanner.py
- `AssetScanner`: Main class
  - `enumerate_subdomains()`: Discovers subdomains via crt.sh + DNS fallback
  - `scan_ports()`: Scans common ports using socket connections
  - `analyze_security()`: Identifies security vulnerabilities
  - `export_json()`: Exports results to JSON

### src/security.py
- `VulnerabilityAnalyzer`: Analyzes open ports for risks
  - Maps ports to known services
  - Assigns risk levels (CRITICAL, HIGH, MEDIUM)
  - Provides remediation recommendations

## Data Flow

Domain Input
↓
Enumerate Subdomains (crt.sh → DNS → Mock)
↓
Scan Ports (socket connections)
↓
Analyze Security (port-to-vulnerability mapping)
↓
Export JSON