#!/usr/bin/env python
"""Entry point for asset enumeration tool"""

from src.scanner import AssetScanner

if __name__ == "__main__":
    scanner = AssetScanner("google.com")
    subdomains = scanner.enumerate_subdomains()
    print(f"\n[+] Found {len(subdomains)} subdomains")

    ports = scanner.scan_ports(hosts=["google.com"])
    print(f"\n[+] Port scan results: {ports}")

    if ports:
        security = scanner.analyze_security()
        print(f"\n[!] Security findings: {security['summary']}")

    scanner.export_json("results.json", include_security=True)
    print("\n[+] Results exported to results.json")
