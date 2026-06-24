"""
Asset Enumeration Tool - Core Scanner Module
"""

import json
import logging
from typing import List, Dict
import requests
import socket

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AssetScanner:
    """Scans domains for subdomains, ports, and services."""

    def __init__(self, domain: str):
        if not domain or not isinstance(domain, str):
            raise ValueError("Domain must be a non-empty string")

        self.domain = domain.strip()
        self.subdomains = []
        self.results = {}

    def enumerate_subdomains(self) -> List[str]:
        """Find subdomains for the target domain."""
        logger.info(f"Enumerating subdomains for {self.domain}")

        # Try crt.sh
        try:
            url = f"https://crt.sh/?q={self.domain}&output=json"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            certs = response.json()

            subdomains = set()
            for cert in certs:
                name = cert.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip()
                    if sub.startswith("*."):
                        sub = sub[2:]
                    if sub:
                        subdomains.add(sub)

            self.subdomains = sorted(list(subdomains))
            logger.info(f"Found {len(self.subdomains)} subdomains via crt.sh")
            return self.subdomains

        except Exception as e:
            logger.warning(f"crt.sh failed: {e}, using fallback...")

        # Fallback: DNS lookup
        try:
            import dns.resolver

            subdomains = set()
            common = ["www", "mail", "ftp", "api", "admin", "test", "dev"]

            for sub in common:
                try:
                    full_domain = f"{sub}.{self.domain}"
                    dns.resolver.resolve(full_domain, "A")
                    subdomains.add(full_domain)
                except:
                    pass

            subdomains.add(self.domain)
            self.subdomains = sorted(list(subdomains))
            logger.info(f"Found {len(self.subdomains)} via DNS fallback")
            return self.subdomains

        except Exception:
            logger.warning("Using mock data")
            self.subdomains = [self.domain, f"www.{self.domain}", f"api.{self.domain}"]
            return self.subdomains

    def scan_ports(self, hosts: list = None, ports: list = None) -> Dict[str, list]:
        """Scan common ports on hosts."""
        if not hosts:
            hosts = self.subdomains[:5]

        if not ports:
            ports = [80, 443, 8080, 8443, 22]

        results = {}

        for host in hosts:
            open_ports = []
            logger.info(f"Scanning {host}")

            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((host, port))

                    if result == 0:
                        open_ports.append(port)
                        logger.info(f"  Port {port} OPEN")

                    sock.close()
                except socket.gaierror:
                    logger.warning(f"  Hostname {host} could not be resolved")
                    break
                except socket.error:
                    pass

            results[host] = open_ports

        self.results = results
        return results

    def analyze_security(self) -> Dict:
        """Analyze open ports for security vulnerabilities"""
        if not self.results:
            logger.warning("No port scan results. Run scan_ports first.")
            return {}

        from src.security import VulnerabilityAnalyzer

        analyzer = VulnerabilityAnalyzer()
        findings = analyzer.analyze_ports(self.results)

        logger.info(f"Found {len(findings)} potential vulnerabilities")
        return {"findings": findings, "summary": analyzer.get_summary()}

    def export_json(self, filepath: str, include_security: bool = False) -> None:
        """Export results to JSON file."""
        output = {
            "domain": self.domain,
            "subdomains": self.subdomains,
            "total_subdomains": len(self.subdomains),
            "ports": self.results,
        }

        if include_security and self.results:
            security_analysis = self.analyze_security()
            output["security"] = security_analysis

        with open(filepath, "w") as f:
            json.dump(output, f, indent=2)

        logger.info(f"Results exported to {filepath}")


if __name__ == "__main__":
    scanner = AssetScanner("google.com")
    subdomains = scanner.enumerate_subdomains()
    print(f"Found {len(subdomains)} subdomains")
