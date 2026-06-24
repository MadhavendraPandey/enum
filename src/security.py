"""
Security vulnerability analyzer
"""

import logging
from typing import List, Dict

logger = logging.getLogger(__name__)


class VulnerabilityAnalyzer:
    """Analyzes security vulnerabilities based on port/service data"""

    # Known dangerous port-service mappings
    DANGEROUS_SERVICES = {
        22: {"name": "SSH", "risk": "HIGH", "note": "SSH exposed, brute force risk"},
        3306: {
            "name": "MySQL",
            "risk": "CRITICAL",
            "note": "Database exposed to internet",
        },
        5432: {
            "name": "PostgreSQL",
            "risk": "CRITICAL",
            "note": "Database exposed to internet",
        },
        3389: {"name": "RDP", "risk": "HIGH", "note": "Remote desktop exposed"},
        27017: {
            "name": "MongoDB",
            "risk": "CRITICAL",
            "note": "NoSQL DB exposed, data theft risk",
        },
        6379: {
            "name": "Redis",
            "risk": "CRITICAL",
            "note": "Cache DB exposed, data theft risk",
        },
        9200: {
            "name": "Elasticsearch",
            "risk": "CRITICAL",
            "note": "Search engine exposed",
        },
        80: {"name": "HTTP", "risk": "MEDIUM", "note": "Unencrypted web traffic"},
    }

    def __init__(self):
        self.findings = []

    def analyze_ports(self, port_results: Dict[str, list]) -> List[Dict]:
        """
        Analyze open ports for vulnerabilities.

        Args:
            port_results: Dict of {host: [open_ports]}

        Returns:
            List of vulnerability findings
        """
        findings = []

        for host, ports in port_results.items():
            logger.info(f"Analyzing {host}")

            for port in ports:
                if port in self.DANGEROUS_SERVICES:
                    service = self.DANGEROUS_SERVICES[port]

                    finding = {
                        "host": host,
                        "port": port,
                        "service": service["name"],
                        "risk": service["risk"],
                        "description": service["note"],
                        "recommendation": self._get_recommendation(port),
                    }

                    findings.append(finding)
                    logger.warning(
                        f"  [{service['risk']}] Port {port} ({service['name']}): {service['note']}"
                    )

        self.findings = findings
        return findings

    def _get_recommendation(self, port: int) -> str:
        """Get remediation recommendation for a port"""
        recommendations = {
            22: "Restrict SSH to specific IPs, use key-based auth, change default port",
            3306: "Move database behind firewall, use private networks, enable auth",
            5432: "Move database behind firewall, restrict access to app servers only",
            3389: "Disable RDP exposure, use VPN for remote access",
            27017: "Enable authentication, move behind firewall, use IP whitelisting",
            6379: "Use password auth, move behind firewall, restrict access",
            9200: "Add authentication, move behind firewall, disable public access",
            80: "Enforce HTTPS (port 443), redirect HTTP to HTTPS",
        }
        return recommendations.get(
            port, "Investigate open port, determine if necessary"
        )

    def get_summary(self) -> Dict:
        """Get summary of findings"""
        if not self.findings:
            return {"total": 0, "critical": 0, "high": 0, "medium": 0}

        summary = {
            "total": len(self.findings),
            "critical": len([f for f in self.findings if f["risk"] == "CRITICAL"]),
            "high": len([f for f in self.findings if f["risk"] == "HIGH"]),
            "medium": len([f for f in self.findings if f["risk"] == "MEDIUM"]),
        }

        return summary
