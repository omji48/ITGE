"""
Nmap XML parser.

Parses Nmap XML output into raw service observations for graph enrichment.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET


class NmapXMLParser:
    """Parser for Nmap XML exports."""

    def validate_format(self, file_path: Path) -> bool:
        if not file_path.exists():
            return False

        try:
            root = ET.parse(file_path).getroot()
        except ET.ParseError:
            return False

        return root.tag == "nmaprun"

    def parse(self, file_path: Path) -> list[dict[str, Any]]:
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        if not self.validate_format(file_path):
            raise ValueError(f"Invalid Nmap XML format: {file_path}")

        root = ET.parse(file_path).getroot()
        observations: list[dict[str, Any]] = []

        for host in root.findall("host"):
            address_elem = host.find("address")
            address = address_elem.get("addr") if address_elem is not None else None

            hostnames = []
            hostnames_elem = host.find("hostnames")
            if hostnames_elem is not None:
                for hostname in hostnames_elem.findall("hostname"):
                    value = hostname.get("name")
                    if value:
                        hostnames.append(value)

            ports_elem = host.find("ports")
            if ports_elem is None:
                continue

            for port in ports_elem.findall("port"):
                state = port.find("state")
                if state is not None and state.get("state") != "open":
                    continue

                service = port.find("service")
                observations.append(
                    {
                        "address": address,
                        "hostnames": hostnames,
                        "port": int(port.get("portid", "0")),
                        "protocol": port.get("protocol", "tcp"),
                        "service_name": service.get("name") if service is not None else None,
                        "product": service.get("product") if service is not None else None,
                        "version": service.get("version") if service is not None else None,
                        "tunnel": service.get("tunnel") if service is not None else None,
                        "source": "nmap",
                        "raw": ET.tostring(port, encoding="unicode"),
                    }
                )

        return observations
