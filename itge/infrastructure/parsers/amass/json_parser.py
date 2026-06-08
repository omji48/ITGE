"""
Amass JSON parser.

Parses Amass JSONL or JSON array output into raw asset observations that the
ingestion service can convert into graph entities.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class AmassJSONParser:
    """Parser for Amass JSON exports."""

    def validate_format(self, file_path: Path) -> bool:
        if not file_path.exists():
            return False

        try:
            content = file_path.read_text(encoding="utf-8").strip()
        except OSError:
            return False

        if not content:
            return False

        first_line = content.splitlines()[0].strip()
        return first_line.startswith("{") or first_line.startswith("[")

    def parse(self, file_path: Path) -> list[dict[str, Any]]:
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        if not self.validate_format(file_path):
            raise ValueError(f"Invalid Amass JSON format: {file_path}")

        content = file_path.read_text(encoding="utf-8").strip()
        if not content:
            return []

        observations: list[dict[str, Any]] = []

        if content.startswith("["):
            data = json.loads(content)
            if isinstance(data, list):
                iterable = data
            else:
                iterable = [data]
        else:
            iterable = [json.loads(line) for line in content.splitlines() if line.strip()]

        for record in iterable:
            name = record.get("name") or record.get("domain")
            if not name:
                continue

            addresses = record.get("addresses") or []
            ports = record.get("ports") or []
            services = record.get("services") or []

            observations.append(
                {
                    "name": str(name),
                    "domain": str(record.get("domain") or name),
                    "addresses": addresses,
                    "ports": ports,
                    "services": services,
                    "source": "amass",
                    "tag": record.get("tag"),
                    "raw": record,
                }
            )

        return observations
