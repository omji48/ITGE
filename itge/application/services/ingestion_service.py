"""
Ingestion service - orchestrates parsing and normalization across sources.

Supports HTTP traffic sources and asset-discovery sources so the graph can be
built from Burp, ZAP, Amass, and Nmap in one consistent pipeline.
"""

from __future__ import annotations

from pathlib import Path
from typing import AsyncIterator

from pydantic import BaseModel, Field

from ...domain.models import DataStore, SensitivityLevel, Service
from ...infrastructure.normalizers.traffic_normalizer import (
    NormalizationResult,
    TrafficNormalizer,
)
from ...infrastructure.parsers import (
    AmassJSONParser,
    BaseParser,
    BurpXMLParser,
    NmapXMLParser,
    ParserStats,
    ZAPXMLParser,
)


class IngestionStats(BaseModel):
    """Statistics from an ingestion operation."""

    total_transactions: int = 0
    successful_normalizations: int = 0
    failed_normalizations: int = 0

    endpoints_created: int = 0
    services_created: int = 0
    data_stores_created: int = 0
    personas_created: int = 0
    tokens_created: int = 0
    providers_created: int = 0
    roles_created: int = 0
    relationships_created: int = 0

    parser_stats: ParserStats | None = None
    errors: list[str] = Field(default_factory=list)


class IngestionService:
    """
    Orchestrates multi-source ingestion.

    Pipeline:
    1. Parse traffic or discovery export
    2. Normalize to domain entities
    3. Return graph-ready results
    """

    def __init__(self) -> None:
        self.normalizer = TrafficNormalizer()
        self.stats = IngestionStats()

    async def ingest_file(
        self,
        file_path: str | Path,
        file_type: str | None = None,
    ) -> AsyncIterator[NormalizationResult]:
        path = Path(file_path)

        if file_type in {"amass_json", "nmap_xml"}:
            async for result in self._ingest_discovery_source(path, file_type):
                yield result
            return

        parser = self._select_http_parser(path, file_type)
        if not parser:
            auto_type = self._auto_detect_specialized_parser(path)
            if auto_type:
                async for result in self._ingest_discovery_source(path, auto_type):
                    yield result
                return
            raise ValueError(f"Unsupported file format: {path}")

        async for transaction in parser.parse(path):
            self.stats.total_transactions += 1
            try:
                result = await self.normalizer.normalize(transaction)
                self._record_result_stats(result)
                yield result
            except Exception as exc:
                self.stats.failed_normalizations += 1
                self.stats.errors.append(f"Normalization failed: {exc}")

        self.stats.parser_stats = parser.get_stats()

    async def _ingest_discovery_source(
        self,
        file_path: Path,
        file_type: str,
    ) -> AsyncIterator[NormalizationResult]:
        if file_type == "amass_json":
            parser = AmassJSONParser()
            observations = parser.parse(file_path)
            for observation in observations:
                self.stats.total_transactions += 1
                result = self._normalize_amass_observation(observation)
                self._record_result_stats(result)
                yield result
            self.stats.parser_stats = ParserStats(
                total_transactions=len(observations),
                successful_parses=len(observations),
                failed_parses=0,
            )
            return

        if file_type == "nmap_xml":
            parser = NmapXMLParser()
            observations = parser.parse(file_path)
            for observation in observations:
                self.stats.total_transactions += 1
                result = self._normalize_nmap_observation(observation)
                self._record_result_stats(result)
                yield result
            self.stats.parser_stats = ParserStats(
                total_transactions=len(observations),
                successful_parses=len(observations),
                failed_parses=0,
            )
            return

        raise ValueError(f"Unsupported discovery format: {file_type}")

    def _select_http_parser(self, file_path: Path, file_type: str | None) -> BaseParser | None:
        if file_type == "burp_xml":
            return BurpXMLParser()
        if file_type == "zap_xml":
            return ZAPXMLParser()

        parsers: list[BaseParser] = [BurpXMLParser(), ZAPXMLParser()]
        for parser in parsers:
            if parser.validate_format(file_path):
                return parser
        return None

    def _auto_detect_specialized_parser(self, file_path: Path) -> str | None:
        if AmassJSONParser().validate_format(file_path):
            return "amass_json"
        if NmapXMLParser().validate_format(file_path):
            return "nmap_xml"
        return None

    def _normalize_amass_observation(self, observation: dict) -> NormalizationResult:
        result = NormalizationResult()
        host = observation["name"]
        ports = observation.get("ports") or []
        services = observation.get("services") or []

        if not ports and services:
            ports = [service.get("port") for service in services if service.get("port")]
        if not ports:
            ports = [443]

        for port in ports:
            protocol = "https" if int(port) in {443, 8443} else "http"
            service = Service(
                name=host,
                host=host,
                port=int(port),
                protocol=protocol,
                version=None,
                banner=None,
                cpe=None,
                is_public=True,
                tls_enabled=protocol == "https",
                trust_zone="external",
                source="amass",
                confidence=0.8,
                metadata={"domain": observation.get("domain"), "tag": observation.get("tag")},
            )
            result.services.append(service)

        if any(keyword in host.lower() for keyword in ["db", "cache", "redis", "storage"]):
            store_type = "database" if "db" in host.lower() else "cache"
            result.data_stores.append(
                DataStore(
                    name=f"{host}:discovered",
                    store_type=store_type,
                    host=host,
                    connection_string=f"discovered://{host}",
                    sensitivity_level=SensitivityLevel.INTERNAL,
                    data_classification=[],
                    requires_authentication=True,
                    access_control_type="unknown",
                    compliance_tags=[],
                    trust_zone="internal",
                    source="amass",
                    confidence=0.55,
                    metadata={"raw_source": "amass"},
                )
            )

        return result

    def _normalize_nmap_observation(self, observation: dict) -> NormalizationResult:
        result = NormalizationResult()
        port = int(observation["port"])
        protocol = "https" if port in {443, 8443} or observation.get("tunnel") == "ssl" else "http"
        host = (observation.get("hostnames") or [observation.get("address")])[0]
        service_name = observation.get("service_name") or f"port-{port}"

        result.services.append(
            Service(
                name=service_name,
                host=host,
                port=port,
                protocol=protocol if protocol in {"http", "https"} else observation.get("protocol", "tcp"),
                version=observation.get("version"),
                banner=observation.get("product"),
                cpe=None,
                is_public=True,
                tls_enabled=protocol == "https",
                trust_zone="external" if port in {80, 443, 8080, 8443} else "dmz",
                source="nmap",
                confidence=0.88,
                metadata={"address": observation.get("address"), "raw": observation.get("raw")},
            )
        )

        if service_name.lower() in {"mysql", "postgresql", "mongodb", "redis", "mssql"}:
            result.data_stores.append(
                DataStore(
                    name=f"{host}:{port}",
                    store_type=service_name.lower(),
                    host=host,
                    connection_string=f"{service_name.lower()}://{host}:{port}",
                    sensitivity_level=SensitivityLevel.INTERNAL,
                    data_classification=[],
                    requires_authentication=True,
                    access_control_type="network",
                    compliance_tags=[],
                    trust_zone="internal",
                    source="nmap",
                    confidence=0.9,
                    metadata={"address": observation.get("address")},
                )
            )

        return result

    def _record_result_stats(self, result: NormalizationResult) -> None:
        self.stats.successful_normalizations += 1
        self.stats.endpoints_created += len(result.endpoints)
        self.stats.services_created += len(result.services)
        self.stats.data_stores_created += len(result.data_stores)
        self.stats.personas_created += len(result.personas)
        self.stats.tokens_created += len(result.tokens)
        self.stats.providers_created += len(result.identity_providers)
        self.stats.roles_created += len(result.roles)
        self.stats.relationships_created += len(result.relationships)

    def get_stats(self) -> IngestionStats:
        return self.stats

    def reset_stats(self) -> None:
        self.stats = IngestionStats()
