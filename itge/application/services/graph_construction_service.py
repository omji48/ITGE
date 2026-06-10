"""
Graph construction service - converts normalized entities into Neo4j nodes/edges.
"""

from __future__ import annotations

from typing import Any

from ...domain.models.base import BaseEntity, BaseRelationship
from ...infrastructure.graph.neo4j_repository import GraphRepository
from ...infrastructure.normalizers.traffic_normalizer import NormalizationResult


class GraphConstructionService:
    """Orchestrates graph construction from normalization results."""

    def __init__(self, repository: GraphRepository):
        self.repository = repository
        self.stats = {
            "nodes_created": 0,
            "relationships_created": 0,
            "nodes_updated": 0,
            "relationships_updated": 0,
        }

    async def build_from_normalization_result(self, result: NormalizationResult) -> dict[str, int]:
        stats = {"nodes_created": 0, "relationships_created": 0}

        all_entities: list[BaseEntity] = []
        all_entities.extend(result.endpoints)
        all_entities.extend(result.services)
        all_entities.extend(result.data_stores)
        all_entities.extend(result.identity_providers)
        all_entities.extend(result.tokens)
        all_entities.extend(result.roles)
        all_entities.extend(result.personas)

        nodes_created = await self.repository.batch_create_nodes(all_entities)
        relationships_created = await self.repository.batch_create_relationships(result.relationships)

        stats["nodes_created"] = nodes_created
        stats["relationships_created"] = relationships_created
        self.stats["nodes_created"] += nodes_created
        self.stats["relationships_created"] += relationships_created

        return stats

    async def add_entity(self, entity: BaseEntity) -> dict[str, Any]:
        node = await self.repository.create_node(entity, merge=True)
        self.stats["nodes_created"] += 1
        return node

    async def add_relationship(self, relationship: BaseRelationship) -> dict[str, Any]:
        rel = await self.repository.create_relationship(relationship, merge=True)
        self.stats["relationships_created"] += 1
        return rel

    async def get_statistics(self) -> dict[str, Any]:
        graph_stats = await self.repository.get_statistics()
        return {"service_stats": self.stats, "graph_stats": graph_stats}

    def reset_stats(self) -> None:
        self.stats = {
            "nodes_created": 0,
            "relationships_created": 0,
            "nodes_updated": 0,
            "relationships_updated": 0,
        }
