"""
Neo4j Graph Repository - manages graph database operations.

Handles node/edge creation, updates, and queries with deduplication.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID
import json

from neo4j import AsyncGraphDatabase, AsyncDriver, AsyncSession

from ...domain.models.base import BaseEntity, BaseRelationship
from ...domain.models.asset import Endpoint, Service, DataStore
from ...domain.models.identity import IdentityProvider, Token, Role, UserPersona
from ...domain.models.relationships import (
    IssuesToken, ValidatesToken, Trusts, Forwards,
    Accesses, EscalatesTo, RequiresRole, CrossesBoundary
)


class GraphRepository:
    """
    Neo4j graph repository for ITGE.
    
    Manages:
    - Schema constraints and indexes
    - Node creation with deduplication
    - Relationship creation
    - Incremental updates
    - Performance optimization
    """
    
    # Node label mapping
    NODE_LABELS = {
        Endpoint: "Endpoint",
        Service: "Service",
        DataStore: "DataStore",
        IdentityProvider: "IdentityProvider",
        Token: "Token",
        Role: "Role",
        UserPersona: "UserPersona"
    }
    
    # Relationship type mapping
    RELATIONSHIP_TYPES = {
        IssuesToken: "ISSUES_TOKEN",
        ValidatesToken: "VALIDATES_TOKEN",
        Trusts: "TRUSTS",
        Forwards: "FORWARDS",
        Accesses: "ACCESSES",
        EscalatesTo: "ESCALATES_TO",
        RequiresRole: "REQUIRES_ROLE",
        CrossesBoundary: "CROSSES_BOUNDARY"
    }
    
    def __init__(self, uri: str, user: str, password: str):
        """
        Initialize graph repository.
        
        Args:
            uri: Neo4j connection URI (e.g., "bolt://localhost:7687")
            user: Database username
            password: Database password
        """
        self.driver: AsyncDriver = AsyncGraphDatabase.driver(uri, auth=(user, password))

    async def verify_connection(self) -> bool:
        """Verify database connectivity and authentication."""
        await self.driver.verify_connectivity()
        return True
    
    async def close(self):
        """Close database connection"""
        await self.driver.close()
    
    async def initialize_schema(self):
        """
        Initialize database schema with constraints and indexes.
        
        Creates:
        - Unique constraints on node IDs
        - Indexes on high-value properties
        - Full-text search indexes
        """
        async with self.driver.session() as session:
            # Create unique constraints on ID for all node types
            for entity_class, label in self.NODE_LABELS.items():
                await session.run(
                    f"CREATE CONSTRAINT {label.lower()}_id_unique IF NOT EXISTS "
                    f"FOR (n:{label}) REQUIRE n.id IS UNIQUE"
                )
            
            # Create indexes on frequently queried properties
            
            # Endpoint indexes
            await session.run(
                "CREATE INDEX endpoint_url IF NOT EXISTS "
                "FOR (e:Endpoint) ON (e.url)"
            )
            await session.run(
                "CREATE INDEX endpoint_trust_zone IF NOT EXISTS "
                "FOR (e:Endpoint) ON (e.trust_zone)"
            )
            await session.run(
                "CREATE INDEX endpoint_sensitive_data IF NOT EXISTS "
                "FOR (e:Endpoint) ON (e.sensitive_data)"
            )
            
            # DataStore indexes
            await session.run(
                "CREATE INDEX datastore_sensitivity IF NOT EXISTS "
                "FOR (d:DataStore) ON (d.sensitivity_level)"
            )
            
            # Token indexes
            await session.run(
                "CREATE INDEX token_issuer IF NOT EXISTS "
                "FOR (t:Token) ON (t.issuer)"
            )
            
            # Role indexes
            await session.run(
                "CREATE INDEX role_privilege IF NOT EXISTS "
                "FOR (r:Role) ON (r.privilege_level)"
            )
            
            # IdentityProvider indexes
            await session.run(
                "CREATE INDEX provider_type IF NOT EXISTS "
                "FOR (ip:IdentityProvider) ON (ip.provider_type)"
            )
            
            # Full-text search indexes
            await session.run(
                "CREATE FULLTEXT INDEX endpoint_search IF NOT EXISTS "
                "FOR (e:Endpoint) ON EACH [e.url, e.path]"
            )
    
    async def create_node(
        self,
        entity: BaseEntity,
        merge: bool = True
    ) -> dict[str, Any]:
        """
        Create or update a node in the graph.
        
        Args:
            entity: Entity to create as node
            merge: If True, use MERGE (upsert), else CREATE
        
        Returns:
            Created/updated node properties
        """
        label = self.NODE_LABELS.get(type(entity))
        if not label:
            raise ValueError(f"Unknown entity type: {type(entity)}")
        
        # Convert entity to dict, then sanitize nested structures for Neo4j.
        properties = entity.model_dump(
            exclude={'metadata'},
            exclude_none=True,
            mode='json'
        )
        
        # Add metadata as separate properties with prefix
        if entity.metadata:
            for key, value in entity.metadata.items():
                # Flatten metadata into properties
                if isinstance(value, (str, int, float, bool)):
                    properties[f"meta_{key}"] = value
        
        properties = self._sanitize_properties(properties)
        
        async with self.driver.session() as session:
            operation = "MERGE" if merge else "CREATE"
            
            query = f"""
            {operation} (n:{label} {{id: $id}})
            SET n += $properties
            RETURN n
            """
            
            result = await session.run(
                query,
                id=properties['id'],
                properties=properties
            )
            
            record = await result.single()
            return dict(record['n']) if record else {}
    
    async def create_relationship(
        self,
        relationship: BaseRelationship,
        merge: bool = True
    ) -> dict[str, Any]:
        """
        Create or update a relationship in the graph.
        
        Args:
            relationship: Relationship to create
            merge: If True, use MERGE (upsert), else CREATE
        
        Returns:
            Created/updated relationship properties
        """
        rel_type = self.RELATIONSHIP_TYPES.get(type(relationship))
        if not rel_type:
            raise ValueError(f"Unknown relationship type: {type(relationship)}")
        
        # Convert relationship to dict
        properties = relationship.model_dump(
            exclude={'source_id', 'target_id', 'metadata'},
            exclude_none=True,
            mode='json'
        )
        
        # Add metadata
        if relationship.metadata:
            for key, value in relationship.metadata.items():
                if isinstance(value, (str, int, float, bool)):
                    properties[f"meta_{key}"] = value
        
        properties = self._sanitize_properties(properties)
        
        async with self.driver.session() as session:
            operation = "MERGE" if merge else "CREATE"
            
            query = f"""
            MATCH (source {{id: $source_id}})
            MATCH (target {{id: $target_id}})
            {operation} (source)-[r:{rel_type}]->(target)
            SET r += $properties
            RETURN r
            """
            
            result = await session.run(
                query,
                source_id=str(relationship.source_id),
                target_id=str(relationship.target_id),
                properties=properties
            )
            
            record = await result.single()
            return dict(record['r']) if record else {}
    
    async def batch_create_nodes(
        self,
        entities: list[BaseEntity],
        batch_size: int = 100
    ) -> int:
        """
        Create multiple nodes in batches for performance.
        
        Args:
            entities: List of entities to create
            batch_size: Number of nodes per batch
        
        Returns:
            Number of nodes created
        """
        count = 0
        
        for i in range(0, len(entities), batch_size):
            batch = entities[i:i + batch_size]
            
            for entity in batch:
                await self.create_node(entity, merge=True)
                count += 1
        
        return count
    
    async def batch_create_relationships(
        self,
        relationships: list[BaseRelationship],
        batch_size: int = 100
    ) -> int:
        """
        Create multiple relationships in batches.
        
        Args:
            relationships: List of relationships to create
            batch_size: Number of relationships per batch
        
        Returns:
            Number of relationships created
        """
        count = 0
        
        for i in range(0, len(relationships), batch_size):
            batch = relationships[i:i + batch_size]
            
            for relationship in batch:
                await self.create_relationship(relationship, merge=True)
                count += 1
        
        return count
    
    async def find_node_by_id(self, node_id: UUID) -> dict[str, Any] | None:
        """Find node by ID"""
        async with self.driver.session() as session:
            result = await session.run(
                "MATCH (n {id: $id}) RETURN n",
                id=str(node_id)
            )
            record = await result.single()
            return dict(record['n']) if record else None
    
    async def find_nodes_by_label(
        self,
        label: str,
        limit: int = 100
    ) -> list[dict[str, Any]]:
        """Find nodes by label"""
        async with self.driver.session() as session:
            result = await session.run(
                f"MATCH (n:{label}) RETURN n LIMIT $limit",
                limit=limit
            )
            return [dict(record['n']) async for record in result]
    
    async def find_high_value_nodes(self) -> dict[str, list[dict[str, Any]]]:
        """
        Find high-value nodes for attack path analysis.
        
        Returns nodes that are valuable targets:
        - Admin/high-privilege roles
        - Sensitive data stores
        - Token issuers
        - Admin endpoints
        """
        high_value = {}
        
        async with self.driver.session() as session:
            # High-privilege roles
            result = await session.run(
                "MATCH (r:Role) WHERE r.privilege_level >= 80 RETURN r"
            )
            high_value['high_privilege_roles'] = [
                dict(record['r']) async for record in result
            ]
            
            # Sensitive data stores
            result = await session.run(
                "MATCH (d:DataStore) "
                "WHERE d.sensitivity_level IN ['confidential', 'restricted'] "
                "RETURN d"
            )
            high_value['sensitive_datastores'] = [
                dict(record['d']) async for record in result
            ]
            
            # Token issuers
            result = await session.run(
                "MATCH (ip:IdentityProvider) RETURN ip"
            )
            high_value['token_issuers'] = [
                dict(record['ip']) async for record in result
            ]
            
            # Admin endpoints
            result = await session.run(
                "MATCH (e:Endpoint) WHERE e.trust_zone = 'admin' RETURN e"
            )
            high_value['admin_endpoints'] = [
                dict(record['e']) async for record in result
            ]
        
        return high_value
    
    async def delete_all(self):
        """Delete all nodes and relationships (use with caution!)"""
        async with self.driver.session() as session:
            await session.run("MATCH (n) DETACH DELETE n")
    
    async def get_statistics(self) -> dict[str, Any]:
        """Get graph statistics"""
        async with self.driver.session() as session:
            # Node counts
            node_counts = {}
            for label in self.NODE_LABELS.values():
                result = await session.run(
                    f"MATCH (n:{label}) RETURN count(n) as count"
                )
                record = await result.single()
                node_counts[label] = record['count'] if record else 0
            
            # Relationship counts
            rel_counts = {}
            for rel_type in self.RELATIONSHIP_TYPES.values():
                result = await session.run(
                    f"MATCH ()-[r:{rel_type}]->() RETURN count(r) as count"
                )
                record = await result.single()
                rel_counts[rel_type] = record['count'] if record else 0
            
            # Total counts
            result = await session.run("MATCH (n) RETURN count(n) as count")
            record = await result.single()
            total_nodes = record['count'] if record else 0
            
            result = await session.run("MATCH ()-[r]->() RETURN count(r) as count")
            record = await result.single()
            total_relationships = record['count'] if record else 0
            
            return {
                'total_nodes': total_nodes,
                'total_relationships': total_relationships,
                'nodes_by_type': node_counts,
                'relationships_by_type': rel_counts
            }

    def _sanitize_properties(self, properties: dict[str, Any]) -> dict[str, Any]:
        """Coerce nested Python values into Neo4j-storable primitives."""
        sanitized: dict[str, Any] = {}
        for key, value in properties.items():
            if hasattr(value, "value"):
                sanitized[key] = value.value
            elif isinstance(value, UUID):
                sanitized[key] = str(value)
            elif isinstance(value, dict):
                sanitized[key] = json.dumps(value, default=str, sort_keys=True)
            elif isinstance(value, list):
                if all(isinstance(item, (str, int, float, bool)) or item is None for item in value):
                    sanitized[key] = value
                else:
                    sanitized[key] = json.dumps(value, default=str)
            else:
                sanitized[key] = value
        return sanitized
