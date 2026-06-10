"""
Graph path finder - Cypher-based path finding algorithms.
"""

from __future__ import annotations

from typing import Any

from neo4j import AsyncSession


class GraphPathFinder:
    """Finds attack paths in Neo4j using flexible Cypher queries."""

    async def find_all_paths_from_persona(
        self,
        session: AsyncSession,
        persona_name: str,
        persona_privilege: int,
        persona_trust_zone: str,
        target_criteria: dict[str, Any],
        max_hops: int = 10,
    ) -> list[dict[str, Any]]:
        target_label = target_criteria.get("label", "DataStore")
        target_filters, params = self._build_target_filters(target_criteria)
        params["persona_name"] = persona_name
        params["persona_privilege"] = persona_privilege
        params["persona_trust_zone"] = persona_trust_zone

        query = f"""
        OPTIONAL MATCH (persona:UserPersona {{name: $persona_name}})
        WITH persona
        MATCH (start)
        WHERE (
            persona IS NOT NULL
            AND start.id IN coalesce(persona.can_access_endpoints, [])
        )
        OR (
            start.trust_zone = $persona_trust_zone
            AND (
                coalesce(start.privilege_level, 0) <= $persona_privilege
                OR coalesce(start.requires_auth, false) = false
                OR 'Endpoint' IN labels(start)
            )
        )
        MATCH (target:{target_label})
        WHERE {target_filters}
        MATCH path = shortestPath((start)-[*1..{int(max_hops)}]->(target))
        RETURN
            start,
            target,
            length(path) AS path_length,
            [node IN nodes(path) | node {{
                .*,
                _label: head(labels(node))
            }}] AS path_nodes,
            [rel IN relationships(path) | rel {{
                .*,
                type: type(rel)
            }}] AS path_rels
        ORDER BY path_length ASC
        LIMIT 100
        """

        result = await session.run(query, **params)
        paths = []
        async for record in result:
            paths.append(
                {
                    "start": dict(record["start"]),
                    "target": dict(record["target"]),
                    "path_length": record["path_length"],
                    "path_nodes": list(record["path_nodes"]),
                    "path_rels": list(record["path_rels"]),
                }
            )
        return paths

    def _build_target_filters(self, target_criteria: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        filters: list[str] = ["true"]
        params: dict[str, Any] = {}

        for key, value in target_criteria.items():
            if key == "label":
                continue
            if key == "sensitivity":
                filters.append("target.sensitivity_level = $sensitivity")
                params["sensitivity"] = value
            elif key == "privilege":
                filters.append("coalesce(target.privilege_level, 0) >= $privilege")
                params["privilege"] = value
            else:
                param_key = f"target_{key}"
                filters.append(f"target.{key} = ${param_key}")
                params[param_key] = value

        return " AND ".join(filters), params
