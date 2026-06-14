"""
Example: attack path simulation against a populated Neo4j graph.
"""

import asyncio

from itge.application.services.attack_path_service import AttackPathSimulationService
from itge.infrastructure.graph.neo4j_repository import GraphRepository


async def simulate_attack_paths(
    neo4j_uri: str = "bolt://localhost:7687",
    neo4j_user: str = "neo4j",
    neo4j_password: str = "password",
) -> None:
    print("=" * 70)
    print("ITGE - Attack Path Simulation")
    print("=" * 70)

    repo = GraphRepository(neo4j_uri, neo4j_user, neo4j_password)
    try:
        await repo.verify_connection()
        simulation_service = AttackPathSimulationService(repo)

        scenarios = [
            (
                "Unauthenticated -> Confidential Data",
                {
                    "start_persona": "Unauthenticated Attacker",
                    "start_privilege": 0,
                    "start_trust_zone": "external",
                    "target_criteria": {"label": "DataStore", "sensitivity": "confidential"},
                },
            ),
            (
                "Low-Privilege -> Admin Role",
                {
                    "start_persona": "Low-Privilege User",
                    "start_privilege": 20,
                    "start_trust_zone": "internal",
                    "target_criteria": {"label": "Role", "privilege": 80},
                },
            ),
        ]

        for title, params in scenarios:
            print("\n" + "=" * 70)
            print(title)
            print("=" * 70)
            result = await simulation_service.simulate_attack_paths(
                **params,
                max_hops=8,
                max_paths=10,
            )

            print(f"Found {result.total_paths_found} paths")
            print(f"Average risk score: {result.avg_risk_score:.2f}")
            print(f"Average path length: {result.avg_path_length:.1f}")

            if result.highest_risk_paths:
                print("\nTop path:")
                print(result.highest_risk_paths[0].get_explainable_reasoning())
    finally:
        await repo.close()


if __name__ == "__main__":
    import sys

    neo4j_uri = sys.argv[1] if len(sys.argv) > 1 else "bolt://localhost:7687"
    neo4j_user = sys.argv[2] if len(sys.argv) > 2 else "neo4j"
    neo4j_password = sys.argv[3] if len(sys.argv) > 3 else "password"
    asyncio.run(simulate_attack_paths(neo4j_uri, neo4j_user, neo4j_password))
