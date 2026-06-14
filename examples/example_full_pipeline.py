"""
Example: Complete pipeline from ingestion to graph construction.

Demonstrates the full ITGE pipeline.
"""

import asyncio
from pathlib import Path

from itge.application.services.ingestion_service import IngestionService
from itge.application.services.trust_detection_service import TrustDetectionService
from itge.application.services.graph_construction_service import GraphConstructionService
from itge.infrastructure.graph.neo4j_repository import GraphRepository


async def full_pipeline(
    file_path: str,
    neo4j_uri: str = "bolt://localhost:7687",
    neo4j_user: str = "neo4j",
    neo4j_password: str = "password"
):
    """
    Run complete ITGE pipeline.
    
    1. Ingest traffic
    2. Detect trust issues
    3. Build graph
    4. Display results
    """
    
    print("=" * 60)
    print("ITGE - Identity & Trust Graph Engine")
    print("=" * 60)
    
    # Initialize services
    ingestion_service = IngestionService()
    trust_service = TrustDetectionService()
    
    # Initialize graph repository
    graph_repo = GraphRepository(neo4j_uri, neo4j_user, neo4j_password)
    
    try:
        # Initialize schema
        print("\n[1/4] Initializing graph schema...")
        await graph_repo.initialize_schema()
        print("✓ Schema initialized")
        
        # Initialize graph construction service
        graph_service = GraphConstructionService(graph_repo)
        
        # Ingest traffic
        print(f"\n[2/4] Ingesting traffic from {Path(file_path).name}...")
        
        total_transactions = 0
        total_findings = 0
        
        async for result in ingestion_service.ingest_file(Path(file_path)):
            total_transactions += 1
            
            # Detect trust issues
            findings = trust_service.analyze_normalization_result(result)
            total_findings += len(findings)
            
            # Build graph
            stats = await graph_service.build_from_normalization_result(result)
            
            print(f"  Transaction {total_transactions}: "
                  f"{stats['nodes_created']} nodes, "
                  f"{stats['relationships_created']} edges, "
                  f"{len(findings)} findings")
        
        print(f"✓ Ingested {total_transactions} transactions")
        
        # Display trust findings
        print(f"\n[3/4] Trust Detection Results...")
        trust_stats = trust_service.get_statistics()
        
        print(f"Total Findings: {trust_stats['total_findings']}")
        print(f"  Critical: {trust_stats['critical_count']}")
        print(f"  High: {trust_stats['high_count']}")
        print(f"  Medium: {trust_stats['medium_count']}")
        print(f"  Low: {trust_stats['low_count']}")
        
        # Display high-risk findings
        high_risk = trust_service.get_high_risk_findings(risk_threshold=0.7)
        if high_risk:
            print(f"\nHigh-Risk Findings ({len(high_risk)}):")
            for finding in high_risk[:5]:
                print(f"  [{finding.severity.value.upper()}] {finding.title}")
                print(f"    Risk: {finding.get_risk_score():.2f}")
        
        # Display graph statistics
        print(f"\n[4/4] Graph Construction Results...")
        construction_stats = await graph_service.get_statistics()
        
        graph_stats = construction_stats['graph_stats']
        print(f"Total Nodes: {graph_stats['total_nodes']}")
        print(f"Total Relationships: {graph_stats['total_relationships']}")
        
        print(f"\nNodes by Type:")
        for node_type, count in graph_stats['nodes_by_type'].items():
            print(f"  {node_type}: {count}")
        
        print(f"\nRelationships by Type:")
        for rel_type, count in graph_stats['relationships_by_type'].items():
            if count > 0:
                print(f"  {rel_type}: {count}")
        
        # Find high-value nodes
        print(f"\n[Bonus] High-Value Targets...")
        high_value = await graph_repo.find_high_value_nodes()
        
        for category, nodes in high_value.items():
            if nodes:
                print(f"  {category}: {len(nodes)}")
        
        print("\n" + "=" * 60)
        print("Pipeline Complete!")
        print("=" * 60)
        print(f"\nGraph database ready at: {neo4j_uri}")
        print("You can now query the graph for attack paths.")
        
    finally:
        # Close connection
        await graph_repo.close()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python example_full_pipeline.py <path_to_export_file> [neo4j_uri] [user] [password]")
        print("\nExample:")
        print("  python example_full_pipeline.py burp_export.xml")
        print("  python example_full_pipeline.py burp_export.xml bolt://localhost:7687 neo4j mypassword")
        sys.exit(1)
    
    file_path = sys.argv[1]
    neo4j_uri = sys.argv[2] if len(sys.argv) > 2 else "bolt://localhost:7687"
    neo4j_user = sys.argv[3] if len(sys.argv) > 3 else "neo4j"
    neo4j_password = sys.argv[4] if len(sys.argv) > 4 else "password"
    
    asyncio.run(full_pipeline(file_path, neo4j_uri, neo4j_user, neo4j_password))
