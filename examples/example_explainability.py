"""
Example: Attack path explainability.

Demonstrates how to generate structured explanations for attack paths.
"""

import asyncio
import json

from itge.infrastructure.graph.neo4j_repository import GraphRepository
from itge.application.services.attack_path_service import AttackPathSimulationService
from itge.application.services.explainability_service import ExplainabilityService


async def explain_attack_paths(
    neo4j_uri: str = "bolt://localhost:7687",
    neo4j_user: str = "neo4j",
    neo4j_password: str = "password"
):
    """
    Generate explainable attack path analysis.
    """
    
    print("=" * 70)
    print("ITGE - Attack Path Explainability")
    print("=" * 70)
    
    # Initialize services
    repo = GraphRepository(neo4j_uri, neo4j_user, neo4j_password)
    
    try:
        simulation_service = AttackPathSimulationService(repo)
        explainability_service = ExplainabilityService()
        
        # Simulate attack paths
        print("\n[1/3] Simulating attack paths...")
        
        result = await simulation_service.simulate_attack_paths(
            start_persona="Unauthenticated Attacker",
            start_privilege=0,
            start_trust_zone="public",
            target_criteria={
                'label': 'DataStore',
                'sensitivity': 'confidential'
            },
            max_hops=10,
            max_paths=20
        )
        
        print(f"✓ Found {result.total_paths_found} attack paths")
        
        if not result.paths:
            print("\nNo paths found. Please ensure graph is populated with data.")
            return
        
        # Generate explanations for top 3 paths
        print("\n[2/3] Generating explanations for top paths...")
        
        explanations = []
        for path in result.highest_risk_paths[:3]:
            explanation = explainability_service.explain_path(
                path=path,
                all_paths=result.paths,
                trust_findings=None  # Could pass trust findings here
            )
            explanations.append(explanation)
        
        print(f"✓ Generated {len(explanations)} explanations")
        
        # Display explanations
        print("\n[3/3] Displaying explanations...")
        print("=" * 70)
        
        for i, explanation in enumerate(explanations, 1):
            print(f"\n{'='*70}")
            print(f"PATH {i} EXPLANATION")
            print("=" * 70)
            
            # Display human-readable summary
            print("\n" + "─" * 70)
            print("HUMAN-READABLE SUMMARY")
            print("─" * 70)
            print(f"\n{explanation.human_readable_summary}")
            
            # Display trust assumptions
            if explanation.trust_assumptions:
                print("\n" + "─" * 70)
                print(f"TRUST ASSUMPTIONS EXPLOITED ({len(explanation.trust_assumptions)})")
                print("─" * 70)
                
                for j, assumption in enumerate(explanation.trust_assumptions, 1):
                    print(f"\n{j}. {assumption.assumption_type.value.replace('_', ' ').title()}")
                    print(f"   Entity: {assumption.source_entity_name}")
                    print(f"   Technique: {assumption.exploitation_technique}")
                    print(f"   Risk: Exploitability {assumption.exploitability:.2f}, Impact {assumption.impact:.2f}")
            
            # Display boundary crossings
            if explanation.boundary_crossings:
                print("\n" + "─" * 70)
                print(f"TRUST BOUNDARY CROSSINGS ({len(explanation.boundary_crossings)})")
                print("─" * 70)
                
                for crossing in explanation.boundary_crossings:
                    print(f"\n   Step {crossing.step_number}: {crossing.from_zone} → {crossing.to_zone}")
                    print(f"   Mechanism: {crossing.crossing_mechanism}")
                    print(f"   Risk Multiplier: {crossing.risk_multiplier:.2f}x")
                    print(f"   {crossing.explanation}")
            
            # Display token reuse
            if explanation.token_reuse_risks:
                print("\n" + "─" * 70)
                print(f"TOKEN REUSE RISKS ({len(explanation.token_reuse_risks)})")
                print("─" * 70)
                
                for risk in explanation.token_reuse_risks:
                    print(f"\n   Token: {risk.token_type} from {risk.issuer}")
                    print(f"   Issued at step {risk.issued_at_step}, reused at steps: {', '.join(map(str, risk.reused_at_steps))}")
                    print(f"   Accepted by {len(risk.accepted_by_entities)} services")
                    print(f"   Lateral movement risk: {risk.lateral_movement_risk:.2f}")
            
            # Display ranking
            print("\n" + "─" * 70)
            print("COMPARATIVE RANKING")
            print("─" * 70)
            
            print(f"\n   Rank: #{explanation.ranking.this_path_rank} out of {explanation.ranking.total_paths}")
            print(f"   Score: {explanation.ranking.this_path_score:.2f} (avg: {explanation.ranking.avg_path_score:.2f})")
            print(f"   Percentile: Top {100 - explanation.ranking.score_percentile:.0f}%")
            
            print(f"\n   Why this path ranks higher:")
            for advantage in explanation.ranking.key_advantages:
                print(f"   • {advantage}")
            
            # Display risk summary
            print("\n" + "─" * 70)
            print("RISK SUMMARY")
            print("─" * 70)
            
            print(f"\n   Overall Risk Score: {explanation.risk_summary['overall_risk_score']:.2f}")
            print(f"   Confidence: {explanation.risk_summary['confidence']:.2f}")
            print(f"   Exploitability: {explanation.risk_summary['exploitability']:.2f}")
            print(f"   Impact: {explanation.risk_summary['impact']:.2f}")
            print(f"   Trust Gap Multiplier: {explanation.risk_summary['trust_gap_multiplier']:.2f}x")
            print(f"   Exposure Multiplier: {explanation.risk_summary['exposure_multiplier']:.2f}x")
        
        # Export as JSON
        print("\n\n" + "=" * 70)
        print("JSON EXPORT")
        print("=" * 70)
        
        print("\nExporting first path explanation as JSON...")
        
        json_output = explanations[0].to_json_dict()
        json_str = json.dumps(json_output, indent=2, default=str)
        
        # Save to file
        output_file = "attack_path_explanation.json"
        with open(output_file, 'w') as f:
            f.write(json_str)
        
        print(f"✓ Saved to {output_file}")
        print(f"\nJSON structure preview:")
        print(json_str[:500] + "...")
        
        # Export as Markdown
        print("\n\n" + "=" * 70)
        print("MARKDOWN EXPORT")
        print("=" * 70)
        
        print("\nExporting first path explanation as Markdown...")
        
        markdown_output = explanations[0].to_markdown()
        
        # Save to file
        md_file = "attack_path_explanation.md"
        with open(md_file, 'w') as f:
            f.write(markdown_output)
        
        print(f"✓ Saved to {md_file}")
        
        # Summary
        print("\n\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)
        
        total_assumptions = sum(len(e.trust_assumptions) for e in explanations)
        total_crossings = sum(len(e.boundary_crossings) for e in explanations)
        total_token_risks = sum(len(e.token_reuse_risks) for e in explanations)
        
        print(f"\nAnalyzed {len(explanations)} attack paths:")
        print(f"  • {total_assumptions} trust assumptions exploited")
        print(f"  • {total_crossings} boundary crossings identified")
        print(f"  • {total_token_risks} token reuse risks detected")
        
        print(f"\nExported formats:")
        print(f"  • JSON: {output_file}")
        print(f"  • Markdown: {md_file}")
        
        print("\n" + "=" * 70)
        print("Explainability Analysis Complete!")
        print("=" * 70)
        
    finally:
        await repo.close()


if __name__ == "__main__":
    import sys
    
    neo4j_uri = sys.argv[1] if len(sys.argv) > 1 else "bolt://localhost:7687"
    neo4j_user = sys.argv[2] if len(sys.argv) > 2 else "neo4j"
    neo4j_password = sys.argv[3] if len(sys.argv) > 3 else "password"
    
    asyncio.run(explain_attack_paths(neo4j_uri, neo4j_user, neo4j_password))
