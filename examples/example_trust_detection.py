"""
Example usage of the trust detection engine.

Demonstrates how to use trust detection with ingestion pipeline.
"""

import asyncio
from pathlib import Path

from itge.application.services.ingestion_service import IngestionService
from itge.application.services.trust_detection_service import TrustDetectionService


async def detect_trust_issues(file_path: str):
    """Example: Detect trust issues in traffic export"""
    
    # Initialize services
    ingestion_service = IngestionService()
    trust_service = TrustDetectionService()
    
    path = Path(file_path)
    
    print(f"Analyzing {path.name} for trust issues...")
    print("=" * 60)
    
    # Ingest and analyze
    async for result in ingestion_service.ingest_file(path):
        # Run trust detection
        findings = trust_service.analyze_normalization_result(result)
        
        # Display findings
        for finding in findings:
            print(f"\n[{finding.severity.value.upper()}] {finding.title}")
            print(f"Category: {finding.category.value}")
            print(f"Confidence: {finding.confidence:.2f}")
            print(f"Risk Score: {finding.get_risk_score():.2f}")
            print(f"\nDescription: {finding.description}")
            
            if finding.evidence:
                print(f"\nEvidence:")
                for evidence in finding.evidence[:3]:  # Show first 3
                    print(f"  - {evidence}")
            
            if finding.recommendation:
                print(f"\nRecommendation: {finding.recommendation}")
            
            print("-" * 60)
    
    # Print statistics
    print("\n" + "=" * 60)
    print("TRUST DETECTION STATISTICS")
    print("=" * 60)
    
    stats = trust_service.get_statistics()
    print(f"Total Findings: {stats['total_findings']}")
    print(f"\nBy Severity:")
    print(f"  Critical: {stats['critical_count']}")
    print(f"  High: {stats['high_count']}")
    print(f"  Medium: {stats['medium_count']}")
    print(f"  Low: {stats['low_count']}")
    
    print(f"\nBy Category:")
    for category, count in stats['by_category'].items():
        print(f"  {category}: {count}")
    
    print(f"\nAverage Confidence: {stats['average_confidence']:.2f}")
    print(f"Average Risk Score: {stats['average_risk_score']:.2f}")
    
    # Show high-risk findings
    high_risk = trust_service.get_high_risk_findings(risk_threshold=0.7)
    if high_risk:
        print(f"\n{'='*60}")
        print(f"HIGH-RISK FINDINGS ({len(high_risk)} total)")
        print("=" * 60)
        
        for finding in high_risk[:5]:  # Show top 5
            print(f"\n{finding.title}")
            print(f"  Risk: {finding.get_risk_score():.2f}")
            print(f"  Severity: {finding.severity.value}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python example_trust_detection.py <path_to_export_file>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    asyncio.run(detect_trust_issues(file_path))
