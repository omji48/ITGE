"""
Example usage of the ingestion engine.

Demonstrates how to use the traffic ingestion pipeline.
"""

import asyncio
from pathlib import Path

from itge.application.services.ingestion_service import IngestionService


async def ingest_burp_export(file_path: str):
    """Example: Ingest Burp Suite export"""
    
    service = IngestionService()
    path = Path(file_path)
    
    print(f"Ingesting {path.name}...")
    print("-" * 60)
    
    async for result in service.ingest_file(path, file_type='burp_xml'):
        # Process endpoints
        for endpoint in result.endpoints:
            print(f"\n[Endpoint] {endpoint.method.value} {endpoint.url}")
            print(f"  Auth Required: {endpoint.requires_auth}")
            print(f"  Auth Type: {endpoint.auth_type.value}")
            print(f"  Sensitive Data: {endpoint.sensitive_data}")
            print(f"  Trust Zone: {endpoint.trust_zone}")
        
        # Process tokens
        for token in result.tokens:
            print(f"\n[Token] {token.token_type.value}")
            if token.issuer:
                print(f"  Issuer: {token.issuer}")
            if token.subject:
                print(f"  Subject: {token.subject}")
            if token.claims:
                print(f"  Claims: {list(token.claims.keys())}")
        
        # Process identity providers
        for provider in result.identity_providers:
            print(f"\n[Identity Provider] {provider.name}")
            print(f"  Type: {provider.provider_type.value}")
            if provider.issuer:
                print(f"  Issuer: {provider.issuer}")
        
        # Process roles
        for role in result.roles:
            print(f"\n[Role] {role.name}")
            print(f"  Privilege Level: {role.privilege_level}/100")
            print(f"  Assignment Method: {role.assignment_method}")
        
        # Process relationships
        for rel in result.relationships:
            rel_type = rel.__class__.__name__
            print(f"\n[Relationship] {rel_type}")
            print(f"  Confidence: {rel.confidence:.2f}")
        
        # Show detections
        if result.detections:
            print(f"\n[Detections] {len(result.detections)} patterns detected:")
            for detection in result.detections:
                print(f"  - {detection['detection_type']} (confidence: {detection['confidence']:.2f})")
    
    # Print statistics
    print("\n" + "=" * 60)
    print("INGESTION STATISTICS")
    print("=" * 60)
    stats = service.get_stats()
    print(f"Total Transactions: {stats.total_transactions}")
    print(f"Successful Normalizations: {stats.successful_normalizations}")
    print(f"Failed Normalizations: {stats.failed_normalizations}")
    print(f"\nEntities Created:")
    print(f"  Endpoints: {stats.endpoints_created}")
    print(f"  Tokens: {stats.tokens_created}")
    print(f"  Identity Providers: {stats.providers_created}")
    print(f"  Roles: {stats.roles_created}")
    print(f"  Relationships: {stats.relationships_created}")
    
    if stats.parser_stats:
        print(f"\nParser Statistics:")
        print(f"  Total Parsed: {stats.parser_stats.total_transactions}")
        print(f"  Successful: {stats.parser_stats.successful_parses}")
        print(f"  Failed: {stats.parser_stats.failed_parses}")
        
        if stats.parser_stats.errors:
            print(f"\nParser Errors:")
            for error in stats.parser_stats.errors[:5]:  # Show first 5
                print(f"  - {error}")


async def ingest_zap_export(file_path: str):
    """Example: Ingest OWASP ZAP export"""
    
    service = IngestionService()
    path = Path(file_path)
    
    print(f"Ingesting {path.name}...")
    
    async for result in service.ingest_file(path, file_type='zap_xml'):
        # Similar processing as Burp example
        for endpoint in result.endpoints:
            print(f"[Endpoint] {endpoint.method.value} {endpoint.url}")
    
    stats = service.get_stats()
    print(f"\nProcessed {stats.total_transactions} transactions")
    print(f"Created {stats.endpoints_created} endpoints")


async def auto_detect_and_ingest(file_path: str):
    """Example: Auto-detect format and ingest"""
    
    service = IngestionService()
    path = Path(file_path)
    
    print(f"Auto-detecting format for {path.name}...")
    
    try:
        async for result in service.ingest_file(path):
            print(f"Processed transaction: {len(result.endpoints)} endpoints")
    except ValueError as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python example_ingestion.py <path_to_export_file>")
        print("\nSupported formats:")
        print("  - Burp Suite XML export")
        print("  - OWASP ZAP XML export")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    # Run ingestion
    asyncio.run(ingest_burp_export(file_path))
