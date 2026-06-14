import pytest

from itge.infrastructure.normalizers.traffic_normalizer import TrafficNormalizer
from itge.infrastructure.parsers.base import RawHTTPTransaction


@pytest.mark.asyncio
async def test_normalizer_infers_services_datastores_and_personas() -> None:
    transaction = RawHTTPTransaction(
        url="https://api.example.com/admin/users?role=admin",
        method="GET",
        request_headers={"X-Role": "admin"},
        request_body=None,
        status_code=200,
        response_headers={"Access-Control-Allow-Origin": "*"},
        response_body='{"email":"admin@example.com","token":"secret"}',
        timestamp=None,
        source="burp",
        host="api.example.com",
        port=443,
        protocol="https",
        path="/admin/users",
    )

    result = await TrafficNormalizer().normalize(transaction)

    assert len(result.endpoints) == 1
    assert len(result.services) == 1
    assert result.data_stores
    assert result.personas
    assert any(rel.relationship_type == "requires_role" for rel in result.relationships)
    assert any(rel.relationship_type == "accesses" for rel in result.relationships)
