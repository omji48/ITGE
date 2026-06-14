from types import SimpleNamespace
from uuid import uuid4

import pytest

from itge.application.services.attack_path_service import AttackPathSimulationService


@pytest.mark.asyncio
async def test_attack_path_conversion_calculates_risk() -> None:
    service = AttackPathSimulationService(repository=SimpleNamespace())
    start_id = str(uuid4())
    role_id = str(uuid4())
    target_id = str(uuid4())

    raw_path = {
        "path_nodes": [
            {"id": start_id, "_label": "Endpoint", "url": "https://app.example.com", "trust_zone": "external", "requires_auth": False},
            {"id": role_id, "_label": "Role", "name": "admin", "privilege_level": 90, "trust_zone": "internal"},
            {"id": target_id, "_label": "DataStore", "name": "users_db", "sensitivity_level": "confidential", "trust_zone": "internal"},
        ],
        "path_rels": [
            {"type": "REQUIRES_ROLE", "confidence": 0.9, "exploitability": 0.8},
            {"type": "ACCESSES", "confidence": 0.8, "exploitability": 0.7},
        ],
    }

    attack_path = await service._convert_to_attack_path(
        raw_path=raw_path,
        start_persona="Unauthenticated Attacker",
        start_privilege=0,
        start_trust_zone="external",
    )

    assert attack_path is not None
    assert attack_path.risk_score > 0
    assert attack_path.path_length == 2
    assert attack_path.boundary_crossings >= 1
