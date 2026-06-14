import json

import pytest

from itge.application.services.ingestion_service import IngestionService


@pytest.mark.asyncio
async def test_ingestion_service_supports_amass(tmp_path) -> None:
    payload = {
        "name": "api.example.com",
        "domain": "example.com",
        "ports": [443, 8443],
        "addresses": [{"ip": "1.2.3.4"}],
    }
    file_path = tmp_path / "amass.json"
    file_path.write_text(json.dumps(payload), encoding="utf-8")

    results = []
    async for result in IngestionService().ingest_file(file_path, file_type="amass_json"):
        results.append(result)

    assert len(results) == 1
    assert len(results[0].services) == 2


@pytest.mark.asyncio
async def test_ingestion_service_supports_nmap(tmp_path) -> None:
    xml = """
    <nmaprun>
      <host>
        <address addr="10.0.0.5" addrtype="ipv4" />
        <hostnames><hostname name="db.internal.local" /></hostnames>
        <ports>
          <port protocol="tcp" portid="5432">
            <state state="open" />
            <service name="postgresql" product="PostgreSQL" version="16" />
          </port>
        </ports>
      </host>
    </nmaprun>
    """
    file_path = tmp_path / "scan.xml"
    file_path.write_text(xml.strip(), encoding="utf-8")

    results = []
    async for result in IngestionService().ingest_file(file_path, file_type="nmap_xml"):
        results.append(result)

    assert len(results) == 1
    assert results[0].services
    assert results[0].data_stores
