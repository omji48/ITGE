import json

from fastapi.testclient import TestClient

from itge.api.main import create_app
from itge.cli.config import ITGEConfig


def test_api_health_and_latest_analysis(tmp_path) -> None:
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    (output_dir / "analysis_result.json").write_text(
        json.dumps(
            {
                "total_paths_found": 2,
                "avg_path_length": 3.0,
                "avg_risk_score": 0.7,
                "max_risk_score": 0.9,
                "computation_time_ms": 42.0,
                "highest_risk_paths": [{"target_node_name": "users_db", "risk_score": 0.9}],
            }
        ),
        encoding="utf-8",
    )
    app = create_app(ITGEConfig(output_dir=output_dir))
    client = TestClient(app)

    assert client.get("/health").json()["status"] == "ok"
    latest = client.get("/analysis/latest")
    assert latest.status_code == 200
    assert latest.json()["total_paths_found"] == 2
