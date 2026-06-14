import json

from itge.infrastructure.detectors.pattern_detector import PatternDetector
from itge.infrastructure.parsers.base import RawHTTPTransaction


def _jwt() -> str:
    return (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoidXNlcjEiLCJyb2xlIjoiYWRtaW4ifQ."
        "signature"
    )


def test_pattern_detector_extracts_jwt_roles_and_sensitive_data() -> None:
    token = _jwt()
    transaction = RawHTTPTransaction(
        url="https://app.example.com/api/account?role=admin",
        method="GET",
        request_headers={"Authorization": f"Bearer {token}", "X-Role": "admin"},
        request_body=None,
        status_code=200,
        response_headers={"Access-Control-Allow-Origin": "*"},
        response_body=json.dumps({"access_token": token, "profile": {"email": "user@example.com"}}),
        timestamp=None,
        source="burp",
        host="app.example.com",
        port=443,
        protocol="https",
        path="/api/account",
    )

    detections = PatternDetector().analyze(transaction)
    detection_types = {item["detection_type"] for item in detections}

    assert "jwt_in_request" in detection_types
    assert "role_in_jwt" in detection_types
    assert "role_in_parameter" in detection_types
    assert "role_in_header" in detection_types
    assert "cors_wildcard" in detection_types
    assert "sensitive_endpoint_pattern" in detection_types or "sensitive_data_endpoint" in detection_types
