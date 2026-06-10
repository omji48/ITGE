"""
Automatic detection of identity and trust patterns in HTTP traffic.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from ..parsers.base import RawHTTPTransaction


class DetectionResult(dict):
    """Detection result with type and metadata."""

    def __init__(self, detection_type: str, confidence: float, **metadata: Any):
        super().__init__(
            detection_type=detection_type,
            confidence=confidence,
            metadata=metadata,
        )


class PatternDetector:
    """Detects identity, trust, and data patterns in raw HTTP traffic."""

    JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
    OAUTH_PARAMS = {
        "authorization": ["client_id", "redirect_uri", "response_type", "scope", "state"],
        "token": ["grant_type", "code", "client_id", "client_secret", "code_verifier"],
        "callback": ["code", "state"],
    }
    AUTH_PATH_PATTERNS = [
        r"/login",
        r"/signin",
        r"/auth",
        r"/authenticate",
        r"/oauth",
        r"/token",
        r"/session",
        r"/sso",
    ]
    ROLE_INDICATORS = [
        "role",
        "roles",
        "privilege",
        "permission",
        "permissions",
        "group",
        "groups",
        "access_level",
        "user_type",
    ]
    SENSITIVE_DATA_INDICATORS = [
        "password",
        "secret",
        "token",
        "key",
        "credential",
        "ssn",
        "credit_card",
        "api_key",
        "private",
    ]

    def __init__(self) -> None:
        self.detections: list[DetectionResult] = []

    def analyze(self, transaction: RawHTTPTransaction) -> list[DetectionResult]:
        self.detections = []
        self._detect_jwt(transaction)
        self._detect_oauth(transaction)
        self._detect_token_issuance(transaction)
        self._detect_token_validation(transaction)
        self._detect_roles(transaction)
        self._detect_trust_assumptions(transaction)
        self._detect_sensitive_data(transaction)
        return self.detections

    def _detect_jwt(self, transaction: RawHTTPTransaction) -> None:
        auth_header = transaction.request_headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            if self.JWT_PATTERN.match(token):
                self.detections.append(
                    DetectionResult(
                        detection_type="jwt_in_request",
                        confidence=0.95,
                        location="Authorization header",
                        token_preview=token[:50] + "...",
                        claims=self._parse_jwt(token),
                    )
                )

        if transaction.response_body:
            for match in self.JWT_PATTERN.findall(transaction.response_body):
                self.detections.append(
                    DetectionResult(
                        detection_type="jwt_in_response",
                        confidence=0.9,
                        location="response body",
                        token_preview=match[:50] + "...",
                        claims=self._parse_jwt(match),
                    )
                )

        cookie_header = transaction.response_headers.get("Set-Cookie", "")
        if cookie_header:
            for match in self.JWT_PATTERN.findall(cookie_header):
                self.detections.append(
                    DetectionResult(
                        detection_type="jwt_in_cookie",
                        confidence=0.92,
                        location="Set-Cookie header",
                        token_preview=match[:50] + "...",
                        claims=self._parse_jwt(match),
                    )
                )

    def _parse_jwt(self, token: str) -> dict[str, Any]:
        parts = token.split(".")
        if len(parts) != 3:
            return {}

        try:
            header = json.loads(self._urlsafe_decode(parts[0]))
            payload = json.loads(self._urlsafe_decode(parts[1]))
        except Exception:
            return {}

        merged = dict(payload)
        if "alg" in header and "alg" not in merged:
            merged["alg"] = header["alg"]
        return merged

    def _urlsafe_decode(self, value: str) -> bytes:
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(value + padding)

    def _detect_oauth(self, transaction: RawHTTPTransaction) -> None:
        path_lower = transaction.path.lower()
        parsed = urlparse(transaction.url)
        params = parse_qs(parsed.query)
        body_params = parse_qs(transaction.request_body or "")
        param_keys = set(params.keys()) | set(body_params.keys())

        if any(pattern in path_lower for pattern in ["/authorize", "/oauth/authorize"]):
            authz_params = set(self.OAUTH_PARAMS["authorization"])
            matched_params = param_keys & authz_params
            if matched_params:
                self.detections.append(
                    DetectionResult(
                        detection_type="oauth_authorization_endpoint",
                        confidence=min(0.95, (len(matched_params) / len(authz_params)) + 0.3),
                        matched_params=sorted(matched_params),
                        client_id=(params.get("client_id") or body_params.get("client_id") or [None])[0],
                        redirect_uri=(params.get("redirect_uri") or body_params.get("redirect_uri") or [None])[0],
                        scope=(params.get("scope") or body_params.get("scope") or [None])[0],
                    )
                )

                if "state" not in param_keys:
                    self.detections.append(
                        DetectionResult(
                            detection_type="oauth_missing_state",
                            confidence=0.88,
                            endpoint_path=transaction.path,
                        )
                    )
                if "code_challenge" not in param_keys:
                    self.detections.append(
                        DetectionResult(
                            detection_type="oauth_missing_pkce",
                            confidence=0.74,
                            endpoint_path=transaction.path,
                        )
                    )

        if any(pattern in path_lower for pattern in ["/token", "/oauth/token"]) and transaction.method.upper() == "POST":
            self.detections.append(
                DetectionResult(
                    detection_type="oauth_token_endpoint",
                    confidence=0.85,
                    method=transaction.method,
                )
            )

        if "code" in params:
            self.detections.append(
                DetectionResult(
                    detection_type="oauth_callback",
                    confidence=0.9 if "state" in params else 0.75,
                    has_code=True,
                    has_state="state" in params,
                )
            )

    def _detect_token_issuance(self, transaction: RawHTTPTransaction) -> None:
        if not transaction.response_body:
            return

        try:
            response_json = json.loads(transaction.response_body)
            token_fields = ["access_token", "token", "id_token", "refresh_token", "session_token"]
            found_tokens = [field for field in token_fields if field in response_json]
            if found_tokens:
                self.detections.append(
                    DetectionResult(
                        detection_type="token_issuance",
                        confidence=0.85 if len(found_tokens) > 1 else 0.75,
                        token_fields=found_tokens,
                        endpoint_path=transaction.path,
                        method=transaction.method,
                    )
                )
        except json.JSONDecodeError:
            pass

        path_lower = transaction.path.lower()
        if any(re.search(pattern, path_lower) for pattern in self.AUTH_PATH_PATTERNS):
            if transaction.status_code in [200, 201, 302]:
                self.detections.append(
                    DetectionResult(
                        detection_type="potential_token_issuance",
                        confidence=0.6,
                        reason="auth_path_pattern",
                        path=transaction.path,
                    )
                )

    def _detect_token_validation(self, transaction: RawHTTPTransaction) -> None:
        has_auth = any(
            header in transaction.request_headers for header in ["Authorization", "X-Auth-Token", "X-API-Key"]
        )
        if not has_auth:
            return

        if transaction.status_code in [200, 201, 204]:
            self.detections.append(
                DetectionResult(
                    detection_type="token_validation",
                    confidence=0.8,
                    validates_auth=True,
                    endpoint_path=transaction.path,
                )
            )
        elif transaction.status_code in [401, 403]:
            self.detections.append(
                DetectionResult(
                    detection_type="token_validation",
                    confidence=0.85,
                    validates_auth=True,
                    auth_failed=True,
                    endpoint_path=transaction.path,
                )
            )

    def _detect_roles(self, transaction: RawHTTPTransaction) -> None:
        auth_header = transaction.request_headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            if self.JWT_PATTERN.match(token):
                claims = self._parse_jwt(token)
                for indicator in self.ROLE_INDICATORS:
                    if indicator in claims:
                        self.detections.append(
                            DetectionResult(
                                detection_type="role_in_jwt",
                                confidence=0.95,
                                role_field=indicator,
                                role_value=claims[indicator],
                                location="JWT claims",
                            )
                        )

        parsed = urlparse(transaction.url)
        params = parse_qs(parsed.query)
        for indicator in self.ROLE_INDICATORS:
            if indicator in params:
                self.detections.append(
                    DetectionResult(
                        detection_type="role_in_parameter",
                        confidence=0.7,
                        role_field=indicator,
                        role_value=params[indicator][0],
                        location="query parameter",
                        exploitability=0.85,
                    )
                )

        try:
            body_json = json.loads(transaction.request_body or "{}") if (transaction.request_body or "").strip().startswith("{") else {}
        except json.JSONDecodeError:
            body_json = {}

        for indicator in self.ROLE_INDICATORS:
            if indicator in body_json:
                self.detections.append(
                    DetectionResult(
                        detection_type="role_in_body",
                        confidence=0.78,
                        role_field=indicator,
                        role_value=body_json[indicator],
                        location="request body",
                        exploitability=0.9,
                    )
                )

        for header, value in transaction.request_headers.items():
            if any(indicator in header.lower() for indicator in self.ROLE_INDICATORS):
                self.detections.append(
                    DetectionResult(
                        detection_type="role_in_header",
                        confidence=0.75,
                        header_name=header,
                        role_field=header,
                        role_value=value,
                        header_value=value,
                        location="HTTP header",
                        exploitability=0.8,
                    )
                )

    def _detect_trust_assumptions(self, transaction: RawHTTPTransaction) -> None:
        cors_origin = transaction.response_headers.get("Access-Control-Allow-Origin")
        cors_credentials = transaction.response_headers.get("Access-Control-Allow-Credentials")
        if cors_origin:
            if cors_origin == "*":
                self.detections.append(
                    DetectionResult(
                        detection_type="cors_wildcard",
                        confidence=0.95 if cors_credentials == "true" else 0.7,
                        origin=cors_origin,
                        allows_credentials=cors_credentials == "true",
                        exploitability=0.9 if cors_credentials == "true" else 0.6,
                    )
                )
            else:
                self.detections.append(
                    DetectionResult(
                        detection_type="cors_configured",
                        confidence=0.8,
                        origin=cors_origin,
                        allows_credentials=cors_credentials == "true",
                    )
                )

        trusted_headers = [
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Original-URL",
            "X-Rewrite-URL",
            "X-User-Id",
            "X-Role",
            "X-Admin",
        ]
        for header in trusted_headers:
            if header in transaction.request_headers:
                self.detections.append(
                    DetectionResult(
                        detection_type="header_trust_assumption",
                        confidence=0.75,
                        header_name=header,
                        header_value=transaction.request_headers[header],
                        exploitability=0.85,
                    )
                )

    def _detect_sensitive_data(self, transaction: RawHTTPTransaction) -> None:
        path_lower = transaction.path.lower()
        body_lower = (transaction.response_body or "").lower()

        for indicator in self.SENSITIVE_DATA_INDICATORS:
            if indicator in path_lower or indicator in body_lower:
                self.detections.append(
                    DetectionResult(
                        detection_type="sensitive_data_endpoint",
                        confidence=0.65,
                        indicator=indicator,
                        path=transaction.path,
                        method=transaction.method,
                    )
                )

        for pattern in [r"/admin", r"/user", r"/account", r"/profile", r"/payment", r"/billing", r"/api/key"]:
            if re.search(pattern, path_lower):
                self.detections.append(
                    DetectionResult(
                        detection_type="sensitive_endpoint_pattern",
                        confidence=0.6,
                        pattern=pattern,
                        path=transaction.path,
                    )
                )
