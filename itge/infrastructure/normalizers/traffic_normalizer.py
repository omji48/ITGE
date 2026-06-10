"""
Traffic normalizer - converts raw observations to graph-ready domain models.

This module bridges parser output and the domain layer by extracting endpoints,
services, identities, roles, personas, datastores, and the relationships that
connect them.
"""

from __future__ import annotations

from typing import Any

from ...domain.models import (
    Accesses,
    AuthType,
    CrossesBoundary,
    DataStore,
    Endpoint,
    EscalatesTo,
    HTTPMethod,
    IdentityProvider,
    IssuesToken,
    ProviderType,
    RequiresRole,
    Role,
    SensitivityLevel,
    Service,
    Token,
    TokenType,
    Trusts,
    UserPersona,
    ValidatesToken,
)
from ...domain.models.relationships import AccessType, TrustType
from ..detectors.pattern_detector import DetectionResult, PatternDetector
from ..parsers.base import RawHTTPTransaction


class NormalizationResult:
    """Result of normalizing one observation into entities and relationships."""

    def __init__(self) -> None:
        self.endpoints: list[Endpoint] = []
        self.services: list[Service] = []
        self.data_stores: list[DataStore] = []
        self.identity_providers: list[IdentityProvider] = []
        self.tokens: list[Token] = []
        self.roles: list[Role] = []
        self.personas: list[UserPersona] = []
        self.relationships: list[Any] = []
        self.detections: list[DetectionResult] = []


class TrafficNormalizer:
    """
    Normalizes HTTP transactions into domain models with richer graph context.

    Besides direct endpoint and token extraction, the normalizer also infers:
    - host-level services
    - likely datastores behind sensitive endpoints
    - default attacker personas for graph entry points
    - role requirements and privilege escalation edges
    - trust-boundary crossings around sensitive data access
    """

    def __init__(self) -> None:
        self.detector = PatternDetector()
        self._endpoint_cache: dict[str, Endpoint] = {}
        self._service_cache: dict[str, Service] = {}
        self._datastore_cache: dict[str, DataStore] = {}
        self._token_cache: dict[str, Token] = {}
        self._provider_cache: dict[str, IdentityProvider] = {}
        self._role_cache: dict[str, Role] = {}
        self._persona_cache: dict[str, UserPersona] = {}

    async def normalize(self, transaction: RawHTTPTransaction) -> NormalizationResult:
        """Normalize a single transaction into graph entities."""
        result = NormalizationResult()

        detections = self.detector.analyze(transaction)
        result.detections = detections

        endpoint = self._create_endpoint(transaction, detections)
        result.endpoints.append(endpoint)

        service = self._create_service(transaction, endpoint)
        result.services.append(service)

        for detection in detections:
            detection_type = detection["detection_type"]

            if detection_type in {"jwt_in_response", "jwt_in_cookie"}:
                token, provider, relationship = self._create_token_issuance(
                    transaction, detection, endpoint
                )
                if token:
                    result.tokens.append(token)
                if provider:
                    result.identity_providers.append(provider)
                if relationship:
                    result.relationships.append(relationship)

            elif detection_type == "jwt_in_request":
                token, relationship = self._create_token_validation(
                    transaction, detection, endpoint
                )
                if token:
                    result.tokens.append(token)
                if relationship:
                    result.relationships.append(relationship)

            elif detection_type == "oauth_authorization_endpoint":
                provider = self._create_oauth_provider(transaction, detection)
                if provider:
                    result.identity_providers.append(provider)

            elif detection_type in {"role_in_jwt", "role_in_parameter", "role_in_header", "role_in_body"}:
                role = self._create_role(detection)
                if role:
                    result.roles.append(role)
                    result.relationships.append(
                        RequiresRole(
                            source_id=endpoint.id,
                            target_id=role.id,
                            enforcement_method=role.assignment_method or "unknown",
                            enforcement_location="request",
                            bypassable=role.assignment_method in {"parameter", "header"},
                            bypass_methods=self._role_bypass_methods(role.assignment_method),
                            has_fallback=False,
                            fallback_behavior="deny",
                            confidence=detection["confidence"],
                            evidence=[
                                f"Role {role.name} observed in {detection['metadata'].get('location', 'request')}"
                            ],
                        )
                    )

            elif detection_type == "cors_wildcard":
                trust = self._create_cors_trust(endpoint, detection)
                if trust:
                    result.relationships.append(trust)

        datastore = self._create_datastore(transaction, endpoint, detections)
        if datastore:
            result.data_stores.append(datastore)
            result.relationships.append(
                Accesses(
                    source_id=endpoint.id,
                    target_id=datastore.id,
                    access_type=self._determine_access_type(transaction.method),
                    requires_auth=endpoint.requires_auth,
                    required_privilege_level=self._estimate_endpoint_privilege(endpoint, result.roles),
                    required_roles=[role.name for role in result.roles],
                    query_pattern=endpoint.path,
                    uses_parameterized_queries=True,
                    data_fields=self._extract_data_fields(transaction, detections),
                    filters_data=endpoint.requires_auth,
                    confidence=0.72,
                    evidence=[f"Endpoint {endpoint.path} appears to expose sensitive data"],
                )
            )

            if endpoint.trust_zone != datastore.trust_zone:
                result.relationships.append(
                    CrossesBoundary(
                        source_id=endpoint.id,
                        target_id=datastore.id,
                        boundary_type="data",
                        from_zone=endpoint.trust_zone,
                        to_zone=datastore.trust_zone,
                        enforcement_strength=0.7 if endpoint.requires_auth else 0.35,
                        enforced_by=["application", service.name],
                        requires_authentication=endpoint.requires_auth,
                        requires_authorization=bool(result.roles),
                        required_privilege_level=self._estimate_endpoint_privilege(endpoint, result.roles),
                        confidence=0.75,
                        evidence=[f"{endpoint.url} crosses into {datastore.trust_zone} data boundary"],
                    )
                )

        result.personas.extend(self._create_personas(endpoint, result.roles, result.tokens))
        result.relationships.extend(self._infer_role_escalations(result.roles))

        return result

    def _create_endpoint(
        self,
        transaction: RawHTTPTransaction,
        detections: list[DetectionResult],
    ) -> Endpoint:
        requires_auth = self._detect_auth_requirement(transaction, detections)
        auth_type = self._detect_auth_type(transaction, detections)
        sensitive_data = any(
            detection["detection_type"] in {"sensitive_data_endpoint", "sensitive_endpoint_pattern"}
            for detection in detections
        )
        trust_zone = self._determine_trust_zone(transaction, requires_auth)

        cache_key = f"{transaction.method}:{transaction.url}"
        cached = self._endpoint_cache.get(cache_key)
        if cached:
            return cached

        endpoint = Endpoint(
            url=transaction.url,
            method=HTTPMethod(transaction.method.upper()),
            host=transaction.host,
            path=transaction.path,
            query_params=self._parse_query_params(transaction.url),
            request_headers=transaction.request_headers,
            request_body=transaction.request_body,
            response_headers=transaction.response_headers,
            response_body=transaction.response_body,
            status_code=transaction.status_code,
            requires_auth=requires_auth,
            auth_type=auth_type,
            sensitive_data=sensitive_data,
            trust_zone=trust_zone,
            source=transaction.source,
            confidence=0.95,
            metadata={
                "timestamp": transaction.timestamp,
                "protocol": transaction.protocol,
                "port": transaction.port,
            },
        )
        self._endpoint_cache[cache_key] = endpoint
        return endpoint

    def _create_service(self, transaction: RawHTTPTransaction, endpoint: Endpoint) -> Service:
        cache_key = f"{transaction.host}:{transaction.port or self._default_port(transaction.protocol)}"
        cached = self._service_cache.get(cache_key)
        if cached:
            return cached

        service = Service(
            name=transaction.host,
            host=transaction.host,
            port=transaction.port or self._default_port(transaction.protocol),
            protocol=transaction.protocol,
            version=None,
            banner=None,
            cpe=None,
            is_public=endpoint.trust_zone in {"public", "external"},
            tls_enabled=transaction.protocol == "https",
            trust_zone=endpoint.trust_zone,
            source=transaction.source,
            confidence=0.9,
            metadata={"primary_endpoint": str(endpoint.url)},
        )
        self._service_cache[cache_key] = service
        return service

    def _create_datastore(
        self,
        transaction: RawHTTPTransaction,
        endpoint: Endpoint,
        detections: list[DetectionResult],
    ) -> DataStore | None:
        if not endpoint.sensitive_data:
            return None

        path_lower = transaction.path.lower()
        store_type = "api"
        if any(term in path_lower for term in {"db", "sql", "user", "account", "payment"}):
            store_type = "database"
        elif any(term in path_lower for term in {"cache", "session", "redis"}):
            store_type = "cache"
        elif any(term in path_lower for term in {"storage", "bucket", "blob", "file"}):
            store_type = "object_storage"

        name = f"{transaction.host}{transaction.path}:store"
        cached = self._datastore_cache.get(name)
        if cached:
            return cached

        datastore = DataStore(
            name=name,
            store_type=store_type,
            host=transaction.host,
            connection_string=f"{transaction.protocol}://{transaction.host}",
            sensitivity_level=self._determine_sensitivity(path_lower),
            data_classification=self._infer_data_classification(transaction, detections),
            requires_authentication=endpoint.requires_auth,
            access_control_type="rbac" if endpoint.requires_auth else "none",
            compliance_tags=self._infer_compliance_tags(transaction, detections),
            trust_zone="internal" if endpoint.trust_zone in {"external", "public"} else endpoint.trust_zone,
            source=transaction.source,
            confidence=0.72,
            metadata={"derived_from_endpoint": str(endpoint.id)},
        )
        self._datastore_cache[name] = datastore
        return datastore

    def _create_token_issuance(
        self,
        transaction: RawHTTPTransaction,
        detection: DetectionResult,
        endpoint: Endpoint,
    ) -> tuple[Token | None, IdentityProvider | None, IssuesToken | None]:
        claims = detection["metadata"].get("claims", {})
        token_preview = detection["metadata"].get("token_preview", "")

        token = Token(
            token_type=TokenType.JWT,
            issuer=claims.get("iss"),
            audience=self._normalize_audience(claims.get("aud")),
            subject=claims.get("sub"),
            claims=claims,
            algorithm=claims.get("alg"),
            source=transaction.source,
            confidence=detection["confidence"],
            metadata={
                "token_preview": token_preview,
                "issued_by_endpoint": str(endpoint.id),
            },
        )

        issuer = claims.get("iss", transaction.host)
        provider_key = f"jwt:{issuer}"
        provider = self._provider_cache.get(provider_key)
        if provider is None:
            provider = IdentityProvider(
                name=f"JWT Issuer: {issuer}",
                provider_type=ProviderType.JWT,
                issuer=issuer,
                source=transaction.source,
                confidence=detection["confidence"],
                metadata={"discovered_from": transaction.url},
            )
            self._provider_cache[provider_key] = provider

        relationship = IssuesToken(
            source_id=provider.id,
            target_id=token.id,
            issuance_method="jwt_response",
            endpoint_url=transaction.url,
            confidence=detection["confidence"],
            evidence=[f"JWT found in {detection['metadata']['location']}"],
        )

        return token, provider, relationship

    def _create_token_validation(
        self,
        transaction: RawHTTPTransaction,
        detection: DetectionResult,
        endpoint: Endpoint,
    ) -> tuple[Token | None, ValidatesToken | None]:
        claims = detection["metadata"].get("claims", {})
        token_key = f"jwt:{claims.get('iss', 'unknown')}:{claims.get('sub', 'unknown')}"
        token = self._token_cache.get(token_key)

        if token is None:
            token = Token(
                token_type=TokenType.JWT,
                issuer=claims.get("iss"),
                audience=self._normalize_audience(claims.get("aud")),
                subject=claims.get("sub"),
                claims=claims,
                algorithm=claims.get("alg"),
                source=transaction.source,
                confidence=detection["confidence"],
            )
            self._token_cache[token_key] = token

        relationship = ValidatesToken(
            source_id=endpoint.id,
            target_id=token.id,
            validation_method="jwt_signature",
            required=True,
            can_bypass=False,
            token_location="header",
            token_parameter="Authorization",
            confidence=detection["confidence"],
            evidence=["JWT in Authorization header"],
        )

        return token, relationship

    def _create_oauth_provider(
        self,
        transaction: RawHTTPTransaction,
        detection: DetectionResult,
    ) -> IdentityProvider:
        metadata = detection["metadata"]
        return IdentityProvider(
            name=f"OAuth Provider: {transaction.host}",
            provider_type=ProviderType.OAUTH,
            authorization_endpoint=transaction.url,
            client_id=metadata.get("client_id"),
            scopes=metadata.get("scope", "").split() if metadata.get("scope") else [],
            supports_state="state" in metadata.get("matched_params", []),
            supports_pkce="code_challenge" in metadata.get("matched_params", []),
            source=transaction.source,
            confidence=detection["confidence"],
            metadata={
                "redirect_uri": metadata.get("redirect_uri"),
                "matched_params": metadata.get("matched_params", []),
            },
        )

    def _create_role(self, detection: DetectionResult) -> Role | None:
        metadata = detection["metadata"]
        role_value = metadata.get("role_value")
        if not role_value:
            return None

        cache_key = f"{role_value}:{metadata.get('location')}:{metadata.get('role_field')}"
        cached = self._role_cache.get(cache_key)
        if cached:
            return cached

        role = Role(
            name=str(role_value),
            privilege_level=self._estimate_privilege_level(str(role_value)),
            assigned_by=metadata.get("location", "unknown"),
            assignment_method=detection["detection_type"].replace("role_in_", ""),
            assignment_location=metadata.get("role_field"),
            source="detection",
            confidence=detection["confidence"],
            metadata={"exploitability": metadata.get("exploitability", 0.0)},
        )
        self._role_cache[cache_key] = role
        return role

    def _create_cors_trust(self, endpoint: Endpoint, detection: DetectionResult) -> Trusts:
        metadata = detection["metadata"]
        return Trusts(
            source_id=endpoint.id,
            target_id=endpoint.id,
            trust_type=TrustType.CORS,
            cors_origin=metadata.get("origin"),
            cors_credentials=metadata.get("allows_credentials", False),
            exploitability=metadata.get("exploitability", 0.0),
            confidence=detection["confidence"],
            evidence=[f"CORS origin: {metadata.get('origin')}"],
            vulnerabilities=["wildcard_cors"] if metadata.get("origin") == "*" else [],
        )

    def _detect_auth_requirement(
        self,
        transaction: RawHTTPTransaction,
        detections: list[DetectionResult],
    ) -> bool:
        has_auth_header = any(
            header in transaction.request_headers
            for header in ["Authorization", "X-Auth-Token", "X-API-Key"]
        )
        has_validation = any(
            detection["detection_type"] == "token_validation" for detection in detections
        )
        requires_auth_status = transaction.status_code in [401, 403]
        return has_auth_header or has_validation or requires_auth_status

    def _detect_auth_type(
        self,
        transaction: RawHTTPTransaction,
        detections: list[DetectionResult],
    ) -> AuthType:
        auth_header = transaction.request_headers.get("Authorization", "")

        if auth_header.startswith("Bearer "):
            has_jwt = any(
                detection["detection_type"] == "jwt_in_request" for detection in detections
            )
            return AuthType.JWT if has_jwt else AuthType.BEARER
        if auth_header.startswith("Basic "):
            return AuthType.BASIC
        if "X-API-Key" in transaction.request_headers:
            return AuthType.API_KEY
        if "Cookie" in transaction.request_headers or "Set-Cookie" in transaction.response_headers:
            return AuthType.COOKIE
        return AuthType.NONE

    def _determine_trust_zone(self, transaction: RawHTTPTransaction, requires_auth: bool) -> str:
        path_lower = transaction.path.lower()
        if "/admin" in path_lower:
            return "admin"
        if "/internal" in path_lower:
            return "internal"
        if "/api" in path_lower and requires_auth:
            return "internal"
        if not requires_auth:
            return "external"
        return "internal"

    def _parse_query_params(self, url: str) -> dict[str, list[str]]:
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(url)
        return parse_qs(parsed.query)

    def _estimate_privilege_level(self, role_name: str) -> int:
        role_lower = role_name.lower()
        if any(term in role_lower for term in ["admin", "root", "superuser", "administrator"]):
            return 90
        if any(term in role_lower for term in ["moderator", "manager", "editor", "staff"]):
            return 60
        if any(term in role_lower for term in ["user", "member", "customer"]):
            return 20
        if any(term in role_lower for term in ["guest", "anonymous", "public"]):
            return 0
        return 10

    def _determine_sensitivity(self, path_lower: str) -> SensitivityLevel:
        if any(term in path_lower for term in ["admin", "secret", "credential", "payment", "billing"]):
            return SensitivityLevel.RESTRICTED
        if any(term in path_lower for term in ["user", "profile", "account", "token", "key"]):
            return SensitivityLevel.CONFIDENTIAL
        if any(term in path_lower for term in ["internal", "report", "analytics"]):
            return SensitivityLevel.INTERNAL
        return SensitivityLevel.UNKNOWN

    def _default_port(self, protocol: str) -> int:
        return 443 if protocol == "https" else 80

    def _normalize_audience(self, value: Any) -> list[str] | None:
        if value is None:
            return None
        if isinstance(value, list):
            return [str(item) for item in value if item]
        return [str(value)]

    def _determine_access_type(self, method: str) -> AccessType:
        method_upper = method.upper()
        if method_upper == "GET":
            return AccessType.READ
        if method_upper in {"POST", "PUT", "PATCH"}:
            return AccessType.WRITE
        if method_upper == "DELETE":
            return AccessType.DELETE
        return AccessType.READ

    def _extract_data_fields(
        self,
        transaction: RawHTTPTransaction,
        detections: list[DetectionResult],
    ) -> list[str]:
        fields: set[str] = set()
        haystack = f"{transaction.path} {transaction.response_body or ''}".lower()
        for token in ["email", "password", "token", "secret", "profile", "account", "payment"]:
            if token in haystack:
                fields.add(token)
        for detection in detections:
            indicator = detection["metadata"].get("indicator")
            if indicator:
                fields.add(str(indicator))
        return sorted(fields)

    def _infer_data_classification(
        self,
        transaction: RawHTTPTransaction,
        detections: list[DetectionResult],
    ) -> list[str]:
        mapping = {
            "password": "credentials",
            "token": "api_keys",
            "credit_card": "financial",
            "payment": "financial",
            "ssn": "pii",
            "profile": "pii",
            "user": "pii",
        }
        haystack = f"{transaction.path} {transaction.response_body or ''}".lower()
        values = {classification for key, classification in mapping.items() if key in haystack}
        for detection in detections:
            indicator = str(detection["metadata"].get("indicator", "")).lower()
            classification = mapping.get(indicator)
            if classification:
                values.add(classification)
        return sorted(values)

    def _infer_compliance_tags(
        self,
        transaction: RawHTTPTransaction,
        detections: list[DetectionResult],
    ) -> list[str]:
        classes = self._infer_data_classification(transaction, detections)
        tags = set()
        if "financial" in classes:
            tags.add("pci-dss")
        if "pii" in classes:
            tags.add("gdpr")
        if "health" in classes:
            tags.add("hipaa")
        return sorted(tags)

    def _estimate_endpoint_privilege(self, endpoint: Endpoint, roles: list[Role]) -> int:
        if roles:
            return max(role.privilege_level for role in roles)
        if endpoint.trust_zone == "admin":
            return 90
        if endpoint.requires_auth:
            return 20
        return 0

    def _create_personas(
        self,
        endpoint: Endpoint,
        roles: list[Role],
        tokens: list[Token],
    ) -> list[UserPersona]:
        defaults = [
            {
                "name": "Unauthenticated Attacker",
                "description": "External actor without valid credentials.",
                "has_account": False,
                "privilege_level": 0,
                "starting_position": "external",
                "attack_goals": ["reconnaissance", "initial_access"],
            },
            {
                "name": "Low-Privilege User",
                "description": "Authenticated user with standard application permissions.",
                "has_account": True,
                "privilege_level": 20,
                "starting_position": "internal" if endpoint.requires_auth else "external",
                "attack_goals": ["privilege_escalation", "data_access"],
            },
            {
                "name": "Partner Integration",
                "description": "Semi-trusted external system calling exposed APIs.",
                "has_account": True,
                "privilege_level": 35,
                "starting_position": "dmz",
                "attack_goals": ["lateral_movement", "service_abuse"],
            },
        ]

        personas: list[UserPersona] = []
        for config in defaults:
            cache_key = config["name"]
            cached = self._persona_cache.get(cache_key)
            if cached:
                personas.append(cached)
                continue

            persona = UserPersona(
                name=config["name"],
                description=config["description"],
                has_account=config["has_account"],
                role_ids=[str(role.id) for role in roles if role.privilege_level <= config["privilege_level"]],
                privilege_level=config["privilege_level"],
                has_tokens=[str(token.id) for token in tokens] if config["has_account"] else [],
                can_access_endpoints=[str(endpoint.id)],
                starting_position=config["starting_position"],
                attack_goals=config["attack_goals"],
                source="derived",
                confidence=0.65,
            )
            self._persona_cache[cache_key] = persona
            personas.append(persona)

        return personas

    def _infer_role_escalations(self, roles: list[Role]) -> list[EscalatesTo]:
        unique_roles = {role.name.lower(): role for role in roles}
        ordered = sorted(unique_roles.values(), key=lambda role: role.privilege_level)
        relationships: list[EscalatesTo] = []

        for current, target in zip(ordered, ordered[1:]):
            if target.privilege_level <= current.privilege_level:
                continue
            relationships.append(
                EscalatesTo(
                    source_id=current.id,
                    target_id=target.id,
                    escalation_method="role_manipulation",
                    difficulty=0.35 if current.assignment_method in {"parameter", "header"} else 0.55,
                    prerequisites=[f"Control {target.assignment_location or 'role value'}"],
                    exploits_vulnerability=True,
                    vulnerability_type="authorization_logic_flaw",
                    detectability=0.45,
                    confidence=0.7,
                    evidence=[f"Observed privilege ladder from {current.name} to {target.name}"],
                )
            )

        return relationships

    def _role_bypass_methods(self, assignment_method: str | None) -> list[str]:
        if assignment_method == "parameter":
            return ["parameter_manipulation"]
        if assignment_method == "header":
            return ["header_spoofing"]
        if assignment_method == "jwt":
            return ["token_forgery"]
        return []
