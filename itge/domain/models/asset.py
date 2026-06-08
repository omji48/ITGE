"""
Asset models: Endpoint, Service, DataStore

Assets are discoverable entities in the target environment.
They represent attack surface and potential targets.
"""

from enum import Enum
from typing import Literal, Optional

from pydantic import Field, HttpUrl, field_validator

from .base import BaseEntity


class HTTPMethod(str, Enum):
    """Standard HTTP methods"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"
    CONNECT = "CONNECT"


class AuthType(str, Enum):
    """Authentication types"""
    NONE = "none"
    BEARER = "bearer"
    BASIC = "basic"
    DIGEST = "digest"
    API_KEY = "api_key"
    COOKIE = "cookie"
    OAUTH = "oauth"
    JWT = "jwt"
    CUSTOM = "custom"


class SensitivityLevel(str, Enum):
    """Data sensitivity classification"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    UNKNOWN = "unknown"


class Endpoint(BaseEntity):
    """
    HTTP/API endpoint.
    
    Represents a single HTTP endpoint that can be accessed,
    potentially requiring authentication/authorization.
    
    Design notes:
    - URL is the primary identifier for deduplication
    - Request/response data stored for analysis
    - Auth requirements detected and stored
    - Sensitivity flag for data access endpoints
    """
    
    entity_type: Literal["endpoint"] = "endpoint"
    
    # URL components
    url: HttpUrl = Field(
        ...,
        description="Full URL of the endpoint"
    )
    
    method: HTTPMethod = Field(
        ...,
        description="HTTP method"
    )
    
    host: str = Field(
        ...,
        description="Hostname (e.g., 'api.example.com')",
        min_length=1
    )
    
    path: str = Field(
        ...,
        description="URL path (e.g., '/api/v1/users')",
        min_length=1
    )
    
    query_params: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Query parameters (key -> list of values)"
    )
    
    # Request data
    request_headers: dict[str, str] = Field(
        default_factory=dict,
        description="HTTP request headers"
    )
    
    request_body: Optional[str] = Field(
        default=None,
        description="Request body (if applicable)"
    )
    
    # Response data
    response_headers: dict[str, str] = Field(
        default_factory=dict,
        description="HTTP response headers"
    )
    
    response_body: Optional[str] = Field(
        default=None,
        description="Response body (truncated if large)"
    )
    
    status_code: Optional[int] = Field(
        default=None,
        ge=100,
        le=599,
        description="HTTP status code"
    )
    
    # Authentication/Authorization
    requires_auth: bool = Field(
        default=False,
        description="Whether this endpoint requires authentication"
    )
    
    auth_type: AuthType = Field(
        default=AuthType.NONE,
        description="Type of authentication required"
    )
    
    auth_location: Optional[str] = Field(
        default=None,
        description="Where auth token is expected (header name, cookie name, etc.)"
    )
    
    # Security indicators
    sensitive_data: bool = Field(
        default=False,
        description="Whether this endpoint accesses sensitive data"
    )
    
    data_operations: list[str] = Field(
        default_factory=list,
        description="Data operations performed: 'read', 'write', 'delete'"
    )
    
    # Trust zone
    trust_zone: str = Field(
        default="unknown",
        description="Trust zone: 'external', 'dmz', 'internal', 'admin'"
    )
    
    @field_validator('url')
    @classmethod
    def validate_url(cls, v: HttpUrl) -> HttpUrl:
        """Ensure URL is valid HTTP/HTTPS"""
        if v.scheme not in ['http', 'https']:
            raise ValueError("URL must use http or https scheme")
        return v


class Service(BaseEntity):
    """
    Network service or application.
    
    Represents a running service (web server, database, etc.)
    that may host multiple endpoints or be a target itself.
    
    Design notes:
    - Host + port uniquely identify a service
    - Version info for vulnerability correlation
    - CPE for standardized identification
    """
    
    entity_type: Literal["service"] = "service"
    
    # Identification
    name: str = Field(
        ...,
        description="Service name (e.g., 'nginx', 'postgresql')",
        min_length=1
    )
    
    host: str = Field(
        ...,
        description="Hostname or IP address",
        min_length=1
    )
    
    port: int = Field(
        ...,
        ge=1,
        le=65535,
        description="Port number"
    )
    
    protocol: str = Field(
        ...,
        description="Protocol (e.g., 'http', 'https', 'ssh', 'postgresql')",
        min_length=1
    )
    
    # Version information
    version: Optional[str] = Field(
        default=None,
        description="Service version (if detected)"
    )
    
    banner: Optional[str] = Field(
        default=None,
        description="Service banner (from connection)"
    )
    
    cpe: Optional[str] = Field(
        default=None,
        description="Common Platform Enumeration identifier"
    )
    
    # Service characteristics
    is_public: bool = Field(
        default=False,
        description="Whether service is publicly accessible"
    )
    
    tls_enabled: bool = Field(
        default=False,
        description="Whether TLS/SSL is enabled"
    )
    
    # Trust zone
    trust_zone: str = Field(
        default="unknown",
        description="Trust zone: 'external', 'dmz', 'internal', 'admin'"
    )


class DataStore(BaseEntity):
    """
    Data storage endpoint (database, object storage, cache, etc.).
    
    Represents where sensitive data is stored.
    Primary target for attack path analysis.
    
    Design notes:
    - Sensitivity level drives impact scoring
    - Data classification for compliance/risk
    - Access patterns for lateral movement analysis
    """
    
    entity_type: Literal["data_store"] = "data_store"
    
    # Identification
    name: str = Field(
        ...,
        description="Data store name (e.g., 'users_db', 'session_cache')",
        min_length=1
    )
    
    store_type: str = Field(
        ...,
        description="Type: 'database', 's3', 'redis', 'file_system', 'api'",
        min_length=1
    )
    
    # Location
    host: Optional[str] = Field(
        default=None,
        description="Hostname or connection string"
    )
    
    connection_string: Optional[str] = Field(
        default=None,
        description="Connection string (sanitized, no credentials)"
    )
    
    # Sensitivity
    sensitivity_level: SensitivityLevel = Field(
        default=SensitivityLevel.UNKNOWN,
        description="Data sensitivity classification"
    )
    
    data_classification: list[str] = Field(
        default_factory=list,
        description="Data types: 'pii', 'financial', 'health', 'credentials', 'api_keys'"
    )
    
    # Access control
    requires_authentication: bool = Field(
        default=True,
        description="Whether authentication is required"
    )
    
    access_control_type: Optional[str] = Field(
        default=None,
        description="Access control mechanism: 'rbac', 'acl', 'none'"
    )
    
    # Compliance
    compliance_tags: list[str] = Field(
        default_factory=list,
        description="Compliance frameworks: 'gdpr', 'hipaa', 'pci-dss', 'sox'"
    )
    
    # Trust zone
    trust_zone: str = Field(
        default="internal",
        description="Trust zone: 'external', 'dmz', 'internal', 'admin'"
    )
