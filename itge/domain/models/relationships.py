"""
Relationship models for graph edges.

Relationships connect entities and carry metadata about
the nature and strength of the connection.
"""

from enum import Enum
from typing import Literal, Optional

from pydantic import Field

from .base import BaseRelationship


class TrustType(str, Enum):
    """Types of trust relationships"""
    CORS = "cors"
    HEADER_FORWARDING = "header_forwarding"
    SERVICE_MESH = "service_mesh"
    MUTUAL_TLS = "mutual_tls"
    IP_WHITELIST = "ip_whitelist"
    SHARED_SECRET = "shared_secret"
    IMPLICIT = "implicit"


class ForwardType(str, Enum):
    """Types of forwarding"""
    REDIRECT = "redirect"
    PROXY = "proxy"
    API_CALL = "api_call"
    WEBHOOK = "webhook"
    SSO = "sso"


class AccessType(str, Enum):
    """Types of data access"""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"


class IssuesToken(BaseRelationship):
    """
    IdentityProvider -> Token
    
    Represents token issuance.
    Critical for understanding identity origin.
    
    Design notes:
    - Tracks how tokens are created
    - Method indicates OAuth flow, login, etc.
    - Confidence based on detection certainty
    """
    
    relationship_type: Literal["issues_token"] = "issues_token"
    
    # Issuance details
    issuance_method: str = Field(
        ...,
        description="How token is issued: 'oauth_flow', 'login_response', 'api_endpoint'",
        min_length=1
    )
    
    endpoint_url: Optional[str] = Field(
        default=None,
        description="Endpoint where token is issued"
    )
    
    # OAuth/OIDC specific
    grant_type: Optional[str] = Field(
        default=None,
        description="OAuth grant type: 'authorization_code', 'client_credentials', 'implicit'"
    )
    
    # Security
    uses_pkce: bool = Field(
        default=False,
        description="Whether PKCE is used (OAuth security)"
    )
    
    uses_state: bool = Field(
        default=False,
        description="Whether state parameter is used (CSRF protection)"
    )


class ValidatesToken(BaseRelationship):
    """
    Endpoint -> Token
    
    Represents token validation.
    Shows which endpoints trust which tokens.
    
    Design notes:
    - Validation method indicates security strength
    - Required flag for access control analysis
    - Bypass potential for vulnerability assessment
    """
    
    relationship_type: Literal["validates_token"] = "validates_token"
    
    # Validation details
    validation_method: str = Field(
        ...,
        description="How token is validated: 'jwt_signature', 'session_lookup', 'api_call', 'none'",
        min_length=1
    )
    
    validation_location: Optional[str] = Field(
        default=None,
        description="Where validation occurs: 'middleware', 'endpoint', 'gateway'"
    )
    
    # Requirements
    required: bool = Field(
        default=True,
        description="Whether token validation is required for access"
    )
    
    # Security assessment
    can_bypass: bool = Field(
        default=False,
        description="Whether validation can be bypassed"
    )
    
    bypass_methods: list[str] = Field(
        default_factory=list,
        description="Known bypass methods: 'algorithm_none', 'missing_validation', 'weak_secret'"
    )
    
    # Token location
    token_location: str = Field(
        default="header",
        description="Where token is expected: 'header', 'cookie', 'query', 'body'"
    )
    
    token_parameter: Optional[str] = Field(
        default=None,
        description="Header/parameter name for token (e.g., 'Authorization', 'session_id')"
    )


class Trusts(BaseRelationship):
    """
    Service/Endpoint -> Service/Endpoint
    
    Represents trust relationship between services.
    Critical for trust boundary analysis.
    
    Design notes:
    - Trust type indicates mechanism (CORS, headers, etc.)
    - Exploitability for attack path scoring
    - Bidirectional flag for mutual trust
    """
    
    relationship_type: Literal["trusts"] = "trusts"
    
    # Trust details
    trust_type: TrustType = Field(
        ...,
        description="Type of trust relationship"
    )
    
    # CORS specific
    cors_origin: Optional[str] = Field(
        default=None,
        description="CORS allowed origin (if trust_type is CORS)"
    )
    
    cors_credentials: bool = Field(
        default=False,
        description="Whether credentials are allowed in CORS"
    )
    
    # Header trust specific
    trusted_headers: list[str] = Field(
        default_factory=list,
        description="Headers that are trusted: 'X-Forwarded-For', 'X-User-Id', etc."
    )
    
    # Mutual trust
    is_bidirectional: bool = Field(
        default=False,
        description="Whether trust is mutual"
    )
    
    # Security assessment
    exploitability: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="How exploitable this trust relationship is (0.0-1.0)"
    )
    
    vulnerabilities: list[str] = Field(
        default_factory=list,
        description="Vulnerabilities: 'wildcard_cors', 'reflected_origin', 'header_injection'"
    )


class Forwards(BaseRelationship):
    """
    Endpoint -> Endpoint
    
    Represents request forwarding.
    Important for understanding request flow and potential bypasses.
    
    Design notes:
    - Forward type indicates mechanism
    - Auth preservation for security analysis
    - Transformation for data flow tracking
    """
    
    relationship_type: Literal["forwards"] = "forwards"
    
    # Forwarding details
    forward_type: ForwardType = Field(
        ...,
        description="Type of forwarding"
    )
    
    # Authentication handling
    preserves_auth: bool = Field(
        default=False,
        description="Whether authentication is preserved in forwarding"
    )
    
    adds_auth: bool = Field(
        default=False,
        description="Whether new authentication is added"
    )
    
    strips_auth: bool = Field(
        default=False,
        description="Whether authentication is removed"
    )
    
    # Data transformation
    transforms_data: bool = Field(
        default=False,
        description="Whether data is transformed during forwarding"
    )
    
    transformation_type: Optional[str] = Field(
        default=None,
        description="Type of transformation: 'filter', 'enrich', 'sanitize'"
    )
    
    # Conditions
    conditional: bool = Field(
        default=False,
        description="Whether forwarding is conditional"
    )
    
    conditions: list[str] = Field(
        default_factory=list,
        description="Forwarding conditions"
    )


class Accesses(BaseRelationship):
    """
    Endpoint -> DataStore
    
    Represents data access.
    Primary relationship for impact analysis.
    
    Design notes:
    - Access type for operation analysis
    - Required privilege for access control
    - Query pattern for SQL injection, etc.
    """
    
    relationship_type: Literal["accesses"] = "accesses"
    
    # Access details
    access_type: AccessType = Field(
        ...,
        description="Type of access operation"
    )
    
    # Access control
    requires_auth: bool = Field(
        default=True,
        description="Whether authentication is required"
    )
    
    required_privilege_level: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Minimum privilege level required"
    )
    
    required_roles: list[str] = Field(
        default_factory=list,
        description="Role names required for access"
    )
    
    # Query details
    query_pattern: Optional[str] = Field(
        default=None,
        description="Query pattern (sanitized, no actual data)"
    )
    
    uses_parameterized_queries: bool = Field(
        default=True,
        description="Whether parameterized queries are used (SQL injection protection)"
    )
    
    # Data scope
    data_fields: list[str] = Field(
        default_factory=list,
        description="Data fields accessed"
    )
    
    filters_data: bool = Field(
        default=False,
        description="Whether data is filtered based on user context"
    )


class EscalatesTo(BaseRelationship):
    """
    Role -> Role
    
    Represents privilege escalation path.
    Critical for privilege escalation analysis.
    
    Design notes:
    - Escalation method for exploit development
    - Difficulty for exploitability scoring
    - Prerequisites for attack path planning
    """
    
    relationship_type: Literal["escalates_to"] = "escalates_to"
    
    # Escalation details
    escalation_method: str = Field(
        ...,
        description="How escalation occurs: 'parameter_manipulation', 'token_forgery', 'exploit'",
        min_length=1
    )
    
    # Difficulty
    difficulty: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Difficulty of escalation (0.0=easy, 1.0=hard)"
    )
    
    # Prerequisites
    prerequisites: list[str] = Field(
        default_factory=list,
        description="Prerequisites for escalation"
    )
    
    # Vulnerability
    exploits_vulnerability: bool = Field(
        default=False,
        description="Whether escalation exploits a vulnerability"
    )
    
    vulnerability_type: Optional[str] = Field(
        default=None,
        description="Type of vulnerability: 'idor', 'mass_assignment', 'logic_flaw'"
    )
    
    # Detection
    detectability: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="How detectable this escalation is (0.0=undetectable, 1.0=obvious)"
    )


class RequiresRole(BaseRelationship):
    """
    Endpoint -> Role
    
    Represents authorization requirement.
    Shows which endpoints require which roles.
    
    Design notes:
    - Enforcement method for security assessment
    - Bypassable flag for vulnerability detection
    - Fallback behavior for access control analysis
    """
    
    relationship_type: Literal["requires_role"] = "requires_role"
    
    # Enforcement
    enforcement_method: str = Field(
        ...,
        description="How role is enforced: 'jwt_claim', 'parameter', 'header', 'database'",
        min_length=1
    )
    
    enforcement_location: Optional[str] = Field(
        default=None,
        description="Where enforcement occurs: 'middleware', 'endpoint', 'gateway'"
    )
    
    # Security
    bypassable: bool = Field(
        default=False,
        description="Whether role check can be bypassed"
    )
    
    bypass_methods: list[str] = Field(
        default_factory=list,
        description="Known bypass methods"
    )
    
    # Fallback
    has_fallback: bool = Field(
        default=False,
        description="Whether there's a fallback if role check fails"
    )
    
    fallback_behavior: Optional[str] = Field(
        default=None,
        description="Fallback behavior: 'deny', 'allow', 'default_role'"
    )


class CrossesBoundary(BaseRelationship):
    """
    Any -> Any
    
    Represents crossing a trust boundary.
    Meta-relationship for trust boundary analysis.
    
    Design notes:
    - Boundary type for categorization
    - Enforcement strength for weakness detection
    - Zone transition for attack path visualization
    """
    
    relationship_type: Literal["crosses_boundary"] = "crosses_boundary"
    
    # Boundary details
    boundary_type: str = Field(
        ...,
        description="Type of boundary: 'network', 'authentication', 'authorization', 'data'",
        min_length=1
    )
    
    # Zones
    from_zone: str = Field(
        ...,
        description="Source trust zone: 'external', 'dmz', 'internal', 'admin'",
        min_length=1
    )
    
    to_zone: str = Field(
        ...,
        description="Target trust zone: 'external', 'dmz', 'internal', 'admin'",
        min_length=1
    )
    
    # Enforcement
    enforcement_strength: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="How well the boundary is enforced (0.0=none, 1.0=strong)"
    )
    
    enforced_by: list[str] = Field(
        default_factory=list,
        description="What enforces the boundary: service names, firewall, etc."
    )
    
    # Requirements
    requires_authentication: bool = Field(
        default=False,
        description="Whether authentication is required to cross"
    )
    
    requires_authorization: bool = Field(
        default=False,
        description="Whether authorization is required to cross"
    )
    
    required_privilege_level: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Minimum privilege level to cross"
    )
