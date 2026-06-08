"""
Identity models: IdentityProvider, Token, Role, UserPersona

These models represent the identity and access control layer,
which is central to trust boundary analysis.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import Field, HttpUrl, field_validator

from .base import BaseEntity


class ProviderType(str, Enum):
    """Identity provider types"""
    OAUTH = "oauth"
    SAML = "saml"
    OIDC = "oidc"
    JWT = "jwt"
    SESSION = "session"
    API_KEY = "api_key"
    BASIC_AUTH = "basic_auth"
    CUSTOM = "custom"


class TokenType(str, Enum):
    """Token types"""
    JWT = "jwt"
    SESSION_COOKIE = "session_cookie"
    API_KEY = "api_key"
    BEARER = "bearer"
    OAUTH_ACCESS = "oauth_access"
    OAUTH_REFRESH = "oauth_refresh"
    SAML_ASSERTION = "saml_assertion"
    CUSTOM = "custom"


class IdentityProvider(BaseEntity):
    """
    Identity issuance point.
    
    Represents a system that issues identity tokens/credentials.
    Examples: OAuth server, login endpoint, JWT issuer.
    
    Design notes:
    - Tracks where identities originate
    - Critical for trust boundary analysis
    - Issuer field for JWT validation
    """
    
    entity_type: Literal["identity_provider"] = "identity_provider"
    
    # Identification
    name: str = Field(
        ...,
        description="Provider name (e.g., 'Google OAuth', 'Internal Login')",
        min_length=1
    )
    
    provider_type: ProviderType = Field(
        ...,
        description="Type of identity provider"
    )
    
    # Issuer identification (for JWT/SAML)
    issuer: Optional[str] = Field(
        default=None,
        description="Issuer identifier (JWT 'iss' claim, SAML issuer)"
    )
    
    # OAuth/OIDC endpoints
    authorization_endpoint: Optional[HttpUrl] = Field(
        default=None,
        description="OAuth authorization endpoint"
    )
    
    token_endpoint: Optional[HttpUrl] = Field(
        default=None,
        description="OAuth token endpoint"
    )
    
    userinfo_endpoint: Optional[HttpUrl] = Field(
        default=None,
        description="OIDC userinfo endpoint"
    )
    
    jwks_uri: Optional[HttpUrl] = Field(
        default=None,
        description="JSON Web Key Set URI for token validation"
    )
    
    # OAuth/OIDC configuration
    client_id: Optional[str] = Field(
        default=None,
        description="OAuth client ID (if discovered)"
    )
    
    scopes: list[str] = Field(
        default_factory=list,
        description="Supported OAuth scopes"
    )
    
    # Trust relationships
    trusted_by: list[str] = Field(
        default_factory=list,
        description="Services/endpoints that trust this provider"
    )
    
    # Security
    supports_pkce: bool = Field(
        default=False,
        description="Whether PKCE is supported (OAuth security)"
    )
    
    supports_state: bool = Field(
        default=False,
        description="Whether state parameter is used (CSRF protection)"
    )


class Token(BaseEntity):
    """
    Identity token (JWT, session cookie, API key, etc.).
    
    Represents a credential that proves identity.
    Central to authentication and authorization analysis.
    
    Design notes:
    - Tracks token issuance and validation
    - JWT claims for authorization analysis
    - Expiration for session management
    - Validation method for security assessment
    """
    
    entity_type: Literal["token"] = "token"
    
    # Type
    token_type: TokenType = Field(
        ...,
        description="Type of token"
    )
    
    # JWT-specific fields
    issuer: Optional[str] = Field(
        default=None,
        description="JWT 'iss' claim - who issued this token"
    )
    
    audience: Optional[list[str]] = Field(
        default=None,
        description="JWT 'aud' claim - intended recipients"
    )
    
    subject: Optional[str] = Field(
        default=None,
        description="JWT 'sub' claim - subject identifier"
    )
    
    claims: dict[str, Any] = Field(
        default_factory=dict,
        description="JWT claims or token payload"
    )
    
    algorithm: Optional[str] = Field(
        default=None,
        description="JWT signing algorithm (e.g., 'HS256', 'RS256')"
    )
    
    # Session cookie specific
    cookie_name: Optional[str] = Field(
        default=None,
        description="Cookie name (for session tokens)"
    )
    
    cookie_attributes: dict[str, str] = Field(
        default_factory=dict,
        description="Cookie attributes: 'HttpOnly', 'Secure', 'SameSite'"
    )
    
    # API key specific
    key_location: Optional[str] = Field(
        default=None,
        description="Where key is sent: 'header', 'query', 'body'"
    )
    
    key_name: Optional[str] = Field(
        default=None,
        description="Parameter/header name for API key"
    )
    
    # Validation
    validated_by: list[str] = Field(
        default_factory=list,
        description="Endpoint IDs that validate this token"
    )
    
    validation_method: Optional[str] = Field(
        default=None,
        description="How token is validated: 'signature', 'database', 'cache', 'none'"
    )
    
    # Lifecycle
    issued_at: Optional[datetime] = Field(
        default=None,
        description="When token was issued (JWT 'iat')"
    )
    
    expires_at: Optional[datetime] = Field(
        default=None,
        description="When token expires (JWT 'exp')"
    )
    
    can_refresh: bool = Field(
        default=False,
        description="Whether token can be refreshed"
    )
    
    # Security assessment
    is_secure: bool = Field(
        default=True,
        description="Security assessment (strong algorithm, proper validation)"
    )
    
    vulnerabilities: list[str] = Field(
        default_factory=list,
        description="Detected vulnerabilities: 'weak_secret', 'no_expiration', 'algorithm_none'"
    )
    
    @field_validator('algorithm')
    @classmethod
    def validate_algorithm(cls, v: Optional[str]) -> Optional[str]:
        """Flag weak algorithms"""
        if v and v.lower() in ['none', 'hs256']:
            # HS256 is not weak per se, but requires careful secret management
            # 'none' algorithm is a critical vulnerability
            pass
        return v


class Role(BaseEntity):
    """
    User role or privilege level.
    
    Represents authorization level within the system.
    Critical for privilege escalation analysis.
    
    Design notes:
    - Privilege level (0-100) for quantitative comparison
    - Permissions list for capability analysis
    - Escalation paths for attack modeling
    """
    
    entity_type: Literal["role"] = "role"
    
    # Identification
    name: str = Field(
        ...,
        description="Role name (e.g., 'admin', 'user', 'guest')",
        min_length=1
    )
    
    # Privilege quantification
    privilege_level: int = Field(
        ...,
        ge=0,
        le=100,
        description="Privilege level: 0=lowest (guest), 100=highest (superadmin)"
    )
    
    # Capabilities
    permissions: list[str] = Field(
        default_factory=list,
        description="Permissions granted to this role"
    )
    
    # Assignment
    assigned_by: Optional[str] = Field(
        default=None,
        description="How role is assigned: identity provider, endpoint, claim"
    )
    
    assignment_method: Optional[str] = Field(
        default=None,
        description="Assignment mechanism: 'jwt_claim', 'parameter', 'header', 'database'"
    )
    
    assignment_location: Optional[str] = Field(
        default=None,
        description="Where role is specified: claim name, parameter name, header name"
    )
    
    # Escalation potential
    can_escalate_to: list[str] = Field(
        default_factory=list,
        description="Role names this role can escalate to"
    )
    
    escalation_methods: list[str] = Field(
        default_factory=list,
        description="Methods for escalation: 'parameter_manipulation', 'token_forgery'"
    )
    
    # Security
    is_default: bool = Field(
        default=False,
        description="Whether this is a default role for new users"
    )
    
    requires_approval: bool = Field(
        default=False,
        description="Whether assignment requires manual approval"
    )


class UserPersona(BaseEntity):
    """
    User persona for attack simulation.
    
    Represents a hypothetical attacker starting point.
    Used for attack path modeling from different privilege levels.
    
    Design notes:
    - Starting point for attack path analysis
    - Models different attacker capabilities
    - Links to roles for privilege context
    """
    
    entity_type: Literal["user_persona"] = "user_persona"
    
    # Identification
    name: str = Field(
        ...,
        description="Persona name (e.g., 'Unauthenticated User', 'Low-Privilege User')",
        min_length=1
    )
    
    description: str = Field(
        ...,
        description="Persona description and capabilities",
        min_length=1
    )
    
    # Privilege context
    has_account: bool = Field(
        default=False,
        description="Whether persona has a valid account"
    )
    
    role_ids: list[str] = Field(
        default_factory=list,
        description="Role IDs this persona has"
    )
    
    privilege_level: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Overall privilege level"
    )
    
    # Capabilities
    has_tokens: list[str] = Field(
        default_factory=list,
        description="Token IDs this persona possesses"
    )
    
    can_access_endpoints: list[str] = Field(
        default_factory=list,
        description="Endpoint IDs this persona can access"
    )
    
    # Attack context
    starting_position: str = Field(
        default="external",
        description="Starting trust zone: 'external', 'dmz', 'internal'"
    )
    
    attack_goals: list[str] = Field(
        default_factory=list,
        description="Attack objectives: 'data_exfiltration', 'privilege_escalation'"
    )
