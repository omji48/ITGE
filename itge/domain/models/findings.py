"""
Trust finding models - structured output from trust detection.

Represents security findings from trust analysis.
"""

from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class FindingSeverity(str, Enum):
    """Severity levels for findings"""
    CRITICAL = "critical"  # Immediate exploitation possible
    HIGH = "high"          # Likely exploitable
    MEDIUM = "medium"      # Potentially exploitable
    LOW = "low"            # Informational
    INFO = "info"          # No direct security impact


class FindingCategory(str, Enum):
    """Categories of trust findings"""
    JWT_TRUST = "jwt_trust"
    OAUTH_TRUST = "oauth_trust"
    HEADER_TRUST = "header_trust"
    ROLE_MISUSE = "role_misuse"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    TOKEN_VALIDATION = "token_validation"
    TRUST_BOUNDARY = "trust_boundary"


class TrustFinding(BaseModel):
    """
    Structured trust finding from detection engine.
    
    Represents a detected trust issue with evidence and scoring.
    """
    
    id: UUID = Field(default_factory=uuid4)
    
    # Classification
    category: FindingCategory
    severity: FindingSeverity
    title: str
    description: str
    
    # Scoring
    confidence: float = Field(ge=0.0, le=1.0)
    exploitability: float = Field(ge=0.0, le=1.0)
    impact: float = Field(ge=0.0, le=1.0)
    
    # Evidence
    evidence: list[str] = Field(default_factory=list)
    affected_entities: list[UUID] = Field(default_factory=list)
    
    # Context
    endpoint_url: str | None = None
    method: str | None = None
    
    # Remediation
    recommendation: str | None = None
    references: list[str] = Field(default_factory=list)
    
    # Metadata
    metadata: dict = Field(default_factory=dict)
    
    def get_risk_score(self) -> float:
        """
        Calculate composite risk score.
        
        Risk = Confidence × Exploitability × Impact
        """
        return self.confidence * self.exploitability * self.impact


class JWTTrustFinding(TrustFinding):
    """JWT-specific trust finding"""
    
    category: FindingCategory = FindingCategory.JWT_TRUST
    
    # JWT-specific fields
    token_id: UUID | None = None
    issuer: str | None = None
    algorithm: str | None = None
    audience: list[str] | None = None


class OAuthTrustFinding(TrustFinding):
    """OAuth-specific trust finding"""
    
    category: FindingCategory = FindingCategory.OAUTH_TRUST
    
    # OAuth-specific fields
    provider_id: UUID | None = None
    flow_type: str | None = None
    client_id: str | None = None


class HeaderTrustFinding(TrustFinding):
    """Header-based trust finding"""
    
    category: FindingCategory = FindingCategory.HEADER_TRUST
    
    # Header-specific fields
    header_name: str
    header_value: str | None = None
    trusted_by_endpoints: list[UUID] = Field(default_factory=list)


class RoleMisuseFinding(TrustFinding):
    """Role parameter misuse finding"""
    
    category: FindingCategory = FindingCategory.ROLE_MISUSE
    
    # Role-specific fields
    role_name: str
    role_location: str  # "query", "body", "header", "jwt"
    parameter_name: str | None = None
    privilege_level: int | None = None
