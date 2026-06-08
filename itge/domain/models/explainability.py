"""
Explainability models - structured explanations for attack paths.

Provides JSON-serializable explanations with entity references.
"""

from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field


class TrustAssumptionType(str, Enum):
    """Types of trust assumptions that can be exploited"""
    HEADER_TRUST = "header_trust"
    TOKEN_AUDIENCE = "token_audience"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    ROLE_PARAMETER = "role_parameter"
    IP_TRUST = "ip_trust"
    FORWARDED_HEADER = "forwarded_header"
    SERVICE_TRUST = "service_trust"
    IMPLICIT_TRUST = "implicit_trust"


class ExploitedTrustAssumption(BaseModel):
    """
    Represents a trust assumption exploited in the attack path.
    """
    
    assumption_type: TrustAssumptionType
    description: str
    
    # Entity references
    source_entity_id: UUID
    source_entity_type: str
    source_entity_name: str
    
    target_entity_id: UUID | None = None
    target_entity_type: str | None = None
    target_entity_name: str | None = None
    
    # Details
    exploitability: float = Field(ge=0.0, le=1.0)
    impact: float = Field(ge=0.0, le=1.0)
    
    # Evidence
    evidence: list[str] = Field(default_factory=list)
    
    # How to exploit
    exploitation_technique: str
    
    # Metadata
    metadata: dict = Field(default_factory=dict)


class BoundaryCrossing(BaseModel):
    """
    Represents a trust boundary crossing in the attack path.
    """
    
    step_number: int
    
    # Zones
    from_zone: str
    to_zone: str
    zone_gap: int  # Hierarchy difference
    
    # Entities involved
    source_entity_id: UUID
    source_entity_name: str
    target_entity_id: UUID
    target_entity_name: str
    
    # Crossing details
    crossing_mechanism: str  # "token_validation", "service_trust", etc.
    requires_authentication: bool
    authentication_strength: str | None = None  # "weak", "medium", "strong"
    
    # Risk
    risk_multiplier: float = Field(ge=1.0)
    
    # Explanation
    explanation: str


class TokenReuseRisk(BaseModel):
    """
    Represents token reuse risk in the attack path.
    """
    
    token_id: UUID
    token_type: str
    issuer: str
    
    # Reuse details
    issued_at_step: int
    reused_at_steps: list[int]
    reuse_count: int
    
    # Scope issues
    missing_audience: bool
    audience_too_broad: bool
    actual_audience: list[str] | None = None
    
    # Services where token is accepted
    accepted_by_entities: list[dict[str, str]]  # [{"id": "...", "name": "...", "type": "..."}]
    
    # Risk
    lateral_movement_risk: float = Field(ge=0.0, le=1.0)
    
    # Explanation
    explanation: str


class ComparativeRanking(BaseModel):
    """
    Explains why this path ranks higher than alternatives.
    """
    
    this_path_rank: int
    total_paths: int
    
    # Scoring breakdown
    this_path_score: float
    avg_path_score: float
    score_percentile: float  # 0-100
    
    # Comparison factors
    factors: list[dict[str, str | float]]  # [{"factor": "...", "this_path": ..., "avg": ...}]
    
    # Key advantages
    key_advantages: list[str]
    
    # Explanation
    explanation: str


class PathExplanation(BaseModel):
    """
    Complete structured explanation for an attack path.
    
    Provides both JSON-serializable data and human-readable text.
    """
    
    path_id: UUID
    path_summary: str
    
    # Trust assumptions exploited
    trust_assumptions: list[ExploitedTrustAssumption]
    
    # Boundary crossings
    boundary_crossings: list[BoundaryCrossing]
    
    # Token reuse
    token_reuse_risks: list[TokenReuseRisk]
    
    # Comparative ranking
    ranking: ComparativeRanking
    
    # Step-by-step explanation
    step_explanations: list[dict[str, str]]  # [{"step": 1, "action": "...", "why": "..."}]
    
    # Risk summary
    risk_summary: dict[str, float | int]
    
    # Human-readable summary
    human_readable_summary: str
    
    # Metadata
    metadata: dict = Field(default_factory=dict)
    
    def to_json_dict(self) -> dict:
        """Export as JSON-serializable dictionary"""
        return self.model_dump(mode='json')
    
    def to_markdown(self) -> str:
        """Export as formatted markdown"""
        lines = [
            f"# Attack Path Explanation",
            f"",
            f"**Path ID**: `{self.path_id}`",
            f"",
            f"## Summary",
            f"",
            f"{self.path_summary}",
            f"",
            f"## Trust Assumptions Exploited ({len(self.trust_assumptions)})",
            f""
        ]
        
        for i, assumption in enumerate(self.trust_assumptions, 1):
            lines.extend([
                f"",
                f"### {i}. {assumption.assumption_type.value.replace('_', ' ').title()}",
                f"",
                f"**Description**: {assumption.description}",
                f"",
                f"**Exploits**: {assumption.source_entity_name}",
                f"",
                f"**Technique**: {assumption.exploitation_technique}",
                f"",
                f"**Risk**: Exploitability {assumption.exploitability:.2f}, Impact {assumption.impact:.2f}",
                f""
            ])
        
        if self.boundary_crossings:
            lines.extend([
                f"",
                f"## Trust Boundary Crossings ({len(self.boundary_crossings)})",
                f""
            ])
            
            for crossing in self.boundary_crossings:
                lines.extend([
                    f"",
                    f"**Step {crossing.step_number}**: {crossing.from_zone} → {crossing.to_zone}",
                    f"",
                    f"- Mechanism: {crossing.crossing_mechanism}",
                    f"- Requires Auth: {crossing.requires_authentication}",
                    f"- Risk Multiplier: {crossing.risk_multiplier:.2f}x",
                    f"- {crossing.explanation}",
                    f""
                ])
        
        if self.token_reuse_risks:
            lines.extend([
                f"",
                f"## Token Reuse Risks ({len(self.token_reuse_risks)})",
                f""
            ])
            
            for risk in self.token_reuse_risks:
                lines.extend([
                    f"",
                    f"**Token**: {risk.token_type} from {risk.issuer}",
                    f"",
                    f"- Issued at step {risk.issued_at_step}",
                    f"- Reused at steps: {', '.join(map(str, risk.reused_at_steps))}",
                    f"- Accepted by {len(risk.accepted_by_entities)} services",
                    f"- Lateral movement risk: {risk.lateral_movement_risk:.2f}",
                    f"- {risk.explanation}",
                    f""
                ])
        
        lines.extend([
            f"",
            f"## Ranking",
            f"",
            f"**Rank**: #{self.ranking.this_path_rank} out of {self.ranking.total_paths} paths",
            f"",
            f"**Score**: {self.ranking.this_path_score:.2f} (avg: {self.ranking.avg_path_score:.2f})",
            f"",
            f"**Percentile**: Top {100 - self.ranking.score_percentile:.0f}%",
            f"",
            f"**Why this path ranks higher**:",
            f""
        ])
        
        for advantage in self.ranking.key_advantages:
            lines.append(f"- {advantage}")
        
        lines.extend([
            f"",
            f"## Human-Readable Summary",
            f"",
            f"{self.human_readable_summary}",
            f""
        ])
        
        return "\n".join(lines)
