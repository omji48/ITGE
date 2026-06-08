"""
Attack path models - structured attack path representations.

Represents computed attack paths with scoring and reasoning.
"""

from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class PathStepType(str, Enum):
    """Type of step in attack path"""
    AUTHENTICATE = "authenticate"
    VALIDATE_TOKEN = "validate_token"
    ISSUE_TOKEN = "issue_token"
    TRUST_RELATIONSHIP = "trust_relationship"
    FORWARD_REQUEST = "forward_request"
    ACCESS_DATA = "access_data"
    ESCALATE_PRIVILEGE = "escalate_privilege"
    CROSS_BOUNDARY = "cross_boundary"
    REQUIRE_ROLE = "require_role"


class AttackPathStep(BaseModel):
    """
    Single step in an attack path.
    
    Represents one transition in the graph.
    """
    
    step_number: int
    step_type: PathStepType
    
    # Graph elements
    source_node_id: UUID
    source_node_type: str
    source_node_name: str
    
    target_node_id: UUID
    target_node_type: str
    target_node_name: str
    
    relationship_type: str
    
    # Strategic reasoning
    action_description: str
    reasoning: str
    
    # Scoring
    confidence: float = Field(ge=0.0, le=1.0)
    exploitability: float = Field(ge=0.0, le=1.0)
    
    # Context
    trust_zone_from: str | None = None
    trust_zone_to: str | None = None
    crosses_boundary: bool = False
    
    privilege_from: int | None = None
    privilege_to: int | None = None
    escalates_privilege: bool = False
    
    # Evidence
    evidence: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


class AttackPath(BaseModel):
    """
    Complete attack path from start to target.
    
    Represents a strategic attack sequence.
    """
    
    id: UUID = Field(default_factory=uuid4)
    
    # Path definition
    steps: list[AttackPathStep]
    
    # Start and end
    start_persona: str
    start_privilege: int
    start_trust_zone: str
    
    target_node_id: UUID
    target_node_type: str
    target_node_name: str
    target_sensitivity: str | None = None
    
    # Path metrics
    path_length: int
    boundary_crossings: int
    privilege_escalations: int
    
    # Scoring
    overall_confidence: float = Field(ge=0.0, le=1.0)
    overall_exploitability: float = Field(ge=0.0, le=1.0)
    impact_score: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    
    # Multipliers
    trust_gap_multiplier: float = Field(ge=1.0)
    exposure_multiplier: float = Field(ge=1.0)
    
    # Summary
    summary: str
    strategic_value: str
    
    # Metadata
    metadata: dict = Field(default_factory=dict)
    
    def calculate_risk_score(self) -> float:
        """
        Calculate composite risk score.
        
        Risk = (Confidence × Exploitability × Impact) × TrustGap × Exposure
        """
        base_score = self.overall_confidence * self.overall_exploitability * self.impact_score
        adjusted_score = base_score * self.trust_gap_multiplier * self.exposure_multiplier
        
        # Normalize to 0-1
        self.risk_score = min(adjusted_score, 1.0)
        return self.risk_score
    
    def get_explainable_reasoning(self) -> str:
        """
        Generate human-readable explanation of attack path.
        """
        lines = [
            f"Attack Path: {self.start_persona} → {self.target_node_name}",
            f"",
            f"Summary: {self.summary}",
            f"Strategic Value: {self.strategic_value}",
            f"",
            f"Metrics:",
            f"  Path Length: {self.path_length} steps",
            f"  Boundary Crossings: {self.boundary_crossings}",
            f"  Privilege Escalations: {self.privilege_escalations}",
            f"  Risk Score: {self.risk_score:.2f}",
            f"",
            f"Attack Steps:",
        ]
        
        for step in self.steps:
            lines.append(f"")
            lines.append(f"Step {step.step_number}: {step.action_description}")
            lines.append(f"  {step.source_node_name} → {step.target_node_name}")
            lines.append(f"  Reasoning: {step.reasoning}")
            
            if step.crosses_boundary:
                lines.append(f"  ⚠️  Crosses trust boundary: {step.trust_zone_from} → {step.trust_zone_to}")
            
            if step.escalates_privilege:
                lines.append(f"  ⬆️  Escalates privilege: {step.privilege_from} → {step.privilege_to}")
            
            lines.append(f"  Confidence: {step.confidence:.2f}, Exploitability: {step.exploitability:.2f}")
        
        lines.append(f"")
        lines.append(f"Risk Calculation:")
        lines.append(f"  Base: {self.overall_confidence:.2f} × {self.overall_exploitability:.2f} × {self.impact_score:.2f} = {self.overall_confidence * self.overall_exploitability * self.impact_score:.2f}")
        lines.append(f"  Trust Gap Multiplier: {self.trust_gap_multiplier:.2f}x")
        lines.append(f"  Exposure Multiplier: {self.exposure_multiplier:.2f}x")
        lines.append(f"  Final Risk Score: {self.risk_score:.2f}")
        
        return "\n".join(lines)


class PathSimulationResult(BaseModel):
    """
    Result from path simulation.
    
    Contains all discovered paths with statistics.
    """
    
    # Input parameters
    start_persona: str
    target_criteria: dict
    
    # Results
    paths: list[AttackPath]
    total_paths_found: int
    
    # Statistics
    avg_path_length: float
    avg_risk_score: float
    max_risk_score: float
    
    paths_with_boundary_crossing: int
    paths_with_privilege_escalation: int
    
    # Top paths
    highest_risk_paths: list[AttackPath] = Field(default_factory=list)
    shortest_paths: list[AttackPath] = Field(default_factory=list)
    
    # Metadata
    computation_time_ms: float
    metadata: dict = Field(default_factory=dict)
