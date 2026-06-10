"""
Explainability Service - generates structured explanations for attack paths.

Analyzes paths and produces JSON + human-readable explanations.
"""

from typing import Any
from uuid import UUID

from ...domain.models.attack_path import AttackPath, AttackPathStep, PathStepType
from ...domain.models.explainability import (
    PathExplanation, ExploitedTrustAssumption, BoundaryCrossing,
    TokenReuseRisk, ComparativeRanking, TrustAssumptionType
)
from ...domain.models.findings import TrustFinding


class ExplainabilityService:
    """
    Generates structured explanations for attack paths.
    
    Produces:
    - Trust assumption analysis
    - Boundary crossing highlights
    - Token reuse risk assessment
    - Comparative ranking explanation
    - Human-readable summaries
    """
    
    def __init__(self):
        self.token_usage_tracker: dict[UUID, list[int]] = {}  # token_id -> [step_numbers]
    
    def explain_path(
        self,
        path: AttackPath,
        all_paths: list[AttackPath] | None = None,
        trust_findings: list[TrustFinding] | None = None
    ) -> PathExplanation:
        """
        Generate complete explanation for attack path.
        
        Args:
            path: Attack path to explain
            all_paths: All paths for comparative ranking
            trust_findings: Related trust findings
        
        Returns:
            PathExplanation with structured data
        """
        
        # Analyze trust assumptions
        trust_assumptions = self._analyze_trust_assumptions(path, trust_findings)
        
        # Analyze boundary crossings
        boundary_crossings = self._analyze_boundary_crossings(path)
        
        # Analyze token reuse
        token_reuse_risks = self._analyze_token_reuse(path)
        
        # Generate comparative ranking
        ranking = self._generate_ranking(path, all_paths or [path])
        
        # Generate step explanations
        step_explanations = self._generate_step_explanations(path)
        
        # Generate risk summary
        risk_summary = self._generate_risk_summary(
            path, trust_assumptions, boundary_crossings, token_reuse_risks
        )
        
        # Generate human-readable summary
        human_summary = self._generate_human_summary(
            path, trust_assumptions, boundary_crossings, token_reuse_risks, ranking
        )
        
        return PathExplanation(
            path_id=path.id,
            path_summary=path.summary,
            trust_assumptions=trust_assumptions,
            boundary_crossings=boundary_crossings,
            token_reuse_risks=token_reuse_risks,
            ranking=ranking,
            step_explanations=step_explanations,
            risk_summary=risk_summary,
            human_readable_summary=human_summary,
            metadata={
                'path_length': path.path_length,
                'risk_score': path.risk_score,
                'strategic_value': path.strategic_value
            }
        )
    
    def _analyze_trust_assumptions(
        self,
        path: AttackPath,
        trust_findings: list[TrustFinding] | None
    ) -> list[ExploitedTrustAssumption]:
        """Identify trust assumptions exploited in the path"""
        
        assumptions: list[ExploitedTrustAssumption] = []
        
        for step in path.steps:
            # Check for header-based trust
            if 'header' in step.relationship_type.lower() or 'header' in step.reasoning.lower():
                assumptions.append(ExploitedTrustAssumption(
                    assumption_type=TrustAssumptionType.HEADER_TRUST,
                    description=f"Server trusts client-controlled headers",
                    source_entity_id=step.source_node_id,
                    source_entity_type=step.source_node_type,
                    source_entity_name=step.source_node_name,
                    target_entity_id=step.target_node_id,
                    target_entity_type=step.target_node_type,
                    target_entity_name=step.target_node_name,
                    exploitability=step.exploitability,
                    impact=0.8,
                    evidence=[f"Step {step.step_number}: {step.action_description}"],
                    exploitation_technique="Manipulate HTTP headers to bypass authentication or authorization checks",
                    metadata={'step_number': step.step_number}
                ))
            
            # Check for token audience issues
            if step.step_type == PathStepType.VALIDATE_TOKEN:
                assumptions.append(ExploitedTrustAssumption(
                    assumption_type=TrustAssumptionType.TOKEN_AUDIENCE,
                    description=f"Token accepted without proper audience validation",
                    source_entity_id=step.source_node_id,
                    source_entity_type=step.source_node_type,
                    source_entity_name=step.source_node_name,
                    target_entity_id=step.target_node_id,
                    target_entity_type=step.target_node_type,
                    target_entity_name=step.target_node_name,
                    exploitability=step.exploitability,
                    impact=0.85,
                    evidence=[
                        f"Step {step.step_number}: Token validation",
                        "Token may be reused across unintended services"
                    ],
                    exploitation_technique="Reuse token obtained from one service to access other services that trust the same issuer",
                    metadata={'step_number': step.step_number}
                ))
            
            # Check for service trust
            if step.step_type == PathStepType.TRUST_RELATIONSHIP:
                assumptions.append(ExploitedTrustAssumption(
                    assumption_type=TrustAssumptionType.SERVICE_TRUST,
                    description=f"Service implicitly trusts requests from another service",
                    source_entity_id=step.source_node_id,
                    source_entity_type=step.source_node_type,
                    source_entity_name=step.source_node_name,
                    target_entity_id=step.target_node_id,
                    target_entity_type=step.target_node_type,
                    target_entity_name=step.target_node_name,
                    exploitability=step.exploitability,
                    impact=0.75,
                    evidence=[f"Step {step.step_number}: {step.reasoning}"],
                    exploitation_technique="Leverage trust relationship to move laterally between services",
                    metadata={'step_number': step.step_number}
                ))
            
            # Check for role parameter misuse
            if 'role' in step.action_description.lower() or step.step_type == PathStepType.REQUIRE_ROLE:
                assumptions.append(ExploitedTrustAssumption(
                    assumption_type=TrustAssumptionType.ROLE_PARAMETER,
                    description=f"Role assignment via client-controlled parameter",
                    source_entity_id=step.source_node_id,
                    source_entity_type=step.source_node_type,
                    source_entity_name=step.source_node_name,
                    target_entity_id=step.target_node_id,
                    target_entity_type=step.target_node_type,
                    target_entity_name=step.target_node_name,
                    exploitability=0.95,
                    impact=0.9,
                    evidence=[f"Step {step.step_number}: Role-based access"],
                    exploitation_technique="Manipulate role parameter in request to claim higher privileges",
                    metadata={'step_number': step.step_number}
                ))
        
        return assumptions
    
    def _analyze_boundary_crossings(self, path: AttackPath) -> list[BoundaryCrossing]:
        """Analyze trust boundary crossings"""
        
        crossings: list[BoundaryCrossing] = []
        
        # Trust zone hierarchy
        zone_hierarchy = {
            'public': 0,
            'external': 1,
            'dmz': 2,
            'internal': 3,
            'admin': 4,
            'privileged': 5
        }
        
        for step in path.steps:
            if step.crosses_boundary:
                from_level = zone_hierarchy.get(step.trust_zone_from.lower(), 0)
                to_level = zone_hierarchy.get(step.trust_zone_to.lower(), 0)
                gap = to_level - from_level
                
                # Determine crossing mechanism
                if step.step_type == PathStepType.VALIDATE_TOKEN:
                    mechanism = "token_validation"
                    auth_strength = "medium"
                elif step.step_type == PathStepType.TRUST_RELATIONSHIP:
                    mechanism = "service_trust"
                    auth_strength = "weak"
                elif step.step_type == PathStepType.ISSUE_TOKEN:
                    mechanism = "authentication"
                    auth_strength = "strong"
                else:
                    mechanism = "implicit_trust"
                    auth_strength = "weak"
                
                # Calculate risk multiplier
                risk_multiplier = 1.0 + (gap * 0.3)
                
                explanation = (
                    f"Crosses from {step.trust_zone_from} to {step.trust_zone_to} "
                    f"via {mechanism}. "
                    f"This represents a {gap}-level trust escalation."
                )
                
                crossings.append(BoundaryCrossing(
                    step_number=step.step_number,
                    from_zone=step.trust_zone_from,
                    to_zone=step.trust_zone_to,
                    zone_gap=gap,
                    source_entity_id=step.source_node_id,
                    source_entity_name=step.source_node_name,
                    target_entity_id=step.target_node_id,
                    target_entity_name=step.target_node_name,
                    crossing_mechanism=mechanism,
                    requires_authentication=step.step_type in [
                        PathStepType.VALIDATE_TOKEN,
                        PathStepType.ISSUE_TOKEN
                    ],
                    authentication_strength=auth_strength,
                    risk_multiplier=risk_multiplier,
                    explanation=explanation
                ))
        
        return crossings
    
    def _analyze_token_reuse(self, path: AttackPath) -> list[TokenReuseRisk]:
        """Analyze token reuse risks"""
        
        risks: list[TokenReuseRisk] = []
        
        # Track token issuance and validation
        token_tracker: dict[str, dict[str, Any]] = {}
        
        for step in path.steps:
            # Track token issuance
            if step.step_type == PathStepType.ISSUE_TOKEN:
                token_key = f"{step.target_node_id}"
                token_tracker[token_key] = {
                    'token_id': step.target_node_id,
                    'token_type': step.target_node_type,
                    'issuer': step.source_node_name,
                    'issued_at_step': step.step_number,
                    'validated_at_steps': [],
                    'accepted_by': []
                }
            
            # Track token validation
            elif step.step_type == PathStepType.VALIDATE_TOKEN:
                token_key = f"{step.source_node_id}"
                
                if token_key in token_tracker:
                    token_tracker[token_key]['validated_at_steps'].append(step.step_number)
                    token_tracker[token_key]['accepted_by'].append({
                        'id': str(step.target_node_id),
                        'name': step.target_node_name,
                        'type': step.target_node_type
                    })
        
        # Generate risks for tokens used multiple times
        for token_key, token_data in token_tracker.items():
            if len(token_data['validated_at_steps']) > 1:
                # Token is reused
                lateral_risk = min(0.5 + (len(token_data['validated_at_steps']) * 0.15), 1.0)
                
                explanation = (
                    f"Token from {token_data['issuer']} is accepted by "
                    f"{len(token_data['accepted_by'])} different services. "
                    f"This enables lateral movement across trust boundaries."
                )
                
                risks.append(TokenReuseRisk(
                    token_id=UUID(str(token_data['token_id'])),
                    token_type=token_data['token_type'],
                    issuer=token_data['issuer'],
                    issued_at_step=token_data['issued_at_step'],
                    reused_at_steps=token_data['validated_at_steps'],
                    reuse_count=len(token_data['validated_at_steps']),
                    missing_audience=True,  # Assumed if reused
                    audience_too_broad=True,
                    actual_audience=None,
                    accepted_by_entities=token_data['accepted_by'],
                    lateral_movement_risk=lateral_risk,
                    explanation=explanation
                ))
        
        return risks
    
    def _generate_ranking(
        self,
        path: AttackPath,
        all_paths: list[AttackPath]
    ) -> ComparativeRanking:
        """Generate comparative ranking explanation"""
        
        # Sort paths by risk score
        sorted_paths = sorted(all_paths, key=lambda p: p.risk_score, reverse=True)
        rank = sorted_paths.index(path) + 1
        
        # Calculate statistics
        avg_score = sum(p.risk_score for p in all_paths) / len(all_paths) if all_paths else 0
        percentile = ((len(all_paths) - rank) / len(all_paths)) * 100 if len(all_paths) > 1 else 100
        
        # Identify key advantages
        advantages = []
        
        if avg_score > 0 and path.risk_score > avg_score:
            advantages.append(f"Risk score {path.risk_score:.2f} is {((path.risk_score / avg_score - 1) * 100):.0f}% higher than average")
        
        if path.boundary_crossings > 0:
            avg_crossings = sum(p.boundary_crossings for p in all_paths) / len(all_paths)
            if path.boundary_crossings >= avg_crossings:
                advantages.append(f"Crosses {path.boundary_crossings} trust boundaries (avg: {avg_crossings:.1f})")
        
        if path.privilege_escalations > 0:
            advantages.append(f"Includes {path.privilege_escalations} privilege escalation{'s' if path.privilege_escalations > 1 else ''}")
        
        if path.path_length < sum(p.path_length for p in all_paths) / len(all_paths):
            advantages.append(f"Shorter path ({path.path_length} steps) than average")
        
        if path.strategic_value in ['CRITICAL', 'HIGH']:
            advantages.append(f"Strategic value: {path.strategic_value}")
        
        if not advantages:
            advantages.append("Viable attack path to target")
        
        # Generate explanation
        explanation = (
            f"This path ranks #{rank} out of {len(all_paths)} discovered paths. "
            f"It scores {path.risk_score:.2f} compared to the average of {avg_score:.2f}, "
            f"placing it in the top {100 - percentile:.0f}% of attack paths."
        )
        
        # Build comparison factors
        factors = [
            {
                'factor': 'Risk Score',
                'this_path': path.risk_score,
                'avg': avg_score
            },
            {
                'factor': 'Path Length',
                'this_path': float(path.path_length),
                'avg': sum(p.path_length for p in all_paths) / len(all_paths)
            },
            {
                'factor': 'Boundary Crossings',
                'this_path': float(path.boundary_crossings),
                'avg': sum(p.boundary_crossings for p in all_paths) / len(all_paths)
            },
            {
                'factor': 'Privilege Escalations',
                'this_path': float(path.privilege_escalations),
                'avg': sum(p.privilege_escalations for p in all_paths) / len(all_paths)
            }
        ]
        
        return ComparativeRanking(
            this_path_rank=rank,
            total_paths=len(all_paths),
            this_path_score=path.risk_score,
            avg_path_score=avg_score,
            score_percentile=percentile,
            factors=factors,
            key_advantages=advantages,
            explanation=explanation
        )
    
    def _generate_step_explanations(self, path: AttackPath) -> list[dict[str, str]]:
        """Generate step-by-step explanations"""
        
        explanations = []
        
        for step in path.steps:
            explanations.append({
                'step': str(step.step_number),
                'action': step.action_description,
                'why': step.reasoning,
                'risk': f"Confidence: {step.confidence:.2f}, Exploitability: {step.exploitability:.2f}"
            })
        
        return explanations
    
    def _generate_risk_summary(
        self,
        path: AttackPath,
        trust_assumptions: list[ExploitedTrustAssumption],
        boundary_crossings: list[BoundaryCrossing],
        token_reuse: list[TokenReuseRisk]
    ) -> dict[str, float | int]:
        """Generate risk summary statistics"""
        
        return {
            'overall_risk_score': path.risk_score,
            'confidence': path.overall_confidence,
            'exploitability': path.overall_exploitability,
            'impact': path.impact_score,
            'trust_gap_multiplier': path.trust_gap_multiplier,
            'exposure_multiplier': path.exposure_multiplier,
            'path_length': path.path_length,
            'boundary_crossings': len(boundary_crossings),
            'privilege_escalations': path.privilege_escalations,
            'trust_assumptions_exploited': len(trust_assumptions),
            'token_reuse_risks': len(token_reuse)
        }
    
    def _generate_human_summary(
        self,
        path: AttackPath,
        trust_assumptions: list[ExploitedTrustAssumption],
        boundary_crossings: list[BoundaryCrossing],
        token_reuse: list[TokenReuseRisk],
        ranking: ComparativeRanking
    ) -> str:
        """Generate human-readable summary"""
        
        lines = []
        
        # Opening
        lines.append(
            f"This attack path allows a {path.start_persona} to reach {path.target_node_name} "
            f"in {path.path_length} steps with a risk score of {path.risk_score:.2f}/1.0."
        )
        
        # Trust assumptions
        if trust_assumptions:
            assumption_types = set(a.assumption_type.value for a in trust_assumptions)
            lines.append(
                f"\nThe path exploits {len(trust_assumptions)} trust assumption(s): "
                f"{', '.join(t.replace('_', ' ') for t in assumption_types)}."
            )
        
        # Boundary crossings
        if boundary_crossings:
            zones = [f"{c.from_zone}→{c.to_zone}" for c in boundary_crossings]
            lines.append(
                f"\nIt crosses {len(boundary_crossings)} trust boundary(ies): {', '.join(zones)}."
            )
        
        # Token reuse
        if token_reuse:
            lines.append(
                f"\nToken reuse enables lateral movement across {sum(r.reuse_count for r in token_reuse)} services."
            )
        
        # Ranking
        lines.append(
            f"\nThis path ranks #{ranking.this_path_rank} out of {ranking.total_paths} paths "
            f"due to: {ranking.key_advantages[0]}."
        )
        
        # Strategic value
        lines.append(
            f"\nStrategic value: {path.strategic_value}. "
            f"Target sensitivity: {path.target_sensitivity or 'unknown'}."
        )
        
        return " ".join(lines)
