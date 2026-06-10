"""
Attack path simulation service - orchestrates path finding and scoring.
"""

from __future__ import annotations

import time
from typing import Any
from uuid import UUID

from ...domain.models.attack_path import (
    AttackPath,
    AttackPathStep,
    PathSimulationResult,
    PathStepType,
)
from ...infrastructure.graph import GraphPathFinder, GraphRepository


class AttackPathSimulationService:
    """Computes strategic attack paths from a persona to target criteria."""

    TRUST_ZONE_HIERARCHY = {
        "public": 0,
        "external": 1,
        "dmz": 2,
        "internal": 3,
        "admin": 4,
        "privileged": 5,
    }

    def __init__(self, repository: GraphRepository):
        self.repository = repository
        self.path_finder = GraphPathFinder()

    async def simulate_attack_paths(
        self,
        start_persona: str,
        start_privilege: int = 0,
        start_trust_zone: str = "public",
        target_criteria: dict[str, Any] | None = None,
        max_hops: int = 10,
        max_paths: int = 50,
    ) -> PathSimulationResult:
        start_time = time.time()

        if target_criteria is None:
            target_criteria = {"label": "DataStore", "sensitivity": "confidential"}

        all_paths: list[AttackPath] = []

        async with self.repository.driver.session() as session:
            raw_paths = await self.path_finder.find_all_paths_from_persona(
                session=session,
                persona_name=start_persona,
                persona_privilege=start_privilege,
                persona_trust_zone=start_trust_zone,
                target_criteria=target_criteria,
                max_hops=max_hops,
            )

            for raw_path in raw_paths[:max_paths]:
                attack_path = await self._convert_to_attack_path(
                    raw_path=raw_path,
                    start_persona=start_persona,
                    start_privilege=start_privilege,
                    start_trust_zone=start_trust_zone,
                )
                if attack_path:
                    all_paths.append(attack_path)

        if all_paths:
            avg_path_length = sum(path.path_length for path in all_paths) / len(all_paths)
            avg_risk_score = sum(path.risk_score for path in all_paths) / len(all_paths)
            max_risk_score = max(path.risk_score for path in all_paths)
            paths_with_boundary = sum(1 for path in all_paths if path.boundary_crossings > 0)
            paths_with_escalation = sum(1 for path in all_paths if path.privilege_escalations > 0)
        else:
            avg_path_length = 0.0
            avg_risk_score = 0.0
            max_risk_score = 0.0
            paths_with_boundary = 0
            paths_with_escalation = 0

        all_paths.sort(key=lambda path: path.risk_score, reverse=True)
        highest_risk = all_paths[:10]
        shortest = sorted(all_paths, key=lambda path: path.path_length)[:10]
        computation_time = (time.time() - start_time) * 1000

        return PathSimulationResult(
            start_persona=start_persona,
            target_criteria=target_criteria,
            paths=all_paths,
            total_paths_found=len(all_paths),
            avg_path_length=avg_path_length,
            avg_risk_score=avg_risk_score,
            max_risk_score=max_risk_score,
            paths_with_boundary_crossing=paths_with_boundary,
            paths_with_privilege_escalation=paths_with_escalation,
            highest_risk_paths=highest_risk,
            shortest_paths=shortest,
            computation_time_ms=computation_time,
        )

    async def _convert_to_attack_path(
        self,
        raw_path: dict[str, Any],
        start_persona: str,
        start_privilege: int,
        start_trust_zone: str,
    ) -> AttackPath | None:
        path_nodes = raw_path["path_nodes"]
        path_rels = raw_path["path_rels"]

        if len(path_nodes) < 2:
            return None

        steps: list[AttackPathStep] = []
        boundary_crossings = 0
        privilege_escalations = 0
        confidences: list[float] = []
        exploitabilities: list[float] = []

        for index, relationship in enumerate(path_rels):
            source_node = path_nodes[index]
            target_node = path_nodes[index + 1]
            rel_type = relationship.get("type", relationship.get("_type", "UNKNOWN"))
            step_type = self._map_relationship_to_step_type(rel_type)

            source_zone = source_node.get("trust_zone", start_trust_zone)
            target_zone = target_node.get("trust_zone", start_trust_zone)
            crosses_boundary = source_zone != target_zone
            if crosses_boundary:
                boundary_crossings += 1

            source_priv = int(source_node.get("privilege_level", start_privilege) or start_privilege)
            target_priv = int(target_node.get("privilege_level", source_priv) or source_priv)
            escalates = target_priv > source_priv
            if escalates:
                privilege_escalations += 1

            confidence = float(relationship.get("confidence", 0.7))
            exploitability = float(
                relationship.get("exploitability", 1 - float(relationship.get("difficulty", 0.4)))
            )
            confidences.append(confidence)
            exploitabilities.append(exploitability)

            action_description, reasoning = self._generate_step_reasoning(
                source_node, target_node, relationship, step_type
            )
            steps.append(
                AttackPathStep(
                    step_number=index + 1,
                    step_type=step_type,
                    source_node_id=UUID(source_node["id"]),
                    source_node_type=source_node.get("_label", "Unknown"),
                    source_node_name=self._get_node_name(source_node),
                    target_node_id=UUID(target_node["id"]),
                    target_node_type=target_node.get("_label", "Unknown"),
                    target_node_name=self._get_node_name(target_node),
                    relationship_type=rel_type,
                    action_description=action_description,
                    reasoning=reasoning,
                    confidence=confidence,
                    exploitability=exploitability,
                    trust_zone_from=source_zone,
                    trust_zone_to=target_zone,
                    crosses_boundary=crosses_boundary,
                    privilege_from=source_priv,
                    privilege_to=target_priv,
                    escalates_privilege=escalates,
                    evidence=[f"Relationship: {rel_type}", f"Confidence: {confidence:.2f}"],
                )
            )

        target_node = path_nodes[-1]
        attack_path = AttackPath(
            steps=steps,
            start_persona=start_persona,
            start_privilege=start_privilege,
            start_trust_zone=start_trust_zone,
            target_node_id=UUID(target_node["id"]),
            target_node_type=target_node.get("_label", "Unknown"),
            target_node_name=self._get_node_name(target_node),
            target_sensitivity=target_node.get("sensitivity_level"),
            path_length=len(steps),
            boundary_crossings=boundary_crossings,
            privilege_escalations=privilege_escalations,
            overall_confidence=sum(confidences) / len(confidences) if confidences else 0.5,
            overall_exploitability=sum(exploitabilities) / len(exploitabilities) if exploitabilities else 0.5,
            impact_score=self._calculate_impact_score(target_node),
            trust_gap_multiplier=self._calculate_trust_gap_multiplier(
                start_trust_zone, target_node.get("trust_zone", start_trust_zone), boundary_crossings
            ),
            exposure_multiplier=self._calculate_exposure_multiplier(path_nodes, steps),
            summary=self._generate_path_summary(
                start_persona,
                target_node,
                len(steps),
                boundary_crossings,
                privilege_escalations,
            ),
            strategic_value=self._assess_strategic_value(
                target_node, boundary_crossings, privilege_escalations
            ),
        )
        attack_path.calculate_risk_score()
        return attack_path

    def _map_relationship_to_step_type(self, rel_type: str) -> PathStepType:
        mapping = {
            "ISSUES_TOKEN": PathStepType.ISSUE_TOKEN,
            "VALIDATES_TOKEN": PathStepType.VALIDATE_TOKEN,
            "TRUSTS": PathStepType.TRUST_RELATIONSHIP,
            "FORWARDS": PathStepType.FORWARD_REQUEST,
            "ACCESSES": PathStepType.ACCESS_DATA,
            "ESCALATES_TO": PathStepType.ESCALATE_PRIVILEGE,
            "CROSSES_BOUNDARY": PathStepType.CROSS_BOUNDARY,
            "REQUIRES_ROLE": PathStepType.REQUIRE_ROLE,
        }
        return mapping.get(rel_type, PathStepType.TRUST_RELATIONSHIP)

    def _get_node_name(self, node: dict[str, Any]) -> str:
        for key in ("url", "name", "issuer", "host"):
            if key in node and node[key]:
                if key == "host":
                    return f"{node['host']}:{node.get('port', 443)}"
                return str(node[key])
        return str(node.get("id", "unknown"))[:8]

    def _generate_step_reasoning(
        self,
        source: dict[str, Any],
        target: dict[str, Any],
        relationship: dict[str, Any],
        step_type: PathStepType,
    ) -> tuple[str, str]:
        source_name = self._get_node_name(source)
        target_name = self._get_node_name(target)

        if step_type == PathStepType.ISSUE_TOKEN:
            return (
                f"Obtain token from {target_name}",
                "Identity provider issues a token that can unlock downstream trust.",
            )
        if step_type == PathStepType.VALIDATE_TOKEN:
            return (
                f"Access {source_name} with a token accepted by the service",
                "Token validation creates a path into protected functionality.",
            )
        if step_type == PathStepType.TRUST_RELATIONSHIP:
            return (
                f"Leverage trust from {source_name} to {target_name}",
                "The target implicitly trusts context or traffic flowing from the source.",
            )
        if step_type == PathStepType.ESCALATE_PRIVILEGE:
            return (
                f"Escalate from {source_name} to {target_name}",
                "A privilege transition increases what the attacker can access next.",
            )
        if step_type == PathStepType.ACCESS_DATA:
            return (
                f"Access sensitive data in {target_name}",
                "This step reaches the data layer and converts trust abuse into impact.",
            )
        if step_type == PathStepType.CROSS_BOUNDARY:
            return (
                f"Cross from {source_name} into {target_name}",
                "The relationship moves the attacker into a higher-trust zone.",
            )
        if step_type == PathStepType.REQUIRE_ROLE:
            return (
                f"Satisfy the role requirement for {source_name}",
                "Access depends on controlling or spoofing the required role context.",
            )
        return (
            f"Transition from {source_name} to {target_name}",
            "The graph relationship allows further movement through the system.",
        )

    def _calculate_impact_score(self, target_node: dict[str, Any]) -> float:
        sensitivity = str(target_node.get("sensitivity_level", "")).lower()
        if sensitivity in {"critical", "restricted"}:
            return 1.0
        if sensitivity == "confidential":
            return 0.9
        if sensitivity == "internal":
            return 0.7
        if sensitivity == "public":
            return 0.3

        privilege = int(target_node.get("privilege_level", 0) or 0)
        if privilege >= 90:
            return 1.0
        if privilege >= 70:
            return 0.85
        if privilege >= 50:
            return 0.7
        return 0.6

    def _calculate_trust_gap_multiplier(self, start_zone: str, end_zone: str, crossings: int) -> float:
        start_level = self.TRUST_ZONE_HIERARCHY.get(start_zone.lower(), 0)
        end_level = self.TRUST_ZONE_HIERARCHY.get(end_zone.lower(), 0)
        gap = max(end_level - start_level, 0)
        return min(1.0 + (gap * 0.25) + (crossings * 0.1), 3.0)

    def _calculate_exposure_multiplier(
        self,
        nodes: list[dict[str, Any]],
        steps: list[AttackPathStep],
    ) -> float:
        public_nodes = sum(
            1 for node in nodes if str(node.get("trust_zone", "")).lower() in {"public", "external"}
        )
        no_auth_nodes = sum(1 for node in nodes if not node.get("requires_auth", True))
        high_exploit_steps = sum(1 for step in steps if step.exploitability >= 0.8)
        multiplier = 1.0 + (public_nodes * 0.15) + (no_auth_nodes * 0.2) + (high_exploit_steps * 0.1)
        return min(multiplier, 3.0)

    def _generate_path_summary(
        self,
        persona: str,
        target: dict[str, Any],
        steps: int,
        boundaries: int,
        escalations: int,
    ) -> str:
        target_name = self._get_node_name(target)
        parts = [f"{persona} can reach {target_name} in {steps} step{'s' if steps != 1 else ''}"]
        if boundaries > 0:
            parts.append(f"crossing {boundaries} trust boundar{'ies' if boundaries != 1 else 'y'}")
        if escalations > 0:
            parts.append(f"escalating privilege {escalations} time{'s' if escalations != 1 else ''}")
        return ", ".join(parts) + "."

    def _assess_strategic_value(
        self,
        target: dict[str, Any],
        boundaries: int,
        escalations: int,
    ) -> str:
        sensitivity = str(target.get("sensitivity_level", "")).lower()
        privilege = int(target.get("privilege_level", 0) or 0)
        if sensitivity in {"critical", "restricted"} or privilege >= 90:
            return "CRITICAL"
        if sensitivity == "confidential" or privilege >= 70:
            return "HIGH"
        if boundaries >= 2 or escalations >= 2:
            return "MEDIUM"
        return "LOW"
