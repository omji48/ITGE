"""
Trust detection service - orchestrates all trust analyzers.
"""

from __future__ import annotations

from typing import Any

from ...domain.models.asset import Endpoint
from ...domain.models.findings import TrustFinding
from ...domain.models.identity import IdentityProvider, Role, Token
from ...infrastructure.analyzers import (
    HeaderTrustAnalyzer,
    JWTTrustAnalyzer,
    OAuthTrustAnalyzer,
    RoleMisuseAnalyzer,
)
from ...infrastructure.normalizers.traffic_normalizer import NormalizationResult


class TrustDetectionService:
    """Runs the trust analyzers over a normalization result."""

    def __init__(self) -> None:
        self.jwt_analyzer = JWTTrustAnalyzer()
        self.oauth_analyzer = OAuthTrustAnalyzer()
        self.header_analyzer = HeaderTrustAnalyzer()
        self.role_analyzer = RoleMisuseAnalyzer()
        self.all_findings: list[TrustFinding] = []

    def analyze_normalization_result(self, result: NormalizationResult) -> list[TrustFinding]:
        findings: list[TrustFinding] = []
        primary_endpoint = result.endpoints[0] if result.endpoints else None

        for endpoint in result.endpoints:
            findings.extend(self.analyze_endpoint(endpoint))

        for token in result.tokens:
            findings.extend(
                self.analyze_token(token, str(primary_endpoint.url) if primary_endpoint else None)
            )

        for provider in result.identity_providers:
            findings.extend(self.analyze_provider(provider, primary_endpoint))

        for role in result.roles:
            findings.extend(self.analyze_role(role, primary_endpoint))

        self.all_findings.extend(findings)
        return findings

    def analyze_endpoint(self, endpoint: Endpoint) -> list[TrustFinding]:
        return list(self.header_analyzer.analyze_endpoint(endpoint))

    def analyze_token(
        self,
        token: Token,
        endpoint_url: str | None = None,
    ) -> list[TrustFinding]:
        return list(self.jwt_analyzer.analyze_token(token, endpoint_url))

    def analyze_provider(
        self,
        provider: IdentityProvider,
        authorization_endpoint: Endpoint | None = None,
    ) -> list[TrustFinding]:
        return list(self.oauth_analyzer.analyze_provider(provider, authorization_endpoint))

    def analyze_role(
        self,
        role: Role,
        endpoint: Endpoint | None = None,
    ) -> list[TrustFinding]:
        return list(self.role_analyzer.analyze_role(role, endpoint))

    def get_findings_by_severity(self, severity: str) -> list[TrustFinding]:
        from ...domain.models.findings import FindingSeverity

        severity_enum = FindingSeverity(severity.lower())
        return [finding for finding in self.all_findings if finding.severity == severity_enum]

    def get_findings_by_category(self, category: str) -> list[TrustFinding]:
        from ...domain.models.findings import FindingCategory

        category_enum = FindingCategory(category.lower())
        return [finding for finding in self.all_findings if finding.category == category_enum]

    def get_high_risk_findings(self, risk_threshold: float = 0.7) -> list[TrustFinding]:
        return [finding for finding in self.all_findings if finding.get_risk_score() >= risk_threshold]

    def get_statistics(self) -> dict[str, Any]:
        from collections import Counter
        from ...domain.models.findings import FindingSeverity

        severity_counts = Counter(finding.severity.value for finding in self.all_findings)
        category_counts = Counter(finding.category.value for finding in self.all_findings)

        return {
            "total_findings": len(self.all_findings),
            "by_severity": dict(severity_counts),
            "by_category": dict(category_counts),
            "critical_count": severity_counts.get(FindingSeverity.CRITICAL.value, 0),
            "high_count": severity_counts.get(FindingSeverity.HIGH.value, 0),
            "medium_count": severity_counts.get(FindingSeverity.MEDIUM.value, 0),
            "low_count": severity_counts.get(FindingSeverity.LOW.value, 0),
            "average_confidence": (
                sum(finding.confidence for finding in self.all_findings) / len(self.all_findings)
                if self.all_findings
                else 0
            ),
            "average_risk_score": (
                sum(finding.get_risk_score() for finding in self.all_findings) / len(self.all_findings)
                if self.all_findings
                else 0
            ),
        }

    def reset(self) -> None:
        self.jwt_analyzer = JWTTrustAnalyzer()
        self.oauth_analyzer = OAuthTrustAnalyzer()
        self.header_analyzer = HeaderTrustAnalyzer()
        self.role_analyzer = RoleMisuseAnalyzer()
        self.all_findings = []
