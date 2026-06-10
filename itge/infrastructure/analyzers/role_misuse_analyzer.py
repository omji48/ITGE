"""
Role Misuse Analyzer - detects role parameter misuse.

Analyzes role assignment mechanisms for security vulnerabilities.
"""

from urllib.parse import urlparse, parse_qs

from ...domain.models.findings import RoleMisuseFinding, FindingSeverity
from ...domain.models.identity import Role
from ...domain.models.asset import Endpoint


class RoleMisuseAnalyzer:
    """
    Analyzes role assignment for misuse patterns.
    
    Detects:
    - Roles in query parameters
    - Roles in request body
    - Roles in headers (client-controlled)
    - Role switching patterns
    - Privilege escalation via role manipulation
    """
    
    def __init__(self):
        self.findings: list[RoleMisuseFinding] = []
        self._role_switches: dict[str, list[tuple[str, str]]] = {}  # endpoint -> [(old_role, new_role)]
    
    def analyze_role(
        self,
        role: Role,
        endpoint: Endpoint | None = None
    ) -> list[RoleMisuseFinding]:
        """
        Analyze role for misuse patterns.
        
        Args:
            role: Role entity to analyze
            endpoint: Optional endpoint where role was observed
        
        Returns:
            List of role misuse findings
        """
        findings: list[RoleMisuseFinding] = []
        
        # Check role assignment method
        if role.assignment_method:
            method = role.assignment_method.lower()
            
            if method in ['parameter', 'query']:
                findings.extend(self._check_role_in_parameter(role, endpoint))
            elif method in ['body', 'post']:
                findings.extend(self._check_role_in_body(role, endpoint))
            elif method in ['header']:
                findings.extend(self._check_role_in_header(role, endpoint))
        
        # Check for high-privilege roles with weak assignment
        findings.extend(self._check_high_privilege_role(role, endpoint))
        
        return findings
    
    def analyze_role_switching(
        self,
        endpoint: Endpoint,
        old_role: str,
        new_role: str
    ) -> list[RoleMisuseFinding]:
        """
        Analyze role switching patterns.
        
        Args:
            endpoint: Endpoint where role switch occurred
            old_role: Previous role
            new_role: New role
        
        Returns:
            List of role misuse findings
        """
        findings: list[RoleMisuseFinding] = []
        
        endpoint_key = endpoint.url
        
        if endpoint_key not in self._role_switches:
            self._role_switches[endpoint_key] = []
        
        self._role_switches[endpoint_key].append((old_role, new_role))
        
        # Check if role switching is happening via client-controlled parameters
        if endpoint.query_params:
            role_params = [k for k in endpoint.query_params.keys() if 'role' in k.lower()]
            
            if role_params:
                findings.append(RoleMisuseFinding(
                    severity=FindingSeverity.CRITICAL,
                    title="Role Switching via Query Parameter",
                    description=f"Endpoint allows role switching from '{old_role}' to '{new_role}' via query parameter. This enables trivial privilege escalation.",
                    confidence=0.95,
                    exploitability=0.95,
                    impact=1.0,
                    evidence=[
                        f"Role switch: {old_role} → {new_role}",
                        f"Role parameter: {role_params[0]}",
                        f"Endpoint: {endpoint.url}",
                        "Client controls role assignment"
                    ],
                    affected_entities=[endpoint.id],
                    endpoint_url=str(endpoint.url),
                    method=endpoint.method.value,
                    recommendation="Remove role parameters from query strings. Assign roles server-side based on authenticated user identity.",
                    references=[
                        "https://owasp.org/www-community/vulnerabilities/Insecure_Direct_Object_Reference",
                        "https://cwe.mitre.org/data/definitions/639.html"
                    ],
                    role_name=new_role,
                    role_location="query",
                    parameter_name=role_params[0],
                    metadata={
                        "old_role": old_role,
                        "new_role": new_role,
                        "cwe": "CWE-639: Authorization Bypass Through User-Controlled Key"
                    }
                ))
        
        return findings
    
    def _check_role_in_parameter(
        self,
        role: Role,
        endpoint: Endpoint | None
    ) -> list[RoleMisuseFinding]:
        """Check for roles in query parameters"""
        findings: list[RoleMisuseFinding] = []
        
        # Determine severity based on privilege level
        if role.privilege_level >= 80:
            severity = FindingSeverity.CRITICAL
            impact = 1.0
        elif role.privilege_level >= 50:
            severity = FindingSeverity.HIGH
            impact = 0.85
        else:
            severity = FindingSeverity.MEDIUM
            impact = 0.70
        
        findings.append(RoleMisuseFinding(
            severity=severity,
            title=f"Role '{role.name}' in Query Parameter",
            description=f"Role '{role.name}' (privilege level {role.privilege_level}/100) is assigned via query parameter. This allows trivial privilege escalation by modifying the URL.",
            confidence=0.90,
            exploitability=0.95,
            impact=impact,
            evidence=[
                f"Role: {role.name}",
                f"Privilege level: {role.privilege_level}/100",
                f"Assignment method: query parameter",
                f"Parameter name: {role.assignment_location}",
                "Client can modify query parameters"
            ],
            affected_entities=[role.id] + ([endpoint.id] if endpoint else []),
            endpoint_url=str(endpoint.url) if endpoint else None,
            method=endpoint.method.value if endpoint else None,
            recommendation="Never assign roles via query parameters. Use server-side session management or cryptographically signed tokens (JWT).",
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema"
            ],
            role_name=role.name,
            role_location="query",
            parameter_name=role.assignment_location,
            privilege_level=role.privilege_level,
            metadata={
                "cwe": "CWE-639: Authorization Bypass Through User-Controlled Key"
            }
        ))
        
        return findings
    
    def _check_role_in_body(
        self,
        role: Role,
        endpoint: Endpoint | None
    ) -> list[RoleMisuseFinding]:
        """Check for roles in request body"""
        findings: list[RoleMisuseFinding] = []
        
        # Determine severity
        if role.privilege_level >= 80:
            severity = FindingSeverity.CRITICAL
            impact = 0.95
        elif role.privilege_level >= 50:
            severity = FindingSeverity.HIGH
            impact = 0.80
        else:
            severity = FindingSeverity.MEDIUM
            impact = 0.65
        
        findings.append(RoleMisuseFinding(
            severity=severity,
            title=f"Role '{role.name}' in Request Body",
            description=f"Role '{role.name}' (privilege level {role.privilege_level}/100) is assigned via request body parameter. This enables privilege escalation via mass assignment or parameter manipulation.",
            confidence=0.85,
            exploitability=0.90,
            impact=impact,
            evidence=[
                f"Role: {role.name}",
                f"Privilege level: {role.privilege_level}/100",
                f"Assignment method: request body",
                "Client controls request body"
            ],
            affected_entities=[role.id] + ([endpoint.id] if endpoint else []),
            endpoint_url=str(endpoint.url) if endpoint else None,
            method=endpoint.method.value if endpoint else None,
            recommendation="Do not accept role assignments from request body. Use server-side authorization based on authenticated identity.",
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_Mass_Assignment"
            ],
            role_name=role.name,
            role_location="body",
            parameter_name=role.assignment_location,
            privilege_level=role.privilege_level,
            metadata={
                "cwe": "CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes"
            }
        ))
        
        return findings
    
    def _check_role_in_header(
        self,
        role: Role,
        endpoint: Endpoint | None
    ) -> list[RoleMisuseFinding]:
        """Check for roles in HTTP headers"""
        findings: list[RoleMisuseFinding] = []
        
        # Determine severity
        if role.privilege_level >= 80:
            severity = FindingSeverity.CRITICAL
            impact = 0.95
        elif role.privilege_level >= 50:
            severity = FindingSeverity.HIGH
            impact = 0.85
        else:
            severity = FindingSeverity.MEDIUM
            impact = 0.70
        
        findings.append(RoleMisuseFinding(
            severity=severity,
            title=f"Role '{role.name}' in HTTP Header",
            description=f"Role '{role.name}' (privilege level {role.privilege_level}/100) is assigned via HTTP header. Unless cryptographically signed, this allows privilege escalation by header manipulation.",
            confidence=0.85,
            exploitability=0.90,
            impact=impact,
            evidence=[
                f"Role: {role.name}",
                f"Privilege level: {role.privilege_level}/100",
                f"Assignment method: HTTP header",
                f"Header name: {role.assignment_location}",
                "Client can set arbitrary headers"
            ],
            affected_entities=[role.id] + ([endpoint.id] if endpoint else []),
            endpoint_url=str(endpoint.url) if endpoint else None,
            method=endpoint.method.value if endpoint else None,
            recommendation="Do not trust role headers from clients. Use cryptographically signed tokens (JWT) or server-side sessions.",
            role_name=role.name,
            role_location="header",
            parameter_name=role.assignment_location,
            privilege_level=role.privilege_level,
            metadata={
                "cwe": "CWE-290: Authentication Bypass by Spoofing"
            }
        ))
        
        return findings
    
    def _check_high_privilege_role(
        self,
        role: Role,
        endpoint: Endpoint | None
    ) -> list[RoleMisuseFinding]:
        """Check for high-privilege roles with weak assignment"""
        findings: list[RoleMisuseFinding] = []
        
        # Only check high-privilege roles
        if role.privilege_level < 70:
            return findings
        
        # Check if assignment method is weak
        weak_methods = ['parameter', 'query', 'body', 'header']
        
        if role.assignment_method and role.assignment_method.lower() in weak_methods:
            findings.append(RoleMisuseFinding(
                severity=FindingSeverity.CRITICAL,
                title=f"High-Privilege Role '{role.name}' with Weak Assignment",
                description=f"High-privilege role '{role.name}' (level {role.privilege_level}/100) uses weak assignment method '{role.assignment_method}'. This enables trivial privilege escalation to admin/high-privilege access.",
                confidence=0.95,
                exploitability=0.95,
                impact=1.0,
                evidence=[
                    f"Role: {role.name}",
                    f"Privilege level: {role.privilege_level}/100 (HIGH)",
                    f"Weak assignment method: {role.assignment_method}",
                    "Client-controlled assignment of high privileges"
                ],
                affected_entities=[role.id] + ([endpoint.id] if endpoint else []),
                endpoint_url=str(endpoint.url) if endpoint else None,
                method=endpoint.method.value if endpoint else None,
                recommendation="High-privilege roles must use strong authentication and authorization. Never allow client-controlled assignment of admin/high-privilege roles.",
                references=[
                    "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control"
                ],
                role_name=role.name,
                role_location=role.assignment_method,
                parameter_name=role.assignment_location,
                privilege_level=role.privilege_level,
                metadata={
                    "cwe": "CWE-269: Improper Privilege Management",
                    "severity_reason": "high_privilege_weak_assignment"
                }
            ))
        
        return findings
    
    def get_all_findings(self) -> list[RoleMisuseFinding]:
        """Get all accumulated findings"""
        return self.findings
