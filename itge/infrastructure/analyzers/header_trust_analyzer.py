"""
Header Trust Analyzer - detects header-based trust assumptions.

Analyzes HTTP headers for security vulnerabilities where servers
trust client-controlled headers.
"""

from ...domain.models.findings import HeaderTrustFinding, FindingSeverity
from ...domain.models.asset import Endpoint


class HeaderTrustAnalyzer:
    """
    Analyzes HTTP headers for trust assumptions.
    
    Detects:
    - X-Forwarded-For reliance (IP spoofing)
    - X-Real-IP trust (IP spoofing)
    - X-Original-URL trust (routing bypass)
    - Internal headers exposed externally
    - Role/privilege headers
    """
    
    # Headers that should never be trusted from clients
    DANGEROUS_TRUST_HEADERS = {
        'X-Forwarded-For': {
            'description': 'Client can spoof source IP address',
            'impact': 0.85,
            'exploitability': 0.90,
            'attack': 'IP-based access control bypass'
        },
        'X-Real-IP': {
            'description': 'Client can spoof real IP address',
            'impact': 0.85,
            'exploitability': 0.90,
            'attack': 'IP-based access control bypass'
        },
        'X-Original-URL': {
            'description': 'Client can manipulate routing decisions',
            'impact': 0.90,
            'exploitability': 0.85,
            'attack': 'Access control bypass via URL rewriting'
        },
        'X-Rewrite-URL': {
            'description': 'Client can manipulate URL rewriting',
            'impact': 0.90,
            'exploitability': 0.85,
            'attack': 'Access control bypass'
        },
        'X-User-Id': {
            'description': 'Client can impersonate any user',
            'impact': 0.95,
            'exploitability': 0.95,
            'attack': 'Authentication bypass via user ID spoofing'
        },
        'X-Role': {
            'description': 'Client can claim any role',
            'impact': 0.95,
            'exploitability': 0.95,
            'attack': 'Privilege escalation via role spoofing'
        },
        'X-Admin': {
            'description': 'Client can claim admin privileges',
            'impact': 1.0,
            'exploitability': 0.95,
            'attack': 'Privilege escalation to admin'
        },
        'X-Privilege': {
            'description': 'Client can set privilege level',
            'impact': 0.95,
            'exploitability': 0.90,
            'attack': 'Privilege escalation'
        },
        'X-Is-Admin': {
            'description': 'Client can claim admin status',
            'impact': 1.0,
            'exploitability': 0.95,
            'attack': 'Privilege escalation to admin'
        }
    }
    
    # Internal headers that should not be exposed
    INTERNAL_HEADERS = {
        'X-Internal-User',
        'X-Internal-IP',
        'X-Backend-Server',
        'X-Internal-Request',
        'X-Debug-Token',
        'X-Service-Token'
    }
    
    def __init__(self):
        self.findings: list[HeaderTrustFinding] = []
    
    def analyze_endpoint(self, endpoint: Endpoint) -> list[HeaderTrustFinding]:
        """
        Analyze endpoint for header trust issues.
        
        Args:
            endpoint: Endpoint entity to analyze
        
        Returns:
            List of header trust findings
        """
        findings: list[HeaderTrustFinding] = []
        
        # Check request headers for dangerous trust
        findings.extend(self._check_dangerous_headers(endpoint))
        
        # Check for internal headers exposed
        findings.extend(self._check_internal_headers(endpoint))
        
        # Check for custom trust headers
        findings.extend(self._check_custom_trust_headers(endpoint))
        
        return findings
    
    def _check_dangerous_headers(self, endpoint: Endpoint) -> list[HeaderTrustFinding]:
        """Check for dangerous header trust"""
        findings: list[HeaderTrustFinding] = []
        
        for header_name, header_info in self.DANGEROUS_TRUST_HEADERS.items():
            # Check if header is present in request
            if header_name in endpoint.request_headers:
                header_value = endpoint.request_headers[header_name]
                
                # Determine severity based on header type
                if 'admin' in header_name.lower() or 'user-id' in header_name.lower():
                    severity = FindingSeverity.CRITICAL
                elif 'role' in header_name.lower() or 'privilege' in header_name.lower():
                    severity = FindingSeverity.CRITICAL
                elif 'url' in header_name.lower():
                    severity = FindingSeverity.HIGH
                else:
                    severity = FindingSeverity.HIGH
                
                findings.append(HeaderTrustFinding(
                    severity=severity,
                    title=f"Server Trusts Client-Controlled Header: {header_name}",
                    description=f"Endpoint accepts and potentially trusts the '{header_name}' header from client requests. {header_info['description']}. This enables {header_info['attack']}.",
                    confidence=0.85,
                    exploitability=header_info['exploitability'],
                    impact=header_info['impact'],
                    evidence=[
                        f"Header '{header_name}' present in request",
                        f"Value: {header_value}",
                        f"Endpoint: {endpoint.url}",
                        "Client-controlled headers should not be trusted for security decisions"
                    ],
                    affected_entities=[endpoint.id],
                    endpoint_url=str(endpoint.url),
                    method=endpoint.method.value,
                    recommendation=f"Do not trust '{header_name}' header from client requests. Obtain this information from authenticated server-side sources.",
                    references=[
                        "https://owasp.org/www-community/attacks/HTTP_Request_Smuggling",
                        "https://portswigger.net/web-security/authentication/other-mechanisms"
                    ],
                    header_name=header_name,
                    header_value=header_value,
                    trusted_by_endpoints=[endpoint.id],
                    metadata={
                        "attack_type": header_info['attack'],
                        "cwe": "CWE-290: Authentication Bypass by Spoofing"
                    }
                ))
        
        return findings
    
    def _check_internal_headers(self, endpoint: Endpoint) -> list[HeaderTrustFinding]:
        """Check for internal headers exposed externally"""
        findings: list[HeaderTrustFinding] = []
        
        # Check response headers for internal leakage
        for header_name in endpoint.response_headers.keys():
            if header_name in self.INTERNAL_HEADERS or 'internal' in header_name.lower():
                header_value = endpoint.response_headers[header_name]
                
                findings.append(HeaderTrustFinding(
                    severity=FindingSeverity.MEDIUM,
                    title=f"Internal Header Exposed: {header_name}",
                    description=f"Endpoint exposes internal header '{header_name}' in responses. This may leak internal architecture details or provide attack vectors.",
                    confidence=0.80,
                    exploitability=0.60,
                    impact=0.65,
                    evidence=[
                        f"Internal header '{header_name}' in response",
                        f"Value: {header_value}",
                        f"Endpoint: {endpoint.url}"
                    ],
                    affected_entities=[endpoint.id],
                    endpoint_url=str(endpoint.url),
                    method=endpoint.method.value,
                    recommendation=f"Remove internal header '{header_name}' from external responses. Use response filtering middleware.",
                    header_name=header_name,
                    header_value=header_value,
                    metadata={
                        "cwe": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"
                    }
                ))
        
        return findings
    
    def _check_custom_trust_headers(self, endpoint: Endpoint) -> list[HeaderTrustFinding]:
        """Check for custom headers that may indicate trust assumptions"""
        findings: list[HeaderTrustFinding] = []
        
        # Look for patterns in custom headers
        suspicious_patterns = [
            'authenticated', 'authorized', 'verified', 'trusted',
            'session', 'token', 'key', 'secret'
        ]
        
        for header_name, header_value in endpoint.request_headers.items():
            # Skip standard headers
            if not header_name.startswith('X-'):
                continue
            
            # Check for suspicious patterns
            header_lower = header_name.lower()
            for pattern in suspicious_patterns:
                if pattern in header_lower:
                    findings.append(HeaderTrustFinding(
                        severity=FindingSeverity.MEDIUM,
                        title=f"Suspicious Custom Header: {header_name}",
                        description=f"Endpoint accepts custom header '{header_name}' which may be used for authentication or authorization decisions. If trusted, this could enable spoofing attacks.",
                        confidence=0.65,
                        exploitability=0.70,
                        impact=0.75,
                        evidence=[
                            f"Custom header '{header_name}' present",
                            f"Value: {header_value}",
                            f"Pattern match: '{pattern}'",
                            "May be used for security decisions"
                        ],
                        affected_entities=[endpoint.id],
                        endpoint_url=str(endpoint.url),
                        method=endpoint.method.value,
                        recommendation=f"Verify that '{header_name}' is not trusted for authentication or authorization. Use cryptographically signed tokens instead.",
                        header_name=header_name,
                        header_value=header_value,
                        metadata={
                            "pattern": pattern
                        }
                    ))
                    break  # Only report once per header
        
        return findings
    
    def get_all_findings(self) -> list[HeaderTrustFinding]:
        """Get all accumulated findings"""
        return self.findings
