"""
JWT Trust Analyzer - detects JWT-specific trust issues.

Analyzes JWT tokens for security vulnerabilities and trust assumptions.
"""

from typing import Any

from ...domain.models.findings import JWTTrustFinding, FindingSeverity
from ...domain.models.identity import Token, TokenType


class JWTTrustAnalyzer:
    """
    Analyzes JWT tokens for trust issues.
    
    Detects:
    - Missing audience validation
    - Weak/insecure algorithms
    - Missing expiration
    - Token reuse across services
    - Signature validation issues
    """
    
    # Weak algorithms that should not be used
    WEAK_ALGORITHMS = ['none', 'HS256']  # 'none' is critical, HS256 is weak for public APIs
    
    # Insecure algorithms
    INSECURE_ALGORITHMS = ['none']
    
    def __init__(self):
        self.findings: list[JWTTrustFinding] = []
        self._seen_tokens: dict[str, list[str]] = {}  # issuer+subject -> [endpoints]
    
    def analyze_token(self, token: Token, endpoint_url: str | None = None) -> list[JWTTrustFinding]:
        """
        Analyze a JWT token for trust issues.
        
        Args:
            token: Token entity to analyze
            endpoint_url: Optional endpoint URL where token was observed
        
        Returns:
            List of trust findings
        """
        findings: list[JWTTrustFinding] = []
        
        if token.token_type != TokenType.JWT:
            return findings
        
        # Check algorithm
        findings.extend(self._check_algorithm(token, endpoint_url))
        
        # Check audience validation
        findings.extend(self._check_audience(token, endpoint_url))
        
        # Check expiration
        findings.extend(self._check_expiration(token, endpoint_url))
        
        # Check token reuse
        findings.extend(self._check_token_reuse(token, endpoint_url))
        
        # Check claims
        findings.extend(self._check_claims(token, endpoint_url))
        
        return findings
    
    def _check_algorithm(self, token: Token, endpoint_url: str | None) -> list[JWTTrustFinding]:
        """Check for weak or insecure algorithms"""
        findings: list[JWTTrustFinding] = []
        
        algorithm = token.algorithm
        if not algorithm:
            # Missing algorithm claim
            findings.append(JWTTrustFinding(
                severity=FindingSeverity.MEDIUM,
                title="JWT Missing Algorithm Claim",
                description="JWT token does not specify an algorithm in the header. This may indicate improper token construction.",
                confidence=0.80,
                exploitability=0.50,
                impact=0.60,
                evidence=[
                    "No 'alg' claim found in JWT header"
                ],
                affected_entities=[token.id],
                endpoint_url=endpoint_url,
                recommendation="Ensure JWT tokens include a valid 'alg' claim in the header.",
                token_id=token.id,
                issuer=token.issuer,
                algorithm=None
            ))
            return findings
        
        algorithm_lower = algorithm.lower()
        
        # Check for 'none' algorithm (critical)
        if algorithm_lower == 'none':
            findings.append(JWTTrustFinding(
                severity=FindingSeverity.CRITICAL,
                title="JWT Algorithm 'none' Accepted",
                description="JWT token uses the 'none' algorithm, which disables signature verification. This allows trivial token forgery.",
                confidence=0.95,
                exploitability=0.95,
                impact=1.0,
                evidence=[
                    f"JWT algorithm: {algorithm}",
                    "The 'none' algorithm allows unsigned tokens"
                ],
                affected_entities=[token.id],
                endpoint_url=endpoint_url,
                recommendation="Reject tokens with 'none' algorithm. Enforce signature verification.",
                references=[
                    "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"
                ],
                token_id=token.id,
                issuer=token.issuer,
                algorithm=algorithm,
                metadata={
                    "cwe": "CWE-347: Improper Verification of Cryptographic Signature"
                }
            ))
        
        # Check for HS256 (symmetric, weaker for distributed systems)
        elif algorithm_lower == 'hs256':
            findings.append(JWTTrustFinding(
                severity=FindingSeverity.MEDIUM,
                title="JWT Uses Symmetric Algorithm (HS256)",
                description="JWT token uses HS256 (HMAC-SHA256), a symmetric algorithm. This requires sharing the secret key with all validators, increasing key exposure risk.",
                confidence=0.85,
                exploitability=0.60,
                impact=0.70,
                evidence=[
                    f"JWT algorithm: {algorithm}",
                    "HS256 requires shared secret across services"
                ],
                affected_entities=[token.id],
                endpoint_url=endpoint_url,
                recommendation="Consider using asymmetric algorithms (RS256, ES256) for better key management in distributed systems.",
                references=[
                    "https://tools.ietf.org/html/rfc7518#section-3.1"
                ],
                token_id=token.id,
                issuer=token.issuer,
                algorithm=algorithm
            ))
        
        return findings
    
    def _check_audience(self, token: Token, endpoint_url: str | None) -> list[JWTTrustFinding]:
        """Check for missing or weak audience validation"""
        findings: list[JWTTrustFinding] = []
        
        if not token.audience or len(token.audience) == 0:
            findings.append(JWTTrustFinding(
                severity=FindingSeverity.HIGH,
                title="JWT Missing Audience Claim",
                description="JWT token does not include an 'aud' (audience) claim. This allows the token to be used across unintended services, enabling token reuse attacks.",
                confidence=0.90,
                exploitability=0.80,
                impact=0.85,
                evidence=[
                    "No 'aud' claim found in JWT",
                    "Token can be reused across any service that trusts the issuer"
                ],
                affected_entities=[token.id],
                endpoint_url=endpoint_url,
                recommendation="Include 'aud' claim in JWT tokens and validate it on the server side. Each service should only accept tokens intended for it.",
                references=[
                    "https://tools.ietf.org/html/rfc7519#section-4.1.3"
                ],
                token_id=token.id,
                issuer=token.issuer,
                audience=None,
                metadata={
                    "cwe": "CWE-284: Improper Access Control"
                }
            ))
        
        # Check for wildcard or overly broad audience
        elif token.audience:
            for aud in token.audience:
                if aud in ['*', 'all', 'any']:
                    findings.append(JWTTrustFinding(
                        severity=FindingSeverity.HIGH,
                        title="JWT Wildcard Audience",
                        description=f"JWT token uses wildcard audience '{aud}', which defeats the purpose of audience validation.",
                        confidence=0.85,
                        exploitability=0.75,
                        impact=0.80,
                        evidence=[
                            f"JWT audience: {aud}",
                            "Wildcard audience allows cross-service token reuse"
                        ],
                        affected_entities=[token.id],
                        endpoint_url=endpoint_url,
                        recommendation="Use specific service identifiers in the 'aud' claim.",
                        token_id=token.id,
                        issuer=token.issuer,
                        audience=token.audience
                    ))
        
        return findings
    
    def _check_expiration(self, token: Token, endpoint_url: str | None) -> list[JWTTrustFinding]:
        """Check for missing or excessive expiration"""
        findings: list[JWTTrustFinding] = []
        
        if not token.expires_at:
            findings.append(JWTTrustFinding(
                severity=FindingSeverity.HIGH,
                title="JWT Missing Expiration",
                description="JWT token does not include an 'exp' (expiration) claim. This allows tokens to be valid indefinitely, increasing the window for token theft and replay attacks.",
                confidence=0.90,
                exploitability=0.70,
                impact=0.80,
                evidence=[
                    "No 'exp' claim found in JWT",
                    "Token has no expiration time"
                ],
                affected_entities=[token.id],
                endpoint_url=endpoint_url,
                recommendation="Include 'exp' claim in JWT tokens with a reasonable expiration time (e.g., 15 minutes for access tokens).",
                references=[
                    "https://tools.ietf.org/html/rfc7519#section-4.1.4"
                ],
                token_id=token.id,
                issuer=token.issuer,
                metadata={
                    "cwe": "CWE-613: Insufficient Session Expiration"
                }
            ))
        
        # Check for excessive expiration (if issued_at is available)
        if token.issued_at and token.expires_at:
            duration = (token.expires_at - token.issued_at).total_seconds()
            
            # More than 24 hours is excessive for access tokens
            if duration > 86400:  # 24 hours
                findings.append(JWTTrustFinding(
                    severity=FindingSeverity.MEDIUM,
                    title="JWT Excessive Expiration Time",
                    description=f"JWT token has an expiration time of {duration / 3600:.1f} hours, which is excessive for an access token.",
                    confidence=0.80,
                    exploitability=0.60,
                    impact=0.70,
                    evidence=[
                        f"Token lifetime: {duration / 3600:.1f} hours",
                        "Long-lived tokens increase theft risk"
                    ],
                    affected_entities=[token.id],
                    endpoint_url=endpoint_url,
                    recommendation="Use shorter expiration times (15-60 minutes) for access tokens. Use refresh tokens for longer sessions.",
                    token_id=token.id,
                    issuer=token.issuer
                ))
        
        return findings
    
    def _check_token_reuse(self, token: Token, endpoint_url: str | None) -> list[JWTTrustFinding]:
        """Check for token reuse across multiple services"""
        findings: list[JWTTrustFinding] = []
        
        if not endpoint_url or not token.issuer or not token.subject:
            return findings
        
        # Track token usage
        token_key = f"{token.issuer}:{token.subject}"
        
        if token_key not in self._seen_tokens:
            self._seen_tokens[token_key] = []
        
        self._seen_tokens[token_key].append(endpoint_url)
        
        # If token is used across multiple endpoints, check if audience is validated
        if len(self._seen_tokens[token_key]) > 1 and not token.audience:
            findings.append(JWTTrustFinding(
                severity=FindingSeverity.HIGH,
                title="JWT Token Reuse Across Services",
                description=f"JWT token is being used across {len(self._seen_tokens[token_key])} different endpoints without audience validation. This enables lateral movement.",
                confidence=0.85,
                exploitability=0.80,
                impact=0.85,
                evidence=[
                    f"Token used on {len(self._seen_tokens[token_key])} endpoints",
                    f"Endpoints: {', '.join(self._seen_tokens[token_key][:3])}",
                    "No audience claim to restrict usage"
                ],
                affected_entities=[token.id],
                endpoint_url=endpoint_url,
                recommendation="Implement audience validation to restrict tokens to specific services.",
                token_id=token.id,
                issuer=token.issuer
            ))
        
        return findings
    
    def _check_claims(self, token: Token, endpoint_url: str | None) -> list[JWTTrustFinding]:
        """Check for security-relevant claims"""
        findings: list[JWTTrustFinding] = []
        
        if not token.claims:
            return findings
        
        # Check for sensitive data in claims
        sensitive_keys = ['password', 'secret', 'api_key', 'private_key', 'ssn', 'credit_card']
        
        for key in token.claims.keys():
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                findings.append(JWTTrustFinding(
                    severity=FindingSeverity.HIGH,
                    title="Sensitive Data in JWT Claims",
                    description=f"JWT token contains potentially sensitive claim '{key}'. JWTs are base64-encoded, not encrypted, and can be decoded by anyone.",
                    confidence=0.75,
                    exploitability=0.90,
                    impact=0.85,
                    evidence=[
                        f"Sensitive claim found: {key}",
                        "JWT claims are only base64-encoded, not encrypted"
                    ],
                    affected_entities=[token.id],
                    endpoint_url=endpoint_url,
                    recommendation="Do not store sensitive data in JWT claims. Use encrypted tokens (JWE) if sensitive data must be included.",
                    token_id=token.id,
                    issuer=token.issuer,
                    metadata={
                        "sensitive_claim": key
                    }
                ))
        
        return findings
    
    def get_all_findings(self) -> list[JWTTrustFinding]:
        """Get all accumulated findings"""
        return self.findings
