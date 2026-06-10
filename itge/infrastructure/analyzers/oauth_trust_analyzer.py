"""
OAuth Trust Analyzer - detects OAuth-specific trust issues.

Analyzes OAuth flows for security vulnerabilities.
"""

from urllib.parse import urlparse, parse_qs

from ...domain.models.findings import OAuthTrustFinding, FindingSeverity
from ...domain.models.identity import IdentityProvider, ProviderType
from ...domain.models.asset import Endpoint


class OAuthTrustAnalyzer:
    """
    Analyzes OAuth flows for trust issues.
    
    Detects:
    - Missing state parameter (CSRF protection)
    - Missing PKCE (for public clients)
    - Open redirect vulnerabilities
    - Insecure redirect URIs
    """
    
    def __init__(self):
        self.findings: list[OAuthTrustFinding] = []
    
    def analyze_provider(
        self, 
        provider: IdentityProvider,
        authorization_endpoint: Endpoint | None = None
    ) -> list[OAuthTrustFinding]:
        """
        Analyze OAuth provider for trust issues.
        
        Args:
            provider: IdentityProvider entity
            authorization_endpoint: Optional endpoint entity for authorization URL
        
        Returns:
            List of OAuth trust findings
        """
        findings: list[OAuthTrustFinding] = []
        
        if provider.provider_type != ProviderType.OAUTH:
            return findings
        
        # Check for missing state parameter
        findings.extend(self._check_state_parameter(provider, authorization_endpoint))
        
        # Check for PKCE support
        findings.extend(self._check_pkce(provider))
        
        # Check redirect URI security
        findings.extend(self._check_redirect_uri(provider, authorization_endpoint))
        
        return findings
    
    def analyze_callback(
        self,
        callback_endpoint: Endpoint,
        has_code: bool,
        has_state: bool
    ) -> list[OAuthTrustFinding]:
        """
        Analyze OAuth callback endpoint.
        
        Args:
            callback_endpoint: Callback endpoint entity
            has_code: Whether 'code' parameter is present
            has_state: Whether 'state' parameter is present
        
        Returns:
            List of OAuth trust findings
        """
        findings: list[OAuthTrustFinding] = []
        
        # Check for missing state in callback
        if has_code and not has_state:
            findings.append(OAuthTrustFinding(
                severity=FindingSeverity.HIGH,
                title="OAuth Callback Missing State Parameter",
                description="OAuth callback endpoint receives authorization code without state parameter. This makes the flow vulnerable to CSRF attacks.",
                confidence=0.90,
                exploitability=0.85,
                impact=0.80,
                evidence=[
                    "Authorization code present in callback",
                    "State parameter missing",
                    f"Callback URL: {callback_endpoint.url}"
                ],
                affected_entities=[callback_endpoint.id],
                endpoint_url=str(callback_endpoint.url),
                method=callback_endpoint.method.value,
                recommendation="Always include and validate the 'state' parameter in OAuth flows to prevent CSRF attacks.",
                references=[
                    "https://tools.ietf.org/html/rfc6749#section-10.12",
                    "https://owasp.org/www-community/attacks/csrf"
                ],
                metadata={
                    "cwe": "CWE-352: Cross-Site Request Forgery (CSRF)"
                }
            ))
        
        return findings
    
    def _check_state_parameter(
        self,
        provider: IdentityProvider,
        authorization_endpoint: Endpoint | None
    ) -> list[OAuthTrustFinding]:
        """Check for missing state parameter in authorization request"""
        findings: list[OAuthTrustFinding] = []
        
        # Check if state is explicitly marked as not supported
        if hasattr(provider, 'supports_state') and not provider.supports_state:
            endpoint_url = str(provider.authorization_endpoint) if provider.authorization_endpoint else None
            
            findings.append(OAuthTrustFinding(
                severity=FindingSeverity.HIGH,
                title="OAuth Flow Missing State Parameter",
                description="OAuth authorization flow does not use the 'state' parameter. This makes the flow vulnerable to CSRF attacks where an attacker can trick a victim into authorizing access to the attacker's account.",
                confidence=0.85,
                exploitability=0.80,
                impact=0.75,
                evidence=[
                    "No 'state' parameter observed in authorization request",
                    "CSRF protection missing"
                ],
                affected_entities=[provider.id],
                endpoint_url=endpoint_url,
                recommendation="Include a cryptographically random 'state' parameter in authorization requests and validate it in the callback.",
                references=[
                    "https://tools.ietf.org/html/rfc6749#section-10.12"
                ],
                provider_id=provider.id,
                flow_type="authorization_code",
                client_id=provider.client_id,
                metadata={
                    "cwe": "CWE-352: Cross-Site Request Forgery (CSRF)"
                }
            ))
        
        return findings
    
    def _check_pkce(self, provider: IdentityProvider) -> list[OAuthTrustFinding]:
        """Check for PKCE support (important for public clients)"""
        findings: list[OAuthTrustFinding] = []
        
        # Check if PKCE is explicitly marked as not supported
        if hasattr(provider, 'supports_pkce') and not provider.supports_pkce:
            findings.append(OAuthTrustFinding(
                severity=FindingSeverity.MEDIUM,
                title="OAuth Flow Missing PKCE",
                description="OAuth flow does not use PKCE (Proof Key for Code Exchange). For public clients (mobile apps, SPAs), this makes the flow vulnerable to authorization code interception attacks.",
                confidence=0.75,
                exploitability=0.65,
                impact=0.70,
                evidence=[
                    "No PKCE parameters observed (code_challenge, code_verifier)",
                    "Public client may be vulnerable to code interception"
                ],
                affected_entities=[provider.id],
                endpoint_url=str(provider.authorization_endpoint) if provider.authorization_endpoint else None,
                recommendation="Implement PKCE for all OAuth flows, especially for public clients. Use code_challenge and code_verifier parameters.",
                references=[
                    "https://tools.ietf.org/html/rfc7636",
                    "https://oauth.net/2/pkce/"
                ],
                provider_id=provider.id,
                flow_type="authorization_code",
                client_id=provider.client_id,
                metadata={
                    "cwe": "CWE-294: Authentication Bypass by Capture-replay"
                }
            ))
        
        return findings
    
    def _check_redirect_uri(
        self,
        provider: IdentityProvider,
        authorization_endpoint: Endpoint | None
    ) -> list[OAuthTrustFinding]:
        """Check for insecure redirect URIs"""
        findings: list[OAuthTrustFinding] = []
        
        # Get redirect_uri from provider metadata
        redirect_uri = provider.metadata.get('redirect_uri') if provider.metadata else None
        
        if not redirect_uri:
            return findings
        
        # Parse redirect URI
        parsed = urlparse(redirect_uri)
        
        # Check for HTTP (not HTTPS)
        if parsed.scheme == 'http':
            findings.append(OAuthTrustFinding(
                severity=FindingSeverity.HIGH,
                title="OAuth Redirect URI Uses HTTP",
                description=f"OAuth redirect URI uses insecure HTTP protocol: {redirect_uri}. This allows authorization codes to be intercepted in transit.",
                confidence=0.90,
                exploitability=0.75,
                impact=0.80,
                evidence=[
                    f"Redirect URI: {redirect_uri}",
                    "HTTP protocol allows man-in-the-middle attacks"
                ],
                affected_entities=[provider.id],
                endpoint_url=str(provider.authorization_endpoint) if provider.authorization_endpoint else None,
                recommendation="Use HTTPS for all OAuth redirect URIs to protect authorization codes in transit.",
                references=[
                    "https://tools.ietf.org/html/rfc6749#section-3.1.2.1"
                ],
                provider_id=provider.id,
                client_id=provider.client_id,
                metadata={
                    "redirect_uri": redirect_uri,
                    "cwe": "CWE-319: Cleartext Transmission of Sensitive Information"
                }
            ))
        
        # Check for wildcard redirect URI
        if '*' in redirect_uri or parsed.netloc == '*':
            findings.append(OAuthTrustFinding(
                severity=FindingSeverity.CRITICAL,
                title="OAuth Wildcard Redirect URI",
                description=f"OAuth redirect URI contains wildcard: {redirect_uri}. This enables open redirect attacks where authorization codes can be sent to attacker-controlled domains.",
                confidence=0.95,
                exploitability=0.90,
                impact=0.95,
                evidence=[
                    f"Redirect URI: {redirect_uri}",
                    "Wildcard allows arbitrary redirect destinations"
                ],
                affected_entities=[provider.id],
                endpoint_url=str(provider.authorization_endpoint) if provider.authorization_endpoint else None,
                recommendation="Use exact redirect URI matching. Never allow wildcards in redirect URIs.",
                references=[
                    "https://tools.ietf.org/html/rfc6749#section-3.1.2.3",
                    "https://cwe.mitre.org/data/definitions/601.html"
                ],
                provider_id=provider.id,
                client_id=provider.client_id,
                metadata={
                    "redirect_uri": redirect_uri,
                    "cwe": "CWE-601: URL Redirection to Untrusted Site ('Open Redirect')"
                }
            ))
        
        # Check for localhost redirect (development only)
        if parsed.hostname in ['localhost', '127.0.0.1']:
            findings.append(OAuthTrustFinding(
                severity=FindingSeverity.LOW,
                title="OAuth Redirect to Localhost",
                description=f"OAuth redirect URI points to localhost: {redirect_uri}. This should only be used in development environments.",
                confidence=0.80,
                exploitability=0.30,
                impact=0.40,
                evidence=[
                    f"Redirect URI: {redirect_uri}",
                    "Localhost redirect detected"
                ],
                affected_entities=[provider.id],
                endpoint_url=str(provider.authorization_endpoint) if provider.authorization_endpoint else None,
                recommendation="Ensure localhost redirects are only used in development. Use production domains in production environments.",
                provider_id=provider.id,
                client_id=provider.client_id,
                metadata={
                    "redirect_uri": redirect_uri
                }
            ))
        
        return findings
    
    def get_all_findings(self) -> list[OAuthTrustFinding]:
        """Get all accumulated findings"""
        return self.findings
