"""
OWASP ZAP XML parser.

Parses OWASP ZAP XML exports and extracts HTTP transactions.
"""

import base64
from pathlib import Path
from typing import AsyncIterator
from xml.etree import ElementTree as ET

import aiofiles

from ..base import BaseParser, RawHTTPTransaction


class ZAPXMLParser(BaseParser):
    """
    Parser for OWASP ZAP XML exports.
    
    ZAP XML format:
    <OWASPZAPReport>
        <site name="https://example.com" host="example.com" port="443" ssl="true">
            <alerts>
                <alertitem>...</alertitem>
            </alerts>
        </site>
    </OWASPZAPReport>
    
    Or session format:
    <session>
        <sessionName>...</sessionName>
        <history>
            <historyitem>
                <historyid>1</historyid>
                <historytype>1</historytype>
                <sessionid>0</sessionid>
                <time>timestamp</time>
                <method>GET</method>
                <uri>https://example.com/path</uri>
                <statuscode>200</statuscode>
                <requestheader>...</requestheader>
                <requestbody></requestbody>
                <responseheader>...</responseheader>
                <responsebody>...</responsebody>
            </historyitem>
        </history>
    </session>
    """
    
    def __init__(self):
        super().__init__()
        self.source = "zap"
    
    def validate_format(self, file_path: Path) -> bool:
        """Validate ZAP XML format"""
        if not file_path.exists():
            return False
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Check for ZAP report or session format
            if root.tag in ["OWASPZAPReport", "session"]:
                return True
            
            return False
            
        except ET.ParseError:
            return False
    
    async def parse(self, file_path: Path) -> AsyncIterator[RawHTTPTransaction]:
        """
        Parse ZAP XML file.
        
        Yields HTTP transactions from ZAP export.
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if not self.validate_format(file_path):
            raise ValueError(f"Invalid ZAP XML format: {file_path}")
        
        # Parse XML
        async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
            content = await f.read()
        
        tree = ET.fromstring(content)
        
        # Determine format and parse accordingly
        if tree.tag == "session":
            async for transaction in self._parse_session_format(tree):
                yield transaction
        elif tree.tag == "OWASPZAPReport":
            async for transaction in self._parse_report_format(tree):
                yield transaction
    
    async def _parse_session_format(self, root: ET.Element) -> AsyncIterator[RawHTTPTransaction]:
        """Parse ZAP session format"""
        history = root.find("history")
        if history is None:
            return
        
        for item in history.findall("historyitem"):
            try:
                transaction = self._parse_history_item(item)
                if transaction:
                    self._record_success()
                    yield transaction
            except Exception as e:
                self._record_error(f"Failed to parse history item: {str(e)}")
    
    async def _parse_report_format(self, root: ET.Element) -> AsyncIterator[RawHTTPTransaction]:
        """
        Parse ZAP report format.
        
        Note: Report format focuses on alerts, not full HTTP history.
        We extract what we can from alert context.
        """
        for site in root.findall("site"):
            site_name = site.get("name", "")
            host = site.get("host", "")
            port_str = site.get("port", "443")
            port = int(port_str) if port_str else 443
            ssl = site.get("ssl", "true") == "true"
            protocol = "https" if ssl else "http"
            
            alerts = site.find("alerts")
            if alerts is None:
                continue
            
            for alert in alerts.findall("alertitem"):
                try:
                    transaction = self._parse_alert_item(alert, host, port, protocol)
                    if transaction:
                        self._record_success()
                        yield transaction
                except Exception as e:
                    self._record_error(f"Failed to parse alert item: {str(e)}")
    
    def _parse_history_item(self, item: ET.Element) -> RawHTTPTransaction | None:
        """Parse history item from session format"""
        
        # Extract basic fields
        uri = self._get_text(item, "uri")
        if not uri:
            return None
        
        method = self._get_text(item, "method", "GET")
        status_code_str = self._get_text(item, "statuscode")
        status_code = int(status_code_str) if status_code_str else None
        timestamp = self._get_text(item, "time")
        
        # Parse URL
        from urllib.parse import urlparse
        parsed = urlparse(uri)
        host = parsed.hostname or ""
        port = parsed.port
        protocol = parsed.scheme or "https"
        path = parsed.path or "/"
        
        # Parse request
        request_header = self._get_text(item, "requestheader")
        request_body = self._get_text(item, "requestbody")
        request_headers = self._parse_zap_headers(request_header)
        
        # Parse response
        response_header = self._get_text(item, "responseheader")
        response_body = self._get_text(item, "responsebody")
        response_headers = self._parse_zap_headers(response_header)
        
        # Truncate large bodies
        if response_body and len(response_body) > 10000:
            response_body = response_body[:10000] + "\n... [truncated]"
        
        return RawHTTPTransaction(
            url=uri,
            method=method,
            request_headers=request_headers,
            request_body=request_body if request_body else None,
            status_code=status_code,
            response_headers=response_headers,
            response_body=response_body if response_body else None,
            timestamp=timestamp,
            source=self.source,
            host=host,
            port=port,
            protocol=protocol,
            path=path,
            raw_data={
                "zap_history_item": ET.tostring(item, encoding='unicode')
            }
        )
    
    def _parse_alert_item(
        self, 
        alert: ET.Element, 
        host: str, 
        port: int, 
        protocol: str
    ) -> RawHTTPTransaction | None:
        """Parse alert item from report format"""
        
        # Extract URL from alert
        uri = self._get_text(alert, "uri")
        if not uri:
            return None
        
        method = self._get_text(alert, "method", "GET")
        
        # Parse URL
        from urllib.parse import urlparse
        parsed = urlparse(uri)
        path = parsed.path or "/"
        
        # Alerts don't have full request/response, just evidence
        evidence = self._get_text(alert, "evidence")
        attack = self._get_text(alert, "attack")
        
        return RawHTTPTransaction(
            url=uri,
            method=method,
            request_headers={},
            request_body=attack if attack else None,
            status_code=None,
            response_headers={},
            response_body=evidence if evidence else None,
            timestamp=None,
            source=self.source,
            host=host,
            port=port,
            protocol=protocol,
            path=path,
            raw_data={
                "zap_alert": ET.tostring(alert, encoding='unicode'),
                "alert_name": self._get_text(alert, "name"),
                "risk": self._get_text(alert, "riskcode")
            }
        )
    
    def _parse_zap_headers(self, header_text: str) -> dict[str, str]:
        """
        Parse ZAP header format.
        
        ZAP headers are newline-separated:
        GET /path HTTP/1.1
        Host: example.com
        User-Agent: Mozilla/5.0
        """
        headers: dict[str, str] = {}
        
        if not header_text:
            return headers
        
        lines = header_text.split('\n')
        
        # Skip first line (request/response line)
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        return headers
    
    def _get_text(self, elem: ET.Element, tag: str, default: str = "") -> str:
        """Safely get text from XML element"""
        child = elem.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        return default
