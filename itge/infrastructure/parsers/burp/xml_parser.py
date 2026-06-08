"""
Burp Suite XML parser.

Parses Burp Suite Pro/Community XML exports and extracts HTTP transactions.
Handles both proxy history and scanner results.
"""

import base64
from pathlib import Path
from typing import AsyncIterator
from urllib.parse import urlparse, parse_qs
from xml.etree import ElementTree as ET

import aiofiles

from ..base import BaseParser, RawHTTPTransaction


class BurpXMLParser(BaseParser):
    """
    Parser for Burp Suite XML exports.
    
    Burp XML format:
    <items>
        <item>
            ...
        </item>
    </items>
    """
    
    def __init__(self):
        super().__init__()
        self.source = "burp"
    
    def validate_format(self, file_path: Path) -> bool:
        """Validate Burp XML format"""
        if not file_path.exists():
            return False
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Check for <items> or <issues> root element
            if root.tag not in ("items", "issues"):
                return False
            
            # Check for at least one <item> or <issue>
            items = root.findall("item") or root.findall("issue")
            return len(items) > 0
            
        except ET.ParseError:
            return False
    
    async def parse(self, file_path: Path) -> AsyncIterator[RawHTTPTransaction]:
        """
        Parse Burp XML file.
        
        Yields HTTP transactions from Burp export.
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if not self.validate_format(file_path):
            raise ValueError(f"Invalid Burp XML format: {file_path}")
        
        # Parse XML (sync operation, but file I/O is async)
        async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
            content = await f.read()
        
        tree = ET.fromstring(content)
        
        # Support both Proxy History (item) and Scanner Issues (issue)
        elements = tree.findall("item") + tree.findall("issue")
        
        for item in elements:
            try:
                transaction = self._parse_item(item)
                if transaction:
                    self._record_success()
                    yield transaction
            except Exception as e:
                self._record_error(f"Failed to parse item: {str(e)}")
    
    def _parse_item(self, item: ET.Element) -> RawHTTPTransaction | None:
        """Parse single <item> or <issue> element"""
        
        # Handle Scanner <issue> which has nested <requestresponse>
        if item.tag == "issue":
            host_elem = item.find("host")
            host_str = host_elem.text if host_elem is not None else ""
            path = self._get_text(item, "path", "/")
            url = f"{host_str}{path}"
            
            host = host_str.replace("http://", "").replace("https://", "").split(":")[0]
            protocol = "https" if "https://" in host_str else "http"
            port_str = "" # Not easily parsed from issue without splitting host
            method = "GET"
            timestamp = self._get_text(item, "time", "")
            
            req_res = item.find("requestresponse")
            request_elem = req_res.find("request") if req_res is not None else None
            response_elem = req_res.find("response") if req_res is not None else None
            
            if request_elem is not None and request_elem.get("method"):
                method = request_elem.get("method")
                
            status_code = None # Not easily parsed from issue structure
            
        else:
            # Handle Proxy <item>
            url = self._get_text(item, "url")
            if not url:
                return None
            
            method = self._get_text(item, "method", "GET")
            host = self._get_text(item, "host", "")
            port_str = self._get_text(item, "port")
            protocol = self._get_text(item, "protocol", "https")
            path = self._get_text(item, "path", "/")
            timestamp = self._get_text(item, "time")
            
            request_elem = item.find("request")
            response_elem = item.find("response")
            
            status_code_str = self._get_text(item, "status")
            status_code = int(status_code_str) if status_code_str else None

        port = int(port_str) if port_str and port_str.isdigit() else None
        
        # Parse request
        request_headers, request_body = self._parse_request(request_elem)
        
        # Parse response
        response_headers, response_body = self._parse_response(response_elem)
        
        return RawHTTPTransaction(
            url=url,
            method=method,
            request_headers=request_headers,
            request_body=request_body,
            status_code=status_code,
            response_headers=response_headers,
            response_body=response_body,
            timestamp=timestamp,
            source=self.source,
            host=host,
            port=port,
            protocol=protocol,
            path=path,
            raw_data={
                "burp_item": ET.tostring(item, encoding='unicode')
            }
        )
    
    def _parse_request(self, request_elem: ET.Element | None) -> tuple[dict[str, str], str | None]:
        """Parse request element and extract headers/body"""
        if request_elem is None:
            return {}, None
        
        # Decode base64 if needed
        is_base64 = request_elem.get("base64") == "true"
        raw_request = request_elem.text or ""
        
        if is_base64:
            try:
                raw_request = base64.b64decode(raw_request).decode('utf-8', errors='ignore')
            except Exception as e:
                self._record_warning(f"Failed to decode base64 request: {e}")
                return {}, None
        
        # Parse HTTP request
        headers, body = self._parse_http_message(raw_request)
        return headers, body
    
    def _parse_response(self, response_elem: ET.Element | None) -> tuple[dict[str, str], str | None]:
        """Parse response element and extract headers/body"""
        if response_elem is None:
            return {}, None
        
        # Decode base64 if needed
        is_base64 = response_elem.get("base64") == "true"
        raw_response = response_elem.text or ""
        
        if is_base64:
            try:
                raw_response = base64.b64decode(raw_response).decode('utf-8', errors='ignore')
            except Exception as e:
                self._record_warning(f"Failed to decode base64 response: {e}")
                return {}, None
        
        # Parse HTTP response
        headers, body = self._parse_http_message(raw_response, is_response=True)
        return headers, body
    
    def _parse_http_message(
        self, 
        raw_message: str, 
        is_response: bool = False
    ) -> tuple[dict[str, str], str | None]:
        """
        Parse raw HTTP message into headers and body.
        
        HTTP format:
        GET /path HTTP/1.1
        Header1: value1
        Header2: value2
        
        body content
        """
        if not raw_message:
            return {}, None
        
        lines = raw_message.split('\n')
        headers: dict[str, str] = {}
        body_start_idx = 0
        
        # Skip first line (request/response line)
        for i, line in enumerate(lines[1:], start=1):
            line = line.strip()
            
            # Empty line marks end of headers
            if not line:
                body_start_idx = i + 1
                break
            
            # Parse header
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        # Extract body
        body = None
        if body_start_idx < len(lines):
            body_lines = lines[body_start_idx:]
            body = '\n'.join(body_lines).strip()
            
            # Truncate large bodies
            if len(body) > 10000:
                body = body[:10000] + "\n... [truncated]"
        
        return headers, body if body else None
    
    def _get_text(self, elem: ET.Element, tag: str, default: str = "") -> str:
        """Safely get text from XML element"""
        child = elem.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        return default
