"""
Base parser interface for all ingestion parsers.

All parsers must implement this interface to ensure consistent behavior.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, AsyncIterator

from pydantic import BaseModel, Field


class RawHTTPTransaction(BaseModel):
    """
    Intermediate representation of HTTP transaction.
    
    This is the normalized output from all parsers before
    conversion to domain models.
    """
    
    # Request
    url: str
    method: str
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str | None = None
    
    # Response
    status_code: int | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str | None = None
    
    # Metadata
    timestamp: str | None = None
    source: str  # "burp", "zap", etc.
    
    # Additional context
    host: str
    port: int | None = None
    protocol: str = "https"
    path: str
    
    # Raw data for debugging
    raw_data: dict[str, Any] = Field(default_factory=dict)


class ParserStats(BaseModel):
    """Statistics from parsing operation"""
    
    total_transactions: int = 0
    successful_parses: int = 0
    failed_parses: int = 0
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class BaseParser(ABC):
    """
    Base class for all traffic parsers.
    
    Parsers convert tool-specific export formats into
    RawHTTPTransaction objects for normalization.
    """
    
    def __init__(self):
        self.stats = ParserStats()
    
    @abstractmethod
    async def parse(self, file_path: Path) -> AsyncIterator[RawHTTPTransaction]:
        """
        Parse file and yield HTTP transactions.
        
        Args:
            file_path: Path to export file
            
        Yields:
            RawHTTPTransaction objects
            
        Raises:
            ValueError: If file format is invalid
            FileNotFoundError: If file doesn't exist
        """
        pass
    
    @abstractmethod
    def validate_format(self, file_path: Path) -> bool:
        """
        Validate that file is in expected format.
        
        Args:
            file_path: Path to file
            
        Returns:
            True if format is valid
        """
        pass
    
    def get_stats(self) -> ParserStats:
        """Get parsing statistics"""
        return self.stats
    
    def _record_error(self, error: str) -> None:
        """Record parsing error"""
        self.stats.errors.append(error)
        self.stats.failed_parses += 1
    
    def _record_warning(self, warning: str) -> None:
        """Record parsing warning"""
        self.stats.warnings.append(warning)
    
    def _record_success(self) -> None:
        """Record successful parse"""
        self.stats.successful_parses += 1
        self.stats.total_transactions += 1
