"""
Base models for all ITGE entities and relationships.

Design principles:
- All entities have UUIDs for graph node identification
- Timestamps for audit trail
- Confidence scores for probabilistic reasoning
- Metadata for extensibility
"""

from datetime import datetime
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, ConfigDict


class BaseEntity(BaseModel):
    """
    Base class for all graph entities (nodes).
    
    Every entity in ITGE inherits from this to ensure:
    - Unique identification (UUID)
    - Provenance tracking (source, discovered_at)
    - Confidence scoring
    - Extensibility (metadata)
    """
    
    model_config = ConfigDict(
        frozen=False,
        validate_assignment=True,
        str_strip_whitespace=True,
        use_enum_values=True,
    )
    
    # Identity
    id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for this entity in the graph"
    )
    
    # Provenance
    source: str = Field(
        ...,
        description="Data source: 'burp', 'zap', 'amass', 'nmap', 'manual'",
        min_length=1,
        max_length=50
    )
    
    discovered_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When this entity was first discovered"
    )
    
    # Confidence
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Confidence in this entity's existence/accuracy (0.0-1.0)"
    )
    
    # Extensibility
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata for extensibility"
    )
    
    # Tags for categorization
    tags: list[str] = Field(
        default_factory=list,
        description="User-defined tags for categorization"
    )
    
    def __hash__(self) -> int:
        """Allow entities to be used in sets/dicts"""
        return hash(self.id)
    
    def __eq__(self, other: object) -> bool:
        """Entities are equal if they have the same ID"""
        if not isinstance(other, BaseEntity):
            return False
        return self.id == other.id


class BaseRelationship(BaseModel):
    """
    Base class for all graph relationships (edges).
    
    Relationships connect entities and carry metadata about
    the connection, including confidence and evidence.
    """
    
    model_config = ConfigDict(
        frozen=False,
        validate_assignment=True,
    )
    
    # Identity
    id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for this relationship"
    )
    
    # Connection
    source_id: UUID = Field(
        ...,
        description="ID of the source entity"
    )
    
    target_id: UUID = Field(
        ...,
        description="ID of the target entity"
    )
    
    # Provenance
    discovered_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When this relationship was discovered"
    )
    
    # Confidence
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Confidence in this relationship (0.0-1.0)"
    )
    
    # Evidence
    evidence: list[str] = Field(
        default_factory=list,
        description="Evidence supporting this relationship"
    )
    
    # Extensibility
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional relationship metadata"
    )
    
    def __hash__(self) -> int:
        """Allow relationships to be used in sets/dicts"""
        return hash(self.id)
    
    def __eq__(self, other: object) -> bool:
        """Relationships are equal if they have the same ID"""
        if not isinstance(other, BaseRelationship):
            return False
        return self.id == other.id
