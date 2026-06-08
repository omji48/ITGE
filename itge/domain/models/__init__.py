"""
ITGE Domain Models

Unified internal schema for representing entities and relationships
in the Identity & Trust Graph Engine.
"""

from .base import BaseEntity, BaseRelationship
from .asset import Endpoint, Service, DataStore, HTTPMethod, AuthType, SensitivityLevel
from .identity import IdentityProvider, Token, Role, UserPersona, ProviderType, TokenType
from .relationships import (
    IssuesToken,
    ValidatesToken,
    Trusts,
    Forwards,
    Accesses,
    EscalatesTo,
    RequiresRole,
    CrossesBoundary,
)

__all__ = [
    # Base
    "BaseEntity",
    "BaseRelationship",
    # Assets
    "Endpoint",
    "Service",
    "DataStore",
    "HTTPMethod",
    "AuthType",
    "SensitivityLevel",
    # Identity
    "IdentityProvider",
    "Token",
    "Role",
    "UserPersona",
    "ProviderType",
    "TokenType",
    # Relationships
    "IssuesToken",
    "ValidatesToken",
    "Trusts",
    "Forwards",
    "Accesses",
    "EscalatesTo",
    "RequiresRole",
    "CrossesBoundary",
]
