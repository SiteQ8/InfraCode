"""
InfraCode Provider Base
Abstract base class for all cloud providers.
"""

from abc import ABC, abstractmethod
from typing import Any, Optional
import logging

logger = logging.getLogger("infracode.providers")


class BaseProvider(ABC):
    """Abstract base class for infrastructure providers."""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.name = self.__class__.__name__
        self._initialized = False

    @abstractmethod
    def initialize(self) -> bool:
        """Initialize provider connection and validate credentials."""
        pass

    @abstractmethod
    def create(self, resource_id: str, resource_type: str, config: dict) -> dict:
        """Create a new resource."""
        pass

    @abstractmethod
    def read(self, resource_id: str, resource_type: str) -> Optional[dict]:
        """Read current state of a resource."""
        pass

    @abstractmethod
    def update(self, resource_id: str, resource_type: str, config: dict) -> dict:
        """Update an existing resource."""
        pass

    @abstractmethod
    def delete(self, resource_id: str, resource_type: str) -> dict:
        """Delete a resource."""
        pass

    @abstractmethod
    def validate_config(self, resource_type: str, config: dict) -> list[str]:
        """Validate resource configuration. Returns list of errors."""
        pass

    @abstractmethod
    def list_resource_types(self) -> list[str]:
        """List all supported resource types."""
        pass

    def get_outputs(self, resource_id: str, resource_type: str) -> dict:
        """Get outputs from a provisioned resource."""
        return {}

    def estimate_cost(self, resource_type: str, config: dict) -> Optional[dict]:
        """Estimate monthly cost for a resource configuration."""
        return None

    def health_check(self) -> dict:
        """Check provider connectivity and health."""
        return {"provider": self.name, "status": "unknown"}
