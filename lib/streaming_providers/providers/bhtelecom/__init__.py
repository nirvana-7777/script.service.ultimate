# streaming_providers/providers/bhtelecom/__init__.py
"""
BH Telecom streaming provider

Provides access to BH Telecom's live TV streaming service.
"""

from .provider import BHTelecomProvider

__all__ = ["BHTelecomProvider"]

__version__ = "1.0.0"