"""Ossifikat: Knowledge Triple-Store with Staging Ossification."""

__version__ = "0.1.0"

from ossifikat.schema import Triple
from ossifikat.store import OssifikatStore

__all__ = ["Triple", "OssifikatStore", "__version__"]
