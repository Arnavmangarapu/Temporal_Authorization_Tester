"""Validated target and temporal-policy configuration."""

from temporal_auth.config.loader import ConfigLoadError, load_config
from temporal_auth.config.models import TargetConfig

__all__ = ["ConfigLoadError", "TargetConfig", "load_config"]
