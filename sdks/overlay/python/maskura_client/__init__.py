"""Canonical Maskura Python SDK namespace."""

import importlib
import sys

from s4_client import *  # noqa: F401,F403
from s4_client import __all__ as _generated_exports
from s4_client import __version__
from s4_client.highlevel import MaskuraClient, S4Client

__all__ = [*_generated_exports, "MaskuraClient", "S4Client"]

for _module in (
    "api",
    "api_client",
    "api_response",
    "configuration",
    "exceptions",
    "models",
    "rest",
):
    sys.modules[f"{__name__}.{_module}"] = importlib.import_module(f"s4_client.{_module}")
