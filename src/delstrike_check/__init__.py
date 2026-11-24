"""delstrike-check: deterministic, local security checks for vibecoded apps (Supabase, Firebase, AI proxies)."""
from __future__ import annotations

__version__ = "0.1.0"

from .scan import Options, Report, scan  # noqa: E402

__all__ = ["Options", "Report", "scan", "__version__"]
