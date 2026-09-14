"""Offline forensic analysis of the on-disk history of AI coding agents.

This package is the analyzer half of the suite. The other half, the two single-file
collectors under collector/, deliberately shares no code with it: they must run with no
dependencies on an endpoint under investigation, while this runs on an analyst workstation
and may be thorough. The evidence bundle is the contract between them.

Design constraint this package serves above all others: an answer must be traceable. Every
event and every finding carries the bundle, the original path, the file hash and the line
or byte offset it came from, because a conclusion that cannot be traced back to a source is
not usable in an investigation.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
