"""Seal -- authorized vulnerability assessment and closure.

This distribution currently contains only ``seal.core``: pure, offline models of
the v1.6 engineering contracts. It is not a deployed security system. There is
no live scanner, service API, database, user login or target-changing capability
here, by design -- see ``docs/BOUNDARY.md``.
"""

__all__ = ["core"]
