"""Central logging setup. Call configure_logging() once, from the CLI
entry point -- library code should just use logging.getLogger(__name__)
and never configure handlers itself.

This is operational logging (console, human-facing, for watching a run
live) -- separate from audit.log's append-only per-run JSONL, which is the
compliance record.
"""

from __future__ import annotations

import logging

_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(level=level.upper(), format=_FORMAT)
