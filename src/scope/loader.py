"""Load and validate a scope record from a YAML file the user supplies."""

from __future__ import annotations

from pathlib import Path

import yaml

from scope.models import ScopeRecord


def load_scope_record(path: str | Path) -> ScopeRecord:
    data = yaml.safe_load(Path(path).read_text())
    return ScopeRecord.model_validate(data)
