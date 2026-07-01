"""Revisionssicheres Audit-Log.

Jede Aktion des Agenten (Tool-Aufruf, Entscheidung, verweigerte Aktion) wird
als JSON-Zeile protokolliert. Das ist bei autorisierten Pentests Pflicht:
Der Auftraggeber muss lueckenlos nachvollziehen koennen, was getestet wurde.
"""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, directory: str | Path = "audit") -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        self.path = self.dir / f"specter-{stamp}.jsonl"

    def record(self, event: str, **fields: Any) -> None:
        entry = {
            "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "event": event,
            **fields,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
