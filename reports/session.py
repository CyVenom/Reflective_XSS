"""Scan session model — captures timing and context for a single scan run."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

_FRAMEWORK_VERSION = "1.0.0"


@dataclass
class ScanSession:
    """
    Timestamped scan session context.

    Attach to :attr:`~modules.base.ModuleResult.metadata` via :meth:`to_dict`
    under the key ``"session"`` so every reporter can access it uniformly.

    Usage::

        session = ScanSession.start(scan_options={"target": url, "crawl": True})
        result  = await module.run(url)
        session.finish()
        result.metadata["session"] = session.to_dict()
    """

    session_id: str
    started_at: datetime
    finished_at: datetime | None = None
    duration_seconds: float = 0.0
    framework_version: str = _FRAMEWORK_VERSION
    scan_options: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def start(cls, scan_options: dict[str, Any] | None = None) -> "ScanSession":
        """Create and start a new session with a random 8-char hex ID."""
        return cls(
            session_id=uuid.uuid4().hex[:8].upper(),
            started_at=datetime.now(timezone.utc),
            scan_options=scan_options or {},
        )

    def finish(self) -> "ScanSession":
        """Record finish time and compute duration. Returns self for chaining."""
        self.finished_at = datetime.now(timezone.utc)
        self.duration_seconds = (self.finished_at - self.started_at).total_seconds()
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id":       self.session_id,
            "started_at":       self.started_at.isoformat(),
            "finished_at":      self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": round(self.duration_seconds, 3),
            "framework_version": self.framework_version,
            "scan_options":     self.scan_options,
        }
