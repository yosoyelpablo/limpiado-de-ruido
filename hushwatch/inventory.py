"""Asset inventory types shared by the Wazuh API client, coverage and silence analyzers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(slots=True)
class AgentInfo:
    id: str
    name: str
    status: str  # active | disconnected | pending | never_connected | unknown
    last_keepalive: datetime | None = None
    date_add: datetime | None = None
    platform: str | None = None  # normalized family: windows | linux | darwin | bsd | ... (raw value in extra)
    os_name: str | None = None
    groups: tuple[str, ...] = ()
    version: str | None = None
    node: str | None = None
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def is_manager(self) -> bool:
        return self.id == "000"
