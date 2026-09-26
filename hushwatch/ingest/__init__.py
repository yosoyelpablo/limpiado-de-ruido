"""Ingest layer: turn inputs into a re-iterable stream of normalized :class:`~hushwatch.models.Event`.

Every source exposes a :class:`~hushwatch.models.DataBasis` (``source.basis``) describing what the analysis
could actually see: input kind, profile, time range, reference "now", event count, malformed lines,
bad / future timestamps, events outside ``--since``/``--until`` (``excluded_by_window``), files left out of input
directories (``skipped_files``), truncation and partial failures (translatable messages). Sources are re-iterable:
the noise backtest reads the input a second time and must see exactly the same events. File sources also offer
``iter_rules(rule_ids)``, the same events restricted to a few rules and read cheaply (raw lines pre-filtered).

This package module stays light: indexer and Wazuh API clients live in their own modules and are imported by
their callers.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator, Sequence
from datetime import datetime
from typing import Protocol, runtime_checkable

from ..config import InputConfig, TenantConfig
from ..models import DataBasis, Event
from .files import FileEventSource, IngestError, ReadStats, iter_documents, rotated_date, rule_line_filter
from .profiles import PROFILES, detect_profile, normalize

__all__ = [
    "PROFILES",
    "EventSource",
    "FileEventSource",
    "IngestError",
    "ReadStats",
    "detect_profile",
    "iter_documents",
    "normalize",
    "open_files",
    "rotated_date",
    "rule_line_filter",
]


@runtime_checkable
class EventSource(Protocol):
    """A re-iterable stream of events plus the DataBasis of its last complete pass."""

    basis: DataBasis

    def __iter__(self) -> Iterator[Event]: ...


def open_files(
    paths: Sequence[str | os.PathLike[str]] | str | os.PathLike[str],
    *,
    profile: str = "auto",
    tenant: TenantConfig,
    since: datetime | None = None,
    until: datetime | None = None,
    max_events: int | None = None,
    project: Sequence[str] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
    input_cfg: InputConfig | None = None,
    keep_fields: bool = True,
) -> FileEventSource:
    """Open alert/event files, directories or globs as a re-iterable :class:`FileEventSource`.

    * ``profile`` — ``auto`` (detected per file from its first documents), ``wazuh4``, ``wazuh5``, ``ecs`` or
      ``generic``.
    * ``since`` / ``until`` — keep events with ``since <= ts < until`` (naive datetimes are taken as UTC);
      Wazuh rotated files outside the range are not even opened.
    * ``max_events`` — stop after this many events and mark ``basis.truncated``.
    * ``project`` — keep only these dotted keys in ``Event.fields`` (plus the keys behind the core attributes);
      ``keep_fields=False`` is the same as ``project=()``.
    * ``on_progress(bytes_done, bytes_total)`` — called about every MiB read and after each file (on-disk bytes).
    * ``input_cfg`` — ``naive_timezone`` and the generic ``mapping``; when omitted, the tenant's file input whose
      ``path`` equals one of ``paths`` is used.

    Raises :class:`IngestError` (a ``ValueError``) at open time for unusable arguments: a missing path, a glob
    without data files, a pipe/device, an unknown profile or timezone. Content problems never raise; they are
    counted in ``basis``.
    """
    return FileEventSource(
        paths,
        profile=profile,
        tenant=tenant,
        since=since,
        until=until,
        max_events=max_events,
        project=project,
        on_progress=on_progress,
        input_cfg=input_cfg,
        keep_fields=keep_fields,
    )
