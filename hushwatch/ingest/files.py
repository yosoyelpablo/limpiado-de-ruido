"""File ingest: stream Events out of alert/event exports with bounded memory.

Supported inputs
----------------
* NDJSON (Wazuh ``alerts.json`` / ``archives.json``, ``.ndjson``, ``.jsonl``): one document per line; blank lines
  are skipped, malformed lines are counted (never fatal) and an unterminated last line (a live file being
  written) is tolerated.
* JSON arrays (read whole, only below :data:`MAX_JSON_DOCUMENT_BYTES`; larger arrays are rejected with a clear
  message) and pretty-printed JSON documents / ``_search`` responses (``hits.hits[]._source``), same limit.
* CSV / TSV with a header row (``,`` ``;`` ``|`` or tab, detected from the header); values stay strings.
* Any of the above gzip-compressed (detected by magic bytes), UTF-8 with or without BOM, or UTF-16 with BOM.
* Directories (recursive, deterministic order, hidden entries skipped), glob patterns and the Wazuh rotated
  layout ``.../alerts/YYYY/Mon/ossec-alerts-DD[-NNN].json(.gz)`` (files pruned by their path date when
  ``since`` / ``until`` are given). Hard links and symlinks to the same file are read once (Wazuh's live
  ``alerts.json`` is a hard link to the current day's rotated file) and ``x.json`` wins over a sibling ``x.json.gz``
  being compressed.

Every pass reads each regular file only up to the size it had when the source was opened, so a second pass
over a live ``alerts.json`` (the noise backtest) sees exactly the same events as the first; a file replaced
(re-linked, rotated) or truncated in between is reported as a partial failure instead of being read.
"""

from __future__ import annotations

import codecs
import contextlib
import csv
import glob
import gzip
import importlib
import io
import itertools
import json
import logging
import os
import re
import stat
import zlib
from collections.abc import Callable, Collection, Generator, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Final, Protocol, cast

from ..config import InputConfig, TenantConfig
from ..i18n import Entity, M, Message, register
from ..models import DataBasis, Event, get_path
from ..timeutil import UTC
from .profiles import (
    DETECT_SAMPLE,
    PROFILES,
    bind,
    canonical_mapping_key,
    detect_profile,
    timestamp_lacks_offset,
    unwrap_hit,
    zone,
)

log = logging.getLogger("hushwatch.ingest")

MAX_LINE_BYTES: Final = 16 * 1024 * 1024  # longer NDJSON lines are counted as malformed and skipped
MAX_CSV_LINE_CHARS: Final = 1024 * 1024
MAX_JSON_DOCUMENT_BYTES: Final = 50 * 1024 * 1024  # JSON arrays / single documents are parsed whole below this
FUTURE_SKEW: Final = timedelta(minutes=5)  # ts beyond wallclock + this counts as a future timestamp
DATA_SUFFIXES: Final[tuple[str, ...]] = (".json", ".ndjson", ".jsonl", ".csv", ".tsv")
_ROLLOVER: Final = timedelta(days=2)
_PROGRESS_STEP: Final = 1 << 20
_DETECT_BYTES: Final = 8 << 20  # profile detection never buffers more than ~this much input per file
_MAX_CSV_ERRORS: Final = 1000
_GZIP_MAGIC: Final = b"\x1f\x8b"
_UNSUPPORTED_MAGIC: Final[tuple[tuple[bytes, str], ...]] = (
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"PK\x03\x04", "zip"),
)
MAX_FIELDS_PER_EVENT: Final = 5000  # flattened keys kept per event (field-explosion guard, reported when hit)
MAX_SKIPPED_LISTED: Final = 200  # skipped files named in the data basis (all are counted)
_WS: Final = re.compile(r"\s*")
_ECS_ALERT_KINDS: Final = ("alert", "signal")  # ECS event.kind values of detection output

register(
    {
        "ingest.warn.alerts_only_wazuh": {
            "en": "The input contains only Wazuh alerts: events that matched a rule at or above "
            "log_alert_level (3 by default). Silence measured here is alert silence, not log-source "
            "silence, so a quiet host may still be healthy. Enable logall_json (archives) for "
            "full-fidelity silence detection.",
            "es": "La entrada solo contiene alertas de Wazuh: eventos que coincidieron con una regla de nivel "
            "igual o superior a log_alert_level (3 por defecto). El silencio medido aquí es silencio de "
            "alertas, no de la fuente de logs, así que un equipo silencioso puede estar sano. Active "
            "logall_json (archives) para detectar silencios con fidelidad completa.",
        },
        "ingest.warn.alerts_only": {
            "en": "The input contains only alerts, not raw events. Silence measured here is alert silence, not "
            "log-source silence, so a quiet source may still be healthy.",
            "es": "La entrada solo contiene alertas, no eventos en bruto. El silencio medido aquí es silencio de "
            "alertas, no de la fuente de logs, así que una fuente silenciosa puede estar sana.",
        },
        "ingest.warn.mixed_kinds": {
            "en": "The input mixes alert files and archive (full event) files. Events that raised an alert appear "
            "in both, so volumes can be counted twice; analyze them separately for exact numbers.",
            "es": "La entrada mezcla archivos de alertas y de archives (eventos completos). Los eventos que "
            "generaron una alerta aparecen en ambos, por lo que los volúmenes pueden contarse dos veces; "
            "analícelos por separado para obtener cifras exactas.",
        },
        "ingest.warn.wazuh5": {
            "en": "Wazuh 5.x data detected. It was parsed on a best-effort basis (5.x is not a stable release and "
            "its field layout is unverified), and Wazuh suppression rules are not generated for 5.x.",
            "es": "Se detectaron datos de Wazuh 5.x. Se procesaron en la medida de lo posible (5.x no es una "
            "versión estable y su estructura de campos no está verificada) y no se generan reglas de supresión "
            "de Wazuh para 5.x.",
        },
        "ingest.warn.truncated": {
            "en": "Reading stopped after {limit} events (max_events): the results cover only part of the input.",
            "es": "La lectura se detuvo tras {limit} eventos (max_events): los resultados cubren solo una parte "
            "de la entrada.",
        },
        "ingest.warn.array_too_large": {
            "en": "{file} is a JSON array or document larger than {limit_mb} MB, which cannot be read with bounded "
            "memory. Convert it to NDJSON (for example: jq -c '.[]' file.json > file.ndjson) and run again.",
            "es": "{file} es un array o documento JSON de más de {limit_mb} MB, que no se puede leer con memoria "
            "acotada. Conviértalo a NDJSON (por ejemplo: jq -c '.[]' archivo.json > archivo.ndjson) y vuelva a "
            "ejecutar.",
        },
        "ingest.warn.read_error": {
            "en": "{file} could not be read completely ({error}); events after that point were not analyzed.",
            "es": "No se pudo leer {file} por completo ({error}); los eventos posteriores a ese punto no se "
            "analizaron.",
        },
        "ingest.warn.no_files": {
            "en": "{path} contains no data files (.json, .ndjson, .jsonl, .csv or .tsv, optionally .gz).",
            "es": "{path} no contiene archivos de datos (.json, .ndjson, .jsonl, .csv o .tsv, opcionalmente .gz).",
        },
        "ingest.warn.skipped_files": {
            "en": "{count} {count:plural:file|files} in the input directories {count:plural:was|were} not "
            "read because {count:plural:it does|they do} not hold JSON, NDJSON or CSV events (for "
            "example {examples}). Convert or rename them if they contain events.",
            "es": "No se {count:plural:leyó|leyeron} {count} {count:plural:archivo|archivos} de los "
            "directorios de entrada porque no contienen eventos JSON, NDJSON ni CSV (por ejemplo "
            "{examples}). Conviértalos o cámbieles el nombre si contienen eventos.",
        },
        "ingest.warn.list_error": {
            "en": "Directory {path} could not be listed ({error}); the files inside it were not analyzed.",
            "es": "No se pudo listar el directorio {path} ({error}); sus archivos no se analizaron.",
        },
        "ingest.warn.out_of_range": {
            "en": "No events fall inside the requested time range: {events} events were outside it and {files} "
            "rotated files were skipped by their date.",
            "es": "Ningún evento cae dentro del rango de tiempo solicitado: {events} eventos quedaron fuera y se "
            "omitieron {files} archivos rotados por su fecha.",
        },
        "ingest.warn.no_timestamp": {
            "en": "None of the {count} documents had a timestamp that could be parsed. For custom formats, set "
            "the input's mapping (ts: <field>) and naive_timezone.",
            "es": "Ninguno de los {count} documentos tenía una marca de tiempo interpretable. Para formatos "
            "propios, configure el mapping de la entrada (ts: <campo>) y naive_timezone.",
        },
        "ingest.warn.mapping_unknown": {
            "en": "Unknown keys in the input mapping were ignored: {keys}.",
            "es": "Se ignoraron claves desconocidas en el mapping de la entrada: {keys}.",
        },
        "ingest.failure": {"en": "{file}: {reason}", "es": "archivo {file}: {reason}"},
        "ingest.reason.list": {
            "en": "cannot list the directory ({reason})",
            "es": "no se puede listar el directorio ({reason})",
        },
        "ingest.reason.no_files": {"en": "no data files", "es": "no hay archivos de datos"},
        "ingest.reason.array_too_large": {"en": "JSON array too large", "es": "array JSON demasiado grande"},
        "ingest.reason.document_too_large": {"en": "JSON document too large", "es": "documento JSON demasiado grande"},
        "ingest.reason.permission": {"en": "permission denied", "es": "permiso denegado"},
        "ingest.reason.truncated": {
            "en": "the compressed data ends unexpectedly",
            "es": "los datos comprimidos terminan de forma inesperada",
        },
        "ingest.reason.corrupt": {"en": "corrupt compressed data", "es": "datos comprimidos corruptos"},
        "ingest.reason.bad_array": {"en": "invalid JSON array", "es": "array JSON no válido"},
        "ingest.reason.csv_errors": {
            "en": "too many consecutive CSV errors",
            "es": "demasiados errores CSV consecutivos",
        },
        "ingest.reason.io": {"en": "I/O error: {detail}", "es": "error de E/S: {detail}"},
        "ingest.reason.compression": {
            "en": "unsupported compression ({format}); decompress it or recompress it with gzip",
            "es": "compresión no soportada ({format}); descomprímalo o vuelva a comprimirlo con gzip",
        },
        "ingest.reason.replaced": {
            "en": "the file was replaced or rotated while it was being analyzed",
            "es": "el archivo se sustituyó o rotó mientras se analizaba",
        },
        "ingest.reason.shrank": {
            "en": "the file was truncated while it was being analyzed",
            "es": "el archivo se truncó mientras se analizaba",
        },
        "ingest.reason.not_regular": {
            "en": "the path no longer points to a regular file",
            "es": "la ruta ya no apunta a un archivo normal",
        },
        "ingest.warn.partly_alerts": {
            "en": "Part of the input contains only alerts (events that matched a detection rule), not raw events. "
            "Silence measured on those sources is alert silence, not log-source silence.",
            "es": "Parte de la entrada solo contiene alertas (eventos que coincidieron con una regla de detección), "
            "no eventos en bruto. El silencio medido en esas fuentes es silencio de alertas, no de la fuente de logs.",
        },
        "ingest.warn.future_majority": {
            "en": "Most events ({count}) are stamped later than this computer's clock allows; the newest event was "
            "used as the reference time. Check the clocks of the SIEM and of this computer.",
            "es": "La mayoría de los eventos ({count}) tienen una marca de tiempo posterior a la que permite el reloj "
            "de este equipo; se usó el evento más reciente como hora de referencia. Revise los relojes del SIEM y de "
            "este equipo.",
        },
        "ingest.warn.naive_utc": {
            "en": "{count} {count:plural:file|files}, for example {file}, {count:plural:has|have} timestamps "
            "without a timezone offset; they were read as UTC. If they are local times, set "
            "naive_timezone for this input: otherwise every event is shifted by the UTC offset, which "
            "looks like silence followed by a burst.",
            "es": "{count} {count:plural:archivo|archivos}, por ejemplo {file}, {count:plural:tiene|tienen} "
            "marcas de tiempo sin desfase horario; se interpretaron como UTC. Si son horas locales, "
            "configure naive_timezone en esta entrada: de lo contrario todos los eventos quedan "
            "desplazados según el desfase respecto a UTC, lo que parece un silencio seguido de una "
            "ráfaga.",
        },
        "ingest.warn.fields_capped": {
            "en": "{count} {count:plural:event|events} had more than {limit} fields; only the first {limit} "
            "and the fields hushwatch relies on were kept.",
            "es": "{count} {count:plural:evento tenía|eventos tenían} más de {limit} campos; solo se "
            "conservaron los {limit} primeros y los campos que usa hushwatch.",
        },
    }
)


class IngestError(ValueError):
    """Unusable input specification (missing path, unknown profile...): a usage error, raised at open time."""


# ---- JSON -----------------------------------------------------------------------------------------------------


def _load_fast() -> Callable[[bytes], Any] | None:
    try:
        module = importlib.import_module("orjson")
    except ImportError:
        return None
    loads = getattr(module, "loads", None)
    return cast("Callable[[bytes], Any]", loads) if callable(loads) else None


_FAST_LOADS: Final = _load_fast()


def _fix_str(text: str) -> str:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:  # lone surrogate escapes ("\ud800") would crash every UTF-8 writer downstream
        return text.encode("utf-8", "surrogatepass").decode("utf-8", "replace")
    return text


def _scrub(value: Any) -> Any:
    if isinstance(value, str):
        return _fix_str(value)
    if isinstance(value, dict):
        return {(_fix_str(k) if isinstance(k, str) else k): _scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value


def _loads(data: bytes) -> Any:
    """Parse one JSON text. Raises ValueError / RecursionError when it is not valid JSON."""
    if _FAST_LOADS is not None:
        try:
            return _FAST_LOADS(data)
        except ValueError:
            pass  # the stdlib accepts slightly more (NaN, lone surrogate escapes, big ints): let it decide
    try:
        value = json.loads(data)
    except UnicodeDecodeError:  # invalid UTF-8 must not hide an event: keep it with U+FFFD replacements
        value = json.loads(data.decode("utf-8", "replace"))
    if b"\\ud" in data or b"\\uD" in data:
        value = _scrub(value)
    return value


# ---- per-pass read statistics ---------------------------------------------------------------------------------


@dataclass(slots=True)
class ReadStats:
    """Counters filled while reading files (one instance per pass)."""

    malformed: int = 0  # unparseable lines / documents / CSV rows
    partial_lines: int = 0  # unterminated last lines (tolerated, not malformed)
    bytes_read: int = 0  # raw (on-disk, compressed) bytes consumed
    partial_failures: list[Message | str] = field(default_factory=list)
    warnings: list[Message | str] = field(default_factory=list)

    def fail(self, label: str, reason: Message, code: str) -> None:
        """Record a file that could not be read completely (``code``: English detail for the debug log)."""
        log.debug("%s: %s", label, code)
        self.partial_failures.append(M("ingest.failure", file=Entity("file", label), reason=reason))
        self.warnings.append(M("ingest.warn.read_error", file=Entity("file", label), error=reason))


def _reason(exc: BaseException) -> tuple[Message, str]:
    if isinstance(exc, PermissionError):
        return M("ingest.reason.permission"), "permission denied"
    if isinstance(exc, EOFError):
        return M("ingest.reason.truncated"), "truncated compressed data"
    if isinstance(exc, (gzip.BadGzipFile, zlib.error)):
        return M("ingest.reason.corrupt"), "corrupt compressed data"
    detail = exc.strerror if isinstance(exc, OSError) and exc.strerror else type(exc).__name__
    return M("ingest.reason.io", detail=detail), f"I/O error ({detail})"


# ---- input resolution -----------------------------------------------------------------------------------------

# Wazuh analysisd names rotated files ossec-alerts-DD.json and, when rotate_interval / max_output_size split a day,
# ossec-alerts-DD-001.json, -002... (src/analysisd/alerts/getloglocation.c); monitord later gzips them.
_ROTATED_NAME: Final = re.compile(r"ossec-(?:alerts|archive)-(\d{2})(?:-(\d{3}))?\.(?:json|log)(?:\.gz)?")
_MONTH_DIRS: Final = {
    m: i
    for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)
}


@dataclass(frozen=True, slots=True)
class _FileSpec:
    path: str  # filesystem path used to open the file
    label: str  # display path
    size: int  # bytes at open time: every pass reads at most this much (consistent snapshot)
    fmt: str  # json | csv | tsv
    rotated: date | None  # Wazuh rotated-layout day
    split: int  # Wazuh size/interval split counter within the day (ossec-alerts-DD-NNN.json), 0 otherwise
    kind_hint: str | None  # alerts | archives | None (from the file name / directory)
    year: int  # default year for year-less (syslog) timestamps
    ref_time: datetime  # mtime, UTC
    key: tuple[int, int]  # (st_dev, st_ino)


@dataclass(slots=True)
class _Resolved:
    files: list[_FileSpec] = field(default_factory=list)
    warnings: list[Message | str] = field(default_factory=list)
    failures: list[Message | str] = field(default_factory=list)
    pruned: int = 0
    skipped: list[str] = field(default_factory=list)  # files inside input directories / globs that were not read
    skipped_total: int = 0


def _strip_gz(name: str) -> str:
    lowered = name.lower()
    return lowered[:-3] if lowered.endswith(".gz") else lowered


def _is_data_file(name: str) -> bool:
    return _strip_gz(name).endswith(DATA_SUFFIXES)


def _format_of(name: str) -> str:
    base = _strip_gz(name)
    if base.endswith(".csv"):
        return "csv"
    if base.endswith(".tsv"):
        return "tsv"
    return "json"


def _rotated(path: str | Path) -> tuple[date, int] | None:
    """(day, split counter) of a Wazuh rotated file; the counter is 0 for ``ossec-alerts-DD.json``."""
    parts = Path(path).parts
    if len(parts) < 3:
        return None
    match = _ROTATED_NAME.fullmatch(parts[-1])
    month = _MONTH_DIRS.get(parts[-2])
    year = parts[-3]
    if match is None or month is None or len(year) != 4 or not year.isdigit():
        return None
    try:
        return date(int(year), month, int(match.group(1))), int(match.group(2) or 0)
    except ValueError:
        return None


def rotated_date(path: str | Path) -> date | None:
    """Day of a Wazuh rotated file (``.../2026/Sep/ossec-alerts-25.json.gz`` or the size-split
    ``ossec-alerts-25-001.json.gz`` -> 2026-09-25), else None."""
    found = _rotated(path)
    return found[0] if found is not None else None


def _kind_hint(path: str) -> str | None:
    parts = Path(path).parts
    name = parts[-1].lower() if parts else ""
    # "alert" wins: "alerts-archive-2025.json" is an archived copy of ALERTS, and calling alerts "archives" would
    # present alert silence as full-fidelity source silence (a false green).
    if "alert" in name:
        return "alerts"
    if "archive" in name:
        return "archives"
    for part in reversed(parts[:-1]):
        lowered = part.lower()
        if lowered in ("archives", "archive"):
            return "archives"
        if lowered == "alerts":
            return "alerts"
    return None


_SNIFF_BYTES: Final = 64 * 1024


def _sniff_json(path: str) -> bool:
    """Whether a file without a data extension (``.log``, no extension...) holds JSON events: its first non-blank
    line (after an optional gzip layer and BOM) is a JSON object, or it starts a JSON array of objects. Reads at most
    ~64 KiB; never raises."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(_SNIFF_BYTES)
        if head.startswith(_GZIP_MAGIC):
            head = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(head, _SNIFF_BYTES)
    except (OSError, zlib.error, ValueError):
        return False
    if head.startswith(codecs.BOM_UTF8):
        head = head[len(codecs.BOM_UTF8) :]
    text = head.lstrip()
    if text.startswith(b"["):
        return text[1:].lstrip().startswith(b"{")
    if not text.startswith(b"{"):
        return False
    end = text.find(b"\n")
    if end < 0:
        return text.rstrip().endswith(b"}") or len(head) >= _SNIFF_BYTES  # one (long) document
    try:
        return isinstance(json.loads(text[:end]), dict)
    except (ValueError, RecursionError):
        return b"\n" in text and text[:end].rstrip() == b"{"  # a pretty-printed document


def _companion(name: str, siblings: set[str]) -> bool:
    """Wazuh writes every JSON log with companions that are not event data: ``.sum`` checksums and the plain-text
    ``alerts.log`` / ``ossec-alerts-DD.log(.gz)`` twin of ``alerts.json``. They are skipped silently when the JSON
    twin is there (a ``.log`` without it is reported: it may be the only copy of the events)."""
    lowered = name.lower()
    if lowered.endswith(".sum"):
        return True
    base = _strip_gz(lowered)
    if not base.endswith(".log"):
        return False
    stem = base[:-4]
    return f"{stem}.json" in siblings or f"{stem}.json.gz" in siblings


def _skip(out: _Resolved, path: str) -> None:
    out.skipped_total += 1
    if len(out.skipped) < MAX_SKIPPED_LISTED:
        out.skipped.append(path)


def _has_magic(text: str) -> bool:
    return any(ch in text for ch in "*?[")


def _walk(root: str, found: list[tuple[str, os.stat_result]], out: _Resolved) -> None:
    def onerror(exc: OSError) -> None:
        where = str(exc.filename or root)
        reason, code = _reason(exc)
        out.warnings.append(M("ingest.warn.list_error", path=Entity("file", where), error=reason))
        listing = M("ingest.reason.list", reason=reason)
        out.failures.append(M("ingest.failure", file=Entity("file", where), reason=listing))
        log.debug("%s: cannot list directory (%s)", where, code)

    for dirpath, dirnames, filenames in os.walk(root, onerror=onerror, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        lowered = {n.lower() for n in filenames}
        for name in sorted(filenames):
            if name.startswith("."):
                continue  # hidden files (.DS_Store, editor swap files...) are never event data
            full = os.path.join(dirpath, name)
            try:
                st = os.stat(full)
            except (FileNotFoundError, NotADirectoryError):
                log.debug("skipping dangling directory entry %s", full)  # e.g. a broken symlink: no data behind it
                continue
            except OSError as exc:  # a data file we cannot even stat must not vanish from the analysis silently
                if not _is_data_file(name):
                    _skip(out, full)
                    continue
                reason, code = _reason(exc)
                out.warnings.append(M("ingest.warn.read_error", file=Entity("file", full), error=reason))
                out.failures.append(M("ingest.failure", file=Entity("file", full), reason=reason))
                log.debug("%s: %s", full, code)
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if _is_data_file(name) or _sniff_json(full):
                found.append((full, st))
            elif not _companion(name, lowered):  # Wazuh's plain-text / checksum twins are not event data
                _skip(out, full)  # never silently: the data basis lists what was left out


def _collect(given: str, out: _Resolved) -> list[tuple[str, os.stat_result]]:
    """Files named by one input argument (a file, a directory or a glob)."""
    expanded = os.path.expanduser(given)
    found: list[tuple[str, os.stat_result]] = []
    try:
        st: os.stat_result | None = os.stat(expanded)
    except (FileNotFoundError, NotADirectoryError):
        st = None
    except OSError as exc:
        raise IngestError(f"cannot access input {given}: {exc.strerror or type(exc).__name__}") from None
    if st is None:
        if not _has_magic(given):
            raise IngestError(f"input not found: {given}")
        matches = sorted(glob.glob(expanded, recursive=True))
        for match in matches:
            try:
                mst = os.stat(match)
            except OSError:
                continue
            if stat.S_ISDIR(mst.st_mode):
                _walk(match, found, out)
            elif stat.S_ISREG(mst.st_mode):
                if _is_data_file(match) or _sniff_json(match):
                    found.append((match, mst))
                else:
                    _skip(out, match)
        if not found:
            raise IngestError(f"no data files match {given}")
        return found
    if stat.S_ISDIR(st.st_mode):
        _walk(expanded, found, out)
        if not found:
            out.warnings.append(M("ingest.warn.no_files", path=Entity("file", given)))
            out.failures.append(M("ingest.failure", file=Entity("file", given), reason=M("ingest.reason.no_files")))
        return found
    if not stat.S_ISREG(st.st_mode):
        raise IngestError(
            f"{given} is not a regular file; pipes and devices cannot be re-read for the second analysis pass, "
            f"save the data to a file first"
        )
    return [(expanded, st)]


def _resolve_inputs(given: Sequence[str], since: datetime | None, until: datetime | None) -> _Resolved:
    out = _Resolved()
    seen: set[tuple[int, int]] = set()
    for argument in given:
        found = _collect(argument, out)
        names = {path for path, _ in found}
        specs: list[_FileSpec] = []
        for path, st in found:
            key = (st.st_dev, st.st_ino)
            if key in seen:
                log.debug("skipping %s: same file as an earlier input (link)", path)
                continue
            if path.lower().endswith(".gz") and path[:-3] in names:
                log.debug("skipping %s: the uncompressed file is also present", path)
                continue
            seen.add(key)
            rotated = _rotated(path)
            day = rotated[0] if rotated is not None else None
            if day is not None and _outside(day, since, until):
                out.pruned += 1
                continue
            mtime = datetime.fromtimestamp(st.st_mtime, tz=UTC)
            specs.append(
                _FileSpec(
                    path=path,
                    label=path if path != os.path.expanduser(argument) else argument,
                    size=st.st_size,
                    fmt=_format_of(path),
                    rotated=day,
                    split=rotated[1] if rotated is not None else 0,
                    kind_hint=_kind_hint(path),
                    year=day.year if day is not None else mtime.year,
                    ref_time=mtime,
                    key=key,
                )
            )
        # chronological: rotated files by (day, split) - "ossec-alerts-25-001" sorts before "ossec-alerts-25." as
        # text but was written after it - then everything else by path
        specs.sort(key=lambda s: (0, s.rotated, s.split, s.path) if s.rotated is not None else (1, date.min, 0, s.path))
        out.files.extend(specs)
    return out


def _outside(day: date, since: datetime | None, until: datetime | None) -> bool:
    """True when a rotated file for local ``day`` cannot hold events in [since, until) whatever the manager's
    UTC offset (-12h..+14h): its events lie within [day - 1d, day + 2d) UTC."""
    start = datetime(day.year, day.month, day.day, tzinfo=UTC)
    if since is not None and start + timedelta(days=2) <= since:
        return True
    return until is not None and start - timedelta(days=1) >= until


# ---- low-level readers ----------------------------------------------------------------------------------------


class _LineReader(Protocol):
    def readline(self, size: int = -1, /) -> bytes: ...

    def read(self, size: int = -1, /) -> bytes: ...


class _Counted(io.RawIOBase):
    """Raw reader that stops after ``cap`` bytes (snapshot of a growing file) and counts what it reads."""

    def __init__(self, raw: io.FileIO, cap: int, stats: ReadStats) -> None:
        super().__init__()
        self._raw = raw
        self._left = cap
        self._stats = stats

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        if self._left <= 0:
            return 0
        view = memoryview(buffer).cast("B")
        if len(view) > self._left:
            view = view[: self._left]
        count = self._raw.readinto(view) or 0
        self._left -= count
        self._stats.bytes_read += count
        return count


class _TextLines:
    """Byte-line view of a decoded text stream (UTF-16 inputs), so one JSON code path serves every encoding."""

    def __init__(self, text: io.TextIOWrapper) -> None:
        self._text = text

    def readline(self, size: int = -1, /) -> bytes:
        return self._text.readline(size).encode("utf-8", "replace")

    def read(self, size: int = -1, /) -> bytes:
        return self._text.read(size).encode("utf-8", "replace")


class _Restart(Exception):
    """Internal: a pretty-printed-document guess failed; re-read the file as NDJSON."""


class _Changed(Exception):
    """Internal: the path no longer names the file that was resolved at open time."""

    def __init__(self, reason: str, code: str) -> None:
        super().__init__(code)
        self.reason = reason
        self.code = code


_OPEN_FLAGS: Final = (
    os.O_RDONLY
    | getattr(os, "O_NONBLOCK", 0)  # a path swapped for a FIFO must not block the run forever
    | getattr(os, "O_NOCTTY", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_BINARY", 0)
)


def _path_key(path: str) -> tuple[int, int] | None:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return st.st_dev, st.st_ino


def _open_snapshot(spec: _FileSpec) -> io.FileIO:
    """Open ``spec.path`` and check it is still the regular file (same inode, not shorter) resolved at open time.

    Wazuh re-links ``alerts.json`` to a new day's file at midnight and ``logrotate copytruncate`` empties files in
    place: reading such a path again would silently analyze different events in the backtest pass.
    """
    fd = os.open(spec.path, _OPEN_FLAGS)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise _Changed("ingest.reason.not_regular", "no longer a regular file")
        opened = (st.st_dev, st.st_ino)
        if spec.key[1] and opened != spec.key and opened == _path_key(spec.path):
            # (a filesystem whose stat() and fstat() disagree - old overlayfs - cannot tell, and is not blamed)
            raise _Changed("ingest.reason.replaced", "file replaced while being analyzed")
        if st.st_size < spec.size:
            raise _Changed("ingest.reason.shrank", "file truncated while being analyzed")
        if hasattr(os, "set_blocking"):
            os.set_blocking(fd, True)
        return io.FileIO(fd, "rb", closefd=True)
    except BaseException:
        os.close(fd)
        raise


@dataclass(slots=True)
class _Gate:
    """Line pre-filter for NDJSON input: when ``keep`` is set, lines it rejects are skipped before JSON parsing
    (the noise backtest only needs a few rules' events). It can be set while the file is being read."""

    keep: Callable[[bytes], bool] | None = None


def _iter_file(spec: _FileSpec, stats: ReadStats, gate: _Gate | None = None) -> Generator[dict[str, Any], None, None]:
    """Documents of one file. Read errors are recorded in ``stats`` (never raised)."""
    force_ndjson = False
    for _attempt in range(2):
        try:
            with contextlib.ExitStack() as stack:
                raw = stack.enter_context(_open_snapshot(spec))
                buffered = stack.enter_context(io.BufferedReader(_Counted(raw, spec.size, stats), 1 << 20))
                stream: io.BufferedReader[Any] | gzip.GzipFile = buffered
                head = buffered.peek(8)[:8]
                if head.startswith(_GZIP_MAGIC):
                    stream = stack.enter_context(gzip.GzipFile(fileobj=buffered, mode="rb"))
                else:
                    for magic, name in _UNSUPPORTED_MAGIC:
                        if head.startswith(magic):
                            stats.fail(spec.label, M("ingest.reason.compression", format=name), f"{name} compressed")
                            return
                yield from _iter_stream(stream, spec, stats, force_ndjson, gate)
            return
        except _Restart:
            force_ndjson = True
        except _Changed as exc:
            stats.fail(spec.label, M(exc.reason), exc.code)
            log.debug("%s changed since it was opened: %s", spec.label, exc.code)
            return
        except (OSError, EOFError, zlib.error) as exc:
            reason, code = _reason(exc)
            stats.fail(spec.label, reason, code)
            log.debug("read error in %s: %s", spec.label, code)
            return
        except Exception as exc:  # last resort: hostile bytes must never abort the whole analysis
            name = type(exc).__name__
            stats.fail(spec.label, M("ingest.reason.io", detail=name), f"unexpected error ({name})")
            log.warning("unexpected error while reading %s: %s", spec.label, name)
            return


def _iter_stream(
    stream: io.BufferedReader[Any] | gzip.GzipFile,
    spec: _FileSpec,
    stats: ReadStats,
    force_ndjson: bool,
    gate: _Gate | None = None,
) -> Iterator[dict[str, Any]]:
    head = stream.peek(4)[:4]
    utf16 = head.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)) and not head.startswith(codecs.BOM_UTF32_LE)
    if not utf16 and head.startswith(codecs.BOM_UTF8):
        stream.read(len(codecs.BOM_UTF8))
    encoding = "utf-16" if utf16 else "utf-8"
    if spec.fmt in ("csv", "tsv"):
        text = io.TextIOWrapper(stream, encoding=encoding, errors="replace", newline="")
        yield from _iter_csv(text, spec, stats)
        return
    reader: _LineReader = stream
    if utf16:
        reader = _TextLines(io.TextIOWrapper(stream, encoding=encoding, errors="replace"))
    yield from _iter_json(reader, spec, stats, force_ndjson, gate)


def _documents(obj: dict[str, Any], stats: ReadStats) -> Iterator[dict[str, Any]]:
    """A parsed JSON object -> event documents (unwraps ``_search`` responses and hits)."""
    hits = obj.get("hits")
    if (
        isinstance(hits, dict)
        and isinstance(hits.get("hits"), list)
        and ("took" in obj or "timed_out" in obj or "_shards" in obj)
    ):
        for hit in hits["hits"]:
            if isinstance(hit, dict):
                yield unwrap_hit(hit)
            else:
                stats.malformed += 1
        return
    yield unwrap_hit(obj)


def _iter_json(
    reader: _LineReader, spec: _FileSpec, stats: ReadStats, force_ndjson: bool, gate: _Gate | None = None
) -> Iterator[dict[str, Any]]:
    limit = MAX_LINE_BYTES + 1
    first = reader.readline(limit)
    while first and not first.strip():
        first = reader.readline(limit)
    if not first:
        return
    if not force_ndjson:
        stripped = first.strip()
        if stripped.startswith(codecs.BOM_UTF8):
            stripped = stripped[len(codecs.BOM_UTF8) :]
        if stripped.startswith(b"["):
            yield from _iter_array(first, reader, spec, stats)
            return
        if stripped.startswith(b"{") and not stripped.endswith(b"}"):
            yield from _iter_document(first, reader, spec, stats)  # raises _Restart before yielding if not JSON
            return
    yield from _iter_ndjson(first, reader, stats, gate)


def _iter_ndjson(
    first: bytes, reader: _LineReader, stats: ReadStats, gate: _Gate | None = None
) -> Iterator[dict[str, Any]]:
    limit = MAX_LINE_BYTES + 1
    line = first
    while line:
        if len(line) >= limit and not line.endswith(b"\n"):
            stats.malformed += 1  # over-long line: skip the rest of it without holding it in memory
            while line and not line.endswith(b"\n"):
                line = reader.readline(limit)
            line = reader.readline(limit)
            continue
        if gate is not None and gate.keep is not None and not gate.keep(line):
            line = reader.readline(limit)  # pre-filtered out (a superset test): not parsed, not counted
            continue
        text = line.strip()
        if text:
            if text.startswith(codecs.BOM_UTF8):
                text = text[len(codecs.BOM_UTF8) :]
            try:
                obj = _loads(text)
            except (ValueError, RecursionError):
                if line.endswith(b"\n"):
                    stats.malformed += 1
                else:
                    stats.partial_lines += 1  # unterminated last line: the writer is mid-line
            else:
                if type(obj) is dict and "_source" not in obj and "hits" not in obj:
                    yield obj  # the common case, without a generator per line
                elif isinstance(obj, dict):
                    yield from _documents(obj, stats)
                else:
                    stats.malformed += 1
        line = reader.readline(limit)


def _read_whole(first: bytes, reader: _LineReader) -> tuple[bytes, bool]:
    """``first`` plus the rest of the stream (at most MAX_JSON_DOCUMENT_BYTES + 1 bytes) and whether it was
    larger than MAX_JSON_DOCUMENT_BYTES (then the data is only a head)."""
    rest = reader.read(max(0, MAX_JSON_DOCUMENT_BYTES + 1 - len(first)))
    data = first + rest
    return data, len(data) > MAX_JSON_DOCUMENT_BYTES


def _second_line_is_object(data: bytes) -> bool:
    """True when the first non-blank line after the first one starts a JSON object (NDJSON), False for the
    continuation lines of a pretty-printed document."""
    position = data.find(b"\n")
    while position >= 0:
        end = data.find(b"\n", position + 1)
        line = data[position + 1 : end if end >= 0 else len(data)].strip()
        if line:
            return line.startswith(b"{")
        position = end
    return False


def _too_large(spec: _FileSpec, stats: ReadStats, what: str = "array") -> None:
    reason = M("ingest.reason.document_too_large" if what == "document" else "ingest.reason.array_too_large")
    stats.partial_failures.append(M("ingest.failure", file=Entity("file", spec.label), reason=reason))
    stats.warnings.append(
        M("ingest.warn.array_too_large", file=Entity("file", spec.label), limit_mb=MAX_JSON_DOCUMENT_BYTES >> 20)
    )


def _iter_array(first: bytes, reader: _LineReader, spec: _FileSpec, stats: ReadStats) -> Iterator[dict[str, Any]]:
    # A first line that is a complete "[...]" followed by more lines is an NDJSON file whose first line is junk
    # (or not an object), not a JSON array: re-read it as NDJSON instead of rejecting the whole file.
    complete_line = first.endswith(b"\n") and first.rstrip().endswith(b"]")
    data, too_large = _read_whole(first, reader)
    if too_large:
        del data
        if complete_line:
            raise _Restart
        _too_large(spec, stats)
        return
    if data.startswith(codecs.BOM_UTF8):
        data = data[len(codecs.BOM_UTF8) :]
    try:
        value = _loads(data)
    except (ValueError, RecursionError):
        if complete_line and data.strip().count(b"\n") > 0:
            raise _Restart from None
        stats.malformed += 1
        stats.fail(spec.label, M("ingest.reason.bad_array"), "invalid JSON array")
        return
    del data
    if not isinstance(value, list):
        stats.malformed += 1
        return
    for index in range(len(value)):
        item = value[index]
        value[index] = None  # release documents as they are consumed
        if isinstance(item, dict):
            yield from _documents(item, stats)
        else:
            stats.malformed += 1


def _skip_ws(text: str, position: int) -> int:
    match = _WS.match(text, position)
    return match.end() if match is not None else position


def _iter_document(first: bytes, reader: _LineReader, spec: _FileSpec, stats: ReadStats) -> Iterator[dict[str, Any]]:
    """Pretty-printed JSON object(s) (``jq .`` output, a saved ``_search`` response).

    An invalid document is counted as malformed and reading resumes at the next line that starts with ``{`` (the
    next top-level object of ``jq .`` style output), so one broken document never hides the rest of the file.
    """
    data, too_large = _read_whole(first, reader)
    if too_large:
        if _second_line_is_object(data):
            raise _Restart  # NDJSON whose first line is broken: read it line by line
        del data
        _too_large(spec, stats, "document")  # too big to parse with bounded memory
        return
    text = data.decode("utf-8", "replace").lstrip("\ufeff")
    del data
    scrub = "\\ud" in text or "\\uD" in text
    decoder = json.JSONDecoder()
    position = _skip_ws(text, 0)
    decoded = 0
    pending = 0  # invalid documents seen before the first valid one (discarded if we fall back to NDJSON)
    while position < len(text):
        try:
            obj, end = decoder.raw_decode(text, position)
            if scrub:
                obj = _scrub(obj)
        except (ValueError, RecursionError):
            if decoded:
                stats.malformed += 1
            else:
                pending += 1
            resume = text.find("\n{", position)
            if resume < 0:
                break
            position = resume + 1
            continue
        if decoded == 0 and pending:
            stats.malformed += pending
        decoded += 1
        if isinstance(obj, dict):
            yield from _documents(obj, stats)
        else:
            stats.malformed += 1
        position = _skip_ws(text, end)
    if decoded == 0:
        raise _Restart


def _csv_lines(text: io.TextIOWrapper, stats: ReadStats) -> Iterator[str]:
    limit = MAX_CSV_LINE_CHARS + 1
    while True:
        line = text.readline(limit)
        if not line:
            return
        if len(line) >= limit and not line.endswith(("\n", "\r")):
            stats.malformed += 1
            while line and not line.endswith(("\n", "\r")):
                line = text.readline(limit)
            continue
        yield line


def _sniff_delimiter(header: str) -> str:
    counts = {d: header.count(d) for d in (",", ";", "\t", "|")}
    best = max(counts, key=lambda d: counts[d])
    return best if counts[best] > 0 else ","


def _iter_csv(text: io.TextIOWrapper, spec: _FileSpec, stats: ReadStats) -> Iterator[dict[str, Any]]:
    lines = _csv_lines(text, stats)
    header_line = next((line for line in lines if line.strip()), None)
    if header_line is None:
        return
    delimiter = "\t" if spec.fmt == "tsv" else _sniff_delimiter(header_line)
    reader = csv.reader(itertools.chain([header_line], lines), delimiter=delimiter)
    try:
        header = next(reader)
    except (csv.Error, StopIteration):
        stats.malformed += 1
        return
    names = [name.strip().lstrip("\ufeff").strip() for name in header]
    if not any(names):
        stats.malformed += 1
        return
    errors = 0
    while True:
        try:
            row = next(reader)
        except StopIteration:
            return
        except csv.Error:
            stats.malformed += 1
            errors += 1
            if errors >= _MAX_CSV_ERRORS:
                stats.fail(spec.label, M("ingest.reason.csv_errors"), "too many CSV errors")
                return
            continue
        errors = 0
        doc = {name: cell for name, cell in zip(names, row, strict=False) if name and cell != ""}
        if doc:
            yield doc


# ---- public helpers -------------------------------------------------------------------------------------------


def _as_list(paths: Sequence[str | os.PathLike[str]] | str | os.PathLike[str]) -> list[str]:
    items: Sequence[str | os.PathLike[str]] = [paths] if isinstance(paths, (str, os.PathLike)) else paths
    out: list[str] = []
    for item in items:
        text = os.fspath(item)
        if not isinstance(text, str) or not text:
            raise IngestError("input paths must be non-empty strings or paths")
        out.append(text)
    if not out:
        raise IngestError("no input paths given")
    return out


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def iter_documents(
    paths: Sequence[str | os.PathLike[str]] | str | os.PathLike[str],
    since: datetime | None = None,
    *,
    until: datetime | None = None,
    stats: ReadStats | None = None,
) -> Iterator[tuple[dict[str, Any], str]]:
    """Yield ``(raw document, source label)`` for every document in ``paths`` (files, directories, globs).

    Inputs are resolved immediately (``IngestError`` for a missing path); reading is lazy and streaming.
    Rotated Wazuh files outside ``[since, until)`` are skipped by their path date; documents themselves are not
    time-filtered. Malformed lines and read failures are counted in ``stats`` (pass one to inspect them).
    """
    resolved = _resolve_inputs(_as_list(paths), _aware(since), _aware(until))
    sink = stats if stats is not None else ReadStats()
    sink.partial_failures.extend(resolved.failures)
    sink.warnings.extend(resolved.warnings)
    return _iter_resolved(resolved.files, sink)


def _iter_resolved(files: list[_FileSpec], stats: ReadStats) -> Iterator[tuple[dict[str, Any], str]]:
    for spec in files:
        docs = _iter_file(spec, stats)
        try:
            for doc in docs:
                yield doc, spec.label
        finally:
            docs.close()


# ---- rule pre-filter ------------------------------------------------------------------------------------------

# rule ids that JSON writes verbatim (no escapes: no quote, backslash, slash, control or non-ASCII characters)
_VERBATIM_ID: Final = re.compile(r"[ !#-.0-\[\]-~]{1,256}")


def rule_line_filter(rule_ids: Collection[str], *, numbers: bool = True) -> Callable[[bytes], bool] | None:
    """A cheap test on one raw NDJSON line: False only when the line cannot hold an event of one of ``rule_ids``.

    A rule id is a JSON string (``"5710"``, written verbatim) or, in some exports, a number (``: 5710,``); both forms
    are looked for (``numbers=False``: strings only, as Wazuh writes ``rule.id``). None when an id could be written
    with escapes (then every line must be parsed).
    """
    ids = sorted({r for r in rule_ids if isinstance(r, str) and r})
    if not ids or any(_VERBATIM_ID.fullmatch(r) is None for r in ids):
        return None
    quoted = tuple(b'"' + r.encode("ascii") + b'"' for r in ids)
    digits = [r.encode("ascii") for r in ids if r.isdigit()] if numbers else []
    bare = (
        re.compile(rb"(?<=[:\[,\s])(?:" + b"|".join(re.escape(d) for d in digits) + rb")(?=[,\]}\s.eE])")
        if digits
        else None
    )

    def keep(line: bytes) -> bool:
        for needle in quoted:
            if needle in line:
                return True
        if bare is None:
            return False
        return any(d in line for d in digits) and bare.search(line) is not None

    return keep


# ---- the event source -----------------------------------------------------------------------------------------


def _matching_input(tenant: TenantConfig, given: Sequence[str]) -> InputConfig | None:
    wanted = set(given) | {os.path.expanduser(g) for g in given}
    for item in tenant.inputs:
        if item.type == "file" and item.path and (item.path in wanted or os.path.expanduser(item.path) in wanted):
            return item
    return None


@dataclass(slots=True)
class _FileTally:
    rule: int = 0
    norule: int = 0
    bad: int = 0
    archive_index: bool = False


def _file_kind(spec: _FileSpec, profile: str, tally: _FileTally) -> str | None:
    if tally.rule == 0 and tally.norule == 0:
        return None
    if spec.kind_hint == "archives" or tally.archive_index:
        return "archives"
    if profile == "generic":
        return "alerts" if tally.rule > 0 else "unknown"
    return "archives" if tally.norule > 0 else "alerts"


class FileEventSource:
    """Re-iterable stream of :class:`Event` from files, with a :class:`DataBasis` describing it.

    Every full iteration re-reads the files and rebuilds ``basis`` from scratch (so the backtest's second pass
    never double counts); ``basis`` is replaced only when a pass completes (normally or by hitting
    ``max_events``, which sets ``basis.truncated``). Events outside ``[since, until)`` are skipped, events with
    unparseable timestamps are counted in ``bad_timestamps`` and events later than wallclock + 5 min are counted
    in ``future_timestamps`` but still yielded. ``basis.now`` is the newest event that is not in the future
    (a few clock-skewed sources must not push "now" ahead and make every other source look silent), unless most
    events are in the future: then the whole data set is ahead of this computer's clock and ``now`` is the newest
    event (``basis.end``), with a warning.
    """

    def __init__(
        self,
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
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        given = _as_list(paths)
        if profile not in ("auto", *PROFILES):
            raise IngestError(f"unknown profile {profile!r}; expected auto, {', '.join(PROFILES)}")
        if max_events is not None and (isinstance(max_events, bool) or max_events < 0):
            raise IngestError("max_events must be a non-negative integer")
        self._since = _aware(since)
        self._until = _aware(until)
        if self._since is not None and self._until is not None and self._since >= self._until:
            raise IngestError("since must be earlier than until")
        self.tenant = tenant
        self.input_cfg = input_cfg if input_cfg is not None else _matching_input(tenant, given)
        self._config_warnings: list[Message | str] = []
        if self.input_cfg is not None:
            if self.input_cfg.naive_timezone:
                try:
                    zone(self.input_cfg.naive_timezone)
                except ValueError as exc:
                    raise IngestError(str(exc)) from None
            unknown = sorted(k for k in self.input_cfg.mapping if canonical_mapping_key(str(k)) is None)
            if unknown:
                self._config_warnings.append(M("ingest.warn.mapping_unknown", keys=unknown))
        self.paths = given
        self.profile = profile
        self._max_events = max_events
        self._project: tuple[str, ...] | None = tuple(project) if project is not None else None
        if self._project is None and not keep_fields:
            self._project = ()
        self._on_progress = on_progress
        self._clock = clock or (lambda: datetime.now(UTC))
        self._resolved = _resolve_inputs(given, self._since, self._until)
        self._total_bytes = sum(spec.size for spec in self._resolved.files)
        self.basis = DataBasis(profile="unknown" if profile == "auto" else profile, sources=list(given))

    @property
    def files(self) -> list[str]:
        """Resolved file paths, in reading order."""
        return [spec.label for spec in self._resolved.files]

    def __iter__(self) -> Iterator[Event]:
        stats = ReadStats()
        future_limit = self._clock() + FUTURE_SKEW
        since, until, limit = self._since, self._until, self._max_events
        project, input_cfg = self._project, self.input_cfg
        progress = self._on_progress
        events = bad = future = filtered = capped = 0
        start: datetime | None = None
        end: datetime | None = None
        now: datetime | None = None
        excluded_newest: datetime | None = None  # newest event left out by since/until (explains an empty window)
        truncated = False
        reported = 0
        file_profiles: list[str] = []
        kinds: dict[str, str] = {}  # kind -> profile of the first file of that kind
        check_naive = input_cfg is None or not input_cfg.naive_timezone
        naive_files: list[str] = []  # files whose timestamps carry no offset (read as UTC)

        for spec in self._resolved.files:
            docs = _iter_file(spec, stats)
            tally = _FileTally()
            try:
                profile = self.profile
                stream: Iterator[dict[str, Any]] = docs
                if profile == "auto":
                    head = self._detection_sample(docs, stats)
                    profile = detect_profile(head) if head else "generic"
                    stream = itertools.chain(head, docs)
                norm = bind(profile, input_cfg=input_cfg, default_year=spec.year, project=project)
                # only generic data can carry year-less (syslog) timestamps; every other profile's time has a year
                rollover_after = spec.ref_time + _ROLLOVER if spec.rotated is None and profile == "generic" else None
                # Wazuh archives documents lack the WHOLE rule object; a document with any rule attribute (an
                # export without the rule.id column) is still an alert, not a full-fidelity archived event
                wazuh = profile in ("wazuh4", "wazuh5")
                for doc in stream:
                    try:
                        event = norm(doc)
                        if event is not None and rollover_after is not None and event.ts > rollover_after:
                            event = self._year_rollover(doc, profile, spec.year, event)
                    except Exception as exc:  # one hostile document must never abort the analysis: count it
                        stats.malformed += 1
                        log.debug("document in %s could not be normalized (%s)", spec.label, type(exc).__name__)
                        continue
                    if event is None:
                        tally.bad += 1
                        continue
                    if check_naive and tally.rule == tally.norule == 0:  # first dated document of the file
                        with contextlib.suppress(Exception):
                            if timestamp_lacks_offset(doc, profile, input_cfg=input_cfg):
                                naive_files.append(spec.label)
                    if (
                        event.rule_id is not None
                        or (wazuh and (event.rule_name is not None or event.severity is not None))
                        or (profile == "ecs" and get_path(event.fields, "event.kind") in _ECS_ALERT_KINDS)
                    ):
                        tally.rule += 1
                    else:
                        tally.norule += 1
                    if not tally.archive_index:
                        index = doc.get("_index")
                        tally.archive_index = isinstance(index, str) and "archives" in index
                    ts = event.ts
                    if (since is not None and ts < since) or (until is not None and ts >= until):
                        filtered += 1
                        if (excluded_newest is None or ts > excluded_newest) and ts <= future_limit:
                            excluded_newest = ts
                        continue
                    if limit is not None and events >= limit:
                        truncated = True
                        break
                    events += 1
                    if start is None or ts < start:
                        start = ts
                    if end is None or ts > end:
                        end = ts
                    if ts > future_limit:
                        future += 1
                    elif now is None or ts > now:
                        now = ts
                    if progress is not None and not events & 1023 and stats.bytes_read - reported >= _PROGRESS_STEP:
                        reported = stats.bytes_read
                        progress(min(reported, self._total_bytes), self._total_bytes)
                    if len(event.fields) > MAX_FIELDS_PER_EVENT:
                        event.fields = self._cap_fields(doc, profile, spec.year, event.fields)
                        capped += 1
                    yield event
            finally:
                docs.close()
            bad += tally.bad
            if tally.rule or tally.norule or tally.bad:
                file_profiles.append(profile)
            kind = _file_kind(spec, profile, tally)
            if kind is not None:
                kinds.setdefault(kind, profile)
            if progress is not None:
                reported = stats.bytes_read
                progress(min(reported, self._total_bytes), self._total_bytes)
            if truncated:
                break

        self.basis = self._build_basis(
            stats,
            events=events,
            bad=bad,
            future=future,
            filtered=filtered,
            capped=capped,
            start=start,
            end=end,
            now=now,
            truncated=truncated,
            file_profiles=file_profiles,
            kinds=kinds,
            naive_files=naive_files,
            excluded_newest=excluded_newest,
        )
        log.debug(
            "ingest pass: %d events, %d malformed, %d partial last lines, %d bad timestamps, %d future, "
            "%d filtered, truncated=%s",
            events,
            stats.malformed,
            stats.partial_lines,
            bad,
            future,
            filtered,
            truncated,
        )

    def iter_rules(self, rule_ids: Collection[str]) -> Iterator[Event]:
        """The events of ``rule_ids`` only, exactly as a full iteration yields them (same files, time window and
        fields), read cheaply for the noise backtest: NDJSON lines that cannot hold one of those rules are skipped
        before JSON parsing (a superset test on the raw bytes, then an exact check on the normalized rule id).

        ``basis`` is left untouched (it describes the full pass). With ``max_events`` the full pass decides which
        events were analyzed, so then every document is read and filtered.
        """
        wanted = frozenset(r for r in rule_ids if isinstance(r, str) and r)
        if not wanted:
            return
        if self._max_events is not None:
            saved = self.basis
            try:
                yield from (event for event in self if event.rule_id in wanted)
            finally:
                self.basis = saved
            return
        keep_any = rule_line_filter(wanted)
        keep_strings = rule_line_filter(wanted, numbers=False)  # Wazuh always writes rule.id as a JSON string
        stats = ReadStats()
        since, until = self._since, self._until
        project, input_cfg = self._project, self.input_cfg
        for spec in self._resolved.files:
            gate = _Gate()
            docs = _iter_file(spec, stats, gate)
            try:
                profile = self.profile
                stream: Iterator[dict[str, Any]] = docs
                if profile == "auto":  # detected from the same head as the full pass (parsed unfiltered)
                    head = self._detection_sample(docs, stats)
                    profile = detect_profile(head) if head else "generic"
                    stream = itertools.chain(head, docs)
                gate.keep = keep_strings if profile in ("wazuh4", "wazuh5") else keep_any
                norm = bind(profile, input_cfg=input_cfg, default_year=spec.year, project=project)
                rollover_after = spec.ref_time + _ROLLOVER if spec.rotated is None and profile == "generic" else None
                for doc in stream:
                    try:
                        event = norm(doc)
                        if event is not None and rollover_after is not None and event.ts > rollover_after:
                            event = self._year_rollover(doc, profile, spec.year, event)
                    except Exception as exc:  # counted by the full pass; never abort the backtest over one document
                        log.debug("document in %s could not be normalized (%s)", spec.label, type(exc).__name__)
                        continue
                    if event is None or event.rule_id not in wanted:
                        continue
                    ts = event.ts
                    if (since is not None and ts < since) or (until is not None and ts >= until):
                        continue
                    if len(event.fields) > MAX_FIELDS_PER_EVENT:
                        event.fields = self._cap_fields(doc, profile, spec.year, event.fields)
                    yield event
            finally:
                docs.close()

    @staticmethod
    def _detection_sample(docs: Iterator[dict[str, Any]], stats: ReadStats) -> list[dict[str, Any]]:
        """First documents of a file for profile detection, bounded by count AND bytes (huge hostile lines)."""
        head: list[dict[str, Any]] = []
        started = stats.bytes_read
        for doc in docs:
            head.append(doc)
            if len(head) >= DETECT_SAMPLE or stats.bytes_read - started > _DETECT_BYTES:
                break
        return head

    def _cap_fields(self, doc: dict[str, Any], profile: str, year: int, fields: dict[str, Any]) -> dict[str, Any]:
        """Keep the first MAX_FIELDS_PER_EVENT flattened keys plus every key behind the core attributes."""
        capped = dict(itertools.islice(fields.items(), MAX_FIELDS_PER_EVENT))
        try:
            core = bind(profile, input_cfg=self.input_cfg, default_year=year, project=self._project or ())(doc)
        except Exception:  # the document already normalized once; never let the guard itself abort the run
            return capped
        if core is not None:
            capped.update(core.fields)
        return capped

    def _year_rollover(self, doc: dict[str, Any], profile: str, year: int, event: Event) -> Event:
        """A year-less syslog timestamp dated after the file's mtime belongs to the previous year (a December
        event read from a file last written in January)."""
        earlier = bind(profile, input_cfg=self.input_cfg, default_year=year - 1, project=self._project)(doc)
        return earlier if earlier is not None and earlier.ts < event.ts else event

    def _build_basis(
        self,
        stats: ReadStats,
        *,
        events: int,
        bad: int,
        future: int,
        filtered: int,
        capped: int,
        start: datetime | None,
        end: datetime | None,
        now: datetime | None,
        truncated: bool,
        file_profiles: list[str],
        kinds: dict[str, str],
        naive_files: list[str],
        excluded_newest: datetime | None = None,
    ) -> DataBasis:
        distinct_profiles = sorted(set(file_profiles))
        if len(distinct_profiles) == 1:
            profile_label = distinct_profiles[0]
        elif distinct_profiles:
            profile_label = "mixed"
        else:
            profile_label = "unknown" if self.profile == "auto" else self.profile

        if not kinds:
            input_kind = "unknown"
        elif len(kinds) == 1:
            input_kind = next(iter(kinds))
        else:
            input_kind = "mixed"

        warnings: list[Message | str] = [*self._resolved.warnings, *self._config_warnings, *stats.warnings]
        if input_kind == "alerts":
            wazuh = kinds["alerts"] in ("wazuh4", "wazuh5")
            warnings.append(M("ingest.warn.alerts_only_wazuh" if wazuh else "ingest.warn.alerts_only"))
        elif "alerts" in kinds and "archives" in kinds:
            warnings.append(M("ingest.warn.mixed_kinds"))
        elif "alerts" in kinds:  # alerts + documents of unknown kind: the alert part still measures alert silence
            warnings.append(M("ingest.warn.partly_alerts"))
        reference = now
        if future * 2 > events:
            # Mostly "future" data means this computer's clock is behind the SIEM's (every timestamp shifted, not
            # a few skewed sources): a reference inside the data would hide the newest silences, so use the end.
            warnings.append(M("ingest.warn.future_majority", count=future))
            reference = end
        elif reference is None:
            reference = end
        if "wazuh5" in distinct_profiles:
            warnings.append(M("ingest.warn.wazuh5"))
        if truncated:
            warnings.append(M("ingest.warn.truncated", limit=self._max_events or 0))
        if events == 0 and (filtered or self._resolved.pruned):
            warnings.append(M("ingest.warn.out_of_range", events=filtered, files=self._resolved.pruned))
        if events == 0 and filtered == 0 and bad > 0:
            warnings.append(M("ingest.warn.no_timestamp", count=bad))
        if capped:
            warnings.append(M("ingest.warn.fields_capped", count=capped, limit=MAX_FIELDS_PER_EVENT))
        if naive_files:
            warnings.append(M("ingest.warn.naive_utc", count=len(naive_files), file=Entity("file", naive_files[0])))
        skipped = self._resolved.skipped
        if self._resolved.skipped_total:
            examples = [Entity("file", path) for path in skipped[:3]]
            warnings.append(M("ingest.warn.skipped_files", count=self._resolved.skipped_total, examples=examples))

        return DataBasis(
            input_kind=input_kind,
            profile=profile_label,
            sources=list(self.paths),
            start=start,
            end=end,
            now=reference,
            now_origin="data",
            events=events,
            malformed=stats.malformed,
            bad_timestamps=bad,
            future_timestamps=future,
            sampled=False,
            truncated=truncated,
            partial_failures=[*self._resolved.failures, *stats.partial_failures],
            excluded_by_window=filtered,
            excluded_newest=excluded_newest,
            skipped_files=list(skipped),
            warnings=warnings,
        )
