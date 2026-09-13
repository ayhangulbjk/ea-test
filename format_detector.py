#!/usr/bin/env python3
"""
WatchEnterprise Format Detector v2

Detects JSON, JSONL, CSV/TSV, key=value, syslog and plain-text logs.
If no path is supplied, built-in self-tests are executed.

Usage:
    python format_detector.py <file|zip|gz|directory>
    python format_detector.py <path> --json
    python format_detector.py
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import re
import sys
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SAMPLE_LINES = 250
MAX_SNIFF_CHARS = 1_000_000
MAX_PROFILE_RECORDS = 50_000

BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf",
    ".parquet", ".xlsx", ".xls", ".db", ".sqlite", ".pkl", ".pyc"
}

ROLE_HINTS = {
    "timestamp": ("timestamp", "time", "ts", "@timestamp", "datetime",
                  "date", "event_time", "created", "created_at", "logged_at", "log_time"),
    "severity": ("severity", "level", "loglevel", "log_level",
                 "priority", "status", "sev"),
    "service": ("service", "app", "application", "component",
                "logger", "source", "module", "job", "program", "svc"),
    "host": ("host", "hostname", "node", "instance", "server", "pod", "container"),
    "message": ("message", "msg", "text", "description",
                "log", "summary", "title", "body", "line"),
}

LEVEL_WORDS = {
    "TRACE", "DEBUG", "INFO", "NOTICE", "WARN", "WARNING",
    "ERROR", "ERR", "CRITICAL", "CRIT", "FATAL", "ALERT", "EMERG"
}

TS_PATTERNS = [
    re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"),
    re.compile(r"\b\d{2}/\d{2}/\d{4}[ T]\d{2}:\d{2}(?::\d{2})?\b"),
    re.compile(r"^\s*[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b"),
    re.compile(r"^\s*\d{10}(?:\.\d+)?\s*$"),
    re.compile(r"^\s*\d{13}\s*$"),
]

SYSLOG_RE = re.compile(
    r"^\s*(?:<\d+>)?[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+"
)

SYSLOG_PARSE_RE = re.compile(
    r"^\s*(?:<\d+>)?"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<program>[^:\[]+?)"
    r"(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

KV_RE = re.compile(
    r'(?P<key>[A-Za-z_][\w.\-@]*?)='
    r'(?P<value>"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|\S+)'
)


def ratio(a: float, b: float) -> float:
    return a / b if b else 0.0


def normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9_@]+", "", value.lower())


# -------------------- loading --------------------

def iter_files(path: Path) -> Iterable[tuple[str, str | None]]:
    if path.is_dir():
        for p in sorted(path.rglob("*")):
            if p.is_file():
                try:
                    yield from iter_bytes(str(p), p.read_bytes())
                except OSError:
                    yield str(p), None
        return

    try:
        yield from iter_bytes(str(path), path.read_bytes())
    except OSError:
        yield str(path), None


def iter_bytes(name: str, data: bytes) -> Iterable[tuple[str, str | None]]:
    lower = name.lower()

    if lower.endswith(".zip"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    child = f"{name}!{info.filename}"
                    try:
                        yield from iter_bytes(child, zf.read(info))
                    except Exception:
                        yield child, None
        except (zipfile.BadZipFile, OSError):
            yield name, None
        return

    if lower.endswith(".gz"):
        try:
            yield from iter_bytes(name[:-3], gzip.decompress(data))
        except (OSError, EOFError):
            yield name, None
        return

    if Path(lower).suffix in BINARY_EXT or b"\x00" in data[:8192]:
        yield name, None
        return

    yield name, data.decode("utf-8-sig", errors="replace")


# -------------------- detection --------------------

def json_document(text: str) -> Any | None:
    if len(text) > MAX_SNIFF_CHARS:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None


def jsonl_score(lines: list[str]) -> tuple[float, int]:
    lines = [x for x in lines if x.strip()]
    valid = 0
    for line in lines:
        try:
            if isinstance(json.loads(line), dict):
                valid += 1
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
    return ratio(valid, len(lines)), valid


def delimiter_score(lines: list[str], delimiter: str) -> tuple[float, dict[str, Any]]:
    lines = [x for x in lines if x.strip()][:100]
    if not lines:
        return 0.0, {}

    counts = [x.count(delimiter) for x in lines]
    with_delim = sum(c > 0 for c in counts)
    if not with_delim:
        return 0.0, {}

    common = Counter(counts).most_common(1)[0][0]
    consistency = ratio(sum(c == common for c in counts), len(counts))
    structural = min(common, 3) / 3

    sniffed = None
    try:
        sniffed = csv.Sniffer().sniff(
            "\n".join(lines), delimiters="\t,;|"
        ).delimiter
    except csv.Error:
        pass

    score = min(
        1.0,
        0.35 * ratio(with_delim, len(lines))
        + 0.45 * consistency
        + 0.20 * structural
        + (0.15 if sniffed == delimiter else 0.0),
    )

    if common == 1 and consistency < 0.75:
        score *= 0.65

    return score, {"delimiter": delimiter}


def kv_score(lines: list[str]) -> float:
    lines = [x for x in lines if x.strip()]
    return ratio(
        sum(len(KV_RE.findall(x)) >= 2 for x in lines),
        len(lines),
    )


def sniff(lines: list[str], text: str | None = None):
    if not lines:
        return "empty", 1.0, {}, [{"format": "empty", "score": 1.0}]

    sample = lines[:SAMPLE_LINES]
    candidates = []

    obj = json_document(text) if text is not None else None

    if isinstance(obj, list):
        records = [x for x in obj if isinstance(x, dict)]
        candidates.append({
            "format": "json_array", "score": 0.99 if records else 0.96,
            "extra": {"records": records}
        })
    elif isinstance(obj, dict):
        lists = [
            (k, v) for k, v in obj.items()
            if isinstance(v, list) and all(isinstance(x, dict) for x in v)
        ]
        if lists:
            key, records = max(lists, key=lambda x: len(x[1]))
            candidates.append({
                "format": "json_object", "score": 0.98,
                "extra": {"records": records, "records_key": key}
            })
        else:
            candidates.append({
                "format": "json_object", "score": 0.93,
                "extra": {"records": [obj]}
            })

    # If the complete document is valid JSON, prefer the document
    # interpretation over JSONL. A one-line JSON object is technically
    # valid JSONL too, but it should not be classified as JSONL.
    js, valid = jsonl_score(sample)
    whole_document_is_json = isinstance(obj, (dict, list))

    if valid and not whole_document_is_json:
        candidates.append({
            "format": "jsonl",
            "score": min(0.97, js),
            "extra": {"jsonl_valid": valid},
        })

    sys_hits = sum(bool(SYSLOG_RE.match(x)) for x in sample)
    if sys_hits:
        candidates.append({"format": "syslog", "score": min(0.97, ratio(sys_hits, len(sample))),
                           "extra": {"hits": sys_hits}})

    jsonish = ratio(
        sum(x.lstrip().startswith(("{", "[")) and x.rstrip().endswith(("}", "]"))
            for x in sample),
        len(sample),
    )

    for delim in ("\t", ",", ";", "|"):
        score, extra = delimiter_score(sample, delim)
        if delim == "," and jsonish >= 0.70:
            score *= 0.15
        if score >= 0.55:
            candidates.append({
                "format": "tsv" if delim == "\t" else "csv",
                "score": score,
                "extra": extra,
            })

    kv = kv_score(sample)
    if kv >= 0.55:
        candidates.append({"format": "kv", "score": min(0.97, kv), "extra": {}})

    candidates.append({
        "format": "plain",
        "score": 0.50 if sum(map(len, sample)) / len(sample) < 300 else 0.58,
        "extra": {},
    })

    candidates.sort(key=lambda x: x["score"], reverse=True)
    best = candidates[0]

    ranked = [
        {"format": x["format"], "score": round(x["score"], 3)}
        for x in candidates
    ]
    return best["format"], round(best["score"], 3), best.get("extra", {}), ranked


# -------------------- extraction --------------------

def unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return value


def flatten(value: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out = {}
    for key, item in value.items():
        full = f"{prefix}{key}"
        if isinstance(item, dict):
            out.update(flatten(item, full + "."))
        else:
            out[full] = item
    return out


def records_from(fmt: str, text: str, extra: dict[str, Any]) -> list[dict[str, Any]]:
    lines = text.splitlines()

    if fmt in ("json_array", "json_object"):
        records = extra.get("records")
        return [flatten(x) for x in records if isinstance(x, dict)]

    if fmt == "jsonl":
        out = []
        for line in lines:
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    out.append(flatten(obj))
            except (json.JSONDecodeError, TypeError, ValueError):
                pass
        return out

    if fmt in ("csv", "tsv"):
        delimiter = extra.get("delimiter", "\t" if fmt == "tsv" else ",")
        try:
            reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
            return [
                dict(r) for r in reader
                if any(v not in (None, "") for v in r.values())
            ]
        except csv.Error:
            return []

    if fmt == "kv":
        out = []
        for line in lines:
            if not line.strip():
                continue
            record = {
                m.group("key"): unquote(m.group("value"))
                for m in KV_RE.finditer(line)
            }
            if record:
                out.append(record)
        return out

    if fmt == "syslog":
        out = []
        for line in lines:
            m = SYSLOG_PARSE_RE.match(line)
            if m:
                out.append(m.groupdict())
        return out

    return [{"line": x} for x in lines if x.strip()]


# -------------------- profiling / roles --------------------

def looks_like_ts(value: Any) -> bool:
    s = str(value).strip()
    return bool(
        re.fullmatch(r"\d{10}(?:\.\d+)?|\d{13}", s)
        or any(p.search(s) for p in TS_PATTERNS)
    )


def parse_ts(value: Any) -> datetime | None:
    s = str(value).strip()

    try:
        if re.fullmatch(r"\d{13}", s):
            return datetime.fromtimestamp(int(s) / 1000, tz=timezone.utc)
        if re.fullmatch(r"\d{10}(?:\.\d+)?", s):
            return datetime.fromtimestamp(float(s), tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None

    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        pass

    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M", "%m/%d/%Y %H:%M",
        "%Y-%m-%d %H:%M:%S,%f",
    ):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass

    m = re.match(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})$", s)
    if m:
        try:
            return datetime.strptime(
                f"{datetime.now().year} {m.group(1)}",
                "%Y %b %d %H:%M:%S",
            )
        except ValueError:
            pass

    return None


def profile_columns(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records = records[:MAX_PROFILE_RECORDS]
    if not records:
        return []

    total = len(records)
    counters = {}
    filled = Counter()
    types = {}

    for record in records:
        for key, value in record.items():
            if value in (None, ""):
                continue
            text = str(value)
            filled[key] += 1
            counters.setdefault(key, Counter())[text[:120]] += 1

            if re.fullmatch(r"-?\d+(?:\.\d+)?", text):
                kind = "number"
            elif looks_like_ts(text):
                kind = "timestamp"
            elif text.upper() in LEVEL_WORDS:
                kind = "level"
            else:
                kind = "text"

            types.setdefault(key, Counter())[kind] += 1

    out = []
    for key, counter in counters.items():
        out.append({
            "column": key,
            "fill_rate": round(ratio(filled[key], total), 3),
            "distinct": len(counter),
            "timestamp_like": round(ratio(types[key]["timestamp"], filled[key]), 2),
            "numeric": round(ratio(types[key]["number"], filled[key]), 2),
            "level_like": round(ratio(types[key]["level"], filled[key]), 2),
            "text_like": round(ratio(types[key]["text"], filled[key]), 2),
            "top_values": [f"{v} ({c})" for v, c in counter.most_common(3)],
            "examples": list(counter.keys())[:3],
        })
    return out


def guess_roles(profile: list[dict[str, Any]]) -> dict[str, str | None]:
    roles = {x: None for x in ROLE_HINTS}
    columns = [x["column"] for x in profile]
    normalized = {normalize_key(x): x for x in columns}

    for role, hints in ROLE_HINTS.items():
        for hint in hints:
            hit = normalized.get(normalize_key(hint))
            if hit:
                roles[role] = hit
                break

    for role, hints in ROLE_HINTS.items():
        if roles[role]:
            continue

        scored = []
        for p in profile:
            name = normalize_key(p["column"])
            name_score = 0.0
            for hint in hints:
                h = normalize_key(hint)
                if name == h:
                    name_score = max(name_score, 1.0)
                elif name.endswith(h):
                    name_score = max(name_score, 0.75)

            if role == "timestamp":
                metric = p["timestamp_like"]
            elif role == "severity":
                metric = p["level_like"]
            elif role == "message":
                metric = p["text_like"]
            else:
                metric = p["fill_rate"]

            scored.append((name_score * 0.70 + metric * 0.30, p))

        scored.sort(key=lambda x: x[0], reverse=True)
        if scored and scored[0][0] >= 0.62:
            roles[role] = scored[0][1]["column"]

    if not roles["timestamp"]:
        candidates = [p for p in profile if p["timestamp_like"] >= 0.80]
        if candidates:
            roles["timestamp"] = max(candidates, key=lambda x: x["timestamp_like"])["column"]

    if not roles["severity"]:
        candidates = [p for p in profile if p["level_like"] >= 0.70]
        if candidates:
            roles["severity"] = max(candidates, key=lambda x: x["level_like"])["column"]

    if not roles["message"]:
        taken = {x for x in roles.values() if x}
        candidates = [
            p for p in profile
            if p["column"] not in taken and p["text_like"] >= 0.50
        ]
        if candidates:
            roles["message"] = max(
                candidates,
                key=lambda x: (x["text_like"], x["fill_rate"])
            )["column"]

    return roles


def time_range(records: list[dict[str, Any]], ts_col: str | None):
    if not ts_col:
        return None

    stamps = [
        parsed for r in records
        if r.get(ts_col) not in (None, "")
        for parsed in [parse_ts(r.get(ts_col))]
        if parsed
    ]

    if not stamps:
        return {"parsed": 0, "note": "timestamp column found but no known format parsed"}

    stamps.sort()
    span = stamps[-1] - stamps[0]
    minutes = max(span.total_seconds() / 60, 1)

    return {
        "parsed": len(stamps),
        "start": stamps[0].isoformat(),
        "end": stamps[-1].isoformat(),
        "span": str(span),
        "avg_per_minute": round(len(stamps) / minutes, 2),
    }


# -------------------- inspection --------------------

def inspect_file(name: str, text: str | None, sample_lines: int) -> dict[str, Any]:
    if text is None:
        return {"file": name, "format": "binary/unsupported", "confidence": 1.0, "note": "skipped"}

    lines = text.splitlines()
    nonempty = [x for x in lines if x.strip()]
    fmt, confidence, extra, candidates = sniff(nonempty[:SAMPLE_LINES], text)

    try:
        records = records_from(fmt, text, extra)
        extraction_error = None
    except Exception as exc:
        records = []
        extraction_error = f"{type(exc).__name__}: {exc}"

    profile = profile_columns(records)
    roles = guess_roles(profile)
    sev = roles.get("severity")
    severity_distribution = Counter(
        str(r.get(sev)) for r in records
        if sev and r.get(sev) not in (None, "")
    )

    result = {
        "product": "WatchEnterprise",
        "file": name,
        "format": fmt,
        "confidence": confidence,
        "format_candidates": candidates,
        "lines": len(lines),
        "records": len(records),
        "bytes": len(text.encode("utf-8", errors="replace")),
        "roles": roles,
        "time_range": time_range(records, roles.get("timestamp")),
        "severity_distribution": dict(severity_distribution.most_common(10)),
        "columns": profile,
        "sample_lines": nonempty[:sample_lines],
    }

    if extraction_error:
        result["extraction_error"] = extraction_error

    return result


def print_report(reports: list[dict[str, Any]]) -> None:
    for r in reports:
        print("=" * 88)
        print(f"PRODUCT  {r.get('product', 'WatchEnterprise')}")
        print(f"FILE     {r['file']}")
        print(f"FORMAT   {r['format']}  (confidence {r.get('confidence', '-')})")

        if r["format"] == "binary/unsupported":
            continue

        print(f"SIZE     {r['lines']} lines, {r['records']} records, {r['bytes']:,} bytes")
        print("ROLES    " + ", ".join(f"{k}={v or '?'}" for k, v in r["roles"].items()))

        print(
            "CANDIDATES "
            + ", ".join(
                f"{x['format']}={x['score']:.2f}"
                for x in r.get("format_candidates", [])[:6]
            )
        )

        tr = r.get("time_range")
        if tr:
            if "start" in tr:
                print(
                    f"TIME     {tr['start']} -> {tr['end']}  "
                    f"span {tr['span']}  ~{tr['avg_per_minute']}/min"
                )
            else:
                print(f"TIME     {tr['note']}")

        if r["severity_distribution"]:
            print(
                "SEVERITY "
                + ", ".join(f"{k}:{v}" for k, v in r["severity_distribution"].items())
            )

        print("COLUMNS")
        for c in sorted(r["columns"], key=lambda x: -x["fill_rate"])[:40]:
            flags = []
            if c["timestamp_like"] >= 0.80:
                flags.append("ts")
            if c["numeric"] >= 0.80:
                flags.append("num")
            if c["level_like"] >= 0.70:
                flags.append("level")
            print(
                f"  {c['column']:<32} fill {c['fill_rate']:>5} "
                f"distinct {c['distinct']:>6} {'/'.join(flags):<9} "
                f"{', '.join(c['top_values'])[:80]}"
            )

        print("SAMPLE")
        for line in r["sample_lines"]:
            print("  " + line[:180])

        if r.get("extraction_error"):
            print("ERROR    " + r["extraction_error"])

    print("=" * 88)
    print(
        "SUMMARY  "
        + ", ".join(
            f"{k}: {v} file(s)"
            for k, v in Counter(r["format"] for r in reports).items()
        )
    )


# -------------------- self test --------------------

def run_self_test() -> int:
    fixtures = {
        "jsonl": (
            '{"timestamp":"2026-09-13T10:00:00Z","level":"INFO","service":"sap","host":"app01","message":"System started"}\n'
            '{"timestamp":"2026-09-13T10:01:00Z","level":"ERROR","service":"sap","host":"app01","message":"Database connection failed"}'
        ),
        "csv": (
            "timestamp,level,service,host,message\n"
            '2026-09-13T10:00:00Z,INFO,sap,app01,"System started"\n'
            '2026-09-13T10:01:00Z,ERROR,sap,app01,"Database connection failed"'
        ),
        "tsv": (
            "timestamp\tlevel\tservice\tmessage\n"
            "2026-09-13T10:00:00Z\tINFO\tsap\tSystem started\n"
            "2026-09-13T10:01:00Z\tERROR\tsap\tDatabase failed"
        ),
        "kv": (
            'timestamp=2026-09-13T10:00:00Z level=INFO service=sap host=app01 message="System started"\n'
            'timestamp=2026-09-13T10:01:00Z level=ERROR service=sap host=app01 message="Database connection failed"'
        ),
        "syslog": (
            "Sep 13 10:00:00 app01 sap[1234]: System started\n"
            "Sep 13 10:01:00 app01 sap[1234]: Database connection failed"
        ),
        "plain": (
            "System started successfully\n"
            "Database connection failed\n"
            "Connection retry scheduled"
        ),
        "json": (
            '[{"timestamp":"2026-09-13T10:00:00Z","level":"INFO","message":"Started"},'
            '{"timestamp":"2026-09-13T10:01:00Z","level":"ERROR","message":"Failed"}]'
        ),
        "nested_json": (
            '{"event":{"timestamp":"2026-09-13T10:00:00Z","level":"ERROR"},'
            '"service":{"name":"sap"},"message":"Nested failure"}'
        ),
    }

    expected = {
        "jsonl": "jsonl",
        "csv": "csv",
        "tsv": "tsv",
        "kv": "kv",
        "syslog": "syslog",
        "plain": "plain",
        "json": "json_array",
        "nested_json": "json_object",
    }

    print("=" * 88)
    print("WATCHENTERPRISE FORMAT DETECTOR V2")
    print("SELF TEST")
    print("=" * 88)

    passed = failed = 0

    for name, text in fixtures.items():
        lines = [x for x in text.splitlines() if x.strip()]
        fmt, confidence, extra, candidates = sniff(lines, text)
        records = records_from(fmt, text, extra)
        profile = profile_columns(records)
        roles = guess_roles(profile)

        ok = fmt == expected[name] and len(records) > 0
        if ok:
            passed += 1
            status = "PASS"
        else:
            failed += 1
            status = "FAIL"

        print(f"[{status}] {name.upper():<14} detected={fmt:<12} expected={expected[name]:<12} "
              f"confidence={confidence:.2f} records={len(records)}")

        if roles:
            print(f"       roles={roles}")

        if not ok:
            print(f"       candidates={candidates}")

    print("-" * 88)
    print(f"RESULT: {passed} passed / {failed} failed")
    print("=" * 88)

    return 0 if failed == 0 else 1


# -------------------- CLI --------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help="file, directory, ZIP or GZIP to inspect; omit for self-test",
    )
    parser.add_argument("--lines", type=int, default=5)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.path is None:
        return run_self_test()

    path = Path(args.path)
    if not path.exists():
        print(f"not found: {path}", file=sys.stderr)
        return 1

    reports = [
        inspect_file(name, text, args.lines)
        for name, text in iter_files(path)
    ]

    if args.json:
        json.dump(reports, sys.stdout, indent=2, ensure_ascii=False, default=str)
    else:
        print_report(reports)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
