"""Offline Week 3 IOC normalization and MISP import preparation (stdlib only)."""

import argparse
import csv
from datetime import date
import hashlib
import io
import ipaddress
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
RAW_FIELDS = (
    "record_id", "indicator", "type", "source", "source_url", "evidence_ref",
    "observation_date", "evidence_role", "notes",
)
NORMALIZED_FIELDS = (
    "indicator", "type", "misp_type", "category", "to_ids", "source_ids",
    "source", "source_url", "evidence_ref", "observation_date", "notes",
)
PROVENANCE_FIELDS = (
    "source", "source_url", "evidence_ref", "observation_date", "notes",
)


def normalize_indicator(value, kind):
    """Accept ASCII DNS names and IPv4 only; never resolve or contact them."""
    value = value.strip().replace("[.]", ".")
    kind = kind.strip().lower()
    if kind in {"ip", "ipv4"}:
        return str(ipaddress.IPv4Address(value)), "ipv4", "ip-dst"
    if kind != "domain":
        raise ValueError(f"unsupported type: {kind!r}")
    value = value.lower().removesuffix(".")
    labels = value.split(".")
    label_pattern = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if (len(value) > 253 or len(labels) < 2
            or not all(re.fullmatch(label_pattern, label) for label in labels)
            or labels[-1].isdigit()):
        raise ValueError(f"invalid ASCII domain: {value!r}")
    return value, "domain", "domain"


def read_records(raw_bytes):
    reader = csv.DictReader(io.StringIO(raw_bytes.decode("utf-8-sig")))
    if reader.fieldnames != list(RAW_FIELDS):
        raise ValueError("raw CSV headers must match the documented schema and order")
    records = []
    record_ids = set()
    for line, row in enumerate(reader, start=2):
        try:
            if None in row or any(value is None or not value.strip() for value in row.values()):
                raise ValueError("missing, empty, or extra field")
            row = {key: value.strip() for key, value in row.items()}
            if not re.fullmatch(r"[A-Za-z0-9_-]+", row["record_id"]):
                raise ValueError("invalid record_id")
            if row["record_id"] in record_ids:
                raise ValueError("duplicate record_id")
            observed = date.fromisoformat(row["observation_date"])
            if observed.isoformat() != row["observation_date"]:
                raise ValueError("observation_date must use YYYY-MM-DD")
            value, kind, misp_type = normalize_indicator(row["indicator"], row["type"])
            role = row["evidence_role"]
            if role not in {"vendor_reported_c2", "passive_dns_context"}:
                raise ValueError("unsupported evidence_role")
            if role == "vendor_reported_c2" and kind != "domain":
                raise ValueError("this workflow permits IDS candidates only for reported C2 domains")
            records.append((row, value, kind, misp_type))
            record_ids.add(row["record_id"])
        except ValueError as error:
            raise ValueError(f"CSV line {line}: {error}") from error
    if not records:
        raise ValueError("raw CSV contains no records")
    return records


def join_unique(values):
    return " | ".join(dict.fromkeys(values))


def build_outputs(raw_path):
    raw_bytes = raw_path.read_bytes()
    records = read_records(raw_bytes)
    groups = {}
    for row, value, kind, misp_type in records:
        groups.setdefault((kind, value, misp_type), []).append(row)
    normalized = []
    for (kind, value, misp_type), evidence in sorted(groups.items()):
        # A contextual observation prevents automatic promotion on merge.
        to_ids = all(row["evidence_role"] == "vendor_reported_c2" for row in evidence)
        normalized.append({
            "indicator": value, "type": kind, "misp_type": misp_type,
            "category": "Network activity", "to_ids": str(to_ids).lower(),
            "source_ids": join_unique(row["record_id"] for row in evidence),
            **{key: join_unique(row[key] for row in evidence) for key in PROVENANCE_FIELDS},
        })
    csv_buffer = io.StringIO(newline="")
    writer = csv.DictWriter(csv_buffer, fieldnames=NORMALIZED_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(normalized)

    attributes = []
    for row in normalized:
        comment = "; ".join([
            "PREPARED IMPORT: historical OSINT; not laboratory evidence",
            f"Raw record IDs: {row['source_ids']}",
            *[f"{key}: {row[key]}" for key in PROVENANCE_FIELDS],
        ])
        attributes.append({
            "type": row["misp_type"], "category": row["category"],
            "value": row["indicator"], "to_ids": row["to_ids"] == "true",
            "distribution": "0", "comment": comment,
        })
    event = {"Event": {
        "info": "Week 3 - ACR Stealer OSINT IOC Processing - PREPARED IMPORT",
        # This is the documented OSINT collection date, not an infection date.
        "date": max(row["observation_date"] for row, *_ in records),
        "distribution": "0", "published": False, "analysis": "0",
        "threat_level_id": "4", "Attribute": attributes,
    }}
    report = {
        "artifact_status": "offline_preparation_only",
        "raw_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "raw_records": len(records), "normalized_indicators": len(normalized),
        "duplicates_merged": len(records) - len(normalized),
        "rejected_records": 0,
        "ids_candidates": sum(row["to_ids"] == "true" for row in normalized),
        "context_only_indicators": sum(row["to_ids"] == "false" for row in normalized),
        "misp_import_performed": False, "misp_correlation_performed": False,
        "live_enrichment_performed": False,
    }
    return {
        "data/week3-iocs-normalized.csv": csv_buffer.getvalue().encode("utf-8"),
        "data/week3-processing-summary.json": (json.dumps(report, indent=2) + "\n").encode(),
        "misp/week3-event-import.json": (json.dumps(event, indent=2) + "\n").encode(),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, default=ROOT / "data/week3-iocs-raw.csv")
    parser.add_argument("--output-root", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true", help="verify generated files without writing")
    args = parser.parse_args(argv)
    try:
        outputs = build_outputs(args.raw)
        if args.raw.resolve() in {(args.output_root / name).resolve() for name in outputs}:
            raise ValueError("raw input must not be a generated output path")
        stale = []
        for name, content in outputs.items():
            target = args.output_root / name
            if args.check:
                if not target.is_file() or target.read_bytes() != content:
                    stale.append(name)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
        if stale:
            print("Generated files missing or stale: " + ", ".join(stale), file=sys.stderr)
            return 1
    except (ValueError, OSError, UnicodeError, csv.Error) as error:
        print(f"Processing failed: {error}", file=sys.stderr)
        return 1
    print("Offline artifacts verified." if args.check else "Offline artifacts generated; no MISP import performed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
