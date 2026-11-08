#!/usr/bin/env python3
"""Index a Week 9 collection into local Elasticsearch and save actual API evidence."""
import argparse
import datetime as dt
import hashlib
import json
import re
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n")


def queries():
    base = {"term": {"event.dataset": "lab.strace"}}
    archive = {"terms": {"process.name": ["tar", "gzip"]}}
    browser = {"wildcard": {"process.args": {"value": "*lab-browser*", "case_insensitive": True}}}
    return {"inventory": {"bool": {"filter": [base]}},
            "archive_utility": {"bool": {"filter": [base, archive]}},
            "lab_browser_archive": {"bool": {"filter": [base, archive, browser]}}}


def mapping():
    return {"settings": {"number_of_shards": 1, "number_of_replicas": 0,
                          "analysis": {"normalizer": {"lowercase": {"type": "custom", "filter": ["lowercase"]}}}},
            "mappings": {"properties": {
                "@timestamp": {"type": "date"},
                "event": {"properties": {k: {"type": "keyword"} for k in ["dataset", "action", "type", "category"]}},
                "process": {"properties": {"name": {"type": "keyword", "normalizer": "lowercase"},
                    "pid": {"type": "long"}, "executable": {"type": "keyword"},
                    "args": {"type": "keyword", "ignore_above": 32760}, "command_line": {"type": "wildcard"}}},
                "lab": {"properties": {k: {"type": "keyword"} for k in ["case", "run_id", "source_file"]}}
            }}}


def regression_cases():
    return [
        ("browser_tar", "tar", ["tar", "-cvzf", "out/test.tar.gz", "lab-browser"], True, True),
        ("browser_gzip", "gzip", ["gzip", "-k", "lab-browser/mock-browser.json"], True, True),
        ("ordinary_backup", "tar", ["tar", "-cvzf", "out/backup.tar.gz", "ordinary-docs"], True, False),
        ("shell_wrapper", "sh", ["sh", "-c", "tar -cvzf out/x lab-browser"], False, False),
        ("missing_name", None, ["tar", "lab-browser"], False, False),
        ("uppercase_name", "TAR", ["tar", "LAB-BROWSER"], True, True),
        ("missing_args", "tar", None, True, False),
        ("different_name", "notgzip", ["gzip", "lab-browser"], False, False),
        ("empty_args", "gzip", [], True, False),
        ("renamed_binary_gap", "archiver", ["archiver", "lab-browser"], False, False),
    ]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("evidence", type=Path)
    p.add_argument("--url", default="http://127.0.0.1:19209")
    args = p.parse_args()
    u = urlsplit(args.url)
    if u.scheme != "http" or u.hostname not in ["127.0.0.1", "localhost", "::1"] or u.username or u.password:
        raise SystemExit("Use a dedicated unauthenticated loopback lab instance only.")
    evidence = args.evidence.resolve()
    collection = json.loads((evidence / "collection.json").read_text())
    if not collection["verification"]["passed"]:
        raise SystemExit("Collection did not pass outcome verification.")
    for rel, expected in json.loads((evidence / "collection-sha256.json").read_text()).items():
        if hashlib.sha256((evidence / rel).read_bytes()).hexdigest() != expected:
            raise SystemExit("Collection hash mismatch: " + rel)
    index = "lab-week9-" + collection["run_id"].lower()
    if not re.fullmatch(r"lab-week9-[0-9tz]+", index):
        raise SystemExit("Invalid run ID")
    if (evidence / "siem").exists():
        raise SystemExit("SIEM evidence already exists; create a fresh collection for a new run.")
    out = evidence / "siem"
    out.mkdir()
    transcript = []

    def request(method, endpoint, body=None, ndjson=False):
        data = body.encode() if ndjson else (json.dumps(body).encode() if body is not None else None)
        started = dt.datetime.now(dt.timezone.utc).isoformat()
        req = urllib.request.Request(args.url.rstrip("/") + endpoint, data=data, method=method,
            headers={"Content-Type": "application/x-ndjson" if ndjson else "application/json"})
        with urllib.request.urlopen(req, timeout=60) as response:
            result = json.load(response)
        transcript.append({"timestamp": started, "method": method, "endpoint": endpoint,
                           "request": body, "response": result})
        save(out / "api-transcript.json", transcript)
        return result

    runtime = request("GET", "/")
    request("PUT", "/" + index, mapping())  # Existing indices are rejected, never overwritten.
    events = [json.loads(line) for line in (evidence / "events.jsonl").read_text().splitlines()]

    def bulk(target, documents):
        body = "".join(json.dumps({"create": {"_index": target, "_id": str(i)}}) + "\n" +
                       json.dumps(doc) + "\n" for i, doc in enumerate(documents))
        response = request("POST", "/_bulk?refresh=wait_for", body, True)
        if response["errors"]:
            raise RuntimeError("Bulk ingestion contained failures")

    bulk(index, events)
    query_set = queries()
    results = {name: request("POST", "/" + index + "/_search", {"size": 1000, "track_total_hits": True,
               "sort": [{"@timestamp": "asc"}], "query": query}) for name, query in query_set.items()}
    request("PUT", "/" + index + "-regression", mapping())
    fixtures = []
    for name, executable, argv, _, _ in regression_cases():
        doc = {"@timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
               "event": {"dataset": "lab.strace"}, "lab": {"case": name}, "process": {}}
        if executable is not None:
            doc["process"]["name"] = executable
        if argv is not None:
            doc["process"]["args"] = argv
        fixtures.append(doc)
    bulk(index + "-regression", fixtures)
    regression = []
    for query_name, field in [("archive_utility", 3), ("lab_browser_archive", 4)]:
        response = request("POST", "/" + index + "-regression/_search",
                           {"size": 100, "query": query_set[query_name]})
        actual = {hit["_source"]["lab"]["case"] for hit in response["hits"]["hits"]}
        for row in regression_cases():
            regression.append({"query": query_name, "case": row[0], "expected": row[field],
                               "actual": row[0] in actual, "passed": row[field] == (row[0] in actual)})
    summary = {"index": index, "event_count": len(events),
               "counts": {k: v["hits"]["total"]["value"] for k, v in results.items()},
               "matching_cases": {k: sorted({h["_source"]["lab"]["case"] for h in v["hits"]["hits"]})
                                  for k, v in results.items()},
               "regression_assertions": len(regression), "regression_passed": all(r["passed"] for r in regression)}
    summary["ingestion_count_passed"] = summary["counts"]["inventory"] == len(events)
    summary["refined_cases_passed"] = summary["matching_cases"]["lab_browser_archive"] == ["atomic_gzip", "atomic_tar"]
    save(out / "runtime.json", runtime)
    save(out / "queries.json", query_set)
    save(out / "results.json", results)
    save(out / "regression.json", regression)
    save(out / "summary.json", summary)
    save(out / "sha256.json", {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.glob("*"))})
    print(json.dumps(summary, indent=2))
    if not all(summary[k] for k in ["regression_passed", "ingestion_count_passed", "refined_cases_passed"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
