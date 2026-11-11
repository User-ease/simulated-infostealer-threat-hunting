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


def queries(version=2):
    base = {"term": {"event.dataset": "lab.strace"}}
    archive = {"terms": {"process.name": ["tar", "gzip"]}}
    browser = {"wildcard": {"process.args": {"value": "*lab-browser*", "case_insensitive": True}}}
    result = {"inventory": {"bool": {"filter": [base]}},
            "archive_utility": {"bool": {"filter": [base, archive]}},
            "lab_browser_archive": {"bool": {"filter": [base, archive, browser]}}}


    if version == 2:
        result["legacy_path"] = result["lab_browser_archive"]
        result["lab_browser_archive"] = {"bool": {"filter": [
            base, archive, {"term": {"lab.archive_mode": "create"}},
            {"exists": {"field": "lab.profile_open_lines"}}]}}
    return result


def creation_mode(name, args):
    """Recognize the tar/gzip creation forms covered by this lab."""
    if name == "tar" and len(args) >= 4:
        # -f consumes the next argument (the archive destination).
        opts = args[1]
        return (re.fullmatch(r"-[czv]+f", opts) is not None and opts.count("c") == 1
                and all(not arg.startswith("-") for arg in args[2:]))
    if name == "gzip" and args:
        flags = [arg for arg in args[1:] if arg.startswith("-")]
        return (any(not arg.startswith("-") for arg in args[1:])
                and all(re.fullmatch(r"-[kc1-9]+", flag) for flag in flags))
    return False


# strace -y supplies the kernel-resolved path on the returned descriptor.
OPEN_READ = re.compile(r' openat\(.*?, (O_RDONLY(?:\|\w+)*)\)\s+= \d+</lab/([^<>]+)>$')


def add_archive_fields(event, evidence, profile_inputs):
    process = event["process"]
    if not creation_mode(process["name"], process["args"]):
        return
    lab = event["lab"]
    lab["archive_mode"] = "create"
    trace = (evidence / lab["source_file"]).read_text().splitlines()
    # A successful exec in this PID changes the image and ends this event's scope.
    lines, paths = [], []
    for number, line in enumerate(trace[lab["source_line"]:], lab["source_line"] + 1):
        if " execve(" in line and re.search(r"= 0$", line):
            break
        match = OPEN_READ.search(line)
        if match and match[2] in profile_inputs and "O_DIRECTORY" not in match[1].split("|"):
            lines.append(number)
            paths.append(match[2])
    if lines:
        lab.update(profile_open_lines=lines, profile_inputs=paths)


def mapping():
    return {"settings": {"number_of_shards": 1, "number_of_replicas": 0,
                          "analysis": {"normalizer": {"lowercase": {"type": "custom", "filter": ["lowercase"]}}}},
            "mappings": {"properties": {
                "@timestamp": {"type": "date"},
                "event": {"properties": {k: {"type": "keyword"} for k in ["dataset", "action", "type", "category"]}},
                "process": {"properties": {"name": {"type": "keyword", "normalizer": "lowercase"},
                    "pid": {"type": "long"}, "executable": {"type": "keyword"},
                    "args": {"type": "keyword", "ignore_above": 32760}, "command_line": {"type": "wildcard"}}},
                "lab": {"properties": {"profile_open_lines": {"type": "integer"},
                    **{k: {"type": "keyword"} for k in ["archive_mode", "profile_inputs", "case", "run_id", "source_file"]}}}
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

    version = 2 if "profile_inputs" in collection else 1
    if version == 2:
        for path, digest in collection["profile_inputs"].items():
            if hashlib.sha256((evidence / "lab" / path).read_bytes()).hexdigest() != digest:
                raise SystemExit("Profile input hash mismatch: " + path)
        for event in events:
            add_archive_fields(event, evidence, collection["profile_inputs"])
    bulk(index, events)
    query_set = queries(version)
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
    path_query = "legacy_path" if version == 2 else "lab_browser_archive"
    for query_name, field in [("archive_utility", 3), (path_query, 4)]:
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
    expected = {"atomic_gzip", "atomic_tar"}
    if version == 2:
        expected.add("renamed_profile")
        controls = []
        expected_old = {"atomic_gzip", "atomic_tar", "destination_only", "list_only", "decompress_only"}
        for case in collection["cases"]:
            name = case["case"]
            row = {"case": name, "command": case["command"].strip()}
            for query_name, expected_cases in [("legacy_path", expected_old), ("lab_browser_archive", expected)]:
                observed = sum(hit["_source"]["lab"]["case"] == name for hit in results[query_name]["hits"]["hits"])
                row[query_name] = {"observed": observed, "expected": int(name in expected_cases)}
            controls.append(row)
        summary["controls"] = controls
        summary["control_counts_passed"] = all(row[k]["observed"] == row[k]["expected"]
            for row in controls for k in ("legacy_path", "lab_browser_archive"))
    summary["query_version"] = version
    summary["refined_cases_passed"] = set(summary["matching_cases"]["lab_browser_archive"]) == expected
    save(out / "runtime.json", runtime)
    save(out / "queries.json", query_set)
    save(out / "results.json", results)
    save(out / "regression.json", regression)
    save(out / "summary.json", summary)
    save(out / "sha256.json", {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.glob("*"))})
    print(json.dumps(summary, indent=2))
    if not (all(summary[k] for k in ["regression_passed", "ingestion_count_passed", "refined_cases_passed"])
            and summary.get("control_counts_passed", True)):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
