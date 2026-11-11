"""Replay filtered native Windows Security XML into a fresh Elasticsearch index."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import ntpath
from pathlib import Path
import re
import shlex
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
CREATE = 'event.code == "4688" and process.name == "tar.exe" and lab.archive_mode == "create"'
READ = 'event.code == "4663" and process.name == "tar.exe" and lab.profile_input == true and lab.read_data == true'
SEQUENCE = f'sequence by host.name, process.pid, winlog.logon.id with maxspan=10s\n  [process where {CREATE}]\n  [file where {READ}]'
QUERIES = {"create": f"process where {CREATE}", "read": f"file where {READ}", "correlated": SEQUENCE}


def archive_mode(command):
    # Controlled bsdtar command lines; retain the complete original as an indexed field.
    tokens = [t.strip('"') for t in shlex.split(command, posix=False)][1:]
    modes = {"c": "create", "t": "list", "x": "extract"}
    modes_found = []
    it = iter(tokens)
    for arg in it:
        if arg == "--" or not arg.startswith("-"):
            break
        if arg in ("--create", "--list", "--extract"):
            modes_found.append(arg[2:])
        elif arg in ("--file", "--directory", "-C", "-f"):
            if next(it, None) is None:
                return "unknown"
        elif arg.startswith(("--file=", "--directory=")) or arg in ("--gzip", "--verbose"):
            continue
        elif re.fullmatch(r"-[ctxzvf]+", arg):
            flags = arg[1:]
            modes_found.extend(modes[f] for f in flags if f in modes)
            if "f" in flags and (not flags.endswith("f") or next(it, None) is None):
                return "unknown"
        else:
            return "unknown"
    if len(modes_found) == 1:
        return modes_found[0]
    return "unknown"


def parse_events(source, manifest):
    documents = []
    for raw in ET.parse(source).getroot():
        system = raw.find(f"{NS}System")
        code = system.findtext(f"{NS}EventID")
        if code not in {"4663", "4688"}:
            raise ValueError(f"Unexpected event ID {code}")
        if (system.find(f"{NS}Provider").get("Name") != "Microsoft-Windows-Security-Auditing"
                or system.findtext(f"{NS}Channel") != "Security"):
            raise ValueError("Unexpected provider/channel")
        fields = {v.get("Name"): v.text or "" for v in raw.findall(f"{NS}EventData/{NS}Data")}
        launch = code == "4688"
        pid = int(fields["NewProcessId" if launch else "ProcessId"], 16)
        exe = fields["NewProcessName" if launch else "ProcessName"]
        target = int(fields.get("TargetLogonId") or "0", 16) if launch else 0
        logon = target or int(fields["SubjectLogonId"], 16)
        path = fields.get("ObjectName", "")
        mask = int(fields.get("AccessMask", "0"), 16)
        document = {
            "@timestamp": system.find(f"{NS}TimeCreated").get("SystemTime"),
            "host": {"name": system.findtext(f"{NS}Computer").lower()},
            "event": {"code": code, "category": "process" if launch else "file"},
            "process": {"pid": pid, "name": ntpath.basename(exe).lower(), "executable": exe},
            "winlog": {"record_id": int(system.findtext(f"{NS}EventRecordID")), "logon": {"id": hex(logon)}},
            "lab": {"profile_input": (not launch and fields.get("ObjectType") == "File"
                                      and ntpath.normcase(path) == ntpath.normcase(manifest["profile_input"])),
                    "read_data": bool(mask & 1)},
        }
        if launch:
            document["process"]["command_line"] = fields["CommandLine"]
            document["lab"]["archive_mode"] = archive_mode(fields["CommandLine"])
        else:
            document["file"] = {"path": path}
            document["winlog"]["access_mask"] = hex(mask)
        documents.append(document)
    ids = [d["winlog"]["record_id"] for d in documents]
    if not ids or len(set(ids)) != len(ids):
        raise ValueError("Expected unique native record IDs")
    return documents


def request(base, method, path, payload=None, ndjson=False):
    data = payload.encode() if ndjson else json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/x-ndjson" if ndjson else "application/json"}
    try:
        with urlopen(Request(base + path, data=data, headers=headers, method=method), timeout=60) as response:
            return json.load(response)
    except HTTPError as exc:
        raise RuntimeError(f"{method} {path}: {exc.read().decode()}") from exc


def replay(evidence, base, output):
    manifest = json.loads((evidence / "manifest.json").read_bytes())
    xml = evidence / "events.xml"
    docs = parse_events(xml, manifest)
    cases = manifest["cases"]
    case_by_pid = {c["pid"]: c for c in cases}
    launches = Counter(d["process"]["pid"] for d in docs if d["event"]["code"] == "4688")
    if launches != Counter(case_by_pid.keys()) or len(case_by_pid) != len(cases):
        raise ValueError("Manifest and native process records disagree")
    if any(d["host"]["name"] != manifest["computer"].lower() or d["process"]["pid"] not in case_by_pid for d in docs):
        raise ValueError("Unexpected host or PID")
    index = "week9-windows-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    output.mkdir(exist_ok=False, parents=True)
    def save(filename, value):
        (output / filename).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    version = request(base, "GET", "/")["version"]["number"]
    field_types = {"@timestamp": "date_nanos", "event.code": "keyword", "event.category": "keyword",
                   "host.name": "keyword", "process.pid": "long", "process.name": "keyword",
                   "process.executable": "keyword", "process.command_line": "wildcard", "file.path": "keyword",
                   "winlog.record_id": "long", "winlog.logon.id": "keyword", "winlog.access_mask": "keyword",
                   "lab.profile_input": "boolean", "lab.read_data": "boolean", "lab.archive_mode": "keyword"}
    mapping = {key: {"type": value} for key, value in field_types.items()}
    request(base, "PUT", "/" + index, {"settings": {"number_of_shards": 1, "number_of_replicas": 0},
                                        "mappings": {"properties": mapping}})
    bulk = "".join(json.dumps({"create": {"_id": str(d["winlog"]["record_id"])}}) + "\n" +
                   json.dumps(d) + "\n" for d in docs)
    if request(base, "POST", f"/{index}/_bulk?refresh=true", bulk, ndjson=True)["errors"]:
        raise RuntimeError("Errors during bulk indexing")
    if request(base, "GET", f"/{index}/_count")["count"] != len(docs):
        raise RuntimeError("Incomplete index")
    matches = {query: {} for query in QUERIES}
    for name, query in QUERIES.items():
        body = {"query": query, "tiebreaker_field": "winlog.record_id", "size": max(100, len(docs))}
        reply = request(base, "POST", f"/{index}/_eql/search?allow_partial_search_results=false", body)
        save(f"{name}.json", {"request": body, "response": reply})
        if reply.get("timed_out") or reply.get("is_partial") or reply.get("is_running"):
            raise RuntimeError(f"Incomplete {name} search")
        groups = (s["events"] for s in reply["hits"]["sequences"]) if name == "correlated" else (
            [e] for e in reply["hits"]["events"])
        for group in groups:
            pid = group[0]["_source"]["process"]["pid"]
            matches[name].setdefault(pid, []).append([int(e["_id"]) for e in group])
    rows = []
    for case in cases:
        pid = case["pid"]
        observed = {key: hits.get(pid, []) for key, hits in matches.items()}
        rows.append({"case": case["name"], "pid": pid, "exit_code": case["exit_code"],
                     "expected_hit": case["expected_hit"], "records": observed,
                     "matched": bool(observed["correlated"]), "member_sha256": case["member_sha256"]})
    summary = {"elasticsearch": version, "index": index, "xml_sha256": hashlib.sha256(xml.read_bytes()).hexdigest(),
               "manifest_sha256": hashlib.sha256((evidence / "manifest.json").read_bytes()).hexdigest(),
               "events": dict(Counter(d["event"]["code"] for d in docs)), "cases": rows,
               "all_expectations_met": all(r["matched"] == r["expected_hit"] for r in rows)}
    save("summary.json", summary)
    print(json.dumps(summary, indent=2))
    if not summary["all_expectations_met"]:
        raise SystemExit("SIEM outcomes differ from declared controls")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("output", type=Path, help="New directory for API requests, responses and the control matrix")
    parser.add_argument("--url", default="http://127.0.0.1:9200")
    args = parser.parse_args()
    replay(args.evidence, args.url.rstrip("/"), args.output)
