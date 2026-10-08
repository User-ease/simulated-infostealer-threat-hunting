"""Import collected Windows events and execute real queries in local Elasticsearch.

No synthetic event generator is used here. The input comes from the separate
Windows collector. This script uses only the Python standard library.
"""

import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_input_hashes(manifest):
    """Verify the published evidence before contacting either service."""
    artifacts = manifest["artifacts"]
    expected = {item["path"]: item["sha256"] for item in artifacts}
    if len(expected) != len(artifacts):
        raise ValueError("Duplicate artifact paths in the collection manifest.")
    for relative in ("evidence/week5/windows-events.xml", "data/week5-powershell-events.jsonl"):
        if sha256(ROOT / relative).lower() != expected.get(relative, "").lower():
            raise ValueError(f"Collection manifest SHA-256 mismatch: {relative}")
    if sha256(ROOT / "scripts/collect_week5_powershell.ps1").lower() != manifest["collector_script_sha256"].lower():
        raise ValueError("Collection manifest SHA-256 mismatch: collector script")


def local_url(value):
    parsed = urlparse(value)
    if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}
            or parsed.username or parsed.password or parsed.path not in {"", "/"}
            or parsed.query or parsed.fragment):
        raise ValueError("Use a plain HTTP loopback URL without credentials or a path.")
    return value.rstrip("/")


class API:
    def __init__(self, base, transcript, name):
        self.base = base
        self.transcript = transcript
        self.name = name

    def call(self, method, path, body=None, ndjson=False, allow_404=False):
        data = None
        headers = {"Content-Type": "application/json", "kbn-xsrf": "week5-lab"}
        if body is not None:
            if ndjson:
                data = body.encode("utf-8")
                headers["Content-Type"] = "application/x-ndjson"
            else:
                data = json.dumps(body).encode("utf-8")
        timestamp = utc_now()
        request = Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urlopen(request, timeout=60) as response:
                status = response.status
                result = json.loads(response.read())
        except HTTPError as error:
            status = error.code
            try:
                result = json.loads(error.read())
            except (ValueError, UnicodeDecodeError):
                result = {"error": "Non-JSON HTTP error response"}
            finally:
                error.close()
            self.transcript.append({"utc": timestamp, "service": self.name,
                                    "method": method, "path": path,
                                    "request": body, "status": status, "response": result})
            if status != 404 or not allow_404:
                raise RuntimeError(f"{self.name} {method} {path}: HTTP {status}") from error
            return status, result
        self.transcript.append({"utc": timestamp, "service": self.name,
                                "method": method, "path": path,
                                "request": body, "status": status, "response": result})
        return status, result


def docker_value(*args):
    result = subprocess.run(["docker", *args], capture_output=True, text=True, check=True, timeout=30)
    return result.stdout.strip()


def docker_runtime():
    """Docker CLI access is optional; never publish labels, mounts, or commands."""
    try:
        ps_lines = docker_value("compose", "-f", str(ROOT / "docker/week5-compose.yml"), "ps", "--format", "json")
        containers = [json.loads(line) for line in ps_lines.splitlines() if line.strip()]
        kibana_container = next(item["Name"] for item in containers if item["Service"] == "kibana")
        package = json.loads(docker_value("exec", kibana_container, "cat", "/usr/share/kibana/package.json"))
        safe_containers = []
        for container in containers:
            safe = {key: container[key] for key in ("ID", "Name", "Service", "Image", "State", "Health")
                    if key in container}
            safe["Publishers"] = [{key: publisher[key] for key in ("URL", "TargetPort", "PublishedPort", "Protocol")
                                   if key in publisher} for publisher in (container.get("Publishers") or [])]
            safe_containers.append(safe)
        images = []
        for service in ("elasticsearch", "kibana"):
            tag = next(item["Image"] for item in containers if item["Service"] == service)
            details = json.loads(docker_value("image", "inspect", tag))[0]
            images.append({"image": tag, "id": details["Id"], "repo_digests": details.get("RepoDigests", [])})
        return {"status": "available", "kibana_version": package["version"],
                "kibana_version_source": "running Kibana container package metadata",
                "docker_engine_version": docker_value("version", "--format", "{{.Server.Version}}"),
                "docker_compose_version": docker_value("compose", "version", "--short"),
                "containers": safe_containers, "images": images}
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, StopIteration) as error:
        # Exception messages can contain local compose paths or Docker command arguments.
        return {"status": "unavailable", "reason": "Docker runtime inspection unavailable",
                "error_type": type(error).__name__}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elasticsearch", default="http://127.0.0.1:9200")
    parser.add_argument("--kibana", default="http://127.0.0.1:5601")
    parser.add_argument("--query-only", action="store_true",
                        help="Query the existing run index; preserve the original execution evidence.")
    parser.add_argument("--resume-existing", action="store_true",
                        help="Finalize an interrupted run using the existing index; never overwrite indexed records.")
    parser.add_argument("--replay", action="store_true",
                        help="Replay the archived collection into a new index; preserve all original evidence.")
    parser.add_argument("--output-dir", type=Path,
                        help="New replay evidence directory; it must not already exist. Requires --replay.")
    parser.add_argument("--index", help="Exact original or replay index to search. Requires --query-only.")
    args = parser.parse_args(argv)
    if sum((args.query_only, args.resume_existing, args.replay)) > 1:
        parser.error("Choose only one of --query-only, --resume-existing, or --replay.")
    if args.output_dir is not None and not args.replay:
        parser.error("--output-dir requires --replay.")
    if args.index is not None and not args.query_only:
        parser.error("--index requires --query-only.")
    es_url = local_url(args.elasticsearch)
    kibana_url = local_url(args.kibana)
    evidence = ROOT / "evidence/week5"
    events_path = ROOT / "data/week5-powershell-events.jsonl"
    manifest_path = evidence / "run-manifest.json"
    queries_path = ROOT / "data/week5-hunt-queries.json"
    manifest = read_json(manifest_path)
    verify_input_hashes(manifest)
    runner_hash = sha256(Path(__file__))
    events = [json.loads(line) for line in events_path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    if len(events) != 4:
        raise ValueError("Expected exactly four collected engine-start events.")
    run_ids = {item["lab"]["run_id"] for item in events}
    if len(run_ids) != 1 or manifest["run_id"] not in run_ids:
        raise ValueError("Dataset and collector manifest do not describe the same run.")
    if len({item["winlog"]["record_id"] for item in events}) != 4:
        raise ValueError("Event record IDs must be distinct.")
    cases = {item["lab"]["case_id"] for item in events}
    expected_cases = {"baseline_plain", "encoded_only", "hidden_bypass", "encoded_hidden_bypass"}
    if cases != expected_cases:
        raise ValueError("The dataset must contain all four documented control cases.")
    for item in events:
        if item["event"]["code"] != "400" or item["winlog"]["channel"] != "Windows PowerShell":
            raise ValueError("Only actual Windows PowerShell Event 400 records are accepted.")
    run_id = manifest["run_id"]
    base_index = "week5-powershell-" + re.sub(r"[^a-z0-9-]", "", run_id.lower())
    if len(base_index) > 200 or not base_index.removeprefix("week5-powershell-"):
        raise ValueError("Invalid lab run ID.")
    index = args.index or base_index
    if args.index and (not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,254}", index)
                       or not (index == base_index or index.startswith(base_index + "-replay-"))):
        raise ValueError("--index must name one exact index for this archived collection.")
    if not args.query_only and not args.replay and (evidence / "hunt-results.json").exists():
        raise FileExistsError("Execution evidence already exists. Use --query-only for a read-only rerun.")
    expected_hits = {
        "inventory": expected_cases,
        "encoded_candidates": {"encoded_only", "encoded_hidden_bypass"},
        "encoded_hidden_bypass": {"encoded_hidden_bypass"},
    }
    query_bytes = queries_path.read_bytes()
    queries = json.loads(query_bytes.decode("utf-8-sig"))["queries"]
    if {query["id"] for query in queries} != set(expected_hits) or len(queries) != 3:
        raise ValueError("Expected the three documented hunt queries.")
    replay_id = None
    output = evidence
    if args.replay:
        replay_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ").lower() + "-" + uuid4().hex[:8]
        index = base_index + "-replay-" + replay_id
        output = args.output_dir if args.output_dir is not None else ROOT / "evidence/week5-replays" / replay_id
        output = output.resolve()
        if output.is_relative_to(evidence.resolve()):
            raise ValueError("Replay output must be outside the original evidence/week5 directory.")
        output.mkdir(parents=True, exist_ok=False)
        (output / "hunt-queries.json").write_bytes(query_bytes)
    transcript = []
    es = API(es_url, transcript, "Elasticsearch")
    kibana = API(kibana_url, transcript, "Kibana")
    _, es_version = es.call("GET", "/")
    _, license_info = es.call("GET", "/_license")
    status, _ = es.call("GET", "/" + index, allow_404=True)
    if args.query_only:
        if status != 200:
            raise ValueError("The collected run index does not exist.")
    else:
        if status == 200 and not args.resume_existing:
            raise FileExistsError("The run index already exists; do not overwrite it.")
        properties = {
            "@timestamp": {"type": "date"},
            "event": {"properties": {"code": {"type": "keyword"}, "provider": {"type": "keyword"},
                                      "action": {"type": "keyword"}}},
            "winlog": {"properties": {"channel": {"type": "keyword"}, "record_id": {"type": "long"}}},
            "host": {"properties": {"name": {"type": "keyword"}}},
            "process": {"properties": {"name": {"type": "keyword"}, "pid": {"type": "long"},
                                        "command_line": {"type": "wildcard"}}},
            "lab": {"properties": {"run_id": {"type": "keyword"}, "case_id": {"type": "keyword"}}},
        }
        if status == 404:
            es.call("PUT", "/" + index, {"settings": {"number_of_shards": 1, "number_of_replicas": 0},
                                          "mappings": {"dynamic": "strict", "properties": properties}})
            bulk_lines = []
            for item in events:
                bulk_lines.extend([json.dumps({"create": {"_index": index, "_id": str(item["winlog"]["record_id"])}}),
                                   json.dumps(item)])
            _, bulk = es.call("POST", "/_bulk?refresh=wait_for", "\n".join(bulk_lines) + "\n", ndjson=True)
            if bulk.get("errors") or any(item["create"]["status"] != 201 for item in bulk["items"]):
                raise RuntimeError("Elasticsearch did not create all four records successfully.")
    _, count = es.call("GET", "/" + index + "/_count")
    if count["count"] != 4:
        raise RuntimeError("The run index must contain exactly four records.")
    _, mapping = es.call("GET", "/" + index + "/_mapping")
    observed_type = mapping[index]["mappings"]["properties"]["process"]["properties"]["command_line"]["type"]
    if observed_type != "wildcard":
        raise RuntimeError("The observed command-line mapping is not the documented wildcard type.")
    results = []
    for query in queries:
        _, response = es.call("POST", "/" + index + "/_search", query["body"])
        hits = response["hits"]["hits"]
        actual_cases = {hit["_source"]["lab"]["case_id"] for hit in hits}
        total = response["hits"]["total"]
        if response.get("timed_out") or response["_shards"]["failed"] or total["relation"] != "eq":
            raise RuntimeError("Incomplete query result.")
        if actual_cases != expected_hits[query["id"]] or total["value"] != len(actual_cases):
            raise RuntimeError(f"Unexpected result for {query['id']}: {sorted(actual_cases)}")
        if query["id"] == "inventory":
            indexed_documents = {hit["_id"]: hit["_source"] for hit in hits}
            input_documents = {str(item["winlog"]["record_id"]): item for item in events}
            if indexed_documents != input_documents:
                raise RuntimeError("The actual indexed documents differ from the collected input.")
        results.append({"id": query["id"], "hits": total["value"],
                        "case_ids": sorted(actual_cases), "response": response})
    _, health = es.call("GET", "/_cluster/health")
    _, kibana_status = kibana.call("GET", "/api/status")
    if not args.query_only:
        view_id = "week5-" + run_id + ("-replay-" + replay_id if replay_id else "")
        view_name = "Week 5 - Windows PowerShell lab" + (" replay " + replay_id if replay_id else "")
        view_status, view = kibana.call("GET", "/api/data_views/data_view/" + view_id, allow_404=True)
        if view_status == 404:
            kibana.call("POST", "/api/data_views/data_view", {"data_view": {
                "id": view_id, "title": index,
                "name": view_name,
                "timeFieldName": "@timestamp"}})
        elif view["data_view"]["title"] != index:
            raise RuntimeError("Existing Kibana data view points at a different index.")
        else:
            view_name = view["data_view"].get("name", view_name)
        docker_info = docker_runtime()
        api_version = kibana_status.get("version", {}).get("number")
        runtime = {
            "recorded_utc": utc_now(), "elasticsearch_url": es_url, "kibana_url": kibana_url,
            "elasticsearch_version_response": es_version, "license_response": license_info,
            "cluster_health": health,
            "kibana_version": api_version or docker_info.get("kibana_version"),
            "kibana_version_source": ("Kibana status API" if api_version else
                                      docker_info.get("kibana_version_source", "unavailable")),
            "kibana_overall_status": kibana_status["status"]["overall"]["level"],
            "docker_inspection": docker_info,
        }
        result_record = {"executed_utc": utc_now(), "run_id": run_id, "index": index,
                         "dataset_sha256": sha256(events_path),
                         "queries_sha256": hashlib.sha256(query_bytes).hexdigest(),
                         "runner_sha256": runner_hash,
                         "input_count": count["count"], "queries": results,
                         "resumed_existing_index": args.resume_existing,
                         "replay_of_run_id": run_id if args.replay else None,
                         "replay_id": replay_id,
                         "new_collection": False if args.replay else None,
                         "data_view_id": view_id,
                         "data_view_name": view_name,
                         "interpretation": "All cases are benign. Results validate only the documented launch-flag query on these four controls."}
        save_json(output / "runtime.json", runtime)
        save_json(output / "api-transcript.json", transcript)
        save_json(output / "hunt-results.json", result_record)
    print(json.dumps({"index": index, "input_count": count["count"],
                      "queries": [{"id": item["id"], "hits": item["hits"], "case_ids": item["case_ids"]} for item in results],
                      "read_only_rerun": args.query_only, "replay_of_run_id": run_id if args.replay else None,
                      "data_view_id": view_id if not args.query_only else None,
                      "data_view_name": view_name if not args.query_only else None,
                      "output_directory": str(output) if not args.query_only else None}, indent=2))


if __name__ == "__main__":
    main()
