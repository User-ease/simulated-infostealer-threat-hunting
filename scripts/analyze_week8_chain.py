"""Replay the Week 8 Windows Security/PowerShell XML and receiver access log in Elasticsearch."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import ntpath
from pathlib import Path
import xml.etree.ElementTree as ET
from zipfile import ZipFile

from analyze_week9_windows import request

ROOT = r"C:\Week8Lab"
PROFILE = ROOT + r"\synthetic-profile"
NAMES = {"config.ini", "cookies.json", "mock-browser.json", "wallet.txt"}
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def load_json(path):
    return json.loads(path.read_bytes())


def native(raw):
    system = raw.find(NS + "System")
    fields = {d.get("Name"): d.text or "" for d in raw.findall(f"{NS}EventData/{NS}Data")}
    code = system.findtext(NS + "EventID")
    channel = system.findtext(NS + "Channel")
    record = int(system.findtext(NS + "EventRecordID"))
    provider = system.find(NS + "Provider").get("Name")
    doc = {"ts": system.find(NS + "TimeCreated").get("SystemTime"), "channel": channel, "provider": provider,
           "host": system.findtext(NS + "Computer"), "code": code, "record": record}
    if channel == "Security":
        if provider != "Microsoft-Windows-Security-Auditing":
            raise ValueError("Unexpected Security provider")
        if code == "4688":
            doc.update(pid=int(fields["NewProcessId"], 16), parent=int(fields["ProcessId"], 16),
                       image=ntpath.basename(fields["NewProcessName"]).lower(), command=fields["CommandLine"])
        elif code == "4663":
            doc.update(pid=int(fields["ProcessId"], 16), path=fields["ObjectName"],
                       read_data=bool(int(fields["AccessMask"], 16) & 1))
        elif code in {"4698", "4699"}:
            doc.update(task=fields["TaskName"])
            if fields.get("TaskContent"):
                task = ET.fromstring(fields["TaskContent"])
                doc.update(logon_trigger=task.find(".//{*}LogonTrigger") is not None,
                           action=" ".join((n.text or "") for n in task.findall(".//{*}Exec/*")))
    else:
        doc["pid"] = int(system.find(NS+"Execution").get("ProcessID"))
        if code == "4104":
            doc.update(path=fields.get("Path", ""), script=fields.get("ScriptBlockText", ""))
    return doc


def replay(evidence, output, url):
    case = load_json(evidence / "completed.json")
    verify = load_json(evidence / "verification.json")
    cleanup = load_json(evidence / "cleanup.json")
    docs = [native(e) for e in ET.parse(evidence / "events.xml").getroot()]
    if {d["host"].lower() for d in docs} != {verify["host"].lower()}:
        raise ValueError("Unexpected native host")
    ids = [(d["channel"], d["record"]) for d in docs]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate native record")
    for n, line in enumerate((evidence / "http.jsonl").read_text(encoding="utf-8-sig").splitlines(), 1):
        event = json.loads(line)
        docs.append({"ts": event.pop("utc"), "channel":"receiver", "record":n, "host":verify["host"], **event})

    index = "week8-chain-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    version = request(url, "GET", "/")["version"]["number"]
    fields = {k: {"type":"keyword"} for k in ("channel","host","provider","code","image","task","path","method","remote","local","sha256")}
    fields.update({k: {"type":"long"} for k in ("pid","parent","record","status","port","bytes_saved")})
    fields.update({k: {"type":"wildcard"} for k in ("command","action","script")})
    fields.update({k: {"type":"boolean"} for k in ("read_data","logon_trigger")})
    fields["ts"] = {"type": "date_nanos"}
    request(url, "PUT", "/"+index, {"settings":{"number_of_shards":1,"number_of_replicas":0},"mappings":{"properties":fields}})
    bulk = "".join(json.dumps({"create":{"_id":f"{d['channel']}:{d['record']}"}})+"\n"+json.dumps(d)+"\n" for d in docs)
    if request(url,"POST",f"/{index}/_bulk?refresh=true",bulk,ndjson=True)["errors"]:
        raise RuntimeError("Bulk indexing failed")
    if request(url,"GET",f"/{index}/_count")["count"] != len(docs):
        raise RuntimeError("Incomplete index")

    queries = {}
    results = {}
    def term(k, v):
        return {"term": {k:v}}
    def wildcard(k, v):
        return {"wildcard": {k:{"value":v,"case_insensitive":True}}}
    def search(label, *conditions):
        body = {"size":1000,"track_total_hits":True,"sort":[{"ts":"asc"},{"record":"asc"}],
                "_source":{"excludes":["script"]},"query":{"bool":{"filter":list(conditions)}}}
        resp = request(url,"POST",f"/{index}/_search?allow_partial_search_results=false",body)
        hits = resp["hits"]
        if resp["timed_out"] or resp["_shards"]["failed"] or len(hits["hits"]) != hits["total"]["value"]:
            raise RuntimeError("Incomplete result: "+label)
        queries[label] = body
        results[label] = [hit["_source"] for hit in hits["hits"]]
        return results[label]
    def only(rows):
        if len(rows) != 1:
            raise ValueError(f"Expected a single event, got {len(rows)}")
        return rows[0]
    def require(test, message):
        if not test:
            raise ValueError(message)

    page = only(search("training_page",term("method","GET"),term("path","/update"),term("status",200),term("local","127.0.0.1")))
    launch = only(search("loader",term("code","4688"),term("image","powershell.exe"),wildcard("command","*loader.ps1*")))
    pid = launch["pid"]
    parent = only(search("launcher",term("code","4688"),term("pid",launch["parent"]),term("image","cmd.exe")))
    require(ROOT.lower()+r"\loader.ps1" in launch["command"].lower() and
            "loader.ps1" in parent["command"].lower() and pid==verify["loader_pid"], "Launcher/loader ancestry")
    search("engine_start",term("code","400"),term("pid",pid))
    scripts=search("archive_script",term("code","4104"),term("pid",pid),term("path",ROOT+r"\loader.ps1"),wildcard("script","*Compress-Archive *"))
    require(scripts,"Missing loader script block")
    task = "\\"+case["task"]
    created = only(search("logon_task",term("code","4698"),term("task",task),term("logon_trigger",True),wildcard("action","*update-marker.cmd*")))
    deleted = only(search("task_deleted",term("code","4699"),term("task",task)))
    ran = search("task_action",term("code","4688"),term("image","cmd.exe"),wildcard("command","*update-marker.cmd*"))
    require(ran and case["task_marker"]==case["run"],"Task execution evidence")
    discovery = search("host_and_user",term("code","4688"),term("parent",pid),{"terms":{"image":["hostname.exe","whoami.exe"]}})
    require({h["image"] for h in discovery}=={"hostname.exe","whoami.exe"},"Host discovery")
    paths = [PROFILE+"\\"+n for n in sorted(NAMES)]
    reads = search("fixture_reads",term("code","4663"),term("pid",pid),term("read_data",True),{"terms":{"path":paths}})
    require({h["path"] for h in reads}==set(paths) and set(case["discovered"])==NAMES,"Fixture discovery and read coverage")
    post = only(search("accepted_upload",term("method","POST"),term("path","/receive"),term("status",201),
                       term("remote","127.0.0.1"),term("local","127.0.0.1"),term("port",18768)))
    reject = only(search("rejected_upload",term("method","POST"),term("status",404),term("path","/rejected")))
    only(search("listing_control",term("code","4688"),term("image","cmd.exe"),term("pid",verify["control_pid"])))
    control = search("listing_file_reads",term("code","4663"),term("pid",verify["control_pid"]),term("read_data",True),{"terms":{"path":paths}})
    require(not control and reject["bytes_saved"]==0 and set(verify["control_names"])==NAMES,"Control mismatch")
    sequence = [page,parent,launch,created,discovery[0],reads[0],post,deleted]
    def instant(row):
        return datetime.fromisoformat(row["ts"].replace("Z","+00:00"))
    require(list(map(instant,sequence))==sorted(map(instant,sequence)),"Unexpected stage order")
    zip_path=evidence/"received.zip"
    digest=hashlib.sha256(zip_path.read_bytes()).hexdigest().upper()
    require(digest==post["sha256"]==case["zip_hash"]==verify["sender_sha256"]==verify["receiver_sha256"] and
            post["bytes_saved"]==case["zip_bytes"]==zip_path.stat().st_size,"Transferred archive mismatch")
    with ZipFile(zip_path) as archive:
        require(sorted(archive.namelist())==sorted(NAMES),"Unexpected ZIP members")
        for name in NAMES:
            require(hashlib.sha256(archive.read(name)).hexdigest().upper()==case["source_hashes"][name],"Member mismatch")
    require(verify["task_absent"] and all(cleanup[k] for k in ("root_absent","task_absent","receiver_stopped")),"Cleanup incomplete")
    summary={"elasticsearch":version,"index":index,"run":case["run"],"native_records":len(ids),"receiver_requests":len(docs)-len(ids),
             "native_counts":dict(Counter(d["code"] for d in docs if "code" in d)),"loader_pid":pid,
             "matched_records":{k:[f"{r['channel']}:{r['record']}" for r in rows] for k,rows in results.items()},
             "sequence":[{"ts":row["ts"],"channel":row["channel"],"record":row["record"]} for row in sequence],
             "archive_bytes":post["bytes_saved"],"archive_sha256":digest,"members":sorted(NAMES),"checks_passed":True}
    output.mkdir(parents=True,exist_ok=False)
    for name,data in (("queries",queries),("hits",results),("summary",summary)):
        (output/(name+".json")).write_text(json.dumps(data,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(summary,indent=2))


if __name__ == "__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("evidence",type=Path)
    p.add_argument("output",type=Path)
    p.add_argument("--url",default="http://127.0.0.1:9200")
    args=p.parse_args()
    replay(args.evidence,args.output,args.url.rstrip("/"))
