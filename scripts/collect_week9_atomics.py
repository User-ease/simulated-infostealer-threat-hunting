#!/usr/bin/env python3
"""Run three reviewed Linux atomics on synthetic files and preserve native strace."""
import argparse
import datetime as dt
import gzip
import hashlib
import json
import platform
import re
import shlex
import shutil
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUIDS = ["b04ed73c-7d43-4dc8-b563-a2fc595cba1a",
         "cde3c2af-3485-49eb-9c1f-0ed60e9cc0af",
         "7af2b51e-ad1c-498c-aca8-d3290c19535a"]


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, obj):
    Path(path).write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


def parse_trace(text, pid, case, run_id, trace_file):
    """Only successful execve calls; failed PATH lookups are not process launches."""
    records = []
    pattern = r'^(\d+\.\d+) execve\(("(?:\\.|[^"\\])*"), (\[.*?\]), .*\)\s+= 0$'
    for line_no, line in enumerate(text.splitlines(), 1):
        match = re.match(pattern, line)
        if not match:
            continue
        timestamp, executable, args = match.groups()
        executable, args = json.loads(executable), json.loads(args)
        records.append({
            "@timestamp": dt.datetime.fromtimestamp(float(timestamp), dt.timezone.utc).isoformat(),
            "event": {"dataset": "lab.strace", "action": "exec", "type": "start", "category": "process"},
            "host": {"name": "LAB-LINUX", "os": {"type": "linux"}},
            "process": {"pid": pid, "executable": executable, "name": Path(executable).name,
                        "args": args, "command_line": shlex.join(args)},
            "lab": {"run_id": run_id, "case": case, "source_file": trace_file, "source_line": line_no}
        })
    return records


def traced(command, case, lab, evidence, run_id):
    trace = evidence / "traces" / case
    started = now()
    result = subprocess.run(
        ["strace", "-ff", "-qq", "-ttt", "-s", "16384", "-e",
         "trace=execve,openat,unlink,unlinkat,rename", "-o", str(trace), "--", "/bin/sh", "-c", command],
        cwd=lab, env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
        capture_output=True, text=True, timeout=30)
    (evidence / (case + ".stdout.txt")).write_text(result.stdout)
    (evidence / (case + ".stderr.txt")).write_text(result.stderr)
    records = []
    for path in sorted(trace.parent.glob(case + ".*")):
        records.extend(parse_trace(path.read_text(), int(path.suffix[1:]), case, run_id,
                                   path.relative_to(evidence).as_posix()))
    return {"case": case, "command": command, "started_at": started, "finished_at": now(),
            "exit_code": result.returncode, "successful_execve_records": len(records)}, records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    options = parser.parse_args()
    if platform.system() != "Linux":
        raise SystemExit("This collector requires Linux. It does not emulate Windows telemetry.")
    for tool in ["strace", "sh", "tar", "gzip", "seq", "sleep"]:
        if not shutil.which(tool):
            raise SystemExit("Missing prerequisite: " + tool)
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    evidence = (options.output or ROOT / "evidence" / "week9" / run_id).resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    (evidence / "traces").mkdir()
    lab = evidence / "lab"
    for name in ["lab-browser", "ordinary-docs", "out"]:
        (lab / name).mkdir(parents=True)
    save(lab / "lab-browser" / "mock-browser.json",
         {"site": "https://training.invalid", "username": "FAKE-STUDENT", "password": "NOT-A-REAL-PASSWORD"})
    save(lab / "lab-browser" / "cookies.json", {"session": "FAKE-SESSION-NOT-VALID"})
    (lab / "ordinary-docs" / "notes.txt").write_text("Ordinary synthetic backup control.\n")
    pinned_path = ROOT / "data/week9/selected-atomics.json"
    pinned = json.loads(pinned_path.read_text())
    tests = pinned["tests"]
    if [t["guid"] for t in tests] != GUIDS:
        raise SystemExit("Unexpected atomic selection; review before execution.")
    inputs = [{}, {"input_file": "lab-browser/mock-browser.json", "input_content": "FAKE-TRAINING-DATA"},
              {"input_file_folder": "lab-browser", "output_file": "out/browser.tar.gz"}]
    cases, events, cleanup = [], [], []
    for test, arguments, name in zip(tests, inputs, ["atomic_shell", "atomic_gzip", "atomic_tar"]):
        command = test["executor"]["command"]
        clean = test["executor"].get("cleanup_command", "")
        for key, value in arguments.items():
            command = command.replace("#{" + key + "}", value)
            clean = clean.replace("#{" + key + "}", value)
        case, observed = traced(command, name, lab, evidence, run_id)
        case.update({"atomic_guid": test["guid"], "technique": test["technique"], "inputs": arguments})
        cases.append(case)
        events.extend(observed)
        if clean:
            cleanup.append((name, clean))
    for name, command in [("benign_backup", "tar -cvzf out/ordinary-backup.tar.gz ordinary-docs\n"),
                          ("plain_control", "printf 'Ordinary control without archiving\\n'\n")]:
        case, observed = traced(command, name, lab, evidence, run_id)
        cases.append(case)
        events.extend(observed)
    cleanup.append(("benign_backup", "rm -f out/ordinary-backup.tar.gz\n"))
    source = lab / "lab-browser/mock-browser.json"
    archive = lab / "out/browser.tar.gz"
    gz = lab / "lab-browser/mock-browser.json.gz"
    verification = {"gzip_roundtrip": gzip.decompress(gz.read_bytes()) == source.read_bytes(),
                    "source_sha256": sha(source), "gzip_sha256": sha(gz), "tar_sha256": sha(archive)}
    with tarfile.open(archive) as tf:
        verification["tar_members"] = tf.getnames()
        verification["tar_roundtrip"] = all(tf.extractfile("lab-browser/" + name).read() ==
                                             (lab / "lab-browser" / name).read_bytes()
                                             for name in ["mock-browser.json", "cookies.json"])
    verification["shell_marker_lines"] = (evidence / "atomic_shell.stdout.txt").read_text().splitlines() == [
        f"{i}, Atomic Red Team was here!" for i in range(1, 6)]
    clean_results = []
    for name, command in cleanup:
        result = subprocess.run(["/bin/sh", "-c", command], cwd=lab, capture_output=True, text=True, timeout=10)
        clean_results.append({"case": name, "command": command, "exit_code": result.returncode,
                              "stdout": result.stdout, "stderr": result.stderr})
    verification["cleanup_passed"] = not any(p.exists() for p in [archive, gz, lab / "out/ordinary-backup.tar.gz"])
    verification["all_commands_succeeded"] = all(c["exit_code"] == 0 for c in cases + clean_results)
    verification["passed"] = all(verification[k] for k in ["gzip_roundtrip", "tar_roundtrip", "shell_marker_lines",
                                                           "cleanup_passed", "all_commands_succeeded"])
    events.sort(key=lambda e: (e["@timestamp"], e["process"]["pid"]))
    (evidence / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events))
    save(evidence / "collection.json", {"run_id": run_id, "finished_at": now(), "platform": "Linux x86_64",
         "python_version": platform.python_version(), "collector_sha256": sha(__file__),
         "selection_sha256": sha(pinned_path), "upstream_commit": pinned["upstream_commit"],
         "sensor": "strace child-process syscall tracing; not a system-wide agent or Windows sensor",
         "host_name_policy": "host.name is the fixed pseudonym LAB-LINUX; no actual hostname collected",
         "cases": cases, "cleanup": clean_results, "verification": verification, "event_count": len(events)})
    save(evidence / "collection-sha256.json", {p.relative_to(evidence).as_posix(): sha(p)
         for p in sorted(evidence.rglob("*")) if p.is_file()})
    print(json.dumps({"evidence": str(evidence), "events": len(events), "passed": verification["passed"]}))
    if not verification["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
