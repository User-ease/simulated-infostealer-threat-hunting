import importlib.util
import json
import unittest
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("collector", ROOT / "scripts/collect_week9_atomics.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class TraceTests(unittest.TestCase):
    def parse(self, line):
        return collector.parse_trace(line, 123, "test", "run", "traces/test.123")

    def test_success_and_native_provenance(self):
        rows = self.parse('1794150000.123456 execve("/usr/bin/tar", ["tar", "-cvzf", "out/a.tar.gz", "lab-browser"], 0x0 /* 4 vars */) = 0')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["process"]["name"], "tar")
        self.assertEqual(rows[0]["lab"]["source_line"], 1)

    def test_failed_path_lookup_is_not_launch(self):
        self.assertEqual(self.parse('1794150000.1 execve("/bad/tar", ["tar"], 0x0) = -1 ENOENT (No such file or directory)'), [])

    def test_file_open_is_not_process(self):
        self.assertEqual(self.parse('1794150000.1 openat(AT_FDCWD, "test", O_RDONLY) = 3'), [])

    def test_quoted_script_and_empty_arguments(self):
        args = ["sh", "-c", "echo \"a\"\nprintf 'b\\n'", ""]
        rows = self.parse('1794150000.1 execve("/bin/sh", ' + json.dumps(args) + ', 0x0) = 0')
        self.assertEqual(rows[0]["process"]["args"], args)

    def test_all_archived_events_trace_back(self):
        runs = list((ROOT / "evidence/week9").glob("*/events.jsonl"))
        self.assertTrue(runs)
        for path in runs:
            expected = [json.loads(line) for line in path.read_text().splitlines()]
            actual = []
            for trace in sorted((path.parent / "traces").glob("*")):
                actual.extend(collector.parse_trace(trace.read_text(), int(trace.suffix[1:]),
                    trace.stem, path.parent.name, trace.relative_to(path.parent).as_posix()))
            key = lambda e: (e["@timestamp"], e["process"]["pid"])
            self.assertEqual(sorted(expected, key=key), sorted(actual, key=key))


class ArchiveEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("analyzer", ROOT / "scripts/analyze_week9_elastic.py")
        cls.analyzer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.analyzer)

    def test_operation_modes(self):
        for name, args, expected in [
                ("tar", ["tar", "-cvzf", "out", "source"], True),
                ("tar", ["tar", "-tf", "source"], False),
                ("tar", ["tar", "-xf", "source"], False),
                ("gzip", ["gzip", "-k", "source"], True),
                ("gzip", ["gzip", "-dc", "source"], False),
                ("tar", ["tar", "--create", "--file=out.tar", "source"], True),
                ("tar", ["tar", "--file", "out.tar", "--gzip", "--create", "source"], True),
                ("tar", ["tar", "-c", "--file=out.tar", "--", "-source"], True),
                ("tar", ["tar", "--list", "--file=out.tar"], False),
                ("tar", ["tar", "--extract", "--file", "out.tar", "source"], False),
                ("tar", ["tar", "--create", "--list", "--file=out.tar", "source"], False),
                ("tar", ["tar", "--file", "--create", "source"], False),
                ("tar", ["tar", "--create", "--file=", "source"], False),
                ("gzip", ["gzip"], False)]:
            with self.subTest(args=args):
                self.assertEqual(self.analyzer.creation_mode(name, args), expected)

    def test_resolved_source_and_exec_boundary(self):
        lines = [
            '1 execve("/bin/tar", ["tar"], {}) = 0',
            '2 openat(4, "cookies.json", O_RDONLY) = 5</lab/ordinary-docs/cookies.json>',
            '3 openat(4, "cookies.json", O_RDONLY) = -1 EACCES (Permission denied)',
            '4 openat(4, "cookies.json", O_WRONLY) = 5</lab/profile-alt/cookies.json>',
            '5 openat(4, "cookies.json", O_RDONLY) = 5</lab/profile-alt/cookies.json>',
            '6 execve("/bin/sh", ["sh"], {}) = 0',
            '7 openat(4, "cookies.json", O_RDONLY) = 5</lab/profile-alt/cookies.json>',
            '8 +++ exited with 0 +++']
        event = {"process": {"name": "tar", "args": ["tar", "-cf", "out", "profile-alt"]},
                 "lab": {"source_file": "sample.trace", "source_line": 1}}
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "sample.trace").write_text("\n".join(lines))
            self.analyzer.add_archive_fields(event, Path(tmp), {"profile-alt/cookies.json"})
        self.assertEqual(event["lab"]["profile_open_lines"], [5])
        self.assertNotIn("exit_code", event["process"])

    def test_archiver_exit_provenance(self):
        for code in (0, 2, None):
            with self.subTest(exit_code=code), tempfile.TemporaryDirectory() as tmp:
                lines = ['1 execve("/usr/bin/tar", [], {}) = 0',
                         '2 openat(3, "cookies.json", O_RDONLY) = 4</lab/profile/cookies.json>']
                if code == 2:
                    lines.append('3 write(0x4, 0x1234, 0x2800) = -1 ENOSPC (No space left on device)')
                if code is not None:
                    lines.append(f'4 +++ exited with {code} +++')
                trace = Path(tmp) / "test.trace"
                trace.write_text("\n".join(lines))
                event = {"process": {"name": "tar", "args": ["tar", "--create", "--file=a.tar", "profile"]},
                         "lab": {"source_file": trace.name, "source_line": 1}}
                self.analyzer.add_archive_fields(event, trace.parent, {"profile/cookies.json"})
                self.assertEqual(event["process"].get("exit_code"), code)
                self.assertEqual(event["lab"].get("exit_line"), len(lines) if code is not None else None)
                self.assertEqual(event["lab"].get("enospc_lines", []), [3] if code == 2 else [])


    def test_saved_live_results_and_trace_references(self):
        for path in (ROOT / "evidence/week9").glob("*/siem/summary.json"):
            summary = json.loads(path.read_text())
            if summary.get("query_version", 1) < 2:
                continue
            results = json.loads((path.parent / "results.json").read_text())
            self.assertTrue(summary["control_counts_passed"])
            for hit in results["lab_browser_archive"]["hits"]["hits"]:
                record = hit["_source"]["lab"]
                trace = (path.parent.parent / record["source_file"]).read_text().splitlines()
                for line, source in zip(record["profile_open_lines"], record["profile_inputs"]):
                    self.assertIn("</lab/" + source + ">", trace[line - 1])
            if summary["query_version"] >= 3:
                self.assertTrue(summary["write_failure_evidence_passed"])
                for bucket, expected_code in [("lab_browser_archive", 0), ("failed_profile_archive", 2)]:
                    for hit in results[bucket]["hits"]["hits"]:
                        source = hit["_source"]
                        lab = source["lab"]
                        trace = (path.parent.parent / lab["source_file"]).read_text().splitlines()
                        self.assertEqual(source["process"]["exit_code"], expected_code)
                        self.assertTrue(trace[lab["exit_line"] - 1].endswith(f"exited with {expected_code} +++"))
                        if expected_code:
                            self.assertTrue(lab["enospc_lines"])
                            for line in lab["enospc_lines"]:
                                self.assertIn("= -1 ENOSPC", trace[line - 1])


if __name__ == "__main__":
    unittest.main()
