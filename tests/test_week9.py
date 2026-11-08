import importlib.util
import json
import unittest
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


if __name__ == "__main__":
    unittest.main()
