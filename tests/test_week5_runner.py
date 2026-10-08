"""Runner regression tests using a local in-memory HTTP substitute, never a live stack."""

import contextlib
import copy
import importlib.util
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlparse


REPO = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("week5_runner", REPO / "scripts/run_week5_hunt.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class Response:
    def __init__(self, status, value):
        self.status = status
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return json.dumps(self.value).encode()


class Services:
    """Emulate the API contract; saved search results are fixed controls, not query tests."""

    def __init__(self, events):
        self.events = events
        self.indices = {}
        self.requests = []
        self.search_number = {}
        self.fail_path = None

    def __call__(self, request, timeout):
        url = urlparse(request.full_url)
        path = url.path
        method = request.get_method()
        self.requests.append((method, path))
        body = json.loads(request.data) if request.data and path != "/_bulk" else None
        if self.fail_path and path.endswith(self.fail_path):
            raise HTTPError(request.full_url, 503, "Service unavailable", {},
                            io.BytesIO(b'{"error":"test service failure"}'))
        if url.port == 5601:
            if path == "/api/status":
                return Response(200, {"status": {"overall": {"level": "available"}}})
            if method == "GET" and path.startswith("/api/data_views/data_view/"):
                return self.missing(request)
            if method == "POST" and path == "/api/data_views/data_view":
                return Response(200, body)
        if path == "/":
            return Response(200, {"version": {"number": "test-version"}})
        if path == "/_license":
            return Response(200, {"license": {"type": "basic"}})
        if path == "/_cluster/health":
            return Response(200, {"status": "green"})
        if path == "/_bulk":
            lines = [json.loads(line) for line in request.data.decode().splitlines()]
            created = []
            for action, document in zip(lines[::2], lines[1::2]):
                self.indices[action["create"]["_index"]].append(document)
                created.append({"create": {"status": 201}})
            return Response(200, {"errors": False, "items": created})
        parts = path.strip("/").split("/")
        index = parts[0]
        if len(parts) == 1:
            if method == "PUT":
                if index in self.indices:
                    raise AssertionError("Attempted to replace an existing index")
                self.indices[index] = []
                return Response(200, {"acknowledged": True})
            if index in self.indices:
                return Response(200, {index: {}})
            return self.missing(request)
        if parts[1] == "_count":
            return Response(200, {"count": len(self.indices[index])})
        if parts[1] == "_mapping":
            return Response(200, {index: {"mappings": {"properties": {
                "process": {"properties": {"command_line": {"type": "wildcard"}}}}}}})
        if parts[1] == "_search":
            search_number = self.search_number.get(index, 0) % 3
            self.search_number[index] = search_number + 1
            selected = self.indices[index]
            if search_number == 1:
                selected = [item for item in selected if item["lab"]["case_id"] in {
                    "encoded_only", "encoded_hidden_bypass"}]
            elif search_number == 2:
                selected = [item for item in selected if item["lab"]["case_id"] == "encoded_hidden_bypass"]
            return Response(200, {"timed_out": False, "_shards": {"failed": 0, "successful": 1},
                                  "hits": {"total": {"value": len(selected), "relation": "eq"},
                                           "hits": [{"_id": str(item["winlog"]["record_id"]),
                                                     "_source": item} for item in selected]}})
        raise AssertionError(f"Unexpected API request: {method} {path}")

    @staticmethod
    def missing(request):
        raise HTTPError(request.full_url, 404, "Not found", {}, io.BytesIO(b'{"error":"not found"}'))


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for relative in ("scripts/collect_week5_powershell.ps1", "data/week5-powershell-events.jsonl",
                         "data/week5-hunt-queries.json", "evidence/week5/windows-events.xml",
                         "evidence/week5/run-manifest.json"):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / relative, destination)
        for filename in ("hunt-results.json", "runtime.json", "api-transcript.json"):
            (self.root / "evidence/week5" / filename).write_text('{"historical":"preserve me"}\n')
        self.manifest = runner.read_json(self.root / "evidence/week5/run-manifest.json")
        self.events = [json.loads(line) for line in (self.root / "data/week5-powershell-events.jsonl").read_text().splitlines()]
        self.base_index = "week5-powershell-" + self.manifest["run_id"]
        self.original_files = {str(path.relative_to(self.root)): path.read_bytes()
                               for path in self.root.rglob("*") if path.is_file()}
        self.services = Services(self.events)
        self.addCleanup(patch.stopall)
        patch.object(runner, "ROOT", self.root).start()
        self.http = patch.object(runner, "urlopen", side_effect=self.services).start()
        patch.object(runner, "docker_value", side_effect=FileNotFoundError("C:/PRIVATE/docker.exe")).start()

    def invoke(self, *args):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            runner.main(list(args))
        return json.loads(stdout.getvalue())

    def assert_originals_unchanged(self):
        for relative, content in self.original_files.items():
            self.assertEqual((self.root / relative).read_bytes(), content, relative)

    def test_clean_replay_preserves_originals_and_does_not_require_docker_cli(self):
        summary = self.invoke("--replay")
        output = Path(summary["output_directory"])
        self.assertEqual(output.parent, (self.root / "evidence/week5-replays").resolve())
        self.assertTrue(summary["index"].startswith(self.base_index + "-replay-"))
        self.assertNotIn(self.base_index, self.services.indices)
        record = runner.read_json(output / "hunt-results.json")
        self.assertEqual(record["replay_of_run_id"], self.manifest["run_id"])
        self.assertFalse(record["new_collection"])
        self.assertEqual(summary["data_view_id"], record["data_view_id"])
        self.assertEqual(summary["data_view_name"], record["data_view_name"])
        self.assertEqual([query["hits"] for query in record["queries"]], [4, 2, 1])
        self.assertEqual((output / "hunt-queries.json").read_bytes(),
                         (self.root / "data/week5-hunt-queries.json").read_bytes())
        self.assertEqual(record["queries_sha256"], runner.sha256(output / "hunt-queries.json"))
        self.assertEqual(record["runner_sha256"], runner.sha256(Path(runner.__file__)))
        runtime_text = (output / "runtime.json").read_text()
        self.assertNotIn("PRIVATE", runtime_text)
        self.assertEqual(json.loads(runtime_text)["docker_inspection"]["status"], "unavailable")
        self.assertTrue((output / "api-transcript.json").is_file())
        self.assert_originals_unchanged()

    def test_two_replays_are_independent(self):
        first = self.invoke("--replay")
        second = self.invoke("--replay")
        self.assertNotEqual(first["index"], second["index"])
        self.assertNotEqual(first["output_directory"], second["output_directory"])
        self.assertEqual(len(self.services.indices), 2)
        self.assert_originals_unchanged()

    def test_existing_output_is_rejected_before_network(self):
        output = self.root / "already-exists"
        output.mkdir()
        sentinel = output / "keep.txt"
        sentinel.write_text("preserve")
        with self.assertRaises(FileExistsError):
            self.invoke("--replay", "--output-dir", str(output))
        self.http.assert_not_called()
        self.assertEqual(sentinel.read_text(), "preserve")
        self.assert_originals_unchanged()

    def test_replay_output_inside_original_evidence_is_rejected_before_network(self):
        for output in (self.root / "evidence/week5", self.root / "evidence/week5/new-replay"):
            with self.subTest(output=str(output)), self.assertRaisesRegex(ValueError, "outside the original"):
                self.invoke("--replay", "--output-dir", str(output))
        self.http.assert_not_called()
        self.assertFalse((self.root / "evidence/week5/new-replay").exists())
        self.assert_originals_unchanged()

    def test_each_tampered_input_is_blocked_before_network(self):
        for relative in ("evidence/week5/windows-events.xml", "data/week5-powershell-events.jsonl",
                         "scripts/collect_week5_powershell.ps1"):
            with self.subTest(relative=relative):
                path = self.root / relative
                original = path.read_bytes()
                try:
                    path.write_bytes(original + b"\n")
                    with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                        self.invoke("--replay")
                    self.http.assert_not_called()
                    self.assertFalse((self.root / "evidence/week5-replays").exists())
                finally:
                    path.write_bytes(original)

    def test_query_only_original_and_replay_indices_never_write(self):
        for index in (self.base_index, self.base_index + "-replay-test"):
            with self.subTest(index=index):
                self.services.indices[index] = copy.deepcopy(self.events)
                summary = self.invoke("--query-only", "--index", index)
                self.assertTrue(summary["read_only_rerun"])
                self.assertIsNone(summary["output_directory"])
                self.assertIsNone(summary["data_view_id"])
                self.assertIsNone(summary["data_view_name"])
                self.assertEqual(summary["index"], index)
        self.assertEqual(set(self.original_files), {str(path.relative_to(self.root))
                                                  for path in self.root.rglob("*") if path.is_file()})
        self.assert_originals_unchanged()
        self.assertTrue(all(method == "GET" or (method == "POST" and path.endswith("/_search"))
                            for method, path in self.services.requests))

    def test_http_failure_cannot_leave_successful_results(self):
        self.services.fail_path = "/_search"
        output = self.root / "failed-replay"
        with self.assertRaisesRegex(RuntimeError, "HTTP 503"):
            self.invoke("--replay", "--output-dir", str(output))
        self.assertFalse((output / "hunt-results.json").exists())
        self.assert_originals_unchanged()

    def test_kibana_http_failure_cannot_leave_successful_results(self):
        self.services.fail_path = "/api/status"
        output = self.root / "failed-kibana-replay"
        with self.assertRaisesRegex(RuntimeError, "HTTP 503"):
            self.invoke("--replay", "--output-dir", str(output))
        self.assertFalse((output / "hunt-results.json").exists())
        self.assert_originals_unchanged()

    def test_original_write_modes_still_protect_completed_evidence(self):
        for args in ((), ("--resume-existing",)):
            with self.subTest(args=args), self.assertRaises(FileExistsError):
                self.invoke(*args)
        self.http.assert_not_called()
        self.assert_originals_unchanged()

    def test_normal_mode_can_still_ingest_an_unfinished_collection(self):
        (self.root / "evidence/week5/hunt-results.json").unlink()
        summary = self.invoke()
        self.assertEqual(summary["index"], self.base_index)
        record = runner.read_json(self.root / "evidence/week5/hunt-results.json")
        self.assertFalse(record["resumed_existing_index"])
        self.assertIsNone(record["replay_of_run_id"])
        self.assertIn(("POST", "/_bulk"), self.services.requests)

    def test_resume_mode_checks_existing_documents_without_reindexing(self):
        (self.root / "evidence/week5/hunt-results.json").unlink()
        self.services.indices[self.base_index] = copy.deepcopy(self.events)
        summary = self.invoke("--resume-existing")
        self.assertEqual(summary["index"], self.base_index)
        record = runner.read_json(self.root / "evidence/week5/hunt-results.json")
        self.assertTrue(record["resumed_existing_index"])
        self.assertNotIn(("POST", "/_bulk"), self.services.requests)
        self.assertFalse(any(method == "PUT" for method, _ in self.services.requests))

    def test_incompatible_arguments_are_rejected_before_network(self):
        for args in (("--replay", "--query-only"), ("--replay", "--resume-existing"),
                     ("--output-dir", "somewhere"), ("--index", self.base_index)):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.invoke(*args)
        self.http.assert_not_called()

    def test_docker_runtime_allowlist_excludes_private_metadata(self):
        containers = [{"ID": name + "-id", "Name": name + "-container", "Service": name,
                       "Image": name + ":test", "State": "running", "Health": "healthy",
                       "Labels": "PRIVATE-label", "Mounts": "C:/PRIVATE/data", "Command": "PRIVATE-command",
                       "Publishers": [{"URL": "127.0.0.1", "TargetPort": 9200, "PublishedPort": 9200,
                                       "Protocol": "tcp", "private": "PRIVATE-extra"}]}
                      for name in ("elasticsearch", "kibana")]

        def docker(*args):
            if args[0] == "compose" and args[-2:] == ("--format", "json"):
                return "\n".join(json.dumps(item) for item in containers)
            if args[0] == "exec":
                return '{"version":"test-version"}'
            if args[:2] == ("image", "inspect"):
                return '[{"Id":"image-id","RepoDigests":["example@sha256:abc"],"Labels":"PRIVATE"}]'
            return "test-version"

        with patch.object(runner, "docker_value", side_effect=docker):
            result = runner.docker_runtime()
        self.assertEqual(result["status"], "available")
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertEqual(len(result["containers"]), 2)


if __name__ == "__main__":
    unittest.main()
