"""Regression fixtures are synthetic query inputs, never collected Windows events.

Offline tests check the saved DSL against a small independent wildcard evaluator.
Set WEEK5_TEST_ELASTICSEARCH=http://127.0.0.1:9200 to test the same inputs in
Elasticsearch. The live test uses and removes its own unique synthetic index.
"""

import base64
import copy
import fnmatch
import itertools
import json
import os
from pathlib import Path
import unittest
import uuid

from scripts.run_week5_hunt import API, local_url, sha256, utc_now


ROOT = Path(__file__).resolve().parents[1]
QUERIES_PATH = ROOT / "data/week5-hunt-queries.json"
QUERY_IDS = {"inventory", "encoded_candidates", "encoded_hidden_bypass"}


def fixtures():
    """Explicit expected membership includes permutations, case, and near misses."""
    payload = base64.b64encode("Write-Output 'QUERY-REGRESSION'".encode("utf-16le")).decode()
    flags = ["-EncodedCommand " + payload, "-WindowStyle Hidden", "-ExecutionPolicy Bypass"]
    records = []

    def add(name, command, expected, channel="Windows PowerShell", code="400"):
        records.append((name, {
            "@timestamp": "2026-10-08T00:00:00.000Z",
            "event": {"code": code}, "winlog": {"channel": channel},
            "process": {"command_line": "powershell.exe " + command},
            "test": {"case_id": name, "synthetic": True},
        }, set(expected)))

    for number, permutation in enumerate(itertools.permutations(flags)):
        add("permutation_" + str(number), " ".join(permutation), QUERY_IDS)
        # Only change flag/value case: Base64 payload remains unmodified.
        lowercase = [flag.replace("-EncodedCommand", "-encodedcommand")
                     .replace("-WindowStyle Hidden", "-windowstyle hidden")
                     .replace("-ExecutionPolicy Bypass", "-executionpolicy bypass")
                     for flag in permutation]
        add("lowercase_" + str(number), " ".join(lowercase), QUERY_IDS)
    broad = {"inventory", "encoded_candidates"}
    add("missing_hidden", flags[0] + " " + flags[2], broad)
    add("missing_bypass", flags[0] + " " + flags[1], broad)
    add("missing_encoded", flags[1] + " " + flags[2], {"inventory"})
    add("hidden_suffix", flags[0] + " " + flags[2] + " -WindowStyle HiddenExtra", broad)
    add("bypass_suffix", flags[0] + " " + flags[1] + " -ExecutionPolicy BypassExtra", broad)
    add("encoded_suffix", "-EncodedCommandExtra " + payload + " " + " ".join(flags[1:]), {"inventory"})
    add("hidden_prefix", flags[0] + " " + flags[2] + " X-WindowStyle Hidden", broad)
    add("wrong_channel", " ".join(flags), set(), channel="Other channel")
    add("wrong_event", " ".join(flags), set(), code="403")
    return records


def field_value(document, field):
    value = document
    for part in field.split("."):
        value = value[part]
    return value


def matches(query, document):
    if "bool" in query:
        boolean = query["bool"]
        if not all(matches(clause, document) for clause in boolean.get("filter", [])):
            return False
        should = boolean.get("should", [])
        minimum = boolean.get("minimum_should_match", 1 if should and not boolean.get("filter") else 0)
        return sum(matches(clause, document) for clause in should) >= minimum
    if "term" in query:
        return all(field_value(document, field) == value for field, value in query["term"].items())
    if "wildcard" in query:
        field, settings = next(iter(query["wildcard"].items()))
        value, pattern = field_value(document, field), settings["value"]
        if settings.get("case_insensitive"):
            value, pattern = value.lower(), pattern.lower()
        return fnmatch.fnmatchcase(value, pattern)
    raise AssertionError("Unsupported DSL in independent test evaluator: " + repr(query))


class QueryRegressionTests(unittest.TestCase):
    def setUp(self):
        self.queries = json.loads(QUERIES_PATH.read_text(encoding="utf-8"))["queries"]

    def test_canonical_permutations_case_and_near_misses(self):
        for name, document, expected in fixtures():
            with self.subTest(case=name):
                actual = {item["id"] for item in self.queries if matches(item["body"]["query"], document)}
                self.assertEqual(actual, expected)

    def test_archived_four_cases_keep_their_expected_membership(self):
        expected = {
            "inventory": {"baseline_plain", "encoded_only", "hidden_bypass", "encoded_hidden_bypass"},
            "encoded_candidates": {"encoded_only", "encoded_hidden_bypass"},
            "encoded_hidden_bypass": {"encoded_hidden_bypass"},
        }
        documents = [json.loads(line) for line in
                     (ROOT / "data/week5-powershell-events.jsonl").read_text(encoding="utf-8-sig").splitlines()]
        for item in self.queries:
            with self.subTest(query=item["id"]):
                actual = {doc["lab"]["case_id"] for doc in documents if matches(item["body"]["query"], doc)}
                self.assertEqual(actual, expected[item["id"]])

    def test_original_snapshot_retains_the_historical_hash(self):
        historical = json.loads((ROOT / "evidence/week5/hunt-results.json").read_text(encoding="utf-8-sig"))
        self.assertEqual(sha256(ROOT / "evidence/week5/original-hunt-queries.json"), historical["queries_sha256"])
        self.assertNotEqual(sha256(QUERIES_PATH), historical["queries_sha256"])

    def test_fixtures_expose_the_original_end_of_line_bug(self):
        original = json.loads((ROOT / "evidence/week5/original-hunt-queries.json").read_text(encoding="utf-8"))
        refined = next(item["body"]["query"] for item in original["queries"]
                       if item["id"] == "encoded_hidden_bypass")
        missed = [name for name, document, expected in fixtures()
                  if "encoded_hidden_bypass" in expected and not matches(refined, document)]
        self.assertEqual(len(missed), 8)

    @unittest.skipUnless(os.environ.get("WEEK5_TEST_ELASTICSEARCH"), "Live Elasticsearch test is opt-in")
    def test_live_elasticsearch_boundaries(self):
        transcript = []
        api = API(local_url(os.environ["WEEK5_TEST_ELASTICSEARCH"]), transcript, "Elasticsearch")
        index = "week5-synthetic-query-regression-" + uuid.uuid4().hex
        created = False
        output_value = os.environ.get("WEEK5_TEST_REPORT")
        output = Path(output_value) if output_value else None
        if output and output.exists():
            self.fail("Choose a new report path; existing evidence will not be overwritten.")
        report = {"kind": "synthetic-query-regression", "recorded_utc": utc_now(),
                  "queries_sha256": sha256(QUERIES_PATH), "index": index,
                  "note": "Inputs are synthetic strings, not observed launches. No PowerShell payload was executed.",
                  "fixtures": [{"id": name, "document": doc, "expected_queries": sorted(expected)}
                               for name, doc, expected in fixtures()], "queries": []}
        try:
            api.call("PUT", "/" + index, {"settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {"properties": {
                    "@timestamp": {"type": "date"},
                    "event": {"properties": {"code": {"type": "keyword"}}},
                    "winlog": {"properties": {"channel": {"type": "keyword"}}},
                    "process": {"properties": {"command_line": {"type": "wildcard"}}},
                    "test": {"properties": {"case_id": {"type": "keyword"}, "synthetic": {"type": "boolean"}}},
                }}})
            created = True
            lines = []
            for name, document, _ in fixtures():
                lines.extend([json.dumps({"create": {"_index": index, "_id": name}}), json.dumps(document)])
            _, bulk = api.call("POST", "/_bulk?refresh=wait_for", "\n".join(lines) + "\n", ndjson=True)
            self.assertFalse(bulk["errors"])
            self.assertEqual(len(bulk["items"]), len(fixtures()))
            for item in self.queries:
                _, response = api.call("POST", "/" + index + "/_search", copy.deepcopy(item["body"]))
                self.assertFalse(response["timed_out"])
                self.assertEqual(response["_shards"]["failed"], 0)
                expected = {name for name, _, membership in fixtures() if item["id"] in membership}
                self.assertEqual({hit["_id"] for hit in response["hits"]["hits"]}, expected)
                self.assertEqual(response["hits"]["total"], {"value": len(expected), "relation": "eq"})
                report["queries"].append({"id": item["id"], "response": response})
            # Validate the revised, case-sensitive Lucene example shown in the report.
            lucene = ('event.code:400 AND winlog.channel:"Windows PowerShell" '
                      'AND process.command_line:/.* -EncodedCommand .*/ '
                      'AND process.command_line:/.* -WindowStyle Hidden( .*)?/ '
                      'AND process.command_line:/.* -ExecutionPolicy Bypass( .*)?/')
            _, response = api.call("POST", "/" + index + "/_search", {
                "size": 100, "track_total_hits": True, "query": {"query_string": {"query": lucene}}})
            self.assertFalse(response["timed_out"])
            self.assertEqual(response["_shards"]["failed"], 0)
            self.assertEqual({hit["_id"] for hit in response["hits"]["hits"]},
                             {"permutation_" + str(number) for number in range(6)})
            self.assertEqual(response["hits"]["total"], {"value": 6, "relation": "eq"})
            report["lucene_ui_query"] = {"query": lucene, "response": response}
        finally:
            if created:
                api.call("DELETE", "/" + index)
        report["passed"] = True
        report["api_transcript"] = transcript
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("x", encoding="utf-8") as stream:
                json.dump(report, stream, ensure_ascii=False, indent=2)
                stream.write("\n")


if __name__ == "__main__":
    unittest.main()
