"""Synthetic edge cases are test fixtures, never OSINT evidence."""

import contextlib
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest

from scripts.process_week3_iocs import (
    ROOT, RAW_FIELDS, build_outputs, main, normalize_indicator, read_records,
)


def fixture(record_id="test-1", indicator="EXAMPLE[.]TEST.", kind="domain",
            role="vendor_reported_c2"):
    return dict(zip(RAW_FIELDS, (
        record_id, indicator, kind, "Synthetic test fixture", "https://example.test/report",
        "tests/test_week3_iocs.py", "2026-09-24", role, "Synthetic; not observed evidence",
    )))


def csv_bytes(rows):
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=RAW_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue().encode()


class NormalizationTests(unittest.TestCase):
    def test_domain_normalization(self):
        self.assertEqual(normalize_indicator(" ExAmPlE[.]TEST. ", "Domain"),
                         ("example.test", "domain", "domain"))

    def test_ipv4_mapping(self):
        self.assertEqual(normalize_indicator(" 192.0.2.1 ", "ip"),
                         ("192.0.2.1", "ipv4", "ip-dst"))

    def test_invalid_indicators(self):
        for value, kind in [
            ("https://example.test/path", "domain"), ("-bad.test", "domain"),
            ("bad_.test", "domain"), ("a..test", "domain"),
            ("example.test..", "domain"), ("localhost", "domain"),
            ("192.0.2.1", "domain"), ("éxample.test", "domain"),
            ("a" * 64 + ".test", "domain"), ("192.0.2.999", "ip"),
            ("192.000.2.1", "ip"), ("2001:db8::1", "ip"), ("abc", "sha256"),
        ]:
            with self.subTest(value=value, kind=kind), self.assertRaises(ValueError):
                normalize_indicator(value, kind)

    def test_bad_metadata_fails_closed(self):
        for field, value in [
            ("record_id", "bad | id"), ("source", ""), ("evidence_ref", " "),
            ("observation_date", "2026-02-30"), ("observation_date", "20260924"),
            ("evidence_role", "unreviewed"),
        ]:
            row = fixture()
            row[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                read_records(csv_bytes([row]))

    def test_schema_and_duplicate_ids(self):
        valid = csv_bytes([fixture()])
        for content in [b"wrong,header\nx,y\n", csv_bytes([]),
                        csv_bytes([fixture(), fixture()]),
                        valid.rstrip(b"\n") + b",extra\n",
                        valid.rsplit(b",", 1)[0] + b"\n"]:
            with self.subTest(content=content), self.assertRaises(ValueError):
                read_records(content)

    def test_ip_cannot_be_promoted(self):
        with self.assertRaises(ValueError):
            read_records(csv_bytes([fixture(indicator="192.0.2.1", kind="ip")]))

    def test_utf8_bom_supported(self):
        self.assertEqual(len(read_records(b"\xef\xbb\xbf" + csv_bytes([fixture()]))), 1)


class PipelineTests(unittest.TestCase):
    def test_dedup_preserves_sources_and_context_wins(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / "raw.csv"
            second = fixture("test-2", "example.test", role="passive_dns_context")
            second["source"] = "Second synthetic source"
            second["notes"] = "Contains a comma, and a newline\nfor CSV quoting"
            raw.write_bytes(csv_bytes([fixture(), second]))
            outputs = build_outputs(raw)
        rows = list(csv.DictReader(io.StringIO(outputs["data/week3-iocs-normalized.csv"].decode())))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source_ids"], "test-1 | test-2")
        self.assertIn(second["source"], rows[0]["source"])
        self.assertIn(second["notes"], rows[0]["notes"])
        self.assertEqual(rows[0]["to_ids"], "false")
        event = json.loads(outputs["misp/week3-event-import.json"])["Event"]
        self.assertIs(event["Attribute"][0]["to_ids"], False)
        self.assertEqual(json.loads(outputs["data/week3-processing-summary.json"])["duplicates_merged"], 1)

    def test_committed_outputs_match_raw_and_have_safe_settings(self):
        outputs = build_outputs(ROOT / "data/week3-iocs-raw.csv")
        for name, content in outputs.items():
            with self.subTest(name=name):
                self.assertEqual((ROOT / name).read_bytes(), content)
        event = json.loads(outputs["misp/week3-event-import.json"])["Event"]
        self.assertIs(event["published"], False)
        self.assertEqual(event["distribution"], "0")
        self.assertEqual(event["analysis"], "0")
        self.assertEqual(event["threat_level_id"], "4")
        self.assertEqual(len(event["Attribute"]), 3)
        self.assertNotIn("uuid", event)
        self.assertNotIn("id", event)
        for attribute in event["Attribute"]:
            self.assertEqual(attribute["distribution"], "0")
            self.assertEqual(attribute["category"], "Network activity")
            self.assertIs(attribute["to_ids"], attribute["type"] == "domain")
            self.assertIn("Raw record IDs:", attribute["comment"])
            self.assertNotIn("first_seen", attribute)
        summary = json.loads(outputs["data/week3-processing-summary.json"])
        self.assertEqual((summary["raw_records"], summary["normalized_indicators"],
                          summary["ids_candidates"], summary["context_only_indicators"]), (3, 3, 1, 2))
        self.assertIs(summary["misp_import_performed"], False)

    def test_cli_check_detects_drift_without_writing(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            args = ["--output-root", directory]
            self.assertEqual(main(args + ["--check"]), 1)
            self.assertEqual(main(args), 0)
            self.assertEqual(main(args + ["--check"]), 0)
            target = Path(directory) / "misp/week3-event-import.json"
            target.write_text("changed", encoding="utf-8")
            self.assertEqual(main(args + ["--check"]), 1)
            self.assertEqual(target.read_text(), "changed")

    def test_invalid_input_does_not_replace_outputs(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            root = Path(directory)
            self.assertEqual(main(["--output-root", directory]), 0)
            before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
            raw = root / "bad.csv"
            raw.write_bytes(csv_bytes([fixture(), fixture("test-2", "bad..test")]))
            self.assertEqual(main(["--raw", str(raw), "--output-root", directory]), 1)
            for path, content in before.items():
                self.assertEqual(path.read_bytes(), content)


if __name__ == "__main__":
    unittest.main()
