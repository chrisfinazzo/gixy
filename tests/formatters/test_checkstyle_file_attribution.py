"""Checkstyle consumers must receive each diagnostic under its source file."""

import unittest
import xml.etree.ElementTree as ET

from gixy.formatters.checkstyle import CheckstyleFormatter


class TestCheckstyleFileAttribution(unittest.TestCase):
    def test_main_file_after_included_file(self):
        main = "synthetic/nginx.conf"
        included = "synthetic/headers.conf"
        reports = {
            main: [
                {"plugin": "first", "summary": "Included diagnostic",
                 "location": {"file": included, "line": 2}},
                {"plugin": "second", "summary": "Main diagnostic",
                 "location": {"file": main, "line": 8}},
            ]
        }
        root = ET.fromstring(CheckstyleFormatter().format_reports(reports, {}))
        actual = {
            node.get("name"): [error.get("line") for error in node.findall("error")]
            for node in root.findall("file")
        }
        self.assertEqual(actual, {main: ["8"], included: ["2"]})

    def test_missing_location_returns_to_report_file(self):
        main = "synthetic/nginx.conf"
        included = "synthetic/headers.conf"
        reports = {
            main: [
                {"plugin": "first", "summary": "Included diagnostic",
                 "location": {"file": included, "line": 2}},
                {"plugin": "second", "summary": "Main diagnostic"},
            ]
        }
        root = ET.fromstring(CheckstyleFormatter().format_reports(reports, {}))
        actual = {
            node.get("name"): [error.get("line") for error in node.findall("error")]
            for node in root.findall("file")
        }
        self.assertEqual(actual, {main: ["1"], included: ["2"]})

    def test_shared_included_file_is_grouped_once(self):
        main = "synthetic/nginx.conf"
        included = "synthetic/headers.conf"
        reports = {
            main: [
                {"location": {"file": included, "line": 2}},
                {"location": {"file": main, "line": 8}},
                {"location": {"file": included, "line": 5}},
            ]
        }
        root = ET.fromstring(CheckstyleFormatter().format_reports(reports, {}))
        actual = [(node.get("name"), [e.get("line") for e in node.findall("error")])
                  for node in root.findall("file")]
        self.assertEqual(actual, [(main, ["8"]), (included, ["2", "5"])])


if __name__ == "__main__":
    unittest.main()
