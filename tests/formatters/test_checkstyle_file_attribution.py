"""Checkstyle consumers must receive each diagnostic under its source file."""

import unittest
import xml.etree.ElementTree as ET

import pytest

from gixy.formatters.checkstyle import CheckstyleFormatter


class TestCheckstyleFileAttribution(unittest.TestCase):
    def test_main_file_after_included_file(self):
        main = "synthetic/nginx.conf"
        included = "synthetic/headers.conf"
        reports = {
            main: [
                {
                    "plugin": "first",
                    "summary": "Included diagnostic",
                    "location": {"file": included, "line": 2},
                },
                {
                    "plugin": "second",
                    "summary": "Main diagnostic",
                    "location": {"file": main, "line": 8},
                },
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
                {
                    "plugin": "first",
                    "summary": "Included diagnostic",
                    "location": {"file": included, "line": 2},
                },
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
        actual = [
            (node.get("name"), [e.get("line") for e in node.findall("error")])
            for node in root.findall("file")
        ]
        self.assertEqual(actual, [(main, ["8"]), (included, ["2", "5"])])


if __name__ == "__main__":
    unittest.main()


@pytest.mark.parametrize("later_issues", [[], [{"location": {"line": 9}}]])
def test_later_report_roots_reuse_included_file_elements(later_issues):
    reports = {
        "main.conf": [{"location": {"file": "later.conf", "line": 2}}],
        "later.conf": later_issues,
        "empty.conf": [],
    }
    root = ET.fromstring(CheckstyleFormatter().format_reports(reports, {}))
    actual = [
        (node.get("name"), [e.get("line") for e in node.findall("error")])
        for node in root.findall("file")
    ]
    assert actual == [
        ("main.conf", []),
        ("later.conf", ["2", "9"] if later_issues else ["2"]),
        ("empty.conf", []),
    ]


def test_shared_include_across_roots_preserves_every_diagnostic_and_order():
    issue = {
        "plugin": "sample",
        "summary": "summary",
        "reason": "reason",
        "severity": "HIGH",
        "location": {"file": "shared.conf", "line": 4},
    }
    reports = {"one.conf": [issue], "two.conf": [issue]}
    root = ET.fromstring(CheckstyleFormatter().format_reports(reports, {}))
    assert [node.get("name") for node in root] == [
        "one.conf",
        "shared.conf",
        "two.conf",
    ]
    errors = root.find("file[@name='shared.conf']").findall("error")
    assert len(errors) == 2
    assert [error.attrib for error in errors] == [
        {
            "line": "4",
            "column": "1",
            "severity": "error",
            "message": "[sample] summary: reason",
            "source": "gixy.sample",
        }
    ] * 2


def test_all_empty_location_variants_fall_back_to_report_root():
    reports = {
        "main.conf": [
            {"location": {"file": "include.conf", "line": 7}},
            {"location": None},
            {"location": {}},
            {},
            {"location": {"file": None, "line": 8}},
            {"location": {"file": "", "line": 9}},
        ]
    }
    root = ET.fromstring(CheckstyleFormatter().format_reports(reports, {}))
    assert [node.get("name") for node in root] == ["main.conf", "include.conf"]
    assert [e.get("line") for e in root[0]] == ["1", "1", "1", "8", "9"]
    assert [e.get("line") for e in root[1]] == ["7"]
