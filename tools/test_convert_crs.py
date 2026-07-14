#!/usr/bin/env python3
"""Unit tests for the CRS converter's transform-plan encoding."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import convert_crs


class TransformPlanTests(unittest.TestCase):
    def test_exact_plan_preserves_order_and_repetition(self) -> None:
        self.assertEqual(
            convert_crs.encode_transform_plan(
                ["lowercase", "urlDecodeUni", "lowercase"]
            ),
            10858,
        )
        self.assertEqual(
            convert_crs.encode_transform_plan(
                ["urlDecodeUni", "lowercase", "lowercase"]
            ),
            10579,
        )

    def test_all_dataset_transform_names_have_stable_opcodes(self) -> None:
        expected = {
            "base64Decode": 1,
            "cmdLine": 2,
            "compressWhitespace": 3,
            "cssDecode": 4,
            "escapeSeqDecode": 5,
            "hexEncode": 6,
            "htmlEntityDecode": 7,
            "jsDecode": 8,
            "length": 9,
            "lowercase": 10,
            "none": 11,
            "normalizePath": 12,
            "normalizePathWin": 13,
            "removeCommentsChar": 14,
            "removeNulls": 15,
            "removeWhitespace": 16,
            "replaceComments": 17,
            "sha1": 18,
            "urlDecodeUni": 19,
            "utf8toUnicode": 20,
        }
        self.assertEqual(convert_crs.TRANSFORM_OPCODES, expected)
        for name, opcode in expected.items():
            with self.subTest(name=name):
                self.assertEqual(convert_crs.encode_transform_plan([name]), opcode)

    def test_eight_opcodes_fit_i64(self) -> None:
        plan = convert_crs.encode_transform_plan(["utf8toUnicode"] * 8)
        self.assertEqual(plan, 709362340500)
        self.assertLess(plan, 1 << 63)

    def test_rejects_more_than_eight_transforms(self) -> None:
        with self.assertRaisesRegex(ValueError, "at most 8"):
            convert_crs.encode_transform_plan(["none"] * 9)

    def test_rejects_unknown_transform(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown transformation: mystery"):
            convert_crs.encode_transform_plan(["mystery"])

    def test_rendered_rule_has_five_strings_and_decimal_plan(self) -> None:
        directive = convert_crs.Directive(
            kind="SecRule",
            source="REQUEST-TEST.conf",
            source_line=1,
            rule_id=123,
            phase=2,
            chain_index=0,
            targets="TARGET",
            operator="@rx",
            pattern="PATTERN",
            actions=(
                "id:123,phase:2,t:lowercase,t:urlDecodeUni,t:lowercase,"
                "msg:'ordered'"
            ),
            message="ordered",
        )
        self.assertEqual(
            convert_crs.render_directive_call(directive, {}),
            'next = engine_bundle::apply_rule(next, 123, 2, 0, false, '
            '["TARGET", "@rx", "PATTERN", "", "ordered"], '
            '10858, 0, 0, false, 403);',
        )

    def test_enabled_sqli_probe_uses_plan_abi(self) -> None:
        directive = convert_crs.Directive(
            kind="SecMarker",
            source="REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
            source_line=1,
            rule_id=-1,
            phase=0,
            chain_index=0,
            marker="END",
        )
        rendered = convert_crs.render_entry(
            [directive],
            "4.28.0",
            {},
            {"request_942_application_attack_sqli"},
        )
        self.assertIn(
            'apply_rule(next, 942100, 2, 0, false, '
            '["QUERY_STRING|ARGS|REQUEST_BODY", "@detectSQLi", "", "", '
            '"SQL Injection Attack Detected"], 15979, 1, 5, false, 403);',
            rendered,
        )
        self.assertNotIn("none,urlDecodeUni,removeNulls", rendered)


if __name__ == "__main__":
    unittest.main()
