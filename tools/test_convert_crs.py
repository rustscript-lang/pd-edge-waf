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

    def test_operator_opcodes_are_stable_and_encode_negation(self) -> None:
        expected = {
            "@rx": 1,
            "@pm": 2,
            "@pmFromFile": 2,
            "@detectSQLi": 3,
            "@detectXSS": 4,
            "@contains": 5,
            "@beginsWith": 6,
            "@endsWith": 7,
            "@streq": 8,
            "@within": 9,
            "@eq": 10,
            "@lt": 11,
            "@ge": 12,
            "@gt": 13,
            "@validateUrlEncoding": 14,
            "@validateUtf8Encoding": 15,
            "@validateByteRange": 16,
            "@unconditionalMatch": 17,
            "@ipMatch": 18,
        }
        self.assertEqual(convert_crs.OPERATOR_OPCODES, expected)
        self.assertEqual(convert_crs.encode_operator("@rx"), 1)
        self.assertEqual(convert_crs.encode_operator("!@rx"), 33)
        self.assertEqual(convert_crs.encode_operator("!@within"), 41)
        with self.assertRaisesRegex(ValueError, "unknown operator: @mystery"):
            convert_crs.encode_operator("@mystery")

    def test_target_spec_marks_static_exclusions(self) -> None:
        positive = ["ARGS", "", "REQUEST_HEADERS", "Host"]
        excluded = [*positive, "!REQUEST_HEADERS", "Cookie"]
        self.assertEqual(convert_crs.encode_target_spec(1, positive), 66)
        self.assertEqual(
            convert_crs.encode_target_spec(1, excluded),
            convert_crs.TARGET_STATIC_EXCLUSIONS_BIT
            + 2 * convert_crs.TARGET_POSITIVE_COUNT_MULTIPLIER
            + 67,
        )
        counted = ["ARGS", "", "&TX", "COUNT"]
        self.assertEqual(
            convert_crs.encode_target_spec(1, counted),
            convert_crs.TARGET_COUNTED_DESCRIPTORS_BIT
            + convert_crs.TARGET_REGULAR_COUNT_MULTIPLIER
            + 66,
        )
        self.assertEqual(
            convert_crs.pack_target_descriptors(
                ["!REQUEST_HEADERS", "Cookie", "ARGS", "", "&TX", "COUNT"]
            ),
            ["ARGS", "", "TX", "COUNT", "REQUEST_HEADERS", "Cookie"],
        )

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

    def test_target_descriptors_preserve_precompiled_exclusions(self) -> None:
        self.assertEqual(
            convert_crs.target_descriptors(
                "ARGS|REQUEST_HEADERS:Host|!REQUEST_HEADERS:Cookie|&TX:COUNT"
            ),
            [
                "ARGS", "",
                "REQUEST_HEADERS", "Host",
                "!REQUEST_HEADERS", "Cookie",
                "&TX", "COUNT",
            ],
        )

    def test_target_descriptors_preserve_escaped_pipes_and_selector_colons(self) -> None:
        self.assertEqual(
            convert_crs.target_descriptors(
                r"ARGS:/foo\|bar:baz/|REQUEST_HEADERS:Host"
            ),
            [
                "ARGS", r"/foo\|bar:baz/",
                "REQUEST_HEADERS", "Host",
            ],
        )

    def test_rendered_update_target_uses_precompiled_descriptors(self) -> None:
        directive = convert_crs.Directive(
            kind="SecRuleUpdateTargetById",
            source="REQUEST-999.conf",
            source_line=10,
            rule_id=123,
            phase=0,
            chain_index=0,
            value="!REQUEST_HEADERS:Cookie|!ARGS:/^secret:/",
        )
        self.assertEqual(
            convert_crs.render_directive_call(directive, {}),
            'next = engine_bundle::update_target(next, 123, "!REQUEST_HEADERS", "Cookie"); '
            'next = engine_bundle::update_target(next, 123, "!ARGS", "/^secret:/");',
        )

    def test_entry_includes_relevant_target_update_dependencies(self) -> None:
        enabled_rule = convert_crs.Directive(
            kind="SecRule", source="REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
            source_line=1, rule_id=942290, phase=2, chain_index=0,
            targets="REQUEST_COOKIES", operator="@rx", pattern="attack",
        )
        relevant_update = convert_crs.Directive(
            kind="SecRuleUpdateTargetById", source="REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf",
            source_line=2, rule_id=942290, phase=0, chain_index=0,
            value="!REQUEST_COOKIES:_ga",
        )
        irrelevant_update = convert_crs.Directive(
            kind="SecRuleUpdateTargetById", source="REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf",
            source_line=3, rule_id=941100, phase=0, chain_index=0,
            value="!REQUEST_COOKIES:_ga",
        )
        rendered = convert_crs.render_entry(
            [enabled_rule, relevant_update, irrelevant_update],
            "4.28.0", {}, {"request_942_application_attack_sqli"},
        )
        self.assertNotIn("fn evaluate_request_999_common_exceptions_after", rendered)
        self.assertIn(
            '"REQUEST_COOKIES", "", "REQUEST_COOKIES", "_ga"], 81986,',
            rendered,
        )
        self.assertNotIn("update_target(next,", rendered)
        self.assertNotIn("941100", rendered)

    def test_rendered_rule_has_precompiled_targets_and_decimal_plan(self) -> None:
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
            'next = engine_bundle::apply_rule(next, 123, 0, false, '
            '["PATTERN", "", "ordered", "TARGET", ""], '
            '65, 10858, 0, false, 403);',
        )

    def test_state_macro_patterns_use_typed_operator_flags(self) -> None:
        exact = convert_crs.Directive(
            kind="SecRule",
            source="REQUEST-TEST.conf",
            source_line=1,
            rule_id=911100,
            phase=1,
            chain_index=0,
            targets="REQUEST_METHOD",
            operator="!@within",
            pattern="%{TX.allowed_methods}",
        )
        prefixed = convert_crs.Directive(
            kind="SecRule",
            source="REQUEST-TEST.conf",
            source_line=2,
            rule_id=920350,
            phase=1,
            chain_index=0,
            targets="REQUEST_HEADERS:Host",
            operator="@rx",
            pattern=".%{request_headers.host}",
        )
        self.assertIn(
            '["tx.allowed_methods", "", "", "REQUEST_METHOD", ""], 6721,',
            convert_crs.render_directive_call(exact, {}),
        )
        self.assertIn(
            '["request_headers.host", "", "", "REQUEST_HEADERS", "Host"], 8257,',
            convert_crs.render_directive_call(prefixed, {}),
        )

    def test_plan_619_uses_generic_rule_evaluator(self) -> None:
        directive = convert_crs.Directive(
            kind="SecRule",
            source="REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
            source_line=140,
            rule_id=942140,
            phase=2,
            chain_index=0,
            targets="ARGS",
            operator="@rx",
            pattern="PATTERN",
            actions="id:942140,phase:2,t:none,t:urlDecodeUni,severity:'CRITICAL'",
        )
        rendered = convert_crs.render_directive_call(directive, {})
        self.assertTrue(rendered.startswith("next = engine_bundle::apply_rule("))
        self.assertNotIn("apply_rule_619", rendered)
        self.assertIn(", 65, 619, 5, false, 403);", rendered)

    def test_entry_guards_rule_calls_by_phase(self) -> None:
        phase_one = convert_crs.Directive(
            kind="SecRule", source="REQUEST-TEST.conf", source_line=1,
            rule_id=101, phase=1, chain_index=0, targets="ARGS",
            operator="@rx", pattern="one",
        )
        phase_two = convert_crs.Directive(
            kind="SecRule", source="REQUEST-TEST.conf", source_line=2,
            rule_id=202, phase=2, chain_index=0, targets="ARGS",
            operator="@rx", pattern="two",
        )
        rendered = convert_crs.render_entry(
            [phase_one, phase_two], "4.28.0", {}, {"request_test"}
        )
        phase_one_body = rendered.split("fn evaluate_request_test_phase_1", 1)[1].split("fn ", 1)[0]
        phase_two_body = rendered.split("fn evaluate_request_test_phase_2", 1)[1].split("pub fn ", 1)[0]
        self.assertIn("apply_rule(next, 101, 0, false", phase_one_body)
        self.assertNotIn("apply_rule(next, 202, 0, false", phase_one_body)
        self.assertIn("apply_rule(next, 202, 0, false", phase_two_body)
        self.assertNotIn("apply_rule(next, 101, 0, false", phase_two_body)
        self.assertNotIn("category_enabled", phase_one_body)
        self.assertNotIn("category_enabled", phase_two_body)
        self.assertEqual(
            rendered.count('category_enabled(&next, "request_test")'),
            3,
        )
        self.assertIn(
            "engine_bundle::ctx_set_phase(next, 2) } else => {",
            rendered,
        )

    def test_entry_guards_rule_argument_materialization_after_block(self) -> None:
        directives = [
            convert_crs.Directive(
                kind="SecRule", source="REQUEST-TEST.conf", source_line=index,
                rule_id=100 + index, phase=1, chain_index=0, targets="ARGS",
                operator="@rx", pattern=f"pattern-{index}",
            )
            for index in (1, 2)
        ]
        rendered = convert_crs.render_entry(
            directives, "4.28.0", {}, {"request_test"}
        )
        evaluator = rendered.split("fn evaluate_request_test_phase_1", 1)[1].split("pub fn ", 1)[0]
        self.assertNotIn("\n    next = engine_bundle::apply_rule", evaluator)
        self.assertEqual(
            evaluator.count(
                'if engine_bundle::ctx_get(&next, "blocked") != "1" '
                '&& engine_bundle::ctx_get(&next, "skip") == "" {'
            ),
            2,
        )
        self.assertIn("apply_rule(next, 101, 0, false", evaluator)
        self.assertIn("apply_rule(next, 102, 0, false", evaluator)

    def test_expensive_categories_are_guarded_by_safe_prefilters(self) -> None:
        method_control = convert_crs.Directive(
            kind="SecRule", source="REQUEST-911-METHOD-ENFORCEMENT.conf", source_line=1,
            rule_id=911011, phase=1, chain_index=0,
            targets="TX:DETECTION_PARANOIA_LEVEL", operator="@lt", pattern="1",
            actions="id:911011,phase:1,skipAfter:END-REQUEST-911-METHOD-ENFORCEMENT",
        )
        method_rule = convert_crs.Directive(
            kind="SecRule", source="REQUEST-911-METHOD-ENFORCEMENT.conf", source_line=2,
            rule_id=911100, phase=1, chain_index=0, targets="REQUEST_METHOD",
            operator="@within", pattern="GET HEAD POST OPTIONS",
        )
        method_rendered = convert_crs.render_entry(
            [method_control, method_rule],
            "4.28.0",
            {},
            {"request_911_method_enforcement"},
        )
        self.assertEqual(method_rendered.count('ctx_get(&next, "tx.allowed_methods")'), 4)
        self.assertEqual(method_rendered.count('ctx_get(&next, "method")'), 2)
        self.assertIn(
            "next = engine_bundle::record_rule_match(next,",
            method_rendered,
        )
        self.assertNotIn("apply_rule(next, 911100", method_rendered)
        self.assertNotIn("apply_rule(next, 911011", method_rendered)
        self.assertIn(
            'engine_bundle::number(engine_bundle::ctx_get(&next, '
            '"tx.detection_paranoia_level"), 1) < 1',
            method_rendered,
        )
        self.assertIn(
            "engine_bundle::ctx_set_phase(next, 2) } else => {",
            method_rendered,
        )

        sqli_phase_one_rule = convert_crs.Directive(
            kind="SecRule", source="REQUEST-942-APPLICATION-ATTACK-SQLI.conf", source_line=1,
            rule_id=942101, phase=1, chain_index=0, targets="REQUEST_FILENAME",
            operator="@rx", pattern="select",
        )
        sqli_rule = convert_crs.Directive(
            kind="SecRule", source="REQUEST-942-APPLICATION-ATTACK-SQLI.conf", source_line=2,
            rule_id=942100, phase=2, chain_index=0, targets="ARGS",
            operator="@rx", pattern="select",
        )
        sqli_rendered = convert_crs.render_entry(
            [sqli_phase_one_rule, sqli_rule],
            "4.28.0",
            {},
            {"request_942_application_attack_sqli"},
        )
        self.assertEqual(
            sqli_rendered.count("sqli_category_prefilter(&next, false)"), 2
        )
        self.assertEqual(
            sqli_rendered.count("sqli_category_prefilter(&next, true)"), 1
        )
        self.assertEqual(
            sqli_rendered.count("sqli_query_rule_match(&next)"), 1
        )

        combined_rendered = convert_crs.render_entry(
            [method_control, method_rule, sqli_phase_one_rule, sqli_rule],
            "4.28.0",
            {},
            {
                "request_911_method_enforcement",
                "request_942_application_attack_sqli",
            },
        )
        self.assertIn(
            '} else if engine_bundle::category_enabled(&next, '
            '"request_942_application_attack_sqli") '
            '&& engine_bundle::sqli_category_prefilter(&next, false) => {',
            combined_rendered,
        )

        self.assertIn(
            "engine_bundle::ctx_set_phase(next, 2) } else => {",
            sqli_rendered,
        )

    def test_contiguous_plan_619_regex_rules_share_sound_prefilter(self) -> None:
        directives = [
            convert_crs.Directive(
                kind="SecRule",
                source="REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
                source_line=index,
                rule_id=942000 + index,
                phase=2,
                chain_index=0,
                targets="ARGS|ARGS_NAMES",
                operator="@rx",
                pattern=pattern,
                actions="phase:2,t:none,t:urlDecodeUni",
            )
            for index, pattern in enumerate(("first", "second"), 1)
        ]
        rendered = convert_crs.render_entry(
            directives,
            "4.28.0",
            {},
            {"request_942_application_attack_sqli"},
        )
        self.assertEqual(rendered.count("apply_rule(next, -1"), 1)
        self.assertIn("(?:first)|(?:second)", rendered)
        self.assertNotIn("apply_rule_619", rendered)

        first = rendered.index("apply_rule(next, 942001")
        second = rendered.index("apply_rule(next, 942002")
        self.assertLess(first, second)

    def test_enabled_sqli_probe_uses_exact_specialized_matcher(self) -> None:
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
            "sqli_query_rule_match(&next)",
            rendered,
        )
        self.assertIn(
            'record_rule_match(next, ["942100", "5", "0", "403", "", '
            '"SQL Injection Attack Detected"]);',
            rendered,
        )
        self.assertNotIn(
            "apply_rule(next, 942100, 0, false",
            rendered,
        )
        self.assertNotIn("none,urlDecodeUni,removeNulls", rendered)


if __name__ == "__main__":
    unittest.main()
