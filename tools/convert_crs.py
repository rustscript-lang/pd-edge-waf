#!/usr/bin/env python3
"""Convert OWASP CRS ModSecurity directives into split RustScript modules."""

from __future__ import annotations

import argparse
import json
import re
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path

DIRECTIVES = (
    "SecRule",
    "SecAction",
    "SecMarker",
    "SecRuleUpdateTargetById",
    "SecComponentSignature",
)

TRANSFORM_OPCODES = {
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


def encode_transform_plan(transforms: list[str]) -> int:
    if len(transforms) > 8:
        raise ValueError("transform plan supports at most 8 transformations")
    plan = 0
    for index, name in enumerate(transforms):
        try:
            opcode = TRANSFORM_OPCODES[name]
        except KeyError as error:
            raise ValueError(f"unknown transformation: {name}") from error
        plan |= opcode << (index * 5)
    return plan


@dataclass
class Directive:
    kind: str
    source: str
    source_line: int
    rule_id: int
    phase: int
    chain_index: int
    targets: str = ""
    operator: str = ""
    pattern: str = ""
    actions: str = ""
    message: str = ""
    marker: str = ""
    value: str = ""


def logical_directives(text: str) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    pending = ""
    start_line = 0
    for line_no, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not pending:
            if not stripped.startswith(DIRECTIVES):
                continue
            pending = stripped
            start_line = line_no
        else:
            pending += " " + stripped
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        result.append((start_line, pending))
        pending = ""
    if pending:
        raise ValueError(f"unterminated directive beginning at line {start_line}")
    return result


def split_tokens(line: str) -> list[str]:
    tokens: list[str] = []
    current: list[str] = []
    quote: str | None = None
    backslashes = 0
    for char in line:
        if quote is not None:
            if char == quote and backslashes % 2 == 0:
                quote = None
            else:
                current.append(char)
            if char == "\\":
                backslashes += 1
            else:
                backslashes = 0
            continue
        if char in ('"', "'"):
            quote = char
            backslashes = 0
        elif char.isspace():
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(char)
    if quote is not None:
        raise ValueError(f"unterminated quote in directive: {line[:120]}")
    if current:
        tokens.append("".join(current))
    return tokens


def action_value(actions: str, key: str) -> str:
    match = re.search(rf"(?:^|,)\s*{re.escape(key)}:(?:'((?:\\.|[^'])*)'|\"((?:\\.|[^\"])*)\"|([^,]+))", actions)
    if not match:
        return ""
    return next((group for group in match.groups() if group is not None), "").strip()


def action_values(actions: str, key: str) -> list[str]:
    pattern = re.compile(
        rf"(?:^|,)\s*{re.escape(key)}:(?:'((?:\\.|[^'])*)'|\"((?:\\.|[^\"])*)\"|([^,]+))"
    )
    values = []
    for match in pattern.finditer(actions):
        values.append(next((group for group in match.groups() if group is not None), "").strip())
    return values


def has_action(actions: str, name: str) -> bool:
    return re.search(rf"(?:^|,)\s*{re.escape(name)}(?:,|$)", actions) is not None


def paranoia_level(actions: str) -> int:
    match = re.search(r"tag:'paranoia-level/(\d+)'", actions)
    return int(match.group(1)) if match else 0


def anomaly_score(actions: str) -> int:
    severity = action_value(actions, "severity").upper()
    return {"CRITICAL": 5, "ERROR": 4, "WARNING": 3, "NOTICE": 2}.get(severity, 0)


def action_int(actions: str, key: str, default: int) -> int:
    raw = action_value(actions, key)
    match = re.search(r"-?\d+", raw)
    return int(match.group()) if match else default


def split_operator(value: str) -> tuple[str, str]:
    if not value:
        return "", ""
    negated = value.startswith("!")
    body = value[1:] if negated else value
    if body.startswith("@"):
        operator, _, pattern = body.partition(" ")
    else:
        operator, pattern = "@rx", body
    if negated:
        operator = "!" + operator
    return operator, pattern


def parse_conf(path: Path) -> list[Directive]:
    parsed: list[Directive] = []
    chain_parent_id = -1
    chain_index = 0
    expecting_chain = False
    for line_no, logical in logical_directives(path.read_text(encoding="utf-8")):
        tokens = split_tokens(logical)
        kind = tokens[0]
        if kind == "SecRule":
            if len(tokens) < 3:
                raise ValueError(f"{path}:{line_no}: SecRule needs targets and operator")
            actions = tokens[3] if len(tokens) >= 4 else ""
            own_id = action_int(actions, "id", -1)
            if expecting_chain:
                chain_index += 1
                rule_id = own_id if own_id >= 0 else chain_parent_id
            else:
                chain_index = 0
                rule_id = own_id
                chain_parent_id = own_id
            operator, pattern = split_operator(tokens[2])
            parsed.append(
                Directive(
                    kind=kind,
                    source=path.name,
                    source_line=line_no,
                    rule_id=rule_id,
                    phase=action_int(actions, "phase", 0),
                    chain_index=chain_index,
                    targets=tokens[1],
                    operator=operator,
                    pattern=pattern,
                    actions=actions,
                    message=action_value(actions, "msg"),
                )
            )
            expecting_chain = bool(re.search(r"(?:^|,)\s*chain(?:,|$)", actions))
            if not expecting_chain:
                chain_parent_id = -1
                chain_index = 0
        elif kind == "SecAction":
            actions = tokens[1] if len(tokens) >= 2 else ""
            parsed.append(
                Directive(
                    kind=kind,
                    source=path.name,
                    source_line=line_no,
                    rule_id=action_int(actions, "id", -1),
                    phase=action_int(actions, "phase", 0),
                    chain_index=0,
                    actions=actions,
                    message=action_value(actions, "msg"),
                )
            )
            expecting_chain = False
        elif kind == "SecMarker":
            parsed.append(
                Directive(
                    kind=kind,
                    source=path.name,
                    source_line=line_no,
                    rule_id=-1,
                    phase=0,
                    chain_index=0,
                    marker=tokens[1] if len(tokens) >= 2 else "",
                )
            )
            expecting_chain = False
        elif kind == "SecRuleUpdateTargetById":
            if len(tokens) != 3:
                raise ValueError(
                    f"{path}:{line_no}: SecRuleUpdateTargetById needs ID and target"
                )
            parsed.append(
                Directive(
                    kind=kind,
                    source=path.name,
                    source_line=line_no,
                    rule_id=int(tokens[1]),
                    phase=0,
                    chain_index=0,
                    value=tokens[2],
                )
            )
            expecting_chain = False
        elif kind == "SecComponentSignature":
            if len(tokens) != 2:
                raise ValueError(f"{path}:{line_no}: SecComponentSignature needs a value")
            parsed.append(
                Directive(
                    kind=kind,
                    source=path.name,
                    source_line=line_no,
                    rule_id=-1,
                    phase=0,
                    chain_index=0,
                    value=tokens[1],
                )
            )
            expecting_chain = False
    return parsed


def module_name(filename: str) -> str:
    stem = filename.removesuffix(".conf").lower()
    return re.sub(r"[^a-z0-9]+", "_", stem).strip("_")


def rss_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def split_target_specs(targets: str) -> list[str]:
    specs: list[str] = []
    start = 0
    backslashes = 0
    for index, char in enumerate(targets):
        if char == "|" and backslashes % 2 == 0:
            specs.append(targets[start:index])
            start = index + 1
        if char == "\\":
            backslashes += 1
        else:
            backslashes = 0
    specs.append(targets[start:])
    return specs


def target_descriptors(targets: str) -> list[str]:
    descriptors: list[str] = []
    for spec in split_target_specs(targets):
        if not spec:
            continue
        pieces = spec.split(":", 1)
        base = pieces[0]
        selector = pieces[1] if len(pieces) > 1 else ""
        descriptors.extend((base, selector, spec))
    return descriptors


def collect_target_updates(directives: list[Directive]) -> dict[int, list[str]]:
    updates: dict[int, list[str]] = {}
    for directive in directives:
        if directive.kind == "SecRuleUpdateTargetById":
            updates.setdefault(directive.rule_id, []).extend(
                target_descriptors(directive.value)
            )
    return updates


def rule_arguments(
    directive: Directive,
    data_contents: dict[str, str],
    target_updates: dict[int, list[str]] | None = None,
) -> list[str]:
    pattern = directive.pattern
    if directive.operator.lstrip("!") == "@pmFromFile":
        pattern = data_contents.get(pattern, "")
    transforms = action_values(directive.actions, "t")
    descriptors = target_descriptors(directive.targets)
    if target_updates:
        descriptors.extend(target_updates.get(directive.rule_id, []))
    text = [
        rss_string(directive.operator),
        rss_string(pattern),
        rss_string(action_value(directive.actions, "skipAfter")),
        rss_string(directive.message),
        *(rss_string(value) for value in descriptors),
    ]
    return [
        str(directive.rule_id),
        str(directive.phase),
        str(directive.chain_index),
        "true" if has_action(directive.actions, "chain") else "false",
        f"[{', '.join(text)}]",
        str(len(descriptors) // 3),
        str(encode_transform_plan(transforms)),
        str(paranoia_level(directive.actions)),
        str(anomaly_score(directive.actions)),
        "true" if has_action(directive.actions, "deny") else "false",
        str(action_int(directive.actions, "status", 403)),
    ]


def render_directive_call(
    directive: Directive,
    data_contents: dict[str, str],
    target_updates: dict[int, list[str]] | None = None,
) -> str:
    if directive.kind == "SecRule":
        rendered = ", ".join(
            rule_arguments(directive, data_contents, target_updates)
        )
        return f"next = engine_bundle::apply_rule(next, {rendered});"
    if directive.kind == "SecAction":
        return f"next = engine_bundle::apply_action(next, {directive.phase});"
    if directive.kind == "SecMarker":
        return f"next = engine_bundle::apply_marker(next, {rss_string(directive.marker)});"
    if directive.kind == "SecRuleUpdateTargetById":
        descriptors = target_descriptors(directive.value)
        calls = []
        for index in range(0, len(descriptors), 3):
            base, selector, _canonical = descriptors[index : index + 3]
            calls.append(
                "next = engine_bundle::update_target("
                f"next, {directive.rule_id}, {rss_string(base)}, "
                f"{rss_string(selector)});"
            )
        return " ".join(calls)
    return f"next = engine_bundle::component_signature(next, {rss_string(directive.value)});"


def render_module(
    filename: str,
    module: str,
    directives: list[Directive],
    version: str,
    data_contents: dict[str, str],
    target_updates: dict[int, list[str]],
) -> str:
    lines = [
        f"// Generated from OWASP CRS {version}: {filename}",
        "// Executable RustScript; do not edit by hand.",
        "use engine_bundle;",
        "",
        f"pub fn evaluate_{module}(state: map<string>) -> map<string> {{",
        "    let mut next = state;",
    ]
    for directive in directives:
        lines.append(
            f"    {render_directive_call(directive, data_contents, target_updates)}"
        )
    lines.extend(["    next", "}", ""])
    return "\n".join(lines)


def render_entry(
    directives: list[Directive],
    version: str,
    data_contents: dict[str, str],
    enabled_categories: set[str],
) -> str:
    target_updates = collect_target_updates(directives)
    grouped: dict[str, list[Directive]] = {}
    for directive in directives:
        if module_name(directive.source) in enabled_categories:
            grouped.setdefault(directive.source, []).append(directive)

    evaluators: dict[str, str] = {}
    lines = [
        f"// Executable OWASP CRS {version} ruleset.",
        "// Each enabled category executes generated RSS expressions directly.",
        "use engine_bundle;",
        "",
    ]
    for source, source_directives in grouped.items():
        category = module_name(source)
        evaluator = f"evaluate_{category}"
        evaluators[source] = evaluator
        lines.extend(
            [
                f"fn {evaluator}(state: map<string>) -> map<string> {{",
                "    let mut next = state;",
            ]
        )
        if category == "request_942_application_attack_sqli":
            lines.append(
                '    next = engine_bundle::apply_rule(next, 942100, 2, 0, false, ["@detectSQLi", "", "", "SQL Injection Attack Detected", "QUERY_STRING", "", "QUERY_STRING", "ARGS", "", "ARGS", "REQUEST_BODY", "", "REQUEST_BODY"], 3, 15979, 1, 5, false, 403);'
            )
        for directive in source_directives:
            call = render_directive_call(directive, data_contents, target_updates)
            lines.append(
                f'    if engine_bundle::category_enabled(&next, "{category}") {{ {call} }}'
            )
        lines.extend(["    next", "}", ""])

    def append_enabled_call(source: str) -> None:
        category = module_name(source)
        evaluator = evaluators[source]
        lines.append(
            f'    if engine_bundle::category_enabled(&next, "{category}") {{ next = {evaluator}(next); }}'
        )

    lines.extend(
        [
            "pub fn inspect_request(state: map<string>) -> map<string> {",
            "    let mut next = state;",
        ]
    )
    for phase in (1, 2):
        lines.append(f"    next = engine_bundle::set_phase(next, {phase});")
        for source in grouped:
            if source.startswith("REQUEST-"):
                append_enabled_call(source)
    lines.extend(["    next", "}", ""])

    lines.extend(
        [
            "pub fn inspect_response(state: map<string>) -> map<string> {",
            "    let mut next = state;",
        ]
    )
    for phase in (3, 4, 5):
        lines.append(f"    next = engine_bundle::set_phase(next, {phase});")
        for source in grouped:
            if source.startswith("RESPONSE-"):
                append_enabled_call(source)
    lines.extend(
        [
            "    next",
            "}",
            "",
            "pub fn inspect(state: map<string>) -> map<string> {",
            "    inspect_response(inspect_request(state))",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--version", default="4.28.0")
    parser.add_argument(
        "--enable",
        action="append",
        dest="enabled_categories",
        help="Enable a generated category module in ruleset.rss; may be repeated",
    )
    args = parser.parse_args()
    enabled_categories = set(
        args.enabled_categories
        or ["request_911_method_enforcement", "request_942_application_attack_sqli"]
    )

    source_dir = args.source_dir.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    preserved_rss = {
        "engine.rss",
        "engine_text.rss",
        "engine_context.rss",
        "engine_operators.rss",
        "engine_bundle.rss",
        "ruleset_bundle.rss",
        "pd_edge_waf.rss",
    }
    for stale in output_dir.glob("*.rss"):
        if stale.name not in preserved_rss:
            stale.unlink()
    data_dir = output_dir / "data"
    if data_dir.exists():
        shutil.rmtree(data_dir)
    data_dir.mkdir()
    data_files = []
    data_contents: dict[str, str] = {}
    for source_data in sorted(source_dir.glob("*.data")):
        shutil.copy2(source_data, data_dir / source_data.name)
        data_files.append(source_data.name)
        data_contents[source_data.name] = "\n".join(
            line.strip()
            for line in source_data.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )

    manifest_files = []
    modules: list[tuple[str, int]] = []
    all_directives: list[Directive] = []
    parsed_modules: list[tuple[Path, str, list[Directive]]] = []
    for conf in sorted(source_dir.glob("*.conf")):
        directives = parse_conf(conf)
        name = module_name(conf.name)
        parsed_modules.append((conf, name, directives))
        modules.append((name, len(directives)))
        all_directives.extend(directives)
        manifest_files.append(
            {
                "source": conf.name,
                "module": f"rules/{name}.rss",
                "sec_rule": sum(d.kind == "SecRule" for d in directives),
                "sec_action": sum(d.kind == "SecAction" for d in directives),
                "sec_marker": sum(d.kind == "SecMarker" for d in directives),
                "sec_rule_update_target_by_id": sum(
                    d.kind == "SecRuleUpdateTargetById" for d in directives
                ),
                "sec_component_signature": sum(
                    d.kind == "SecComponentSignature" for d in directives
                ),
            }
        )

    target_updates = collect_target_updates(all_directives)
    for conf, name, directives in parsed_modules:
        (output_dir / f"{name}.rss").write_text(
            render_module(
                conf.name,
                name,
                directives,
                args.version,
                data_contents,
                target_updates,
            ),
            encoding="utf-8",
        )

    expected = len(all_directives)
    declared_ids = {
        directive.rule_id
        for directive in all_directives
        if directive.kind in ("SecRule", "SecAction") and directive.rule_id >= 0
    }
    target_update_ids = {
        directive.rule_id
        for directive in all_directives
        if directive.kind == "SecRuleUpdateTargetById"
    }
    missing_update_ids = sorted(target_update_ids - declared_ids)
    if missing_update_ids:
        raise ValueError(f"target updates reference missing rule IDs: {missing_update_ids}")

    marker_names = {
        directive.marker for directive in all_directives if directive.kind == "SecMarker"
    }
    skip_after_names = [
        action_value(directive.actions, "skipAfter")
        for directive in all_directives
        if action_value(directive.actions, "skipAfter")
    ]
    missing_markers = sorted(set(skip_after_names) - marker_names)
    if missing_markers:
        raise ValueError(f"skipAfter references missing markers: {missing_markers}")

    pm_from_file_names = sorted(
        {
            directive.pattern
            for directive in all_directives
            if directive.kind == "SecRule"
            and directive.operator.lstrip("!") == "@pmFromFile"
        }
    )
    missing_data_files = sorted(set(pm_from_file_names) - set(data_files))
    if missing_data_files:
        raise ValueError(f"operators reference missing data files: {missing_data_files}")

    entry_path = output_dir / "ruleset.rss"
    entry_path.write_text(
        render_entry(
            all_directives, args.version, data_contents, enabled_categories
        ),
        encoding="utf-8",
    )
    manifest = {
        "upstream": "coreruleset/coreruleset",
        "version": args.version,
        "source_directory": "rules",
        "enabled_categories": sorted(enabled_categories),
        "category_count": len(modules),
        "directive_count": expected,
        "sec_rule_count": sum(d.kind == "SecRule" for d in all_directives),
        "sec_action_count": sum(d.kind == "SecAction" for d in all_directives),
        "sec_marker_count": sum(d.kind == "SecMarker" for d in all_directives),
        "sec_rule_update_target_by_id_count": sum(
            d.kind == "SecRuleUpdateTargetById" for d in all_directives
        ),
        "sec_component_signature_count": sum(
            d.kind == "SecComponentSignature" for d in all_directives
        ),
        "unique_rule_id_count": len(declared_ids),
        "chain_group_count": sum(
            d.kind == "SecRule"
            and d.chain_index == 0
            and re.search(r"(?:^|,)\s*chain(?:,|$)", d.actions) is not None
            for d in all_directives
        ),
        "chain_child_count": sum(
            d.kind == "SecRule" and d.chain_index > 0 for d in all_directives
        ),
        "skip_after_count": len(skip_after_names),
        "tag_count": sum(
            len(re.findall(r"(?:^|,)\s*tag:", d.actions)) for d in all_directives
        ),
        "transformation_count": sum(
            len(re.findall(r"(?:^|,)\s*t:", d.actions)) for d in all_directives
        ),
        "operator_variant_count": len(
            {d.operator for d in all_directives if d.kind == "SecRule"}
        ),
        "xml_attribute_target_rule_count": sum(
            d.kind == "SecRule" and "XML://@*" in d.targets for d in all_directives
        ),
        "pm_from_file_reference_count": sum(
            d.kind == "SecRule" and d.operator.lstrip("!") == "@pmFromFile"
            for d in all_directives
        ),
        "data_record_count": sum(
            1
            for data_file in sorted(source_dir.glob("*.data"))
            for line in data_file.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ),
        "data_file_count": len(data_files),
        "data_files": data_files,
        "files": manifest_files,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (output_dir / "directives.json").write_text(
        json.dumps([asdict(d) for d in all_directives], indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        f"generated {len(modules)} category modules with {manifest['directive_count']} directives: "
        f"{manifest['sec_rule_count']} SecRule, {manifest['sec_action_count']} SecAction, "
        f"{manifest['sec_marker_count']} SecMarker, "
        f"{manifest['sec_rule_update_target_by_id_count']} SecRuleUpdateTargetById, and "
        f"{manifest['sec_component_signature_count']} SecComponentSignature"
    )


if __name__ == "__main__":
    main()
