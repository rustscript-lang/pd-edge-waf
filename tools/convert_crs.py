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

OPERATOR_OPCODES = {
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
OPERATOR_NEGATED_BIT = 32
TARGET_COUNT_RADIX = 64
TARGET_STATIC_EXCLUSIONS_BIT = 1 << 14
TARGET_COUNTED_DESCRIPTORS_BIT = 1 << 15
TARGET_POSITIVE_COUNT_MULTIPLIER = 1 << 16
TARGET_REGULAR_COUNT_MULTIPLIER = 1 << 22


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


def encode_operator(operator: str) -> int:
    negated = operator.startswith("!")
    name = operator[1:] if negated else operator
    try:
        opcode = OPERATOR_OPCODES[name]
    except KeyError as error:
        raise ValueError(f"unknown operator: {operator}") from error
    return opcode + (OPERATOR_NEGATED_BIT if negated else 0)


def encode_target_spec(operator_code: int, descriptors: list[str]) -> int:
    target_count = len(descriptors) // 2
    positive_count = sum(
        not descriptors[index].startswith("!")
        for index in range(0, len(descriptors), 2)
    )
    regular_count = sum(
        not descriptors[index].startswith(("!", "&"))
        for index in range(0, len(descriptors), 2)
    )
    has_static_exclusions = positive_count != target_count
    has_counted_descriptors = regular_count != positive_count
    return (
        operator_code * TARGET_COUNT_RADIX
        + target_count
        + (TARGET_STATIC_EXCLUSIONS_BIT if has_static_exclusions else 0)
        + (TARGET_COUNTED_DESCRIPTORS_BIT if has_counted_descriptors else 0)
        + (
            positive_count * TARGET_POSITIVE_COUNT_MULTIPLIER
            if has_static_exclusions
            else 0
        )
        + (
            regular_count * TARGET_REGULAR_COUNT_MULTIPLIER
            if has_counted_descriptors
            else 0
        )
    )


def pack_target_descriptors(descriptors: list[str]) -> list[str]:
    regular: list[str] = []
    counted: list[str] = []
    excluded: list[str] = []
    for index in range(0, len(descriptors), 2):
        base, selector = descriptors[index : index + 2]
        if base.startswith("!"):
            excluded.extend((base[1:], selector))
        elif base.startswith("&"):
            counted.extend((base[1:], selector))
        else:
            regular.extend((base, selector))
    return regular + counted + excluded


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
        descriptors.extend((base, selector))
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
    operator_code = encode_operator(directive.operator)
    exact_state = re.fullmatch(r"%\{([^}]+)\}", pattern)
    prefixed_state = re.fullmatch(r"\.%\{([^}]+)\}", pattern)
    if exact_state:
        operator_code += 64
        pattern = exact_state.group(1).lower()
    elif prefixed_state:
        operator_code += 128
        pattern = prefixed_state.group(1).lower()
    transforms = action_values(directive.actions, "t")
    descriptors = target_descriptors(directive.targets)
    if target_updates:
        descriptors.extend(target_updates.get(directive.rule_id, []))
    target_spec = encode_target_spec(operator_code, descriptors)
    descriptors = pack_target_descriptors(descriptors)
    text = [
        rss_string(pattern),
        rss_string(action_value(directive.actions, "skipAfter")),
        rss_string(directive.message),
        *(rss_string(value) for value in descriptors),
    ]
    return [
        str(directive.rule_id),
        str(directive.chain_index),
        "true" if has_action(directive.actions, "chain") else "false",
        f"[{', '.join(text)}]",
        str(target_spec),
        str(encode_transform_plan(transforms)),
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
        arguments = rule_arguments(directive, data_contents, target_updates)
        rendered = ", ".join(arguments)
        evaluator = "apply_rule"
        return f"next = engine_bundle::{evaluator}(next, {rendered});"
    if directive.kind == "SecAction":
        return f"next = engine_bundle::apply_action(next, {directive.phase});"
    if directive.kind == "SecMarker":
        return f"next = engine_bundle::apply_marker(next, {rss_string(directive.marker)});"
    if directive.kind == "SecRuleUpdateTargetById":
        descriptors = target_descriptors(directive.value)
        calls = []
        for index in range(0, len(descriptors), 2):
            base, selector = descriptors[index : index + 2]
            calls.append(
                "next = engine_bundle::update_target("
                f"next, {directive.rule_id}, {rss_string(base)}, "
                f"{rss_string(selector)});"
            )
        return " ".join(calls)
    return f"next = engine_bundle::component_signature(next, {rss_string(directive.value)});"


def is_detection_paranoia_skip(directive: Directive) -> bool:
    return (
        directive.kind == "SecRule"
        and directive.chain_index == 0
        and directive.targets.upper() == "TX:DETECTION_PARANOIA_LEVEL"
        and directive.operator == "@lt"
        and directive.pattern in {"1", "2", "3", "4"}
        and not action_values(directive.actions, "t")
        and anomaly_score(directive.actions) == 0
        and not has_action(directive.actions, "chain")
        and not has_action(directive.actions, "deny")
        and directive.message == ""
        and action_value(directive.actions, "skipAfter") != ""
    )


def render_entry_directive_call(
    directive: Directive,
    data_contents: dict[str, str],
    target_updates: dict[int, list[str]],
) -> str:
    if is_detection_paranoia_skip(directive):
        return (
            "next = engine_bundle::apply_detection_paranoia_skip("
            f"next, {directive.rule_id}, {directive.pattern}, "
            f"{rss_string(action_value(directive.actions, 'skipAfter'))});"
        )
    # apply_rule owns the blocked/skip checks. Repeating them around every
    # generated call only adds map lookups and branches to the hot path.
    return render_directive_call(directive, data_contents, target_updates)


def render_entry_phase_calls(
    directives: list[tuple[Directive, int]],
    markers: list[Directive],
    data_contents: dict[str, str],
    target_updates: dict[int, list[str]],
) -> list[str]:
    """Render a phase while collapsing skipAfter no-op call tails."""
    lines: list[str] = []
    open_skip_guards = 0
    for directive, _ in directives:
        lines.append(
            "    " * open_skip_guards
            + render_entry_directive_call(
                directive, data_contents, target_updates
            )
        )
        if directive.kind == "SecRule" and action_value(
            directive.actions, "skipAfter"
        ):
            lines.append(
                "    " * open_skip_guards
                + 'if engine_bundle::ctx_get(&next, "skip") == "" {'
            )
            open_skip_guards += 1
    while open_skip_guards > 0:
        open_skip_guards -= 1
        lines.append("    " * open_skip_guards + "}")
    lines.extend(
        render_directive_call(marker, data_contents, target_updates)
        for marker in markers
    )
    return lines


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
        f"pub fn evaluate_{module}(next: map<string>) -> map<string> {{",
    ]
    for directive in directives:
        lines.append(
            f"    {render_directive_call(directive, data_contents, target_updates)}"
        )
    lines.extend(["    next", "}", ""])
    return "\n".join(lines)


def plan_619_prefilter_key(
    directive: Directive,
    data_contents: dict[str, str],
    target_updates: dict[int, list[str]],
) -> tuple[tuple[str, ...], int] | None:
    if (
        directive.kind != "SecRule"
        or directive.chain_index != 0
        or directive.operator != "@rx"
        or "%{" in directive.pattern
    ):
        return None
    arguments = rule_arguments(directive, data_contents, target_updates)
    if arguments[5] != "619":
        return None
    descriptors = target_descriptors(directive.targets)
    descriptors.extend(target_updates.get(directive.rule_id, []))
    return tuple(descriptors), 619


def render_plan_619_prefilter(
    directives: list[Directive],
    data_contents: dict[str, str],
    target_updates: dict[int, list[str]],
) -> str:
    key = plan_619_prefilter_key(directives[0], data_contents, target_updates)
    if key is None:
        raise ValueError("plan 619 prefilter requires compatible directives")
    descriptors, transform_plan = key
    descriptors = list(descriptors)
    target_spec = encode_target_spec(OPERATOR_OPCODES["@rx"], descriptors)
    descriptors = pack_target_descriptors(descriptors)
    combined = "|".join(f"(?:{directive.pattern})" for directive in directives)
    text = [
        rss_string(combined),
        rss_string(""),
        rss_string(""),
        *(rss_string(value) for value in descriptors),
    ]
    return (
        "next = engine_bundle::apply_rule(next, -1, 0, false, "
        f"[{', '.join(text)}], {target_spec}, {transform_plan}, 0, false, 403);"
    )


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

    phase_sections: dict[int, list[tuple[str, list[str]]]] = {}
    lines = [
        f"// Executable OWASP CRS {version} ruleset.",
        "// Default ModSecurity and CRS rules execute as generated phase-specific calls.",
        "use engine_bundle;",
        "",
    ]
    for source, source_directives in grouped.items():
        category = module_name(source)
        phased_directives: dict[int, list[tuple[Directive, int]]] = {}
        chain_phase = 0
        chain_paranoia = 0
        markers: list[Directive] = []
        for directive in source_directives:
            if directive.kind == "SecMarker":
                markers.append(directive)
                continue
            effective_phase = directive.phase
            effective_paranoia = 0
            if directive.kind == "SecRule":
                effective_paranoia = paranoia_level(directive.actions)
                if directive.chain_index == 0:
                    chain_phase = directive.phase
                    chain_paranoia = effective_paranoia
                else:
                    if effective_phase == 0:
                        effective_phase = chain_phase
                    if effective_paranoia == 0:
                        effective_paranoia = chain_paranoia
            if effective_phase > 0:
                phased_directives.setdefault(effective_phase, []).append(
                    (directive, effective_paranoia)
                )

        for phase, phase_directives in phased_directives.items():
            calls = render_entry_phase_calls(
                phase_directives, markers, data_contents, target_updates
            )
            phase_sections.setdefault(phase, []).append((category, calls))

    def append_phase(phase: int) -> None:
        lines.append(f"    next = engine_bundle::ctx_set_phase(next, {phase});")
        for category, calls in phase_sections.get(phase, []):
            lines.append(
                "    if engine_bundle::category_enabled("
                f'&next, "{category}") {{'
            )
            lines.extend(f"        {call}" for call in calls)
            lines.append("    }")

    lines.append("pub fn inspect_request(next: map<string>) -> map<string> {")
    for phase in (1, 2):
        append_phase(phase)
    lines.extend(["    next", "}", ""])

    lines.append("pub fn inspect_response(next: map<string>) -> map<string> {")
    for phase in (3, 4, 5):
        append_phase(phase)
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
        "--modsecurity-config",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "config"
        / "MODSECURITY-RECOMMENDED.conf",
        help="ModSecurity recommended SecRule source to compile before CRS",
    )
    parser.add_argument(
        "--enable",
        action="append",
        dest="enabled_categories",
        help="Enable a generated category module in ruleset.rss; may be repeated",
    )
    args = parser.parse_args()

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
    modsecurity_config = args.modsecurity_config.resolve()
    if not modsecurity_config.is_file():
        raise ValueError(f"missing ModSecurity configuration: {modsecurity_config}")
    for conf in [modsecurity_config, *sorted(source_dir.glob("*.conf"))]:
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

    enabled_categories = set(
        args.enabled_categories or (name for _, name, _ in parsed_modules)
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
