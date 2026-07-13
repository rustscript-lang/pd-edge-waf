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


def render_module(filename: str, module: str, directives: list[Directive], version: str) -> str:
    lines = [
        f"// Generated from OWASP CRS {version}: {filename}",
        "// Do not edit by hand; run tools/convert_crs.py.",
        "use waf;",
        "",
        f"pub fn load_{module}() -> int {{",
    ]
    for directive in directives:
        if directive.kind == "SecRule":
            args = [
                directive.source,
                directive.source_line,
                directive.rule_id,
                directive.phase,
                directive.chain_index,
                directive.targets,
                directive.operator,
                directive.pattern,
                directive.actions,
                directive.message,
            ]
            rendered = ", ".join(rss_string(v) if isinstance(v, str) else str(v) for v in args)
            lines.append(f"    waf::rule({rendered});")
        elif directive.kind == "SecAction":
            args = [directive.source, directive.source_line, directive.rule_id, directive.phase, directive.actions]
            rendered = ", ".join(rss_string(v) if isinstance(v, str) else str(v) for v in args)
            lines.append(f"    waf::action({rendered});")
        elif directive.kind == "SecMarker":
            args = [directive.source, directive.source_line, directive.marker]
            rendered = ", ".join(rss_string(v) if isinstance(v, str) else str(v) for v in args)
            lines.append(f"    waf::marker({rendered});")
        elif directive.kind == "SecRuleUpdateTargetById":
            args = [directive.source, directive.source_line, directive.rule_id, directive.value]
            rendered = ", ".join(rss_string(v) if isinstance(v, str) else str(v) for v in args)
            lines.append(f"    waf::update_target({rendered});")
        else:
            args = [directive.source, directive.source_line, directive.value]
            rendered = ", ".join(rss_string(v) if isinstance(v, str) else str(v) for v in args)
            lines.append(f"    waf::component_signature({rendered});")
    lines.extend([f"    {len(directives)}", "}", ""])
    return "\n".join(lines)


def render_entry(modules: list[tuple[str, int]], expected: int, version: str) -> str:
    lines = [
        f"// OWASP CRS {version} translated into category modules.",
        "// Each source category remains in its own RustScript file.",
    ]
    lines.extend(f"use {name};" for name, _ in modules)
    lines.extend(["", "let mut loaded = 0;"])
    lines.extend(f"loaded = loaded + {name}::load_{name}();" for name, _ in modules)
    lines.extend([f"assert(loaded == {expected});", ""])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--version", default="4.28.0")
    args = parser.parse_args()

    source_dir = args.source_dir.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    for stale in output_dir.glob("*.rss"):
        stale.unlink()
    data_dir = output_dir / "data"
    if data_dir.exists():
        shutil.rmtree(data_dir)
    data_dir.mkdir()
    data_files = []
    for source_data in sorted(source_dir.glob("*.data")):
        shutil.copy2(source_data, data_dir / source_data.name)
        data_files.append(source_data.name)

    manifest_files = []
    modules: list[tuple[str, int]] = []
    all_directives: list[Directive] = []
    for conf in sorted(source_dir.glob("*.conf")):
        directives = parse_conf(conf)
        name = module_name(conf.name)
        (output_dir / f"{name}.rss").write_text(
            render_module(conf.name, name, directives, args.version), encoding="utf-8"
        )
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
    entry_path.write_text(render_entry(modules, expected, args.version), encoding="utf-8")
    manifest = {
        "upstream": "coreruleset/coreruleset",
        "version": args.version,
        "source_directory": "rules",
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
