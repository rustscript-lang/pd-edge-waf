#!/usr/bin/env python3
"""Convert OWASP CRS ModSecurity directives into split RustScript modules."""

from __future__ import annotations

import argparse
import json
import re
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path

DIRECTIVES = ("SecRule", "SecAction", "SecMarker")


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
        else:
            args = [directive.source, directive.source_line, directive.marker]
            rendered = ", ".join(rss_string(v) if isinstance(v, str) else str(v) for v in args)
            lines.append(f"    waf::marker({rendered});")
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
            }
        )

    expected = len(all_directives)
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
        f"generated {len(modules)} category modules with {manifest['sec_rule_count']} SecRule, "
        f"{manifest['sec_action_count']} SecAction, and {manifest['sec_marker_count']} SecMarker directives"
    )


if __name__ == "__main__":
    main()
