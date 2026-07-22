#!/usr/bin/env python3
from pathlib import Path
import re


def remove_function(source: str, name: str) -> str:
    marker = f"pub fn {name}("
    start = source.find(marker)
    if start < 0:
        return source
    line_start = source.rfind("\n", 0, start) + 1
    brace = source.find("{", start)
    if brace < 0:
        raise ValueError(f"missing body for RSS function {name}")
    depth = 0
    end = brace
    while end < len(source):
        char = source[end]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end += 1
                break
        end += 1
    if depth != 0:
        raise ValueError(f"unterminated body for RSS function {name}")
    while end < len(source) and source[end] == "\n":
        end += 1
    return source[:line_start] + source[end:]



root = Path(__file__).resolve().parents[1]
rules = root / "rules"
parts = []
for name in ("engine_text.rss", "engine_context.rss", "engine_operators.rss", "engine.rss"):
    text = (rules / name).read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if not line.startswith("use ")]
    text = "\n".join(lines)
    for prefix in ("engine_text::", "engine_context::", "engine_operators::"):
        text = text.replace(prefix, "")
    parts.append(f"// bundled from {name}\n{text}\n")
engine_bundle = "use re;\nuse bytes;\n\n" + "\n".join(parts)
for wrapper in ("lower", "contains", "replace"):
    engine_bundle = remove_function(engine_bundle, wrapper)
engine_bundle = re.sub(r"\blower\(", "string_lower_ascii(", engine_bundle)
engine_bundle = re.sub(r"\bcontains\(", "string_contains(", engine_bundle)
engine_bundle = re.sub(r"(?<!::)\breplace\(", "string_replace_literal(", engine_bundle)

ruleset = (rules / "ruleset.rss").read_text(encoding="utf-8")
ruleset_lines = [line for line in ruleset.splitlines() if not line.startswith("use ")]
ruleset_body = "\n".join(ruleset_lines).replace("engine_bundle::", "")
for helper in ("set_phase", "apply_action", "component_signature"):
    if re.search(rf"\b{helper}\(", ruleset_body) is None:
        engine_bundle = remove_function(engine_bundle, helper)
(rules / "engine_bundle.rss").write_text(engine_bundle, encoding="utf-8")

ruleset_bundle = engine_bundle + "\n// bundled from ruleset.rss\n" + ruleset_body + "\n"
(rules / "ruleset_bundle.rss").write_text(ruleset_bundle, encoding="utf-8")

entry_setup = r'''
let mut state: map<string> = new_state(
    http::request::get_method(),
    http::request::get_path(),
    http::request::get_query(),
    http::request::get_http_version(),
    http::request::get_client_ip(),
    http::request::get_headers(),
    http::request::get_query_args(),
    http::request::get_body()
);
state["enabled_ruleset"] = http::request::get_header("x-waf-enabled-ruleset");
'''.strip()
entry_action = r'''
if (&next)["blocked"] == "1" {
    http::response::set_status(number((&next)["status"], 403));
    http::response::set_header("content-type", "text/plain; charset=utf-8");
    http::response::set_header("x-waf-blocked", "1");
    http::response::set_header("x-waf-score", (&next)["score"]);
    http::response::set_header("x-waf-matched-ids", (&next)["matched_ids"]);
    http::response::set_body("request blocked by OWASP CRS");
} else {
    let mut upstream_host = http::request::get_header("x-waf-upstream-host");
    if upstream_host == "" { upstream_host = "127.0.0.1"; }
    let exchange = http::exchange::default_upstream();
    http::exchange::set_target(
        exchange,
        upstream_host,
        number(http::request::get_header("x-waf-upstream-port"), 18080)
    );
    http::exchange::set_path(exchange, http::request::get_path());
    http::exchange::set_query(exchange, http::request::get_query());
    http::response::set_header("x-waf-blocked", "0");
    http::response::set_header("x-waf-score", (&next)["score"]);
    proxy::forward_native(proxy::stream::downstream(), proxy::stream::exchange(exchange));
}
'''.strip()
entry_source = (
    "use http;\nuse proxy;\n" + ruleset_bundle + "\n" + entry_setup + "\n" +
    "let next: map<string> = inspect_request(state);\n" + entry_action + "\n"
)
(rules / "pd_edge_waf.rss").write_text(entry_source, encoding="utf-8")
