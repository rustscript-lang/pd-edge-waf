use vm::{Value, Vm, VmStatus};

fn run_target_fixture(body: &str) -> Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let engine = std::fs::read_to_string(root.join("rules/engine_bundle.rss"))
        .expect("engine bundle source should be readable");
    let source = format!("{engine}\n{body}\n");
    let compiled = vm::compile_source(&source).expect("target fixture should compile");
    assert!(compiled.program.imports.is_empty());
    let mut vm = Vm::new(compiled.program);
    let status = vm.run().expect("target fixture should execute");
    assert_eq!(status, VmStatus::Halted);
    vm.stack()
        .last()
        .cloned()
        .expect("target fixture should return a value")
}

#[test]
fn precompiled_targets_preserve_selectors_counts_and_dynamic_exclusions() {
    let result = run_target_fixture(
        r#"
let state: map<string> = {
    "request_headers": "Host=example.test\nX-Test=selected\nCookie=a=b",
    "args": "a=1\nb=2",
    "exclude.123": ""
};
let text: [string] = [
    "", "", "",
    "REQUEST_HEADERS", "",
    "ARGS", "",
    "REQUEST_HEADERS", "Cookie"
];
let values: [string] = ctx_targets(&state, &text, 4374531, 123);
assert(values.length == 3);
assert((&values)[0] == "example.test");
assert((&values)[1] == "selected");
assert((&values)[2] == "2");

let updated: map<string> = update_target(state, 123, "REQUEST_HEADERS", "Host");
let remaining: [string] = ctx_targets(&updated, &text, 4374531, 123);
assert(remaining.length == 2);
assert((&remaining)[0] == "selected");
assert((&remaining)[1] == "2");

let regex_updated: map<string> = update_target(updated, 123, "REQUEST_HEADERS", "/^X-/");
let regex_remaining: [string] = ctx_targets(&regex_updated, &text, 4374531, 123);
assert(regex_remaining.length == 1);
assert((&regex_remaining)[0] == "2");

let counted_updated: map<string> = update_target(regex_updated, 123, "ARGS", "a");
let counted_remaining: [string] = ctx_targets(&counted_updated, &text, 4374531, 123);
assert(counted_remaining.length == 1);
assert((&counted_remaining)[0] == "1");

let broad_updated: map<string> = update_target(counted_updated, 123, "REQUEST_HEADERS", "");
let broad_remaining: [string] = ctx_targets(&broad_updated, &text, 4374531, 123);
assert(broad_remaining.length == 1);
assert((&broad_remaining)[0] == "1");

let regex_text: [string] = [
    "", "", "",
    "REQUEST_HEADERS", "/^X-/"
];
let selected: [string] = ctx_targets(&broad_updated, &regex_text, 1, 124);
assert(selected.length == 1);
assert((&selected)[0] == "selected");

let complex_state: map<string> = { "request_headers": "X|Alt:Name=complex" };
let complex_text: [string] = [
    "", "", "",
    "REQUEST_HEADERS", "/^X\\|Alt:Name$/"
];
let complex_selected: [string] = ctx_targets(&complex_state, &complex_text, 1, 125);
assert(complex_selected.length == 1);
assert((&complex_selected)[0] == "complex");
"ok";
"#,
    );
    assert_eq!(result, Value::string("ok"));
}
