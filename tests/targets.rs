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
    "@rx", "", "", "",
    "REQUEST_HEADERS", "", "REQUEST_HEADERS",
    "!REQUEST_HEADERS", "Cookie", "!REQUEST_HEADERS:Cookie",
    "&ARGS", "", "&ARGS"
];
let values: [string] = ctx_targets(&state, &text, 3, 123);
assert(values.length == 3);
assert((&values)[0] == "example.test");
assert((&values)[1] == "selected");
assert((&values)[2] == "2");

let updated: map<string> = ctx_update(state, 123, "!REQUEST_HEADERS");
let remaining: [string] = ctx_targets(&updated, &text, 3, 123);
assert(remaining.length == 1);
assert((&remaining)[0] == "2");

let regex_text: [string] = [
    "@rx", "", "", "",
    "REQUEST_HEADERS", "/^X-/", "REQUEST_HEADERS:/^X-/"
];
let selected: [string] = ctx_targets(&updated, &regex_text, 1, 124);
assert(selected.length == 1);
assert((&selected)[0] == "selected");
"ok";
"#,
    );
    assert_eq!(result, Value::string("ok"));
}
