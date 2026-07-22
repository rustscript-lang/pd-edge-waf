use vm::{Value, Vm, VmStatus};

fn run_transform_fixture(body: &str) -> Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let engine_text = std::fs::read_to_string(root.join("rules/engine_text.rss"))
        .expect("engine text source should be readable");
    let source = format!("{engine_text}\n{body}\n");
    let compiled = vm::compile_source(&source).expect("transform fixture should compile");
    assert!(compiled.program.imports.is_empty());
    let mut vm = Vm::new(compiled.program);
    let status = vm.run().expect("transform fixture should execute");
    assert_eq!(status, VmStatus::Halted);
    vm.stack()
        .last()
        .cloned()
        .expect("transform fixture should return a value")
}

#[test]
fn transform_plan_executes_opcodes_in_encoded_order() {
    let result = run_transform_fixture(
        r#"
assert(transforms("&LT;", 234) == "<");
assert(transforms("&LT;", 327) == "&lt;");
"ok";
"#,
    );
    assert_eq!(result, Value::string("ok"));
}

#[test]
fn transform_plan_processes_repeated_opcodes() {
    let result = run_transform_fixture(
        r#"
assert(transforms("abcd", 9) == "4");
assert(transforms("abcd", 297) == "1");
"ok";
"#,
    );
    assert_eq!(result, Value::string("ok"));
}

#[test]
fn transform_plan_dispatches_supported_primitives_and_known_noops() {
    let result = run_transform_fixture(
        r#"
assert(transforms("%3C+", 19) == "< ");
assert(transforms("%3C+", 4) == "< ");
assert(transforms("%3C+", 8) == "< ");
assert(transforms("&lt;&gt;&quot;&#39;", 7) == "<>\"'");
assert(transforms("a\0b", 15) == "ab");
assert(transforms("a b", 16) == "ab");
assert(transforms("a  b", 3) == "a b");
assert(transforms("a/*x*/b", 17) == "a b");
assert(transforms("A\\B", 12) == "A/B");
assert(transforms("A\\B", 13) == "A/B");
assert(transforms("A\\B", 2) == "ab");
assert(transforms("ABC", 10) == "abc");
assert(transforms("abcd", 9) == "4");
assert(transforms("same", 1) == "same");
assert(transforms("same", 5) == "same");
assert(transforms("same", 6) == "same");
assert(transforms("same", 11) == "same");
assert(transforms("same", 14) == "same");
assert(transforms("same", 18) == "same");
assert(transforms("same", 20) == "same");
assert(transforms("same", 0) == "same");
assert(transforms("%3C+", 619) == "< ");
assert(transforms("%3C+", 14955) == "< ");
assert(transforms("%3C+", 20107) == "< ");
assert(transforms("%3C\0", 15979) == "<");
assert(transforms("%3C\0", 511627) == "<");
assert(transforms("%3C +", 17003) == "<");
assert(transforms("%3C/*x*/", 18027) == "< ");
"ok";
"#,
    );
    assert_eq!(result, Value::string("ok"));
}

#[test]
fn specialized_plan_619_preserves_url_decode_rule_semantics() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let engine = std::fs::read_to_string(root.join("rules/engine_bundle.rss"))
        .expect("engine bundle source should be readable");
    let source = format!(
        r#"{engine}
let encoded: map<string> = new_state(
    "GET", "/", "q=%3C", "HTTP/1.1", "192.0.2.10",
    {{}}, {{ "q": "%3C" }}, ""
);
let blocked: map<string> = apply_rule_619(
    encoded, 1, 0, false,
    ["<", "", "decoded", "ARGS", ""],
    65, 619, 5, false, 403
);
assert((&blocked)["blocked"] == "0");
assert((&blocked)["score"] == "5");
let blocked_after_evaluation: map<string> = apply_rule(
    blocked, 949110, 0, false,
    ["tx.inbound_anomaly_score_threshold", "", "", "TX", "BLOCKING_INBOUND_ANOMALY_SCORE"],
    4865, 11, 0, true, 403
);
assert((&blocked_after_evaluation)["blocked"] == "1");
let plain: map<string> = new_state(
    "GET", "/", "q=plain", "HTTP/1.1", "192.0.2.10",
    {{}}, {{ "q": "plain" }}, ""
);
let allowed: map<string> = apply_rule_619(
    plain, 2, 0, false,
    ["<", "", "decoded", "ARGS", ""],
    65, 619, 5, false, 403
);
assert((&allowed)["blocked"] == "0");
let prefilter_hit: map<string> = apply_rule_619(
    new_state(
        "GET", "/", "q=second", "HTTP/1.1", "192.0.2.10",
        {{}}, {{ "q": "second" }}, ""
    ),
    -1, 0, false,
    ["(?:first)|(?:second)", "", "", "ARGS", ""],
    65, 619, 0, false, 403
);
assert((&prefilter_hit)["prefilter"] == "1");
assert((&prefilter_hit)["blocked"] == "0");
assert((&prefilter_hit)["score"] == "0");
let prefilter_miss: map<string> = apply_rule_619(
    new_state(
        "GET", "/", "q=plain", "HTTP/1.1", "192.0.2.10",
        {{}}, {{ "q": "plain" }}, ""
    ),
    -1, 0, false,
    ["(?:first)|(?:second)", "", "", "ARGS", ""],
    65, 619, 0, false, 403
);
assert((&prefilter_miss)["prefilter"] == "0");
"ok";
"#
    );
    let compiled = vm::compile_source(&source).expect("specialized plan fixture should compile");
    let mut vm = Vm::new(compiled.program);
    assert_eq!(
        vm.run().expect("specialized plan fixture should execute"),
        VmStatus::Halted
    );
    assert_eq!(vm.stack().last(), Some(&Value::string("ok")));
}
