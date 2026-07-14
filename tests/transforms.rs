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
"ok";
"#,
    );
    assert_eq!(result, Value::string("ok"));
}
