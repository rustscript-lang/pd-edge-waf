use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use pd_edge_waf::{CRS_VERSION, RULESET_PATH, manifest};
use vm::{CallOutcome, HostFunctionRegistry, Value, Vm, VmResult, VmStatus};

#[derive(Default)]
struct ExecutionStats {
    rules: usize,
    actions: usize,
    markers: usize,
    rule_ids: HashSet<i64>,
    sources: HashSet<String>,
}

fn stats() -> &'static Mutex<ExecutionStats> {
    static STATS: OnceLock<Mutex<ExecutionStats>> = OnceLock::new();
    STATS.get_or_init(|| Mutex::new(ExecutionStats::default()))
}

fn as_int(value: &Value) -> i64 {
    match value {
        Value::Int(value) => *value,
        other => panic!("expected int argument, got {other:?}"),
    }
}

fn as_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.as_str().to_owned(),
        other => panic!("expected string argument, got {other:?}"),
    }
}

fn no_return() -> VmResult<CallOutcome> {
    Ok(CallOutcome::Return(Vec::new().into()))
}

fn record_rule(args: &[Value]) -> VmResult<CallOutcome> {
    assert_eq!(args.len(), 10);
    let mut state = stats().lock().expect("stats lock");
    state.rules += 1;
    state.sources.insert(as_string(&args[0]));
    let id = as_int(&args[2]);
    if id >= 0 {
        state.rule_ids.insert(id);
    }
    assert!(
        !as_string(&args[5]).is_empty(),
        "rule targets must be retained"
    );
    assert!(
        !as_string(&args[6]).is_empty(),
        "rule operator must be retained"
    );
    no_return()
}

fn record_action(args: &[Value]) -> VmResult<CallOutcome> {
    assert_eq!(args.len(), 5);
    let mut state = stats().lock().expect("stats lock");
    state.actions += 1;
    state.sources.insert(as_string(&args[0]));
    no_return()
}

fn record_marker(args: &[Value]) -> VmResult<CallOutcome> {
    assert_eq!(args.len(), 3);
    let mut state = stats().lock().expect("stats lock");
    state.markers += 1;
    state.sources.insert(as_string(&args[0]));
    no_return()
}

#[test]
fn full_crs_ruleset_compiles_and_executes_in_pd_vm() {
    let expected = manifest();
    assert_eq!(expected.version, CRS_VERSION);
    assert_eq!(expected.category_count, 27);
    assert_eq!(expected.sec_rule_count, 695);
    assert_eq!(expected.sec_action_count, 7);
    assert_eq!(expected.sec_marker_count, 30);
    assert_eq!(expected.data_file_count, 21);
    assert!(
        expected
            .data_files
            .iter()
            .any(|name| name == "sql-errors.data")
    );

    *stats().lock().expect("stats lock") = ExecutionStats::default();
    let compiled = vm::compile_source_file(RULESET_PATH).expect("ruleset should compile");
    let imports = compiled
        .program
        .imports
        .iter()
        .map(|item| (item.name.as_str(), item.arity))
        .collect::<HashSet<_>>();
    assert!(imports.contains(&("waf::rule", 10)));
    assert!(imports.contains(&("waf::action", 5)));
    assert!(imports.contains(&("waf::marker", 3)));

    let mut registry = HostFunctionRegistry::new();
    registry.register_static_args("waf::rule", 10, record_rule);
    registry.register_static_args("waf::action", 5, record_action);
    registry.register_static_args("waf::marker", 3, record_marker);

    let mut vm = Vm::new(compiled.program);
    registry
        .bind_vm_cached(&mut vm)
        .expect("WAF imports should bind");
    assert_eq!(vm.run().expect("ruleset should execute"), VmStatus::Halted);

    let state = stats().lock().expect("stats lock");
    assert_eq!(state.rules, expected.sec_rule_count);
    assert_eq!(state.actions, expected.sec_action_count);
    assert_eq!(state.markers, expected.sec_marker_count);
    assert_eq!(state.sources.len(), expected.category_count - 1); // 999 is an intentionally empty hook.
    assert!(state.rule_ids.contains(&911100));
    assert!(state.rule_ids.contains(&942100));
    assert!(state.rule_ids.contains(&955100));
}
