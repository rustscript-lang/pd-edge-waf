use std::{
    collections::HashMap,
    hint::black_box,
    time::{Duration, Instant},
};

use vm::{JitConfig, JitTraceTerminal, Value, Vm, VmStatus};

const DEFAULT_WARMUP_BATCHES: usize = 1;
const DEFAULT_MEASURED_BATCHES: usize = 5;
const DEFAULT_BATCH_SIZE: usize = 2;
const DEFAULT_JIT_STABLE_REQUESTS: usize = 2;
const DEFAULT_JIT_MAX_WARMUP_REQUESTS: usize = 32;

struct PerfConfig {
    warmup_batches: usize,
    measured_batches: usize,
    batch_size: usize,
    jit_stable_requests: usize,
    jit_max_warmup_requests: usize,
}

impl PerfConfig {
    fn from_env() -> Self {
        Self {
            warmup_batches: env_usize("WAF_PERF_WARMUP_BATCHES", DEFAULT_WARMUP_BATCHES, 1),
            measured_batches: env_usize("WAF_PERF_BATCHES", DEFAULT_MEASURED_BATCHES, 2),
            batch_size: env_usize("WAF_PERF_BATCH_SIZE", DEFAULT_BATCH_SIZE, 2),
            jit_stable_requests: env_usize(
                "WAF_PERF_JIT_STABLE_REQUESTS",
                DEFAULT_JIT_STABLE_REQUESTS,
                2,
            ),
            jit_max_warmup_requests: env_usize(
                "WAF_PERF_JIT_MAX_WARMUP_REQUESTS",
                DEFAULT_JIT_MAX_WARMUP_REQUESTS,
                4,
            ),
        }
    }

    fn fixed_warmup_requests(&self) -> usize {
        self.warmup_batches * self.batch_size
    }
}

struct PerfStats {
    average_request: Duration,
    min_batch_average: Duration,
    max_batch_average: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct JitCompilationState {
    attempts: usize,
    recorded_traces: usize,
    native_traces: usize,
}

impl JitCompilationState {
    fn capture(vm: &Vm) -> Self {
        let snapshot = vm.jit_snapshot();
        Self {
            attempts: snapshot.attempts.len(),
            recorded_traces: snapshot.traces.len(),
            native_traces: vm.jit_native_trace_count(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TraceShape {
    terminal: JitTraceTerminal,
    has_call: bool,
    entry_stack_depth: usize,
    op_count: usize,
    traces: usize,
    executions: u64,
    ssa_exits: usize,
    boxed_load_sites: u64,
    boxed_store_sites: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TraceShapeStats {
    shapes: Vec<TraceShape>,
    native_exec: u64,
    trace_exits: u64,
    loop_backs: u64,
    handoffs: u64,
    short_trace_exec: u64,
    estimated_materialized_slots: u64,
}

impl TraceShapeStats {
    fn capture(vm: &Vm) -> Self {
        let snapshot = vm.jit_snapshot();
        let local_count = vm.program().local_count as u64;
        let mut by_shape = HashMap::new();
        let mut short_trace_exec = 0u64;
        let mut estimated_materialized_slots = 0u64;

        for trace in &snapshot.traces {
            let op_count = trace.op_names().len();
            if op_count <= 10 {
                short_trace_exec = short_trace_exec.saturating_add(trace.executions);
            }
            estimated_materialized_slots = estimated_materialized_slots.saturating_add(
                trace
                    .executions
                    .saturating_mul(trace.ssa_exit_count() as u64)
                    .saturating_mul(local_count),
            );

            let shape = by_shape
                .entry((
                    trace.terminal.clone(),
                    trace.has_call,
                    trace.entry_stack_depth,
                    op_count,
                ))
                .or_insert_with(|| TraceShape {
                    terminal: trace.terminal.clone(),
                    has_call: trace.has_call,
                    entry_stack_depth: trace.entry_stack_depth,
                    op_count,
                    traces: 0,
                    executions: 0,
                    ssa_exits: 0,
                    boxed_load_sites: 0,
                    boxed_store_sites: 0,
                });
            shape.traces = shape.traces.saturating_add(1);
            shape.executions = shape.executions.saturating_add(trace.executions);
            shape.ssa_exits = shape.ssa_exits.saturating_add(trace.ssa_exit_count());
            shape.boxed_load_sites = shape
                .boxed_load_sites
                .saturating_add(trace.boxed_load_site_count());
            shape.boxed_store_sites = shape
                .boxed_store_sites
                .saturating_add(trace.boxed_store_site_count());
        }

        let mut shapes: Vec<_> = by_shape.into_values().collect();
        shapes.sort_by(|left, right| {
            terminal_rank(&left.terminal)
                .cmp(&terminal_rank(&right.terminal))
                .then_with(|| left.has_call.cmp(&right.has_call))
                .then_with(|| left.entry_stack_depth.cmp(&right.entry_stack_depth))
                .then_with(|| left.op_count.cmp(&right.op_count))
        });

        Self {
            shapes,
            native_exec: vm.jit_native_exec_count(),
            trace_exits: snapshot.metrics.trace_exit_count,
            loop_backs: snapshot.metrics.native_loop_back_count,
            handoffs: vm.jit_native_link_handoff_count(),
            short_trace_exec,
            estimated_materialized_slots,
        }
    }

    fn print(&self, label: &str) {
        println!(
            "jit_trace_stats label={label} native_exec={} trace_exits={} loop_backs={} handoffs={} short_trace_exec={} estimated_materialized_slots={}",
            self.native_exec,
            self.trace_exits,
            self.loop_backs,
            self.handoffs,
            self.short_trace_exec,
            self.estimated_materialized_slots,
        );
        for shape in &self.shapes {
            println!(
                "jit_trace_shape label={label} terminal={:?} has_call={} entry_stack_depth={} op_count={} traces={} executions={} ssa_exits={} boxed_load_sites={} boxed_store_sites={}",
                shape.terminal,
                shape.has_call,
                shape.entry_stack_depth,
                shape.op_count,
                shape.traces,
                shape.executions,
                shape.ssa_exits,
                shape.boxed_load_sites,
                shape.boxed_store_sites,
            );
        }
    }
}

fn terminal_rank(terminal: &JitTraceTerminal) -> u8 {
    match terminal {
        JitTraceTerminal::LoopBack => 0,
        JitTraceTerminal::BranchExit => 1,
        JitTraceTerminal::Halt => 2,
    }
}

#[derive(Clone, Copy)]
enum WarmupPolicy {
    Fixed,
    JitUntilStable,
}

fn env_usize(name: &str, default: usize, minimum: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
        .max(minimum)
}

fn baseline_request_program() -> vm::Program {
    let source = r#"
let method = "GET";
let path = "/products";
let query = "category=books&page=2";
let protocol = "HTTP/1.1";
let remote_addr = "192.0.2.10";
let headers: map<string> = {
    "host": "shop.example.test",
    "accept": "text/html,application/xhtml+xml",
    "user-agent": "pd-edge-waf-perf/1.0"
};
let args: map<string> = { "category": "books", "page": "2" };
let body = "";
assert(method == "GET");
assert(path == "/products");
assert(query == "category=books&page=2");
assert(protocol == "HTTP/1.1");
assert(remote_addr == "192.0.2.10");
assert((&headers)["host"] == "shop.example.test");
assert((&args)["category"] == "books");
assert(body == "");
"allow";
"#;
    let compiled =
        vm::compile_source(source).expect("framework baseline perf program should compile");
    assert!(compiled.program.imports.is_empty());
    compiled.program
}

fn default_request_program() -> vm::Program {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let ruleset = std::fs::read_to_string(root.join("rules/ruleset_bundle.rss"))
        .expect("default ruleset bundle should read");
    let source = format!(
        r#"{ruleset}
let state: map<string> = new_state(
    "GET",
    "/products",
    "category=books&page=2",
    "HTTP/1.1",
    "192.0.2.10",
    {{
        "host": "shop.example.test",
        "accept": "text/html,application/xhtml+xml",
        "user-agent": "pd-edge-waf-perf/1.0"
    }},
    {{ "category": "books", "page": "2" }},
    ""
);
let result: map<string> = inspect_request(state);
assert((&result)["blocked"] == "0");
"allow";
"#
    );
    let compiled =
        vm::compile_source(&source).expect("default ruleset perf program should compile");
    assert!(
        compiled.program.local_count <= 256,
        "perf program must fit the standard VM local-slot format"
    );
    assert!(compiled.program.imports.is_empty());
    compiled.program
}

fn execute_and_verify(vm: &mut Vm, expected: &Value, label: &str) -> VmStatus {
    let status = vm.run().unwrap_or_else(|error| {
        let line = vm
            .debug_info()
            .and_then(|info| info.line_for_offset(vm.ip()));
        panic!(
            "{label} request failed at ip {}, line {line:?}, stack_depth={}: {error:?}",
            vm.ip(),
            vm.stack().len(),
        );
    });
    assert_eq!(status, VmStatus::Halted);
    assert_eq!(vm.stack().last(), Some(expected));
    status
}

fn execute_and_reset(vm: &mut Vm, expected: &Value, label: &str) {
    execute_and_verify(vm, expected, label);
    vm.reset_for_reuse();
}

fn run_fixed_warmup(vm: &mut Vm, expected: &Value, label: &str, requests: usize) -> usize {
    for _ in 0..requests {
        execute_and_reset(vm, expected, label);
    }
    requests
}

fn run_jit_warmup_until_stable(
    vm: &mut Vm,
    expected: &Value,
    label: &str,
    config: &PerfConfig,
) -> usize {
    assert!(vm.jit_config().enabled, "JIT warmup requires JIT");
    let minimum_requests = config
        .fixed_warmup_requests()
        .max(vm.jit_config().hot_loop_threshold as usize);
    let required_requests = minimum_requests + config.jit_stable_requests;
    assert!(
        config.jit_max_warmup_requests >= required_requests,
        "WAF_PERF_JIT_MAX_WARMUP_REQUESTS must be at least {required_requests}"
    );

    let mut previous = JitCompilationState::capture(vm);
    let mut stable_requests = 0usize;
    for request in 1..=config.jit_max_warmup_requests {
        execute_and_reset(vm, expected, label);
        let current = JitCompilationState::capture(vm);
        if request >= minimum_requests && current == previous {
            stable_requests += 1;
        } else {
            stable_requests = 0;
        }
        previous = current;

        if stable_requests >= config.jit_stable_requests {
            println!(
                "jit_warmup label={label} requests={request} minimum_requests={minimum_requests} stable_requests={stable_requests} attempts={} recorded_traces={} native_traces={}",
                current.attempts, current.recorded_traces, current.native_traces,
            );
            return request;
        }
    }

    panic!(
        "{label} JIT did not stabilize after {} warmup requests; last state: {previous:?}",
        config.jit_max_warmup_requests
    );
}

fn run_batch(vm: &mut Vm, expected: &Value, label: &str, batch_size: usize) -> Duration {
    let started = Instant::now();
    for request_index in 0..batch_size {
        let status = black_box(execute_and_verify(vm, expected, label));
        assert_eq!(status, VmStatus::Halted);
        if request_index + 1 == batch_size {
            assert_eq!(vm.stack().last(), Some(expected));
        } else {
            black_box(vm.stack().last());
        }
        vm.reset_for_reuse();
    }
    started.elapsed()
}

fn measure_case(
    label: &str,
    mut vm: Vm,
    warmup_policy: WarmupPolicy,
    config: &PerfConfig,
    expected: &Value,
) -> PerfStats {
    let execution_mode = if vm.jit_config().enabled {
        "trace_jit"
    } else {
        "interpreter"
    };
    let warmup_requests = match warmup_policy {
        WarmupPolicy::Fixed => {
            run_fixed_warmup(&mut vm, expected, label, config.fixed_warmup_requests())
        }
        WarmupPolicy::JitUntilStable => {
            run_jit_warmup_until_stable(&mut vm, expected, label, config)
        }
    };
    let jit_before = JitCompilationState::capture(&vm);

    let mut batches = Vec::with_capacity(config.measured_batches);
    for _ in 0..config.measured_batches {
        batches.push(run_batch(&mut vm, expected, label, config.batch_size));
    }

    let jit_after = JitCompilationState::capture(&vm);
    if vm.jit_config().enabled {
        assert_eq!(
            jit_after, jit_before,
            "{label} compiled new JIT traces inside the measured region"
        );
        TraceShapeStats::capture(&vm).print(label);
    }

    let total_duration: Duration = batches.iter().copied().sum();
    let total_requests = config.measured_batches * config.batch_size;
    let stats = PerfStats {
        average_request: total_duration.div_f64(total_requests as f64),
        min_batch_average: batches
            .iter()
            .copied()
            .min()
            .expect("at least two measured batches")
            .div_f64(config.batch_size as f64),
        max_batch_average: batches
            .iter()
            .copied()
            .max()
            .expect("at least two measured batches")
            .div_f64(config.batch_size as f64),
    };

    println!(
        "{label} mode={execution_mode} warmup_requests={warmup_requests} batches={} batch_size={} requests={} average_us={:.3} min_batch_average_us={:.3} max_batch_average_us={:.3} jit_attempts={} recorded_traces={} native_traces={} regex_cache_entries={} regex_compile_count={} regex_cache_hits={}",
        config.measured_batches,
        config.batch_size,
        total_requests,
        stats.average_request.as_secs_f64() * 1_000_000.0,
        stats.min_batch_average.as_secs_f64() * 1_000_000.0,
        stats.max_batch_average.as_secs_f64() * 1_000_000.0,
        jit_after.attempts,
        jit_after.recorded_traces,
        jit_after.native_traces,
        vm.regex_cache_entry_count(),
        vm.regex_cache_compile_count(),
        vm.regex_cache_hit_count(),
    );
    stats
}

fn incremental_average(measured: &PerfStats, baseline: &PerfStats) -> Duration {
    measured
        .average_request
        .saturating_sub(baseline.average_request)
}

fn run_default_ruleset_perf() {
    let config = PerfConfig::from_env();
    let baseline_program = baseline_request_program();
    let default_ruleset_program = default_request_program();
    let expected = Value::string("allow");

    let baseline = measure_case(
        "framework_baseline_perf",
        Vm::new(baseline_program),
        WarmupPolicy::Fixed,
        &config,
        &expected,
    );
    let interpreter = measure_case(
        "default_ruleset_interpreter_perf",
        Vm::new_with_jit_config(
            default_ruleset_program.clone(),
            JitConfig {
                enabled: false,
                ..JitConfig::default()
            },
        ),
        WarmupPolicy::Fixed,
        &config,
        &expected,
    );
    let jit = measure_case(
        "default_ruleset_jit_perf",
        Vm::new(default_ruleset_program),
        WarmupPolicy::JitUntilStable,
        &config,
        &expected,
    );

    let interpreter_incremental = incremental_average(&interpreter, &baseline);
    let jit_incremental = incremental_average(&jit, &baseline);
    let jit_to_interpreter_ratio = jit.average_request.as_secs_f64()
        / interpreter.average_request.as_secs_f64().max(f64::EPSILON);
    println!(
        "waf_comparison_perf baseline_average_us={:.3} interpreter_average_us={:.3} interpreter_incremental_us={:.3} jit_average_us={:.3} jit_incremental_us={:.3} jit_to_interpreter_ratio={jit_to_interpreter_ratio:.3}",
        baseline.average_request.as_secs_f64() * 1_000_000.0,
        interpreter.average_request.as_secs_f64() * 1_000_000.0,
        interpreter_incremental.as_secs_f64() * 1_000_000.0,
        jit.average_request.as_secs_f64() * 1_000_000.0,
        jit_incremental.as_secs_f64() * 1_000_000.0,
    );
}

#[test]
fn trace_shape_stats_capture_real_jit_program() {
    if !JitConfig::default().enabled {
        return;
    }

    let compiled = vm::compile_source(
        r#"
let mut total = 0;
let mut index = 0;
while index < 8 {
    total = total + index;
    index = index + 1;
}
assert(total == 28);
"done";
"#,
    )
    .expect("trace-shape test program should compile");
    let expected = Value::string("done");
    let mut vm = Vm::new_with_jit_config(
        compiled.program,
        JitConfig {
            enabled: true,
            hot_loop_threshold: 1,
            ..JitConfig::default()
        },
    );
    execute_and_reset(&mut vm, &expected, "trace_shape_stats_test");
    execute_and_reset(&mut vm, &expected, "trace_shape_stats_test");

    let stats = TraceShapeStats::capture(&vm);
    let snapshot = vm.jit_snapshot();
    assert!(!stats.shapes.is_empty());
    assert_eq!(stats.native_exec, vm.jit_native_exec_count());
    assert_eq!(stats.trace_exits, snapshot.metrics.trace_exit_count);
    assert_eq!(stats.loop_backs, snapshot.metrics.native_loop_back_count);
    assert_eq!(stats.handoffs, vm.jit_native_link_handoff_count());
    assert_eq!(
        stats.short_trace_exec,
        snapshot
            .traces
            .iter()
            .filter(|trace| trace.op_names().len() <= 10)
            .map(|trace| trace.executions)
            .sum::<u64>()
    );
    assert_eq!(
        stats.estimated_materialized_slots,
        snapshot
            .traces
            .iter()
            .map(|trace| {
                trace
                    .executions
                    .saturating_mul(trace.ssa_exit_count() as u64)
                    .saturating_mul(vm.program().local_count as u64)
            })
            .sum::<u64>()
    );
    assert_eq!(
        stats.shapes.iter().map(|shape| shape.traces).sum::<usize>(),
        snapshot.traces.len()
    );
    assert_eq!(
        stats
            .shapes
            .iter()
            .map(|shape| shape.executions)
            .sum::<u64>(),
        snapshot
            .traces
            .iter()
            .map(|trace| trace.executions)
            .sum::<u64>()
    );
}

#[test]
#[ignore = "performance test; run explicitly with --ignored --nocapture"]
fn baseline_interpreter_and_jit_batch_latency() {
    run_default_ruleset_perf();
}
