use std::{
    collections::HashMap,
    hint::black_box,
    time::{Duration, Instant},
};

use vm::{JitConfig, JitTraceTerminal, Value, Vm, VmStatus};

const DEFAULT_WARMUP_BATCHES: usize = 1;
const DEFAULT_MEASURED_BATCHES: usize = 5;
const DEFAULT_BATCH_SIZE: usize = 2;
const DEFAULT_JIT_STABLE_REQUESTS: usize = 12;
const DEFAULT_JIT_MAX_WARMUP_REQUESTS: usize = 128;
const RUST_MATH_BASELINE_ITERATIONS: usize = 1_000_000;

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
    rust_math_average: Duration,
    normalized_to_rust_math: f64,
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
                    trace.terminal,
                    trace.has_call,
                    trace.entry_stack_depth,
                    op_count,
                ))
                .or_insert_with(|| TraceShape {
                    terminal: trace.terminal,
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
    match format!("{terminal:?}").as_str() {
        "LoopBack" => 0,
        "BranchExit" | "SideExit" => 1,
        "Halt" | "Materialization" => 2,
        "CallValue" => 3,
        _ => 4,
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
assert((&inspect_request(new_state(
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
)))["blocked"] == "0");
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

fn active_request_program(request_source: &str, label: &str) -> vm::Program {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let ruleset = std::fs::read_to_string(root.join("rules/ruleset_bundle.rss"))
        .expect("active ruleset bundle should read");
    let source = format!("{ruleset}\n{request_source}\n\"matched\";\n");
    let compiled = vm::compile_source(&source)
        .unwrap_or_else(|error| panic!("{label} active ruleset program should compile: {error}"));
    assert!(
        compiled.program.local_count <= 256,
        "{label} active ruleset program must fit the standard VM local-slot format"
    );
    assert!(compiled.program.imports.is_empty());
    compiled.program
}

fn active_method_request_program() -> vm::Program {
    active_request_program(
        r#"
let method_result = inspect_request(new_state(
    "TRACE",
    "/",
    "",
    "HTTP/1.1",
    "192.0.2.10",
    { "host": "shop.example.test", "user-agent": "pd-edge-waf-perf/1.0" },
    {},
    ""
));
assert(string_contains(
    "," + (&method_result)["matched_ids"] + ",",
    ",911100,"
));
assert(string_contains("," + (&method_result)["matched_ids"] + ",", ",949110,"));
assert((&method_result)["blocked"] == "1");
"#,
        "method_911",
    )
}

fn active_modsecurity_request_program() -> vm::Program {
    active_request_program(
        r#"
let modsecurity_result = inspect_request(new_state(
    "POST",
    "/api",
    "",
    "HTTP/1.1",
    "192.0.2.10",
    {
        "host": "shop.example.test",
        "content-type": "application/json",
        "user-agent": "pd-edge-waf-perf/1.0"
    },
    {},
    "{}"
));
assert(string_contains(
    "," + (&modsecurity_result)["matched_ids"] + ",",
    ",200001,"
));
assert((&modsecurity_result)["blocked"] == "0");
assert((&modsecurity_result)["reqbody_processor"] == "JSON");
"#,
        "modsecurity_200001",
    )
}

fn active_sqli_request_program() -> vm::Program {
    active_request_program(
        r#"
let sqli_result = inspect_request(new_state(
    "GET",
    "/search",
    "id=1%27%20OR%201%3D1--",
    "HTTP/1.1",
    "192.0.2.10",
    { "host": "shop.example.test", "user-agent": "pd-edge-waf-perf/1.0" },
    { "id": "1' OR 1=1--" },
    ""
));
assert(string_contains(
    "," + (&sqli_result)["matched_ids"] + ",",
    ",942100,"
));
assert(string_contains("," + (&sqli_result)["matched_ids"] + ",", ",949110,"));
assert((&sqli_result)["blocked"] == "1");
"#,
        "sqli_942",
    )
}

fn active_response_sqli_leak_program() -> vm::Program {
    active_request_program(
        r#"
let mut response_state = new_state(
    "GET",
    "/database-error",
    "",
    "HTTP/1.1",
    "192.0.2.10",
    { "host": "shop.example.test" },
    {},
    ""
);
response_state["response_status"] = "500";
response_state["response_headers"] = "content-type=text/html\n";
response_state["response_body"] = "You have an error in your SQL syntax;";
let response_result = inspect_response(response_state);
assert(string_contains(
    "," + (&response_result)["matched_ids"] + ",",
    ",951230,"
));
assert(string_contains("," + (&response_result)["matched_ids"] + ",", ",959100,"));
assert((&response_result)["blocked"] == "1");
"#,
        "response_sqli_951",
    )
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

fn run_rust_math_baseline() -> Duration {
    let mut value = black_box(0x9e37_79b9_7f4a_7c15_u64);
    let started = Instant::now();
    for index in 0..RUST_MATH_BASELINE_ITERATIONS {
        value = value
            .wrapping_mul(0xbf58_476d_1ce4_e5b9)
            .wrapping_add(index as u64)
            .rotate_left(17)
            ^ 0x94d0_49bb_1331_11eb;
    }
    black_box(value);
    started.elapsed()
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
    let execution_mode = if vm.has_aot_program() {
        "aot"
    } else if vm.jit_config().enabled {
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
    let mut rust_math_samples = Vec::with_capacity(config.measured_batches);
    for _ in 0..config.measured_batches {
        let before = run_rust_math_baseline();
        batches.push(run_batch(&mut vm, expected, label, config.batch_size));
        let after = run_rust_math_baseline();
        rust_math_samples.push(before.saturating_add(after).div_f64(2.0));
    }

    let jit_after = JitCompilationState::capture(&vm);
    if vm.jit_config().enabled {
        assert_eq!(
            jit_after, jit_before,
            "{label} compiled new JIT traces inside the measured region"
        );
        TraceShapeStats::capture(&vm).print(label);
        println!(
            "jit_bridge_stats label={label} hits={:?}",
            vm.jit_native_bridge_stats_snapshot()
        );
        let snapshot = vm.jit_snapshot();
        let mut op_executions = std::collections::BTreeMap::<String, u64>::new();
        for trace in &snapshot.traces {
            for op in trace.op_names() {
                let executions = op_executions.entry(op.to_string()).or_default();
                *executions = executions.saturating_add(trace.executions);
            }
        }
        println!(
            "jit_specialized_ops label={label} call={} regex_match={} string_contains={}",
            op_executions.get("call").copied().unwrap_or(0),
            op_executions.get("regex_match").copied().unwrap_or(0),
            op_executions.get("string_contains").copied().unwrap_or(0),
        );
        let mut weighted_ops = op_executions.into_iter().collect::<Vec<_>>();
        weighted_ops.sort_by_key(|(_, executions)| std::cmp::Reverse(*executions));
        println!(
            "jit_weighted_ops label={label} top={:?}",
            weighted_ops.into_iter().take(20).collect::<Vec<_>>()
        );
        let mut nyi_reasons = std::collections::BTreeMap::<String, usize>::new();
        for line in vm
            .dump_jit_info()
            .lines()
            .filter(|line| line.trim_start().starts_with("nyi "))
        {
            let reason = line
                .split_once(" reason=")
                .map(|(_, reason)| reason)
                .unwrap_or("unknown");
            *nyi_reasons.entry(reason.to_string()).or_default() += 1;
        }
        println!("jit_nyi_reasons label={label} counts={nyi_reasons:?}");
        if std::env::var_os("WAF_PERF_DUMP_NYI_IPS").is_some() {
            let disassembly = vm::disassemble_program(vm.program());
            for attempt in snapshot.attempts.iter().filter(|attempt| {
                attempt
                    .result
                    .as_ref()
                    .err()
                    .is_some_and(|reason| reason.message().contains("less-than operands"))
            }) {
                let instruction = disassembly
                    .lines()
                    .find(|line| {
                        line.starts_with(&format!("{:04}\t", attempt.root_ip))
                            || line.starts_with(&format!("{:04} ", attempt.root_ip))
                    })
                    .unwrap_or("");
                println!(
                    "jit_nyi_ip label={label} root_ip={} stack_depth={} line={:?} disasm={instruction}",
                    attempt.root_ip, attempt.entry_stack_depth, attempt.line,
                );
            }
        }
        let mut traces = snapshot.traces.clone();
        traces.sort_by_key(|trace| std::cmp::Reverse(trace.executions));
        for trace in traces.into_iter().take(15) {
            println!(
                "jit_hot_trace label={label} root_ip={} line={:?} executions={} ops={:?} ssa={}",
                trace.root_ip,
                trace.start_line,
                trace.executions,
                trace.op_names,
                trace.ssa_text().replace('\n', " | ")
            );
        }
        if std::env::var_os("WAF_PERF_DUMP_EXIT_IPS").is_some() {
            let mut exit_ip_weights: std::collections::BTreeMap<usize, u64> =
                std::collections::BTreeMap::new();
            for trace in &snapshot.traces {
                if let Some(exit_ip) = trace.terminal_call_exit_ip() {
                    let weight = exit_ip_weights.entry(exit_ip).or_default();
                    *weight = weight.saturating_add(trace.executions);
                }
            }
            let mut ranked: Vec<(usize, u64)> = exit_ip_weights.into_iter().collect();
            ranked.sort_by_key(|(_, weight)| std::cmp::Reverse(*weight));
            let disassembly = vm::disassemble_program(vm.program());
            println!(
                "jit_exit_ip_weights label={label} top={:?}",
                ranked.iter().take(15).collect::<Vec<_>>()
            );
            for (ip, weight) in ranked.into_iter().take(15) {
                let line = disassembly
                    .lines()
                    .find(|line| {
                        line.starts_with(&format!("{ip:04}\t"))
                            || line.starts_with(&format!("{ip:04} "))
                    })
                    .unwrap_or("");
                println!("jit_exit_ip_target label={label} ip={ip} weight={weight} disasm={line}");
                for trace in snapshot
                    .traces
                    .iter()
                    .filter(|trace| trace.terminal_call_exit_ip() == Some(ip))
                    .take(3)
                {
                    println!(
                        "jit_exit_ip_trace label={label} ip={ip} root_ip={} line={:?} executions={} ops={:?}",
                        trace.root_ip,
                        trace.start_line,
                        trace.executions,
                        trace.op_names(),
                    );
                }
            }
        }
    }

    let total_duration: Duration = batches.iter().copied().sum();
    let total_requests = config.measured_batches * config.batch_size;
    let average_request = total_duration.div_f64(total_requests as f64);
    let rust_math_average = rust_math_samples
        .iter()
        .copied()
        .sum::<Duration>()
        .div_f64(rust_math_samples.len() as f64);
    let stats = PerfStats {
        average_request,
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
        rust_math_average,
        normalized_to_rust_math: average_request.as_secs_f64()
            / rust_math_average.as_secs_f64().max(f64::EPSILON),
    };

    println!(
        "{label} mode={execution_mode} warmup_requests={warmup_requests} batches={} batch_size={} requests={} average_us={:.3} min_batch_average_us={:.3} max_batch_average_us={:.3} rust_math_iterations={} rust_math_average_us={:.3} normalized_to_rust_math={:.6} jit_attempts={} recorded_traces={} native_traces={} regex_cache_entries={} regex_compile_count={} regex_cache_hits={}",
        config.measured_batches,
        config.batch_size,
        total_requests,
        stats.average_request.as_secs_f64() * 1_000_000.0,
        stats.min_batch_average.as_secs_f64() * 1_000_000.0,
        stats.max_batch_average.as_secs_f64() * 1_000_000.0,
        RUST_MATH_BASELINE_ITERATIONS,
        stats.rust_math_average.as_secs_f64() * 1_000_000.0,
        stats.normalized_to_rust_math,
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

fn median_paired_ratio(numerators: &[Duration], denominators: &[Duration]) -> f64 {
    assert_eq!(numerators.len(), denominators.len());
    assert!(!numerators.is_empty());
    let mut ratios = numerators
        .iter()
        .zip(denominators)
        .map(|(numerator, denominator)| {
            numerator.as_secs_f64() / denominator.as_secs_f64().max(f64::EPSILON)
        })
        .collect::<Vec<_>>();
    ratios.sort_by(f64::total_cmp);
    let midpoint = ratios.len() / 2;
    if ratios.len() % 2 == 0 {
        (ratios[midpoint - 1] + ratios[midpoint]) / 2.0
    } else {
        ratios[midpoint]
    }
}

fn run_active_rule_workload_perf(label: &str, program: vm::Program, config: &PerfConfig) {
    let expected = Value::string("matched");
    println!(
        "active_waf_program workload={label} local_count={} code_bytes={} constants={}",
        program.local_count,
        program.code.len(),
        program.constants.len(),
    );

    let interpreter = measure_case(
        &format!("active_{label}_interpreter"),
        Vm::new_with_jit_config(
            program.clone(),
            JitConfig {
                enabled: false,
                ..JitConfig::default()
            },
        ),
        WarmupPolicy::Fixed,
        config,
        &expected,
    );

    let mut jit = Vm::new_with_jit_config(
        program.clone(),
        JitConfig {
            max_trace_len: 256,
            ..JitConfig::default()
        },
    );
    run_jit_warmup_until_stable(&mut jit, &expected, &format!("active_{label}_jit"), config);

    let mut aot = Vm::new_with_jit_config(
        program,
        JitConfig {
            enabled: false,
            ..JitConfig::default()
        },
    );
    let aot_compile_started = Instant::now();
    aot.compile_aot()
        .unwrap_or_else(|error| panic!("active {label} AOT should compile: {error}"));
    let aot_compile_elapsed = aot_compile_started.elapsed();
    let aot_info = aot.dump_aot_info();
    assert!(
        aot_info.contains("lowering=interpreter-boundary"),
        "active {label} AOT should select boundary lowering: {aot_info}"
    );
    run_fixed_warmup(
        &mut aot,
        &expected,
        &format!("active_{label}_aot"),
        config.fixed_warmup_requests(),
    );

    let requests = config.measured_batches.saturating_mul(config.batch_size);
    let mut jit_samples = Vec::with_capacity(requests);
    let mut aot_samples = Vec::with_capacity(requests);
    // Interleave every request and alternate ordering so runner load and thermal
    // drift affect both modes symmetrically before taking the paired median.
    for sample in 0..requests {
        if sample % 2 == 0 {
            jit_samples.push(run_batch(
                &mut jit,
                &expected,
                &format!("active_{label}_jit"),
                1,
            ));
            aot_samples.push(run_batch(
                &mut aot,
                &expected,
                &format!("active_{label}_aot"),
                1,
            ));
        } else {
            aot_samples.push(run_batch(
                &mut aot,
                &expected,
                &format!("active_{label}_aot"),
                1,
            ));
            jit_samples.push(run_batch(
                &mut jit,
                &expected,
                &format!("active_{label}_jit"),
                1,
            ));
        }
    }

    let jit_elapsed = jit_samples.iter().copied().sum::<Duration>();
    let aot_elapsed = aot_samples.iter().copied().sum::<Duration>();
    let jit_average = jit_elapsed.div_f64(requests as f64);
    let aot_average = aot_elapsed.div_f64(requests as f64);
    let aot_to_jit = aot_average.as_secs_f64() / jit_average.as_secs_f64().max(f64::EPSILON);
    let paired_median_ratio = median_paired_ratio(&aot_samples, &jit_samples);
    let aot_regression = paired_median_ratio > 1.05;
    let targets_met = !aot_regression && jit_average <= Duration::from_millis(1);
    println!(
        "active_waf_comparison workload={label} requests={requests} interpreter_average_us={:.3} jit_average_us={:.3} aot_average_us={:.3} aot_to_jit_ratio={aot_to_jit:.3} paired_median_aot_to_jit_ratio={paired_median_ratio:.3} aot_regression={aot_regression} aot_compile_ms={:.3} jit_under_1ms={} aot_under_1ms={} targets_met={targets_met}",
        interpreter.average_request.as_secs_f64() * 1_000_000.0,
        jit_average.as_secs_f64() * 1_000_000.0,
        aot_average.as_secs_f64() * 1_000_000.0,
        aot_compile_elapsed.as_secs_f64() * 1_000.0,
        jit_average <= Duration::from_millis(1),
        aot_average <= Duration::from_millis(1),
    );
    let enforce_targets = std::env::var("WAF_PERF_ENFORCE_TARGETS")
        .map(|value| value != "0")
        .unwrap_or(true);
    if enforce_targets {
        assert!(
            !aot_regression,
            "active {label} AOT latency exceeds JIT tolerance: paired_median_ratio={paired_median_ratio:.3}, aggregate_ratio={aot_to_jit:.3}"
        );
    }
}

fn run_active_rule_perf() {
    let config = PerfConfig::from_env();
    run_active_rule_workload_perf(
        "modsecurity_200001",
        active_modsecurity_request_program(),
        &config,
    );
    run_active_rule_workload_perf("method_911", active_method_request_program(), &config);
    run_active_rule_workload_perf("sqli_942", active_sqli_request_program(), &config);
    run_active_rule_workload_perf(
        "response_sqli_951",
        active_response_sqli_leak_program(),
        &config,
    );
}

fn run_default_ruleset_perf() {
    let config = PerfConfig::from_env();
    let baseline_program = baseline_request_program();
    let default_ruleset_program = default_request_program();
    if std::env::var_os("WAF_PERF_DUMP_CALLS").is_some() {
        let re_match_index = vm::builtin_call_index("re::match");
        let disassembly = vm::disassemble_program(&default_ruleset_program);
        let re_match_calls = re_match_index
            .map(|index| disassembly.matches(&format!("call {index} ")).count())
            .unwrap_or(0);
        println!("re_match_builtin_index={re_match_index:?} bytecode_calls={re_match_calls}",);
        for line in disassembly
            .lines()
            .filter(|line| line.contains("call"))
            .take(60)
        {
            println!("waf_call {line}");
        }
    }
    println!(
        "waf_program_shape local_count={} code_bytes={} constants={}",
        default_ruleset_program.local_count,
        default_ruleset_program.code.len(),
        default_ruleset_program.constants.len(),
    );
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
    let mut jit_vm = Vm::new_with_jit_config(
        default_ruleset_program.clone(),
        JitConfig {
            max_trace_len: 256,
            ..JitConfig::default()
        },
    );
    if std::env::var_os("WAF_PERF_BRIDGE_STATS").is_some() {
        jit_vm.set_jit_native_bridge_stats_enabled(true);
    }
    let jit = measure_case(
        "default_ruleset_jit_perf",
        jit_vm,
        WarmupPolicy::JitUntilStable,
        &config,
        &expected,
    );

    let interpreter_incremental = incremental_average(&interpreter, &baseline);
    let jit_incremental = incremental_average(&jit, &baseline);
    let jit_to_interpreter_ratio = jit.average_request.as_secs_f64()
        / interpreter.average_request.as_secs_f64().max(f64::EPSILON);
    let normalized_jit_to_interpreter_ratio =
        jit.normalized_to_rust_math / interpreter.normalized_to_rust_math.max(f64::EPSILON);
    println!(
        "waf_comparison_perf baseline_average_us={:.3} interpreter_average_us={:.3} interpreter_incremental_us={:.3} jit_average_us={:.3} jit_incremental_us={:.3} jit_to_interpreter_ratio={jit_to_interpreter_ratio:.3} interpreter_normalized_to_rust_math={:.6} jit_normalized_to_rust_math={:.6} normalized_jit_to_interpreter_ratio={normalized_jit_to_interpreter_ratio:.3}",
        baseline.average_request.as_secs_f64() * 1_000_000.0,
        interpreter.average_request.as_secs_f64() * 1_000_000.0,
        interpreter_incremental.as_secs_f64() * 1_000_000.0,
        jit.average_request.as_secs_f64() * 1_000_000.0,
        jit_incremental.as_secs_f64() * 1_000_000.0,
        interpreter.normalized_to_rust_math,
        jit.normalized_to_rust_math,
    );

    if std::env::var_os("WAF_PERF_AOT_DIAG").is_some() {
        let mut aot_vm = Vm::new_with_jit_config(
            default_request_program(),
            JitConfig {
                enabled: false,
                ..JitConfig::default()
            },
        );
        let aot_compile_started = Instant::now();
        aot_vm
            .compile_aot()
            .expect("WAF AOT diagnostic should compile");
        let aot_compile_elapsed = aot_compile_started.elapsed();
        let aot_info = aot_vm.dump_aot_info();
        assert!(
            aot_info.contains("lowering=interpreter-boundary"),
            "oversized WAF AOT should select the boundary lowering: {aot_info}"
        );
        println!(
            "waf_aot_compile elapsed_ms={:.3} lowering=interpreter-boundary",
            aot_compile_elapsed.as_secs_f64() * 1_000.0,
        );
        let aot = measure_case(
            "default_ruleset_aot_diag",
            aot_vm,
            WarmupPolicy::Fixed,
            &config,
            &expected,
        );
        println!(
            "waf_aot_diag average_us={:.3} aot_to_interpreter_ratio={:.3}",
            aot.average_request.as_secs_f64() * 1_000_000.0,
            aot.average_request.as_secs_f64()
                / interpreter.average_request.as_secs_f64().max(f64::EPSILON),
        );

        let mut paired_jit = Vm::new_with_jit_config(
            default_request_program(),
            JitConfig {
                max_trace_len: 256,
                ..JitConfig::default()
            },
        );
        run_jit_warmup_until_stable(
            &mut paired_jit,
            &expected,
            "default_ruleset_jit_paired",
            &config,
        );
        let mut paired_aot = Vm::new_with_jit_config(
            default_request_program(),
            JitConfig {
                enabled: false,
                ..JitConfig::default()
            },
        );
        paired_aot
            .compile_aot()
            .expect("paired WAF AOT diagnostic should compile");
        run_fixed_warmup(
            &mut paired_aot,
            &expected,
            "default_ruleset_aot_paired",
            config.fixed_warmup_requests(),
        );

        let mut paired_jit_elapsed = Duration::ZERO;
        let mut paired_aot_elapsed = Duration::ZERO;
        for batch in 0..config.measured_batches {
            if batch % 2 == 0 {
                paired_jit_elapsed += run_batch(
                    &mut paired_jit,
                    &expected,
                    "default_ruleset_jit_paired",
                    config.batch_size,
                );
                paired_aot_elapsed += run_batch(
                    &mut paired_aot,
                    &expected,
                    "default_ruleset_aot_paired",
                    config.batch_size,
                );
            } else {
                paired_aot_elapsed += run_batch(
                    &mut paired_aot,
                    &expected,
                    "default_ruleset_aot_paired",
                    config.batch_size,
                );
                paired_jit_elapsed += run_batch(
                    &mut paired_jit,
                    &expected,
                    "default_ruleset_jit_paired",
                    config.batch_size,
                );
            }
        }
        let paired_requests = config.measured_batches.saturating_mul(config.batch_size);
        let paired_jit_average = paired_jit_elapsed.div_f64(paired_requests as f64);
        let paired_aot_average = paired_aot_elapsed.div_f64(paired_requests as f64);
        let paired_ratio =
            paired_aot_average.as_secs_f64() / paired_jit_average.as_secs_f64().max(f64::EPSILON);
        println!(
            "waf_aot_jit_paired jit_average_us={:.3} aot_average_us={:.3} aot_to_jit_ratio={paired_ratio:.3}",
            paired_jit_average.as_secs_f64() * 1_000_000.0,
            paired_aot_average.as_secs_f64() * 1_000_000.0,
        );
        assert!(
            paired_ratio <= 1.05,
            "paired AOT latency must not exceed JIT by more than measurement tolerance: ratio={paired_ratio:.3}"
        );
    }
}

#[test]
fn paired_ratio_uses_median_to_reject_outliers() {
    let jit = [
        Duration::from_millis(100),
        Duration::from_millis(100),
        Duration::from_millis(100),
        Duration::from_millis(100),
    ];
    let aot = [
        Duration::from_millis(90),
        Duration::from_millis(100),
        Duration::from_millis(110),
        Duration::from_secs(10),
    ];
    assert!((median_paired_ratio(&aot, &jit) - 1.05).abs() < 1e-12);
}

#[test]
fn vm_dependency_specializes_regex_match() {
    if !JitConfig::default().enabled {
        return;
    }
    let compiled = vm::compile_source(
        r#"
use re;
let mut i = 0;
let mut matched = false;
while i < 8 {
    matched = re::match("(?i)^rustscript$", "RustScript");
    i = i + 1;
}
matched;
"#,
    )
    .expect("regex specialization fixture should compile");
    let mut vm = Vm::new_with_jit_config(
        compiled.program,
        JitConfig {
            enabled: true,
            hot_loop_threshold: 1,
            max_trace_len: 512,
        },
    );
    assert_eq!(
        vm.run().expect("regex fixture should run"),
        VmStatus::Halted
    );
    assert_eq!(vm.stack(), &[Value::Bool(true)]);
    let snapshot = vm.jit_snapshot();
    assert!(
        snapshot
            .traces
            .iter()
            .any(|trace| trace.op_names().iter().any(|op| op == "regex_match")),
        "pd-edge-waf VM dependency should specialize regex match:\n{}",
        vm.dump_jit_info()
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
fn active_rule_workloads_prove_matched_rule_ids() {
    let expected = Value::string("matched");
    for (label, program) in [
        ("modsecurity_200001", active_modsecurity_request_program()),
        ("method_911", active_method_request_program()),
        ("sqli_942", active_sqli_request_program()),
        ("response_sqli_951", active_response_sqli_leak_program()),
    ] {
        let mut vm = Vm::new(program);
        execute_and_verify(&mut vm, &expected, label);
    }
}

#[test]
#[ignore = "performance test; run explicitly with --ignored --nocapture"]
fn active_rule_interpreter_jit_aot_latency() {
    run_active_rule_perf();
}

#[test]
#[ignore = "performance test; run explicitly with --ignored --nocapture"]
fn baseline_interpreter_and_jit_batch_latency() {
    run_default_ruleset_perf();
}
