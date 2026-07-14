use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use vm::{JitConfig, Value, Vm, VmStatus};

const DEFAULT_WARMUP_BATCHES: usize = 1;
const DEFAULT_MEASURED_BATCHES: usize = 5;
const DEFAULT_BATCH_SIZE: usize = 2;

struct PerfConfig {
    warmup_batches: usize,
    measured_batches: usize,
    batch_size: usize,
}

impl PerfConfig {
    fn from_env() -> Self {
        Self {
            warmup_batches: env_usize("WAF_PERF_WARMUP_BATCHES", DEFAULT_WARMUP_BATCHES, 1),
            measured_batches: env_usize("WAF_PERF_BATCHES", DEFAULT_MEASURED_BATCHES, 2),
            batch_size: env_usize("WAF_PERF_BATCH_SIZE", DEFAULT_BATCH_SIZE, 2),
        }
    }
}

fn env_usize(name: &str, default: usize, minimum: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
        .max(minimum)
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

fn run_and_verify(vm: &mut Vm, expected: &Value) {
    let status = vm.run().unwrap_or_else(|error| {
        let line = vm
            .debug_info()
            .and_then(|info| info.line_for_offset(vm.ip()));
        panic!(
            "default ruleset perf request failed at ip {}, line {line:?}: {error:?}",
            vm.ip()
        );
    });
    assert_eq!(status, VmStatus::Halted);
    assert_eq!(vm.stack().last(), Some(expected));
}

fn run_batch(vm: &mut Vm, expected: &Value, batch_size: usize) -> Duration {
    let started = Instant::now();
    for request_index in 0..batch_size {
        let status = black_box(
            vm.run()
                .expect("default ruleset measured request should execute"),
        );
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

fn run_default_ruleset_perf() {
    let config = PerfConfig::from_env();
    let program = default_request_program();
    let expected = Value::string("allow");
    let mut vm = Vm::new_with_jit_config(
        program,
        JitConfig {
            enabled: false,
            ..JitConfig::default()
        },
    );

    for _ in 0..config.warmup_batches {
        for _ in 0..config.batch_size {
            run_and_verify(&mut vm, &expected);
            vm.reset_for_reuse();
        }
    }

    let mut batches = Vec::with_capacity(config.measured_batches);
    for _ in 0..config.measured_batches {
        batches.push(run_batch(&mut vm, &expected, config.batch_size));
    }

    let total_duration: Duration = batches.iter().copied().sum();
    let total_requests = config.measured_batches * config.batch_size;
    let average_request = total_duration.div_f64(total_requests as f64);
    let min_batch_average = batches
        .iter()
        .copied()
        .min()
        .expect("at least two measured batches")
        .div_f64(config.batch_size as f64);
    let max_batch_average = batches
        .iter()
        .copied()
        .max()
        .expect("at least two measured batches")
        .div_f64(config.batch_size as f64);

    println!(
        "default_ruleset_perf mode=interpreter batches={} batch_size={} requests={} average_us={:.3} min_batch_average_us={:.3} max_batch_average_us={:.3}",
        config.measured_batches,
        config.batch_size,
        total_requests,
        average_request.as_secs_f64() * 1_000_000.0,
        min_batch_average.as_secs_f64() * 1_000_000.0,
        max_batch_average.as_secs_f64() * 1_000_000.0,
    );
}

#[test]
#[ignore = "performance test; run explicitly with --ignored --nocapture"]
fn default_ruleset_batch_latency() {
    run_default_ruleset_perf();
}
