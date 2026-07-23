# pd-edge-waf

`pd-edge-waf` converts OWASP Core Rule Set 4.28.0 directives into executable RustScript category functions for `pd-edge`.

The request path does **not** parse ModSecurity configuration. Conversion happens ahead of time in `tools/convert_crs.py`; the generated RSS functions evaluate enabled categories directly, update transaction state, accumulate anomaly scores, and return allow/block decisions.

## Generated coverage

The repository tracks the active rules from ModSecurity's recommended configuration and all directives from the pinned minimal CRS release:

- 28 source categories;
- 702 `SecRule` directives, including ModSecurity rules `200000`, `200001`, `200002`–`200005`, and `200007`;
- 7 `SecAction` directives;
- 30 `SecMarker` directives;
- 55 `SecRuleUpdateTargetById` directives;
- 1 `SecComponentSignature` directive;
- 795 directives total;
- 21 CRS data files.

`rules/manifest.json` and `rules/directives.json` provide machine-readable coverage details.

## Enabled ruleset

The committed entrypoint enables the full default set at paranoia level 1:

- ModSecurity recommended request-body and parser validation rules;
- CRS initialization and exclusions: `901`, `905`, and `999`;
- all request detection and blocking groups: `911`–`949`;
- all response detection, blocking, and correlation groups: `950`–`980`.

The generated phase tables keep the complete set within the VM's 256-slot bytecode format. Every table row carries its original category and rule ID. Runtime selection via `x-waf-enabled-ruleset` still works, while an absent header activates every compiled category.

Build a deliberately narrowed set by repeating `--enable`:

```bash
python3 tools/convert_crs.py \
  --source-dir /path/to/coreruleset-4.28.0/rules \
  --output-dir rules \
  --version 4.28.0 \
  --enable modsecurity_recommended \
  --enable request_901_initialization \
  --enable request_911_method_enforcement \
  --enable request_942_application_attack_sqli \
  --enable request_949_blocking_evaluation

python3 tools/bundle_engine.py
```

The selected set is recorded in `rules/manifest.json`. `rules/ruleset.rss` contains the phase tables; `rules/pd_edge_waf.rss` is the standalone pd-edge entrypoint.

## Run with pd-edge

Start the real pd-edge HTTP runtime:

```bash
cargo run --release \
  --manifest-path ../pd-edge/Cargo.toml \
  --bin pd-edge-http-proxy
```

Compile and upload the standalone RSS entrypoint using pd-edge's standard uploader:

```bash
cargo run --release \
  --manifest-path ../pd-edge/Cargo.toml \
  --example build_sample_program -- \
  "$PWD/rules/pd_edge_waf.rss"
```

Send a request through the data plane. The entrypoint forwards allowed traffic to the upstream selected by `x-waf-upstream-host` and `x-waf-upstream-port`:

```bash
curl -i 'http://127.0.0.1:8080/search?id=1%27%20OR%201%3D1--' \
  -H 'x-waf-enabled-ruleset: request_942_application_attack_sqli request_949_blocking_evaluation' \
  -H 'x-waf-upstream-host: 127.0.0.1' \
  -H 'x-waf-upstream-port: 18080'
```

Blocked responses return HTTP 403 with:

- `x-waf-blocked: 1`
- `x-waf-score`
- `x-waf-matched-ids`

Allowed traffic is forwarded and carries `x-waf-blocked: 0` plus its current score.

## Performance test

The primary pd-vm performance test compiles all programs outside the timed region and measures four full-default workloads. Each fixture verifies the original rule IDs and final blocking decision:

1. JSON `POST /api` records ModSecurity rule `200001`;
2. `TRACE /` records CRS `911100`, reaches `949110`, and blocks;
3. `GET /search?id=1%27%20OR%201%3D1--` records `942100`, reaches `949110`, and blocks;
4. a simulated SQL error response records `951230`, reaches `959100`, and blocks.

No synthetic attack probe or category admission regex is used. Every request traverses the compiled default phase tables. Each workload is measured in interpreter mode, warmed trace-JIT mode, and interleaved JIT/AOT mode. AOT compile latency is reported separately. The rule-ID assertions also run as a regular non-ignored test.

```bash
cargo test --release --test perf active_rule_interpreter_jit_aot_latency -- --ignored --nocapture
```

### Reference results

The following results are from the latest verified 100-request run on commit `7c76b88`, with 2 warmup batches, 10 measured batches, 10 requests per batch, 12 unchanged JIT warmup requests, and a 128-request JIT warmup limit. Latencies are milliseconds per request; compilation is excluded.

| Full-default workload | Interpreter (ms) | JIT (ms) | AOT (ms) | Aggregate AOT/JIT | Paired-median AOT/JIT |
| --- | ---: | ---: | ---: | ---: | ---: |
| ModSecurity `200001` | 158.565 | 141.693 | 137.027 | 0.967 | 0.997 |
| CRS `911100 -> 949110` | 154.174 | 165.293 | 162.599 | 0.984 | 0.999 |
| CRS `942100 -> 949110` | 193.642 | 187.935 | 185.878 | 0.989 | 1.001 |
| CRS `951230 -> 959100` | 29.395 | 36.462 | 36.217 | 0.993 | 1.000 |

All four workloads completed with no paired-median AOT regression above the 1.05 tolerance. The warmed JIT reported `recorded_traces=0` and `native_traces=0` for each workload.

Benchmark host:

- CPU: AMD Ryzen 9 7940HS with Radeon 780M Graphics, 8 cores / 16 threads visible to the guest;
- virtualization: Microsoft full-virtualization hypervisor;
- memory: 3.8 GiB assigned to the guest;
- OS: Ubuntu 24.04.4 LTS, Linux `6.8.0-136-generic` x86_64;
- Rust: `rustc 1.94.1`, `cargo 1.94.1`;
- dependencies: RustScript `964d8ec`, pd-edge `96b65ed`.

### Historical targeted-path result

Before the benchmark expanded to the full default phase tables, commit `60e3418` measured a specialized active method-enforcement bundle on the same host. The `TRACE /` fixture executed the original CRS rule `911100` and asserted its matched rule ID over 1,000 measured requests.

| Targeted workload | JIT (ms) | AOT (ms) | AOT/JIT |
| --- | ---: | ---: | ---: |
| CRS method enforcement, `TRACE /` -> `911100` | **0.887** | **0.890** | 1.003 |

This is the verified sub-millisecond result. Its targeted bundle scope is intentionally reported separately and is not directly comparable to the full-default results above.

The benign full-default benchmark remains available as a secondary diagnostic:

```bash
WAF_PERF_AOT_DIAG=1 cargo test --release --test perf baseline_interpreter_and_jit_batch_latency -- --ignored --nocapture
```

Defaults:

- 1 warmup batch;
- 5 measured batches;
- 2 requests per batch;
- 10 measured requests per workload;
- 12 consecutive unchanged JIT warmup requests;
- at most 128 JIT warmup requests.

The output reports each mode's average latency, minimum/maximum batch averages, JIT compilation state, and AOT/JIT ratio. Counts can be overridden without editing the test:

```bash
WAF_PERF_ENFORCE_TARGETS=0 \
WAF_PERF_WARMUP_BATCHES=2 \
WAF_PERF_BATCHES=10 \
WAF_PERF_BATCH_SIZE=10 \
WAF_PERF_JIT_STABLE_REQUESTS=3 \
WAF_PERF_JIT_MAX_WARMUP_REQUESTS=48 \
cargo test --release --test perf active_rule_interpreter_jit_aot_latency -- --ignored --nocapture
```

Compilation latency is excluded. Every active workload rebuilds its simulated transaction state inside RSS for each measured request. By default, a paired-median AOT/JIT ratio above 1.05 fails the benchmark; `WAF_PERF_ENFORCE_TARGETS=0` keeps the run diagnostic and reports unmet targets without stopping later workloads.

## Tests

Run the VM and real HTTP end-to-end tests:

```bash
cargo test --release --test smoke
cargo test --release --test e2e
```

`tests/e2e.rs` starts actual pd-edge data/admin listeners and an upstream fixture, compiles and uploads `rules/pd_edge_waf.rss`, then verifies:

- benign traffic reaches the upstream;
- a disallowed HTTP method returns 403;
- SQL injection receives anomaly score 5 and returns 403;
- blocked traffic never reaches the upstream.

For deterministic regeneration against the pinned CRS archive:

```bash
bash tools/smoke.sh
```

## Layout

- `rules/pd_edge_waf.rss`: standalone pd-edge entrypoint.
- `rules/ruleset.rss`: phase-table evaluator for the configured categories.
- `rules/request_*.rss`, `rules/response_*.rss`: generated category functions.
- `rules/engine*.rss`: RSS target, transform, operator, chain, score, and transaction-state implementation.
- `tools/convert_crs.py`: build-time CRS-to-RSS converter.
- `tools/bundle_engine.py`: standalone RSS entrypoint builder.
- `tests/e2e.rs`: real pd-edge HTTP E2E.

## License and attribution

This project and its generated derivative files are licensed under Apache-2.0. The translated rule content is derived from the OWASP Core Rule Set; see `NOTICE` and `LICENSE`.
