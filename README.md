# pd-edge-waf

`pd-edge-waf` converts OWASP Core Rule Set 4.28.0 directives into executable RustScript category functions for `pd-edge`.

The request path does **not** parse ModSecurity configuration. Conversion happens ahead of time in `tools/convert_crs.py`; the generated RSS functions evaluate enabled categories directly, update transaction state, accumulate anomaly scores, and return allow/block decisions.

## Generated coverage

The repository tracks all active directives from the pinned minimal CRS release:

- 27 source categories;
- 695 `SecRule` directives;
- 7 `SecAction` directives;
- 30 `SecMarker` directives;
- 55 `SecRuleUpdateTargetById` directives;
- 1 `SecComponentSignature` directive;
- 788 directives total;
- 21 CRS data files.

`rules/manifest.json` and `rules/directives.json` provide machine-readable coverage details.

## Enabled ruleset

The standard VM bytecode format has 256 local slots. The converter therefore builds `rules/ruleset.rss` from an explicit set of enabled category modules instead of modifying the VM or compiling every CRS category into one program.

The committed entrypoint enables:

- `request_911_method_enforcement`
- `request_942_application_attack_sqli`

Build another enabled set by repeating `--enable`:

```bash
python3 tools/convert_crs.py \
  --source-dir /path/to/coreruleset-4.28.0/rules \
  --output-dir rules \
  --version 4.28.0 \
  --enable request_911_method_enforcement \
  --enable request_930_application_attack_lfi \
  --enable request_941_application_attack_xss \
  --enable request_942_application_attack_sqli

python3 tools/bundle_engine.py
```

The selected set is recorded in `rules/manifest.json`. `rules/ruleset.rss` contains direct RSS expressions for those categories; `rules/pd_edge_waf.rss` is the standalone pd-edge entrypoint.

At request time, `x-waf-enabled-ruleset` can narrow the compiled set further. Its value is a space-separated list of category module names. If the header is absent, every category compiled into the entrypoint is active.

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
  -H 'x-waf-enabled-ruleset: request_942_application_attack_sqli' \
  -H 'x-waf-upstream-host: 127.0.0.1' \
  -H 'x-waf-upstream-port: 18080'
```

Blocked responses return HTTP 403 with:

- `x-waf-blocked: 1`
- `x-waf-score`
- `x-waf-matched-ids`

Allowed traffic is forwarded and carries `x-waf-blocked: 0` plus its current score.

## Performance test

The pd-vm performance test compiles both cases outside the timed region and evaluates the same fixed benign request context using pd-vm's default execution configuration (trace JIT on supported native targets, interpreter elsewhere). It always measures the framework baseline first. The baseline constructs and validates the simulated request context in RSS without loading any WAF rules or calling `inspect_request`. The second case executes the committed default enabled ruleset.

```bash
cargo test --release --test perf -- --ignored --nocapture
```

Defaults:

- 1 warmup batch;
- 5 measured batches;
- 2 requests per batch;
- 10 measured requests in total.

Each case runs warmup traffic followed by multiple measured batches. The output reports both average latencies, minimum/maximum batch averages, incremental WAF latency, and the default-ruleset-to-baseline ratio. Batch counts can be overridden without editing the test:

```bash
WAF_PERF_WARMUP_BATCHES=2 \
WAF_PERF_BATCHES=10 \
WAF_PERF_BATCH_SIZE=4 \
cargo test --release --test perf -- --ignored --nocapture
```

Compilation latency is excluded. Both cases rebuild the simulated request context inside RSS for every measured request.

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
- `rules/ruleset.rss`: direct evaluator for the configured enabled categories.
- `rules/request_*.rss`, `rules/response_*.rss`: generated category functions.
- `rules/engine*.rss`: RSS target, transform, operator, chain, score, and transaction-state implementation.
- `tools/convert_crs.py`: build-time CRS-to-RSS converter.
- `tools/bundle_engine.py`: standalone RSS entrypoint builder.
- `tests/e2e.rs`: real pd-edge HTTP E2E.

## License and attribution

This project and its generated derivative files are licensed under Apache-2.0. The translated rule content is derived from the OWASP Core Rule Set; see `NOTICE` and `LICENSE`.
