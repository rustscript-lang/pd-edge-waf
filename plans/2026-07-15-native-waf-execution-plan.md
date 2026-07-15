# Native WAF Execution Plan — pd-edge-waf

> **For Hermes:** Execute each stage with strict RED/GREEN verification and keep generated artifacts deterministic.

**Goal:** Compile OWASP CRS rules into a compact native execution plan and prove the design with the enabled 911 and 942 request categories.

**Architecture:** `tools/convert_crs.py` remains the CRS parser and emits both RSS and a versioned native-plan artifact. The first stage implements a Rust executor inside this repository so its semantics and performance can be compared directly with the current RSS evaluator before the runtime interface is promoted into pd-vm and pd-edge.

**Tech Stack:** Python generator, serde/serde_json, regex, Rust integration tests, pd-vm RSS baseline.

---

## Stage 1: 911 + 942 native executor spike

### Task 1: Define the generated plan schema

**Files:**
- Modify: `tools/convert_crs.py`
- Create: `rules/native_plan.json`
- Modify: `tests/smoke.rs`

**Steps:**
1. Add a failing test requiring a versioned native plan with the enabled 911 and 942 categories.
2. Require phase-indexed entries, decoded transforms, target descriptors, operator data, chain metadata, actions, markers, and folded target exclusions.
3. Run `cargo test --release --test smoke native_plan -- --nocapture` and verify RED.
4. Extend the generator and regenerate `rules/native_plan.json`.
5. Verify the plan contains the synthetic 942100 request-query detector plus the generated CRS entries in source order.
6. Re-run the targeted smoke test and verify GREEN.

### Task 2: Add fixed-layout native request and decision types

**Files:**
- Create: `src/native.rs`
- Modify: `src/lib.rs`
- Create: `tests/native_plan.rs`

**Steps:**
1. Write a failing test for loading the generated plan and evaluating a benign GET request.
2. Add typed request collections, transaction fields, score, block status, matched IDs, chain state, and skip marker state.
3. Keep request-time access indexed or typed; do not use the RSS `map<string>` transaction representation.
4. Verify benign output matches the RSS evaluator.

### Task 3: Implement 911 semantics

**Files:**
- Modify: `src/native.rs`
- Modify: `tests/native_plan.rs`

**Steps:**
1. Add RED cases for allowed GET and blocked TRACE.
2. Implement phase, paranoia, `@lt`, `!@within`, marker, score, and block actions.
3. Compare `blocked`, `score`, `status`, and `matched_ids` with RSS.
4. Verify GREEN.

### Task 4: Implement the 942 spike operator set

**Files:**
- Modify: `src/native.rs`
- Modify: `tests/native_plan.rs`

**Steps:**
1. Add RED cases for a benign query, synthetic 942100 SQLi, a regex rule match, and target exclusions.
2. Implement the enabled-category operator set: `@rx`, `!@rx`, `@streq`, `!@streq`, `@lt`, and `@detectSQLi`.
3. Implement the enabled transform set with behavior matching `rules/engine_text.rss`.
4. Implement request targets used by 942, including args, arg names, headers, cookies, filename, basename, body/XML, TX, and matched values.
5. Preserve source order, chain behavior, marker/skip behavior, anomaly score, and block status.
6. Verify native results against RSS fixtures.

### Task 5: Measure the spike

**Files:**
- Create: `tests/native_perf.rs`
- Modify: `README.md`

**Steps:**
1. Add an ignored perf comparison covering the same benign request used by `tests/perf.rs`.
2. Report RSS interpreter, RSS trace JIT, and native-plan latency separately.
3. Report rule count, regex asset count, request allocations when available, and decision equivalence.
4. Run both ignored perf targets in release mode.
5. Record only reproducible numbers; do not hard-code a performance threshold in the spike.

## Stage 2: Full CRS plan coverage

1. Expand the schema to response phases and all 27 categories.
2. Add remaining operators, transforms, data-file phrase sets, dynamic target updates, and response collections.
3. Differential-test the native plan against RSS with generated fixtures and real HTTP E2E.
4. Make unsupported plan entries fail at load time with rule ID and source location.

## Stage 3: Artifact ownership transition

1. Move the validated generic execution types into pd-vm after Stage 1 proves the interface.
2. Keep CRS-specific generation and fixtures in pd-edge-waf.
3. Emit a content-addressed plan artifact consumed by pd-edge alongside VMBC.

## Verification

```bash
python3 tools/convert_crs.py --source-dir .upstream/coreruleset-4.28.0/rules --output-dir rules --version 4.28.0 --enable request_911_method_enforcement --enable request_942_application_attack_sqli
cargo fmt --check
cargo test --release --test smoke
cargo test --release --test native_plan
cargo test --release --test e2e
cargo test --release --test perf -- --ignored --nocapture
cargo test --release --test native_perf -- --ignored --nocapture
```

## Acceptance criteria

- The plan is deterministic and versioned.
- Native and RSS decisions match for the Stage 1 fixture matrix.
- Runtime request state has fixed typed fields rather than RSS string-map state.
- Regex assets compile during plan load and are shared by executions.
- No CRS rule reordering is introduced.
