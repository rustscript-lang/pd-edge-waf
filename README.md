# pd-edge-waf

`pd-edge-waf` is the OWASP Core Rule Set translated into category-scoped RustScript modules for `pd-edge` and `pd-vm` hosts.

The repository is pinned to **OWASP CRS 4.28.0**. Its generated RustScript set contains:

- 27 source categories, kept in separate `.rss` files;
- 695 `SecRule` directives;
- 7 `SecAction` directives;
- 30 `SecMarker` directives;
- 55 `SecRuleUpdateTargetById` directives;
- 1 `SecComponentSignature` directive;
- 788 active directives in total;
- 21 associated CRS data files.

## Layout

- `rules/ruleset.rss` loads every category and checks the total directive count.
- `rules/request_*.rss` and `rules/response_*.rss` mirror the original CRS category boundaries.
- `rules/data/` retains the phrase and signature lists used by `@pmFromFile` and related operators.
- `rules/manifest.json` records per-category and aggregate coverage.
- `rules/directives.json` is a machine-readable audit index of every translated directive.
- `tools/convert_crs.py` performs the deterministic ModSecurity-to-RustScript conversion.
- `tests/smoke.rs` compiles the complete ruleset, binds the WAF descriptor ABI, executes it in `pd-vm`, and verifies representative rule IDs and exact totals.

## RustScript WAF ABI

Every translated category is executable RustScript. It emits structured calls instead of embedding all ModSecurity text in one source file:

```rust
waf::rule(
    source_category,
    source_line,
    rule_id,
    phase,
    chain_index,
    targets,
    operator,
    pattern,
    actions,
    message,
);
```

`SecAction`, `SecMarker`, `SecRuleUpdateTargetById`, and `SecComponentSignature` map to `waf::action(...)`, `waf::marker(...)`, `waf::update_target(...)`, and `waf::component_signature(...)`. Chained rules retain their parent ID and chain position. Targets, operator, pattern, actions, message, source category, and source line remain independently available to the host.

A `pd-edge` host using these modules must register the five `waf::*` imports and implement the desired ModSecurity-compatible operators, transformations, transaction variables, anomaly scoring, skip markers, and disruptive actions. The smoke test supplies a strict descriptor host and proves that the complete translated ruleset compiles, binds, and runs through the VM.

## Verification

Run the local suite against an already downloaded CRS tree:

```bash
CRS_SOURCE_DIR=/path/to/coreruleset-4.28.0/rules bash tools/smoke.sh
```

With no `CRS_SOURCE_DIR`, the script downloads the pinned upstream release, verifies its SHA-256 digest, regenerates the full ruleset in a temporary directory, compares it byte-for-byte with the committed output, then runs Rust formatting and tests:

```bash
bash tools/smoke.sh
```

## Updating CRS

1. Update `CRS_VERSION`, release URL, and SHA-256 in `tools/smoke.sh`.
2. Run `tools/convert_crs.py` against the new release's `rules/` directory.
3. Update the version and expected counts in `src/lib.rs`, `tests/smoke.rs`, and this README.
4. Run `bash tools/smoke.sh`.

## License and attribution

This project and its generated derivative files are licensed under Apache-2.0. The translated rule content is derived from the OWASP Core Rule Set; see `NOTICE` and `LICENSE`.
