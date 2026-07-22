use pd_edge_waf::{CRS_VERSION, manifest};

#[test]
fn generated_crs_structure_is_complete() {
    let expected = manifest();
    assert_eq!(expected.version, CRS_VERSION);
    assert_eq!(
        expected.enabled_categories,
        [
            "request_911_method_enforcement",
            "request_942_application_attack_sqli",
        ]
    );
    assert_eq!(expected.category_count, 27);
    assert_eq!(expected.sec_rule_count, 695);
    assert_eq!(expected.sec_action_count, 7);
    assert_eq!(expected.sec_marker_count, 30);
    assert_eq!(expected.sec_rule_update_target_by_id_count, 55);
    assert_eq!(expected.sec_component_signature_count, 1);
    assert_eq!(expected.directive_count, 788);
    assert_eq!(expected.unique_rule_id_count, 629);
    assert_eq!(expected.chain_group_count, 55);
    assert_eq!(expected.chain_child_count, 73);
    assert_eq!(expected.skip_after_count, 206);
    assert_eq!(expected.tag_count, 3088);
    assert_eq!(expected.transformation_count, 839);
    assert_eq!(expected.operator_variant_count, 28);
    assert_eq!(expected.xml_attribute_target_rule_count, 175);
    assert_eq!(expected.pm_from_file_reference_count, 21);
    assert_eq!(expected.data_record_count, 6192);
    assert_eq!(expected.data_file_count, 21);
}

#[test]
fn generated_rules_preserve_all_crs_regex_operators() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(root.join("rules/directives.json"))
        .expect("generated directive manifest should be readable");
    let directives: Vec<serde_json::Value> =
        serde_json::from_str(&source).expect("generated directive manifest should be valid JSON");
    let positive = directives
        .iter()
        .filter(|directive| directive["kind"] == "SecRule" && directive["operator"] == "@rx")
        .count();
    let negative = directives
        .iter()
        .filter(|directive| directive["kind"] == "SecRule" && directive["operator"] == "!@rx")
        .count();
    assert_eq!(positive, 297);
    assert_eq!(negative, 21);
    assert_eq!(positive + negative, 318);

    let categories = directives
        .iter()
        .filter_map(|directive| directive["source"].as_str())
        .map(|source| {
            source
                .trim_end_matches(".conf")
                .to_ascii_lowercase()
                .replace('-', "_")
        })
        .collect::<std::collections::BTreeSet<_>>();
    let mut generated_positive = 0usize;
    let mut generated_negative = 0usize;
    for category in categories {
        let generated = std::fs::read_to_string(root.join("rules").join(format!("{category}.rss")))
            .expect("generated category module should be readable");
        let operator_codes = generated.lines().filter_map(|line| {
            line.split("], ")
                .nth(1)?
                .split(',')
                .next()?
                .parse::<usize>()
                .ok()
                .map(|target_spec| (target_spec % 16384) / 64)
        });
        for operator_code in operator_codes {
            if operator_code == 1 {
                generated_positive += 1;
            } else if operator_code == 33 {
                generated_negative += 1;
            }
        }
    }
    assert_eq!(generated_positive, 297);
    assert_eq!(generated_negative, 21);
}

#[test]
fn generated_rules_and_runtime_use_typed_rule_abi() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let rules = root.join("rules");
    for entry in std::fs::read_dir(&rules).expect("rules directory should be readable") {
        let path = entry.expect("rule entry should be readable").path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("rss") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("RSS source should be readable");
        assert!(
            !source.contains("apply_rule(next, ["),
            "{} still uses the array rule ABI",
            path.display()
        );
    }

    let generated = std::fs::read_to_string(rules.join("request_911_method_enforcement.rss"))
        .expect("generated rule module should be readable");
    assert!(generated.contains(
        "apply_rule(next, 911100, 0, false, [\"tx.allowed_methods\", \"\", \"Method is not allowed by policy\", \"REQUEST_METHOD\", \"\"], 6721, 0, 5, false, 403)"
    ));
    let transformed =
        std::fs::read_to_string(rules.join("request_944_application_attack_java.rss"))
            .expect("generated transformed rule module should be readable");
    assert!(transformed.contains(
        "apply_rule(next, 944250, 0, false, [\"java\\\\b.+(?:runtime|processbuilder)\", \"\", \"Remote Command Execution: Suspicious Java method detected\", \"ARGS\", \"\", \"ARGS_NAMES\", \"\""
    ));
    assert!(transformed.contains("\"REQUEST_HEADERS\", \"Cookie\"], 540745,"));
    assert!(!transformed.contains("\"!REQUEST_HEADERS\""));
    assert!(!transformed.contains("ARGS|ARGS_NAMES|REQUEST_COOKIES"));
    assert!(!transformed.contains(
        "\"lowercase\", \"\", \"Remote Command Execution: Suspicious Java method detected\""
    ));

    let engine = std::fs::read_to_string(rules.join("engine.rss"))
        .expect("engine source should be readable");
    assert!(!engine.contains("(&rule)["));

    let bundle = std::fs::read_to_string(rules.join("engine_bundle.rss"))
        .expect("engine bundle should be readable");
    assert!(!bundle.contains("pub fn contains("));
    assert!(!bundle.contains("pub fn lower("));
    assert!(!bundle.contains("pub fn replace("));
    assert!(bundle.contains("string_contains("));
    assert!(bundle.contains("string_lower_ascii("));
    assert!(bundle.contains("string_replace_literal("));
    assert!(bundle.contains("re::replace("));
    assert!(bundle.contains("operator: int"));
    assert!(!bundle.contains("operator: string"));
}

#[test]
fn runtime_rule_abi_consumes_typed_transform_plan() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let engine = std::fs::read_to_string(root.join("rules/engine.rss"))
        .expect("engine source should be readable");
    assert!(engine.contains("text: [string], target_count: int, transform_plan: int"));
    assert!(engine.contains("engine_text::transforms((&values)[i], transform_plan)"));

    let context = std::fs::read_to_string(root.join("rules/engine_context.rss"))
        .expect("engine context source should be readable");
    assert!(!context.contains("re::split"));
    assert!(context.contains("string_split_literal"));
    assert!(context.contains("3 + i * 2"));
    assert!(!context.contains("4 + i * 2"));

    let operators = std::fs::read_to_string(root.join("rules/engine_operators.rss"))
        .expect("engine operators source should be readable");
    assert!(!operators.contains("re::split"));
    assert!(operators.contains("string_split_literal"));
}

#[test]
fn enabled_ruleset_fits_the_standard_vm() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let compiled = vm::compile_source_file(root.join("rules/ruleset_bundle.rss"))
        .expect("enabled RSS ruleset should compile");
    assert!(compiled.program.local_count <= 256);
    assert!(compiled.program.imports.is_empty());
}

#[test]
fn sqli_category_prefilter_skips_benign_request_and_admits_obvious_attack() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let engine = std::fs::read_to_string(root.join("rules/engine_bundle.rss"))
        .expect("engine bundle should be readable");
    let source = format!(
        r#"{engine}
let benign: map<string> = new_state(
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
let attack: map<string> = new_state(
    "GET",
    "/products",
    "q=1%20union%20select%20password",
    "HTTP/1.1",
    "192.0.2.10",
    {{ "host": "shop.example.test" }},
    {{ "q": "1 union select password" }},
    ""
);
assert(!sqli_category_prefilter(&benign));
assert(sqli_category_prefilter(&attack));
"ok";
"#
    );
    let compiled = vm::compile_source(&source).expect("prefilter fixture should compile");
    let mut vm = vm::Vm::new(compiled.program);
    assert_eq!(
        vm.run().expect("prefilter fixture should run"),
        vm::VmStatus::Halted
    );
    assert_eq!(vm.stack().last(), Some(&vm::Value::string("ok")));
}

#[test]
fn enabled_ruleset_folds_common_exception_updates_into_rule_payloads() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(root.join("rules/ruleset.rss"))
        .expect("enabled ruleset source should be readable");
    assert!(!source.contains("fn evaluate_request_999_common_exceptions_after"));
    assert!(!source.contains("engine_bundle::update_target(next,"));
    assert!(!source.contains("update_target(next, 941100"));
    let rule = source
        .lines()
        .find(|line| line.contains("apply_rule(next, 942290,"))
        .expect("enabled rule 942290 should exist");
    assert!(rule.contains("\"REQUEST_COOKIES\", \"__gads\""));
    assert!(rule.contains("], 409674, 619,"));
    assert!(!rule.contains("\"!REQUEST_COOKIES\""));
}
