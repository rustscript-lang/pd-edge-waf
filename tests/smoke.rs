use pd_edge_waf::{CRS_VERSION, manifest};

#[test]
fn generated_crs_structure_is_complete() {
    let expected = manifest();
    assert_eq!(expected.version, CRS_VERSION);
    assert_eq!(
        expected.enabled_categories,
        [
            "modsecurity_recommended",
            "request_901_initialization",
            "request_905_common_exceptions",
            "request_911_method_enforcement",
            "request_913_scanner_detection",
            "request_920_protocol_enforcement",
            "request_921_protocol_attack",
            "request_922_multipart_attack",
            "request_930_application_attack_lfi",
            "request_931_application_attack_rfi",
            "request_932_application_attack_rce",
            "request_933_application_attack_php",
            "request_934_application_attack_generic",
            "request_941_application_attack_xss",
            "request_942_application_attack_sqli",
            "request_943_application_attack_session_fixation",
            "request_944_application_attack_java",
            "request_949_blocking_evaluation",
            "request_999_common_exceptions_after",
            "response_950_data_leakages",
            "response_951_data_leakages_sql",
            "response_952_data_leakages_java",
            "response_953_data_leakages_php",
            "response_954_data_leakages_iis",
            "response_955_web_shells",
            "response_956_data_leakages_ruby",
            "response_959_blocking_evaluation",
            "response_980_correlation",
        ]
    );
    assert_eq!(expected.category_count, 28);
    assert_eq!(expected.sec_rule_count, 702);
    assert_eq!(expected.sec_action_count, 7);
    assert_eq!(expected.sec_marker_count, 30);
    assert_eq!(expected.sec_rule_update_target_by_id_count, 55);
    assert_eq!(expected.sec_component_signature_count, 1);
    assert_eq!(expected.directive_count, 795);
    assert_eq!(expected.unique_rule_id_count, 636);
    assert_eq!(expected.chain_group_count, 55);
    assert_eq!(expected.chain_child_count, 73);
    assert_eq!(expected.skip_after_count, 206);
    assert_eq!(expected.tag_count, 3088);
    assert_eq!(expected.transformation_count, 848);
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
    assert_eq!(positive, 299);
    assert_eq!(negative, 21);
    assert_eq!(positive + negative, 320);

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
    assert_eq!(generated_positive, 299);
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
fn default_ruleset_uses_generated_rules_without_synthetic_attack_probes() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let ruleset = std::fs::read_to_string(root.join("rules/ruleset.rss"))
        .expect("ruleset source should be readable");
    let engine = std::fs::read_to_string(root.join("rules/engine_bundle.rss"))
        .expect("engine bundle should be readable");
    assert!(!ruleset.contains("apply_rule_blob"));
    assert!(!engine.contains("apply_rule_blob"));
    assert!(ruleset.contains("apply_rule(next, 911100, 0, false"));
    assert!(ruleset.contains("apply_rule(next, 942100, 0, false"));
    assert!(ruleset.contains("apply_rule(next, 949110, 0, false"));
    assert!(!ruleset.contains("sqli_category_prefilter"));
    assert!(!ruleset.contains("sqli_query_rule_match"));
    assert!(!engine.contains("sqli_category_prefilter"));
    assert!(!engine.contains("sqli_query_rule_match"));
}

#[test]
fn benign_default_request_preserves_final_request_state() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let ruleset = std::fs::read_to_string(root.join("rules/ruleset_bundle.rss"))
        .expect("ruleset bundle should be readable");
    let source = format!(
        r#"{ruleset}
assert((&inspect_request(new_state(
    "GET",
    "/products",
    "category=books&page=2",
    "HTTP/1.1",
    "192.0.2.10",
    {{ "host": "shop.example.test" }},
    {{ "category": "books", "page": "2" }},
    ""
)))["phase"] == "2");
"ok";
"#
    );
    let compiled = vm::compile_source(&source).expect("benign fast-path fixture should compile");
    let mut vm = vm::Vm::new(compiled.program);
    assert_eq!(
        vm.run().expect("benign fast-path fixture should run"),
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
    assert!(source.contains("apply_rule(next, 942290, 0, false"));
    assert!(source.contains("], 409674, 619, 5, false, 403);"));
    assert!(source.contains("\"REQUEST_COOKIES\", \"__gads\""));
    assert!(!source.contains("\"!REQUEST_COOKIES\""));
}
