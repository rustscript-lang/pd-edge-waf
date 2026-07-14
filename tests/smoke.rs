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
        "apply_rule(next, 911100, 1, 0, false, [\"REQUEST_METHOD\", \"!@within\", \"%{tx.allowed_methods}\", \"\", \"\", \"Method is not allowed by policy\"], 1, 5, false, 403)"
    ));

    let engine = std::fs::read_to_string(rules.join("engine.rss"))
        .expect("engine source should be readable");
    assert!(!engine.contains("(&rule)["));
}

#[test]
fn enabled_ruleset_fits_the_standard_vm() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let compiled = vm::compile_source_file(root.join("rules/ruleset_bundle.rss"))
        .expect("enabled RSS ruleset should compile");
    assert!(compiled.program.local_count <= 256);
    assert!(compiled.program.imports.is_empty());
}
