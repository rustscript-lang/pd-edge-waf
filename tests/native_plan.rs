use std::collections::BTreeMap;

use pd_edge_waf::{NativeDecision, NativeEntry, NativeRequest, native_plan};
use vm::{JitConfig, Value, Vm, VmStatus};

fn request(method: &str, path: &str, query: &str) -> NativeRequest {
    NativeRequest {
        method: method.to_string(),
        path: path.to_string(),
        query: query.to_string(),
        protocol: "HTTP/1.1".to_string(),
        client_ip: "127.0.0.1".to_string(),
        headers: BTreeMap::from([
            ("accept".to_string(), "text/plain".to_string()),
            (
                "user-agent".to_string(),
                "pd-edge-waf-native-test".to_string(),
            ),
        ]),
        cookies: BTreeMap::new(),
        args: BTreeMap::new(),
        body: String::new(),
        enabled_categories: Vec::new(),
        paranoia_level: 1,
    }
}

#[test]
fn generated_native_plan_contains_enabled_911_and_942_rules() {
    let plan = native_plan().expect("generated native plan should load");
    assert_eq!(plan.schema_version, 1);
    assert_eq!(plan.categories.len(), 2);
    assert_eq!(plan.categories[0].name, "request_911_method_enforcement");
    assert_eq!(plan.categories[0].entries.len(), 10);
    assert_eq!(
        plan.categories[1].name,
        "request_942_application_attack_sqli"
    );
    assert_eq!(plan.categories[1].entries.len(), 75);
    let rule_942450 = plan.categories[1]
        .entries
        .iter()
        .find_map(|entry| match entry {
            NativeEntry::Rule(rule) if rule.id == 942450 => Some(rule),
            _ => None,
        })
        .expect("rule 942450 should be present");
    assert!(rule_942450.targets.iter().any(|target| {
        target.negated && target.base == "REQUEST_COOKIES" && target.selector == "/^_pk_ref/"
    }));
}

#[test]
fn native_plan_allows_benign_request() {
    let plan = native_plan().expect("generated native plan should load");
    let decision = plan.inspect_request(&request("GET", "/hello", "page=home"));
    assert!(!decision.blocked);
    assert_eq!(decision.score, 0);
    assert_eq!(decision.status, 403);
    assert_eq!(decision.matched_ids, [911013, 942013, 911014, 942014]);
}

#[test]
fn native_plan_blocks_trace_with_911100() {
    let plan = native_plan().expect("generated native plan should load");
    let mut input = request("TRACE", "/", "");
    input.enabled_categories = vec!["request_911_method_enforcement".to_string()];
    let decision = plan.inspect_request(&input);
    assert!(decision.blocked);
    assert_eq!(decision.score, 5);
    assert_eq!(decision.status, 403);
    assert_eq!(decision.matched_ids, [911100]);
}

#[test]
fn native_plan_blocks_sqli_with_942100() {
    let plan = native_plan().expect("generated native plan should load");
    let mut input = request("GET", "/search", "id=1' OR 1=1--");
    input
        .args
        .insert("id".to_string(), "1' OR 1=1--".to_string());
    input.enabled_categories = vec!["request_942_application_attack_sqli".to_string()];
    let decision = plan.inspect_request(&input);
    assert!(decision.blocked);
    assert_eq!(decision.score, 5);
    assert_eq!(decision.status, 403);
    assert_eq!(decision.matched_ids, [942013, 942100]);
}

#[test]
fn native_plan_applies_folded_cookie_target_exclusions() {
    let plan = native_plan().expect("generated native plan should load");
    let mut excluded = request("GET", "/", "");
    excluded.enabled_categories = vec!["request_942_application_attack_sqli".to_string()];
    excluded.paranoia_level = 2;
    excluded
        .cookies
        .insert("_pk_ref.1".to_string(), "0x414141".to_string());
    let excluded_decision = plan.inspect_request(&excluded);
    assert!(!excluded_decision.matched_ids.contains(&942450));

    let mut included = request("GET", "/", "");
    included.enabled_categories = vec!["request_942_application_attack_sqli".to_string()];
    included.paranoia_level = 2;
    included
        .cookies
        .insert("session".to_string(), "0x414141".to_string());
    let included_decision = plan.inspect_request(&included);
    assert!(included_decision.matched_ids.contains(&942450));
}

fn rss_map(values: &BTreeMap<String, String>) -> String {
    values
        .iter()
        .map(|(key, value)| {
            format!(
                "{}: {}",
                serde_json::to_string(key).expect("map key should encode"),
                serde_json::to_string(value).expect("map value should encode")
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn rss_decision(input: &NativeRequest) -> NativeDecision {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let ruleset = std::fs::read_to_string(root.join("rules/ruleset_bundle.rss"))
        .expect("ruleset bundle should read");
    let enabled = input.enabled_categories.join(" ");
    let source = format!(
        r#"{ruleset}
let mut state: map<string> = new_state(
    {method}, {path}, {query}, {protocol}, {client_ip},
    {{ {headers} }}, {{ {args} }}, {body}
);
state["enabled_ruleset"] = {enabled};
state["paranoia"] = {paranoia};
state["tx.detection_paranoia_level"] = {paranoia};
let result: map<string> = inspect_request(state);
[
    (&result)["blocked"],
    (&result)["score"],
    (&result)["status"],
    (&result)["matched_ids"]
];
"#,
        method = serde_json::to_string(&input.method).expect("method should encode"),
        path = serde_json::to_string(&input.path).expect("path should encode"),
        query = serde_json::to_string(&input.query).expect("query should encode"),
        protocol = serde_json::to_string(&input.protocol).expect("protocol should encode"),
        client_ip = serde_json::to_string(&input.client_ip).expect("client IP should encode"),
        headers = rss_map(&input.headers),
        args = rss_map(&input.args),
        body = serde_json::to_string(&input.body).expect("body should encode"),
        enabled = serde_json::to_string(&enabled).expect("enabled categories should encode"),
        paranoia = serde_json::to_string(&input.paranoia_level.max(1).to_string())
            .expect("paranoia level should encode"),
    );
    let compiled = vm::compile_source(&source).expect("RSS differential fixture should compile");
    let mut machine = Vm::new_with_jit_config(
        compiled.program,
        JitConfig {
            enabled: false,
            ..JitConfig::default()
        },
    );
    assert_eq!(
        machine.run().expect("RSS fixture should execute"),
        VmStatus::Halted
    );
    let Value::Array(values) = machine.stack().last().expect("RSS result should exist") else {
        panic!("RSS result should be an array");
    };
    let text = |index: usize| match &values[index] {
        Value::String(value) => value.as_str(),
        other => panic!("RSS result field {index} should be a string, got {other:?}"),
    };
    NativeDecision {
        blocked: text(0) == "1",
        score: text(1).parse().expect("RSS score should be numeric"),
        status: text(2).parse().expect("RSS status should be numeric"),
        matched_ids: text(3)
            .split(',')
            .filter(|value| !value.is_empty())
            .map(|value| value.parse().expect("RSS rule ID should be numeric"))
            .collect(),
        messages: Vec::new(),
        rules_evaluated: 0,
    }
}

#[test]
fn native_plan_matches_rss_for_stage_one_request_matrix() {
    let plan = native_plan().expect("generated native plan should load");
    let benign = request("GET", "/hello", "page=home");

    let mut method = request("TRACE", "/", "");
    method.enabled_categories = vec!["request_911_method_enforcement".to_string()];

    let mut sqli = request("GET", "/search", "id=1' OR 1=1--");
    sqli.args
        .insert("id".to_string(), "1' OR 1=1--".to_string());
    sqli.enabled_categories = vec!["request_942_application_attack_sqli".to_string()];

    for input in [benign, method, sqli] {
        let native = plan.inspect_request(&input);
        let rss = rss_decision(&input);
        assert_eq!(native.blocked, rss.blocked);
        assert_eq!(native.score, rss.score);
        assert_eq!(native.status, rss.status);
        assert_eq!(native.matched_ids, rss.matched_ids);
    }
}

#[test]
fn native_plan_matches_rss_for_regex_rule() {
    let plan = native_plan().expect("generated native plan should load");
    let mut input = request("GET", "/search", "token=0x414141");
    input
        .args
        .insert("token".to_string(), "0x414141".to_string());
    input.enabled_categories = vec!["request_942_application_attack_sqli".to_string()];
    input.paranoia_level = 2;

    let native = plan.inspect_request(&input);
    let rss = rss_decision(&input);
    assert_eq!(native.blocked, rss.blocked);
    assert_eq!(native.score, rss.score);
    assert_eq!(native.status, rss.status);
    assert_eq!(native.matched_ids, rss.matched_ids);
    assert!(native.matched_ids.contains(&942450));
}
