use std::{collections::BTreeMap, hint::black_box, time::Instant};

use pd_edge_waf::{NativeRequest, native_plan};

fn benign_request() -> NativeRequest {
    NativeRequest {
        method: "GET".to_string(),
        path: "/products".to_string(),
        query: "category=books&page=2".to_string(),
        protocol: "HTTP/1.1".to_string(),
        client_ip: "192.0.2.10".to_string(),
        headers: BTreeMap::from([
            ("host".to_string(), "shop.example.test".to_string()),
            (
                "accept".to_string(),
                "text/html,application/xhtml+xml".to_string(),
            ),
            ("user-agent".to_string(), "pd-edge-waf-perf/1.0".to_string()),
        ]),
        cookies: BTreeMap::new(),
        args: BTreeMap::from([
            ("category".to_string(), "books".to_string()),
            ("page".to_string(), "2".to_string()),
        ]),
        body: String::new(),
        enabled_categories: Vec::new(),
        paranoia_level: 1,
    }
}

#[test]
#[ignore = "performance test; run explicitly with --ignored --nocapture"]
fn native_plan_batch_latency() {
    let plan = native_plan().expect("generated native plan should load");
    let request = benign_request();
    for _ in 0..100 {
        black_box(plan.inspect_request(black_box(&request)));
    }

    let requests = std::env::var("WAF_NATIVE_PERF_REQUESTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(10_000usize)
        .max(1);
    let started = Instant::now();
    let mut last = None;
    for _ in 0..requests {
        last = Some(black_box(plan.inspect_request(black_box(&request))));
    }
    let elapsed = started.elapsed();
    let last = last.expect("at least one request should execute");
    assert!(!last.blocked);
    assert_eq!(last.score, 0);

    println!(
        "native_plan_perf requests={requests} average_us={:.3} rules_evaluated={} plan_rules={} static_regex_assets={}",
        elapsed.as_secs_f64() * 1_000_000.0 / requests as f64,
        last.rules_evaluated,
        plan.rule_count(),
        plan.static_regex_count(),
    );
}
