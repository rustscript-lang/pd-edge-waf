use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{Router, routing::any};
use edge::{SharedState, build_admin_app, compile_edge_source_file, serve_http_proxy};
use reqwest::{Method, StatusCode};
use tokio::{net::TcpListener, task::JoinHandle, time::Duration};
use vm::encode_program;

async fn spawn_axum(app: Router) -> (std::net::SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fixture listener should bind");
    let addr = listener
        .local_addr()
        .expect("fixture should have an address");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("fixture server should run");
    });
    (addr, handle)
}

async fn send_with_timeout(request: reqwest::RequestBuilder) -> reqwest::Response {
    tokio::time::timeout(Duration::from_secs(120), request.send())
        .await
        .expect("request should finish before timeout")
        .expect("request should complete")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pd_edge_entrypoint_forwards_benign_and_blocks_attacks() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let entrypoint = root.join("rules/pd_edge_waf.rss");
    let compiled = compile_edge_source_file(&entrypoint).expect("WAF entrypoint should compile");
    assert!(
        compiled.program.local_count <= 256,
        "entrypoint must fit the standard VM local-slot format"
    );
    assert!(
        compiled
            .program
            .root_callable_bindings
            .iter()
            .all(|binding| (binding.local_slot as usize) < compiled.program.local_count),
        "entrypoint root callable binding exceeds local frame: local_count={}, bindings={:?}",
        compiled.program.local_count,
        compiled.program.root_callable_bindings,
    );
    let program = encode_program(&compiled.program).expect("WAF bytecode should encode");

    let upstream_hits = Arc::new(AtomicUsize::new(0));
    let upstream_app = Router::new().fallback(any({
        let upstream_hits = upstream_hits.clone();
        move || {
            let upstream_hits = upstream_hits.clone();
            async move {
                upstream_hits.fetch_add(1, Ordering::SeqCst);
                "upstream-ok"
            }
        }
    }));
    let (upstream_addr, upstream_handle) = spawn_axum(upstream_app).await;

    let state = SharedState::new(program.len() + 1024);
    let data_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("data listener should bind");
    let data_addr = data_listener
        .local_addr()
        .expect("data listener should have an address");
    let data_handle = tokio::spawn({
        let state = state.clone();
        async move {
            serve_http_proxy(data_listener, state)
                .await
                .expect("pd-edge data plane should run");
        }
    });
    let (admin_addr, admin_handle) = spawn_axum(build_admin_app(state)).await;

    let client = reqwest::Client::new();
    let upload = client
        .put(format!("http://{admin_addr}/program"))
        .header("content-type", "application/octet-stream")
        .body(program)
        .send()
        .await
        .expect("program upload should complete");
    let upload_status = upload.status();
    let upload_body = upload.text().await.expect("upload body should read");
    assert_eq!(
        upload_status,
        StatusCode::NO_CONTENT,
        "program upload failed: {upload_body}"
    );

    let request = |method: Method, path: &str, enabled_ruleset: &str| {
        client
            .request(method, format!("http://{data_addr}{path}"))
            .header("accept", "text/plain")
            .header("user-agent", "pd-edge-waf-e2e")
            .header("x-waf-upstream-host", upstream_addr.ip().to_string())
            .header("x-waf-upstream-port", upstream_addr.port().to_string())
            .header("x-waf-enabled-ruleset", enabled_ruleset)
    };

    let benign = send_with_timeout(request(
        Method::GET,
        "/hello?page=home",
        "request_901_initialization request_911_method_enforcement request_920_protocol_enforcement",
    ))
    .await;
    let benign_status = benign.status();
    let benign_headers = benign.headers().clone();
    let benign_body = benign.text().await.expect("benign body should read");
    assert_eq!(benign_status, StatusCode::OK);
    assert_eq!(
        benign_headers
            .get("x-waf-blocked")
            .and_then(|value| value.to_str().ok()),
        Some("0")
    );
    assert_eq!(benign_body, "upstream-ok");
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    let invalid_method = send_with_timeout(request(
        Method::TRACE,
        "/",
        "request_911_method_enforcement",
    ))
    .await;
    assert_eq!(invalid_method.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        invalid_method
            .headers()
            .get("x-waf-blocked")
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );

    let sqli = send_with_timeout(request(
        Method::GET,
        "/search?id=1%27%20OR%201%3D1--",
        "request_942_application_attack_sqli",
    ))
    .await;
    let sqli_status = sqli.status();
    let sqli_headers = sqli.headers().clone();
    let sqli_body = sqli.text().await.expect("SQLi body should read");
    assert_eq!(sqli_status, StatusCode::FORBIDDEN);
    assert_eq!(
        sqli_headers
            .get("x-waf-blocked")
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    assert_eq!(
        sqli_headers
            .get("x-waf-score")
            .and_then(|value| value.to_str().ok()),
        Some("5")
    );
    assert!(
        sqli_headers
            .get("x-waf-matched-ids")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|ids| ids.split(',').any(|id| id == "942100"))
    );
    assert_eq!(sqli_body, "request blocked by OWASP CRS");
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    data_handle.abort();
    admin_handle.abort();
    upstream_handle.abort();
}
