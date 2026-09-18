//! Every checked-in RSS module and entrypoint compiles against the migrated
//! pd-edge production catalog. The sweep enumerates files instead of trusting
//! a hand-written list, so a new fixture cannot be added without being
//! compiled here, and the count is asserted so a silent deletion is caught.

use std::path::{Path, PathBuf};

use edge::{
    ABI_VERSION, compile_edge_source_file, compile_edge_source_with_flavor, function_by_name,
    host_namespace_specs,
};
use vm::{HostFunctionRegistry, SourceFlavor};

/// Planned corpus size at audit time. The live count is enumerated, then
/// asserted equal to this constant so drift is a hard failure.
const EXPECTED_RSS_CORPUS: usize = 36;
const FROZEN_EDGE_ABI: u16 = 25;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn collect(directory: &Path, extension: &str, out: &mut Vec<PathBuf>) {
    let mut entries = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()))
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if path.is_dir() {
            if matches!(name, ".git" | "target" | ".upstream") {
                continue;
            }
            collect(&path, extension, out);
            continue;
        }
        if path.extension().is_some_and(|ext| ext == extension) {
            out.push(path);
        }
    }
}

fn rss_corpus() -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect(&manifest_dir(), "rss", &mut files);
    files.sort();
    files
}

fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    collect(dir, "rs", &mut paths);
    paths.sort();
    paths
}

#[test]
fn the_checked_in_rss_corpus_is_complete() {
    let files = rss_corpus();
    assert_eq!(
        files.len(),
        EXPECTED_RSS_CORPUS,
        "the checked-in RSS corpus changed; audit the new/removed fixtures: {files:#?}"
    );
}

#[test]
fn every_checked_in_rss_file_compiles_through_the_production_edge_catalog() {
    let files = rss_corpus();
    assert_eq!(files.len(), EXPECTED_RSS_CORPUS);
    let mut compiled = Vec::new();
    let mut failures = Vec::new();
    for path in &files {
        match compile_edge_source_file(path) {
            Ok(_) => compiled.push(path.clone()),
            Err(error) => failures.push(format!("{}: {error}", path.display())),
        }
    }
    assert!(
        failures.is_empty(),
        "checked-in RSS files must compile through the production edge catalog with zero accepted-error exclusions:\n{}",
        failures.join("\n\n")
    );
    assert_eq!(
        compiled.len(),
        files.len(),
        "every fixture must compile; no skips under any feature set"
    );
}

#[test]
fn waf_entrypoint_binds_exact_catalog_http_and_proxy_imports() {
    let path = manifest_dir().join("rules/pd_edge_waf.rss");
    let compiled = compile_edge_source_file(&path).expect("WAF entrypoint should compile");
    let imports: Vec<&str> = compiled
        .program
        .imports
        .iter()
        .map(|import| import.name.as_str())
        .collect();
    for required in [
        "http::request::get_method",
        "http::request::get_path",
        "http::request::get_query",
        "http::request::get_http_version",
        "http::request::get_client_ip",
        "http::request::get_headers",
        "http::request::get_query_args",
        "http::request::get_body",
        "http::request::get_header",
        "http::response::set_status",
        "http::response::set_header",
        "http::response::set_body",
        "http::exchange::default_upstream",
        "http::exchange::set_target",
        "http::exchange::set_path",
        "http::exchange::set_query",
        "proxy::forward_native",
        "proxy::stream::downstream",
        "proxy::stream::exchange",
    ] {
        assert!(
            imports.contains(&required),
            "entrypoint missing exact catalog import {required}: {imports:?}"
        );
        let function = function_by_name(required)
            .unwrap_or_else(|| panic!("{required} must exist in the published edge ABI"));
        assert_eq!(function.name, required);
    }
    assert!(
        compiled.program.local_count <= 256,
        "entrypoint must fit the standard VM local-slot format"
    );
}

#[test]
fn local_engine_modules_compile_without_being_absorbed_as_hosts() {
    let engine = manifest_dir().join("rules/engine.rss");
    let compiled = compile_edge_source_file(&engine).expect("engine module should compile");
    let imports: Vec<&str> = compiled
        .program
        .imports
        .iter()
        .map(|import| import.name.as_str())
        .collect();
    assert!(
        imports.iter().all(|import| {
            *import == "re::match"
                || *import == "re::replace"
                || import.starts_with("re::")
                || import.starts_with("bytes::")
        }),
        "engine.rss should keep local engine_* modules and only import stdlib hosts: {imports:?}"
    );
}

#[test]
fn production_rust_sources_are_catalog_consumers() {
    let sources = rust_sources(&manifest_dir().join("src"));
    assert!(!sources.is_empty(), "expected Rust sources under src/");
    for path in sources {
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        for token in [
            "HostApiBuilder",
            "HostApiCatalog",
            "HostFunctionRegistry",
            "HostModuleDescriptor",
            "HostFunctionDescriptor",
            "pd_host_function",
            "register_exact_static",
        ] {
            assert!(
                !source.contains(token),
                "{} is a WAF consumer and must not define guest-visible hosts ({token})",
                path.display()
            );
        }
    }
}

#[test]
fn edge_abi_is_version_25_and_exposes_named_mqtt_event_on_the_published_surface() {
    assert_eq!(ABI_VERSION, FROZEN_EDGE_ABI);
    let namespaces: Vec<&str> = host_namespace_specs()
        .iter()
        .map(|spec| spec.root)
        .collect();
    for required in ["http", "proxy", "runtime", "mqtt"] {
        assert!(
            namespaces.contains(&required),
            "production catalog missing namespace {required}: {namespaces:?}"
        );
    }

    let mqtt_event = function_by_name("mqtt::connection::read_event")
        .expect("mqtt::connection::read_event must exist on the published edge ABI");
    assert_eq!(mqtt_event.name, "mqtt::connection::read_event");
    compile_edge_source_with_flavor(
        "use mqtt;\nlet connection = mqtt::connection::new();\nlet _event = mqtt::connection::read_event(connection);\n",
        SourceFlavor::RustScript,
    )
    .expect("named MqttEvent catalog entry must compile through the production edge catalog");

    let manifest = edge::abi_json();
    assert!(
        manifest.contains("\"abi_version\": 25"),
        "published ABI JSON must record version 25"
    );
    assert!(
        manifest.contains("mqtt::connection::read_event"),
        "published ABI JSON must include the named MQTT event reader"
    );

    for name in [
        "proxy::stream::downstream",
        "proxy::stream::exchange",
        "proxy::forward_native",
    ] {
        let function = function_by_name(name)
            .unwrap_or_else(|| panic!("{name} must stay on the exact ABI as a typed raw handle"));
        assert_eq!(function.name, name);
        assert!(
            function.param_types.iter().all(|ty| ty.as_str() == "int")
                && (function.return_type.as_str() == "int"
                    || function.return_type.as_str() == "string"),
            "{name} must keep typed raw-handle slots, got params={:?} return={}",
            function.param_types,
            function.return_type.as_str()
        );
    }
}

#[test]
fn restricted_registry_denies_uninstalled_hosts_and_keeps_waf_on_exact_imports() {
    let registry = HostFunctionRegistry::restricted();
    assert!(
        !registry.contains_name("tcp::stream::close"),
        "restricted registry must not authorize tcp::stream::close before install"
    );
    assert!(
        !registry.contains_name("udp::socket::close"),
        "restricted registry must not authorize udp::socket::close before install"
    );
    for name in [
        "http::request::get_method",
        "http::response::set_status",
        "proxy::forward_native",
    ] {
        function_by_name(name).unwrap_or_else(|| panic!("{name} must be an exact ABI import"));
    }
}

#[test]
fn catalog_compile_rejects_unknown_host_namespaces_without_an_accepted_error_skip() {
    let result = compile_edge_source_with_flavor(
        "pub fn go() {\n    not_a_waf_host::missing();\n}\n",
        SourceFlavor::RustScript,
    );
    let error = match result {
        Ok(_) => panic!("unknown host namespaces must fail closed"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(!message.is_empty(), "catalog diagnostics must not be empty");
    assert!(
        message.contains("not_a_waf_host") || message.contains("unknown namespace"),
        "unknown host namespaces must be diagnosed: {message}"
    );
    assert!(
        !message.contains("/home/wow"),
        "diagnostics must not mention a machine-specific path: {message}"
    );
}
