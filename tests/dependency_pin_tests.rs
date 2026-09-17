//! The WAF workspace must stay pinned to the frozen RustScript core and the
//! migrated pd-edge catalog by exact revision, in every manifest and in the
//! lockfile.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const FROZEN_CORE_REV: &str = "b1d6cffede77f49410bf63525f30b9a46b02dc01";
const FROZEN_CORE_URL: &str = "https://github.com/rustscript-lang/rustscript.git";
const FROZEN_EDGE_REV: &str = "6320847098530ab78b0d3cd438b714e699caa8db";
const FROZEN_EDGE_URL: &str = "https://github.com/rustscript-lang/pd-edge.git";

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn dependency_line(manifest: &str, dependency: &str) -> String {
    manifest
        .lines()
        .find(|line| line.trim_start().starts_with(&format!("{dependency} = ")))
        .unwrap_or_else(|| panic!("{dependency} dependency is missing from the manifest"))
        .to_string()
}

fn git_lock_source(url: &str, rev: &str) -> String {
    format!("git+{url}?rev={rev}#{rev}")
}

#[test]
fn pd_vm_is_pinned_to_the_frozen_core_revision() {
    let manifest = read(&manifest_dir().join("Cargo.toml"));
    let line = dependency_line(&manifest, "pd-vm");
    assert!(
        line.contains(&format!("git = \"{FROZEN_CORE_URL}\"")),
        "pd-vm must come from the frozen core repository: {line}"
    );
    assert!(
        line.contains(&format!("rev = \"{FROZEN_CORE_REV}\"")),
        "pd-vm must carry the exact frozen revision: {line}"
    );
    assert!(
        !line.contains("path = \""),
        "pd-vm must not use a sibling path pin: {line}"
    );
    assert!(
        !line.contains("branch = "),
        "pd-vm must not follow a moving branch: {line}"
    );
    assert!(
        !line.contains(&format!("rev = \"{}\"", &FROZEN_CORE_REV[..7])),
        "pd-vm must not pin an abbreviated SHA: {line}"
    );
    assert!(
        FROZEN_CORE_REV.len() == 40,
        "the frozen core revision must be a full SHA"
    );
}

#[test]
fn pd_edge_is_pinned_to_the_migrated_revision() {
    let manifest = read(&manifest_dir().join("Cargo.toml"));
    let line = dependency_line(&manifest, "edge");
    assert!(
        line.contains("package = \"pd-edge\""),
        "the `edge` dependency must name the pd-edge package: {line}"
    );
    assert!(
        line.contains(&format!("git = \"{FROZEN_EDGE_URL}\"")),
        "pd-edge must come from the migrated edge repository: {line}"
    );
    assert!(
        line.contains(&format!("rev = \"{FROZEN_EDGE_REV}\"")),
        "pd-edge must carry the exact migrated revision: {line}"
    );
    assert!(
        !line.contains("path = \""),
        "pd-edge must not use a sibling path pin: {line}"
    );
    assert!(
        !line.contains("branch = "),
        "pd-edge must not follow a moving branch: {line}"
    );
    assert!(
        !line.contains(&format!("rev = \"{}\"", &FROZEN_EDGE_REV[..7])),
        "pd-edge must not pin an abbreviated SHA: {line}"
    );
    assert!(
        FROZEN_EDGE_REV.len() == 40,
        "the migrated edge revision must be a full SHA"
    );
}

#[test]
fn no_manifest_uses_a_sibling_core_or_edge_path_pin() {
    let manifest = read(&manifest_dir().join("Cargo.toml"));
    let mut offenders = Vec::new();
    for (index, line) in manifest.lines().enumerate() {
        if line.contains("path = \"../rustscript")
            || line.contains("path = \"../pd-edge")
            || line.contains("path = \"../../rustscript")
            || line.contains("path = \"../../pd-edge")
            || line.contains("/home/")
        {
            offenders.push(format!("{}: {line}", index + 1));
        }
    }
    assert!(
        offenders.is_empty(),
        "sibling path pins must not exist: {offenders:?}"
    );
}

#[test]
fn the_lockfile_proves_frozen_core_and_edge_sources() {
    let lock = read(&manifest_dir().join("Cargo.lock"));
    let expected_core = git_lock_source(FROZEN_CORE_URL, FROZEN_CORE_REV);
    let expected_edge = git_lock_source(FROZEN_EDGE_URL, FROZEN_EDGE_REV);
    let mut proven_core = BTreeSet::new();
    let mut proven_edge = BTreeSet::new();

    let mut lines = lock.lines().peekable();
    while let Some(line) = lines.next() {
        let Some(name) = line
            .trim()
            .strip_prefix("name = \"")
            .and_then(|rest| rest.strip_suffix('"'))
        else {
            continue;
        };
        let version = lines.next().unwrap_or_default().trim().to_string();
        let source = lines.next().unwrap_or_default().trim().to_string();
        if !version.starts_with("version = ") {
            continue;
        }
        if source == format!("source = \"{expected_core}\"") {
            proven_core.insert(name.to_string());
        }
        if source == format!("source = \"{expected_edge}\"") {
            proven_edge.insert(name.to_string());
        }
    }

    for package in ["pd-vm", "pd-host-function", "pd-host-schema"] {
        assert!(
            proven_core.contains(package),
            "Cargo.lock must prove {package} at {expected_core}; core={proven_core:?}"
        );
    }
    for package in ["pd-edge", "pd-edge-abi", "pd-edge-host-function"] {
        assert!(
            proven_edge.contains(package),
            "Cargo.lock must prove {package} at {expected_edge}; edge={proven_edge:?}"
        );
    }
}

#[test]
fn every_locked_core_and_edge_revision_is_the_frozen_one() {
    let lock = read(&manifest_dir().join("Cargo.lock"));
    let sources = lock
        .lines()
        .filter_map(|line| line.trim().strip_prefix("source = \"git+"))
        .collect::<BTreeSet<_>>();
    assert!(
        !sources.is_empty(),
        "the lockfile must resolve at least one git dependency"
    );

    let mut saw_core = false;
    let mut saw_edge = false;
    for source in sources {
        if source.contains("rustscript.git") || source.contains("rustscript?") {
            saw_core = true;
            assert!(
                source.contains(&format!("rev={FROZEN_CORE_REV}#{FROZEN_CORE_REV}")),
                "a stale core revision is locked: {source}"
            );
        }
        if source.contains("pd-edge.git") || source.contains("pd-edge?") {
            saw_edge = true;
            assert!(
                source.contains(&format!("rev={FROZEN_EDGE_REV}#{FROZEN_EDGE_REV}")),
                "a stale edge revision is locked: {source}"
            );
        }
    }
    assert!(saw_core, "Cargo.lock must lock the frozen rustscript core");
    assert!(saw_edge, "Cargo.lock must lock the migrated pd-edge");
}

#[test]
fn ci_does_not_check_out_sibling_path_pins() {
    let workflow = read(&manifest_dir().join(".github/workflows/ci.yml"));
    assert!(
        !workflow.contains("repository: rustscript-lang/rustscript"),
        "CI must resolve rustscript from the Cargo git pin"
    );
    assert!(
        !workflow.contains("repository: rustscript-lang/pd-edge"),
        "CI must resolve pd-edge from the Cargo git pin"
    );
    assert!(
        !workflow.contains("working-directory: pd-edge-waf"),
        "CI must run against the repository root after dropping sibling checkouts"
    );
    assert!(
        workflow.contains("cargo clippy --all-targets --all-features -- -D warnings"),
        "CI must deny Clippy warnings across all targets and features"
    );
}
