use serde::Deserialize;

pub const CRS_VERSION: &str = "4.28.0";
pub const RULESET_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/rules/ruleset.rss");

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct RulesetManifest {
    pub upstream: String,
    pub version: String,
    pub category_count: usize,
    pub directive_count: usize,
    pub sec_rule_count: usize,
    pub sec_action_count: usize,
    pub sec_marker_count: usize,
    pub data_file_count: usize,
    pub data_files: Vec<String>,
    pub files: Vec<CategoryManifest>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct CategoryManifest {
    pub source: String,
    pub module: String,
    pub sec_rule: usize,
    pub sec_action: usize,
    pub sec_marker: usize,
}

pub fn manifest() -> RulesetManifest {
    serde_json::from_str(include_str!("../rules/manifest.json"))
        .expect("generated rules manifest must be valid JSON")
}
