use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    sync::OnceLock,
};

use regex::Regex;
use serde::Deserialize;

const NATIVE_PLAN_JSON: &str = include_str!("../rules/native_plan.json");

#[derive(Debug)]
pub struct NativePlanError {
    message: String,
}

impl NativePlanError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for NativePlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for NativePlanError {}

#[derive(Debug, Deserialize)]
pub struct NativePlan {
    pub schema_version: u32,
    pub crs_version: String,
    pub categories: Vec<NativeCategory>,
}

#[derive(Debug, Deserialize)]
pub struct NativeCategory {
    pub name: String,
    pub entries: Vec<NativeEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum NativeEntry {
    Rule(Box<NativeRule>),
    Marker { name: String },
}

#[derive(Debug, Deserialize)]
pub struct NativeRule {
    pub source: String,
    pub source_line: usize,
    pub id: i64,
    pub phase: u8,
    pub chain_index: usize,
    pub has_chain: bool,
    pub operator: String,
    pub pattern: String,
    pub transforms: Vec<String>,
    pub paranoia_level: u8,
    pub anomaly_score: i32,
    pub disruptive: bool,
    pub status: u16,
    pub skip_after: String,
    pub message: String,
    pub targets: Vec<NativeTarget>,
    #[serde(skip)]
    compiled_regex: Option<Regex>,
}

#[derive(Debug, Deserialize)]
pub struct NativeTarget {
    pub base: String,
    pub selector: String,
    pub canonical: String,
    pub negated: bool,
    pub counted: bool,
    #[serde(skip)]
    compiled_selector: Option<Regex>,
}

#[derive(Debug, Clone, Default)]
pub struct NativeRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub protocol: String,
    pub client_ip: String,
    pub headers: BTreeMap<String, String>,
    pub cookies: BTreeMap<String, String>,
    pub args: BTreeMap<String, String>,
    pub body: String,
    pub enabled_categories: Vec<String>,
    pub paranoia_level: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeDecision {
    pub blocked: bool,
    pub score: i32,
    pub status: u16,
    pub matched_ids: Vec<i64>,
    pub messages: Vec<String>,
    pub rules_evaluated: usize,
}

#[derive(Debug)]
struct PendingChain {
    id: i64,
    score: i32,
    disruptive: bool,
    status: u16,
    skip_after: String,
    message: String,
    matched: bool,
}

#[derive(Debug)]
struct NativeTransaction {
    phase: u8,
    paranoia_level: u8,
    score: i32,
    blocked: bool,
    status: u16,
    matched_ids: Vec<i64>,
    messages: Vec<String>,
    skip: String,
    chain: Option<PendingChain>,
    tx: HashMap<String, String>,
    cookies: BTreeMap<String, String>,
    rules_evaluated: usize,
}

impl NativeTransaction {
    fn new(request: &NativeRequest) -> Self {
        let tx = HashMap::from([
            ("crs_setup_version".to_string(), "428".to_string()),
            (
                "inbound_anomaly_score_threshold".to_string(),
                "5".to_string(),
            ),
            (
                "outbound_anomaly_score_threshold".to_string(),
                "4".to_string(),
            ),
            ("reporting_level".to_string(), "4".to_string()),
            ("early_blocking".to_string(), "0".to_string()),
            ("blocking_paranoia_level".to_string(), "1".to_string()),
            (
                "detection_paranoia_level".to_string(),
                request.paranoia_level.max(1).to_string(),
            ),
            ("sampling_percentage".to_string(), "100".to_string()),
            ("critical_anomaly_score".to_string(), "5".to_string()),
            ("error_anomaly_score".to_string(), "4".to_string()),
            ("warning_anomaly_score".to_string(), "3".to_string()),
            ("notice_anomaly_score".to_string(), "2".to_string()),
            (
                "allowed_methods".to_string(),
                "GET HEAD POST OPTIONS".to_string(),
            ),
            ("inbound_anomaly_score".to_string(), "0".to_string()),
            ("outbound_anomaly_score".to_string(), "0".to_string()),
        ]);
        Self {
            phase: 1,
            paranoia_level: request.paranoia_level.max(1),
            score: 0,
            blocked: false,
            status: 403,
            matched_ids: Vec::new(),
            messages: Vec::new(),
            skip: String::new(),
            chain: None,
            tx,
            cookies: request.cookies.clone(),
            rules_evaluated: 0,
        }
    }

    fn set_phase(&mut self, phase: u8) {
        self.phase = phase;
        self.skip.clear();
        self.chain = None;
    }

    fn record(
        &mut self,
        id: i64,
        score: i32,
        disruptive: bool,
        status: u16,
        skip_after: &str,
        message: &str,
    ) {
        if id >= 0 {
            self.matched_ids.push(id);
        }
        if !message.is_empty() {
            self.messages.push(message.to_string());
        }
        self.score += score;
        self.tx
            .insert("inbound_anomaly_score".to_string(), self.score.to_string());
        if disruptive || self.score >= 5 {
            self.blocked = true;
            self.status = status;
        }
        if !skip_after.is_empty() {
            self.skip = skip_after.to_string();
        }
    }

    fn decision(self) -> NativeDecision {
        NativeDecision {
            blocked: self.blocked,
            score: self.score,
            status: self.status,
            matched_ids: self.matched_ids,
            messages: self.messages,
            rules_evaluated: self.rules_evaluated,
        }
    }
}

impl NativePlan {
    fn load() -> Result<Self, NativePlanError> {
        let mut plan: Self = serde_json::from_str(NATIVE_PLAN_JSON)
            .map_err(|error| NativePlanError::new(format!("invalid native WAF plan: {error}")))?;
        if plan.schema_version != 1 {
            return Err(NativePlanError::new(format!(
                "unsupported native WAF plan schema {}",
                plan.schema_version
            )));
        }
        if plan.crs_version != crate::CRS_VERSION {
            return Err(NativePlanError::new(format!(
                "native WAF plan CRS version {} does not match {}",
                plan.crs_version,
                crate::CRS_VERSION
            )));
        }
        for category in &mut plan.categories {
            for entry in &mut category.entries {
                let NativeEntry::Rule(rule) = entry else {
                    continue;
                };
                if rule.operator.trim_start_matches('!') == "@rx" && !rule.pattern.contains("%{") {
                    rule.compiled_regex = Some(Regex::new(&rule.pattern).map_err(|error| {
                        NativePlanError::new(format!(
                            "{}:{} rule {} has invalid regex: {error}",
                            rule.source, rule.source_line, rule.id
                        ))
                    })?);
                }
                for target in &mut rule.targets {
                    if let Some(pattern) = selector_regex_pattern(&target.selector) {
                        target.compiled_selector = Some(Regex::new(pattern).map_err(|error| {
                            NativePlanError::new(format!(
                                "{}:{} rule {} has invalid target selector: {error}",
                                rule.source, rule.source_line, rule.id
                            ))
                        })?);
                    }
                }
            }
        }
        Ok(plan)
    }

    pub fn rule_count(&self) -> usize {
        self.categories
            .iter()
            .flat_map(|category| &category.entries)
            .filter(|entry| matches!(entry, NativeEntry::Rule(_)))
            .count()
    }

    pub fn static_regex_count(&self) -> usize {
        self.categories
            .iter()
            .flat_map(|category| &category.entries)
            .filter(
                |entry| matches!(entry, NativeEntry::Rule(rule) if rule.compiled_regex.is_some()),
            )
            .count()
    }

    pub fn inspect_request(&self, request: &NativeRequest) -> NativeDecision {
        let mut transaction = NativeTransaction::new(request);
        for phase in [1, 2] {
            transaction.set_phase(phase);
            for category in &self.categories {
                if transaction.blocked {
                    break;
                }
                if !request.enabled_categories.is_empty()
                    && !request
                        .enabled_categories
                        .iter()
                        .any(|enabled| enabled == &category.name)
                {
                    continue;
                }
                execute_category(category, request, &mut transaction);
            }
        }
        transaction.decision()
    }
}

pub fn native_plan() -> Result<&'static NativePlan, &'static NativePlanError> {
    static PLAN: OnceLock<Result<NativePlan, NativePlanError>> = OnceLock::new();
    match PLAN.get_or_init(NativePlan::load) {
        Ok(plan) => Ok(plan),
        Err(error) => Err(error),
    }
}

fn execute_category(
    category: &NativeCategory,
    request: &NativeRequest,
    transaction: &mut NativeTransaction,
) {
    for entry in &category.entries {
        if transaction.blocked {
            break;
        }
        match entry {
            NativeEntry::Marker { name } => {
                if transaction.skip == *name {
                    transaction.skip.clear();
                }
            }
            NativeEntry::Rule(rule) => execute_rule(rule, request, transaction),
        }
    }
}

fn execute_rule(rule: &NativeRule, request: &NativeRequest, transaction: &mut NativeTransaction) {
    if rule.phase != transaction.phase
        || rule.paranoia_level > transaction.paranoia_level
        || !transaction.skip.is_empty()
    {
        return;
    }
    transaction.rules_evaluated += 1;
    let parent_matched = rule.chain_index == 0
        || transaction
            .chain
            .as_ref()
            .is_some_and(|chain| chain.matched);
    let matched = parent_matched
        && target_values(rule, request, transaction)
            .into_iter()
            .map(|value| apply_transforms(value, &rule.transforms))
            .any(|value| operator_matches(rule, transaction, &value));

    if rule.chain_index == 0 && rule.has_chain {
        transaction.chain = Some(PendingChain {
            id: rule.id,
            score: rule.anomaly_score,
            disruptive: rule.disruptive,
            status: rule.status,
            skip_after: rule.skip_after.clone(),
            message: rule.message.clone(),
            matched,
        });
    } else if rule.chain_index > 0 {
        let chain_complete = !rule.has_chain;
        if let Some(chain) = transaction.chain.as_mut() {
            chain.matched &= matched;
        }
        if chain_complete
            && let Some(chain) = transaction.chain.take()
            && chain.matched
        {
            transaction.record(
                chain.id,
                chain.score,
                chain.disruptive,
                chain.status,
                &chain.skip_after,
                &chain.message,
            );
        }
    } else if matched {
        transaction.record(
            rule.id,
            rule.anomaly_score,
            rule.disruptive,
            rule.status,
            &rule.skip_after,
            &rule.message,
        );
    }
}

fn target_values(
    rule: &NativeRule,
    request: &NativeRequest,
    transaction: &NativeTransaction,
) -> Vec<String> {
    let mut values = Vec::new();
    for target in rule.targets.iter().filter(|target| !target.negated) {
        let mut selected = select_target_values(target, request, transaction, rule);
        if target.counted {
            values.push(selected.len().to_string());
        } else {
            values.append(&mut selected);
        }
    }
    values
}

fn select_target_values(
    target: &NativeTarget,
    request: &NativeRequest,
    transaction: &NativeTransaction,
    rule: &NativeRule,
) -> Vec<String> {
    let scalar = |value: &str| {
        if target_is_excluded(rule, &target.base, "") {
            Vec::new()
        } else {
            vec![value.to_string()]
        }
    };
    match target.base.as_str() {
        "REQUEST_METHOD" => scalar(&request.method),
        "REQUEST_FILENAME" | "REQUEST_URI" | "REQUEST_URI_RAW" | "REQUEST_BASENAME" => {
            scalar(&request.path)
        }
        "QUERY_STRING" => scalar(&request.query),
        "REQUEST_BODY" | "XML" => scalar(&request.body),
        "REQUEST_PROTOCOL" => scalar(&request.protocol),
        "REMOTE_ADDR" => scalar(&request.client_ip),
        "REQUEST_HEADERS" => pair_values(&request.headers, target, rule, false),
        "REQUEST_HEADERS_NAMES" => pair_values(&request.headers, target, rule, true),
        "REQUEST_COOKIES" => pair_values(&transaction.cookies, target, rule, false),
        "REQUEST_COOKIES_NAMES" => pair_values(&transaction.cookies, target, rule, true),
        "ARGS" | "ARGS_GET" => pair_values(&request.args, target, rule, false),
        "ARGS_NAMES" | "ARGS_GET_NAMES" => pair_values(&request.args, target, rule, true),
        "TX" if !target.selector.starts_with('/') => transaction
            .tx
            .get(&target.selector.to_ascii_lowercase())
            .map(|value| vec![value.clone()])
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn pair_values(
    collection: &BTreeMap<String, String>,
    target: &NativeTarget,
    rule: &NativeRule,
    names: bool,
) -> Vec<String> {
    collection
        .iter()
        .filter(|(name, _)| selector_matches(target, name))
        .filter(|(name, _)| !target_is_excluded(rule, &target.base, name))
        .map(|(name, value)| if names { name.clone() } else { value.clone() })
        .collect()
}

fn target_is_excluded(rule: &NativeRule, base: &str, name: &str) -> bool {
    rule.targets.iter().any(|candidate| {
        candidate.negated
            && candidate.base == base
            && (candidate.selector.is_empty()
                || (!name.is_empty() && selector_matches(candidate, name)))
    })
}

fn selector_matches(target: &NativeTarget, name: &str) -> bool {
    target.selector.is_empty()
        || name.eq_ignore_ascii_case(&target.selector)
        || target
            .compiled_selector
            .as_ref()
            .is_some_and(|selector| selector.is_match(name))
}

fn selector_regex_pattern(selector: &str) -> Option<&str> {
    selector
        .strip_prefix('/')
        .and_then(|selector| selector.strip_suffix('/'))
}

fn operator_matches(rule: &NativeRule, transaction: &NativeTransaction, value: &str) -> bool {
    let negated = rule.operator.starts_with('!');
    let operator = rule.operator.trim_start_matches('!');
    let expected = expand_operator_pattern(&rule.pattern, &transaction.tx);
    let matched = match operator {
        "@rx" => {
            if expected == rule.pattern {
                rule.compiled_regex
                    .as_ref()
                    .is_some_and(|regex| regex.is_match(value))
            } else {
                Regex::new(&expected).is_ok_and(|regex| regex.is_match(value))
            }
        }
        "@detectSQLi" => detect_sqli(value),
        "@streq" => value == expected,
        "@within" => format!(" {expected} ").contains(&format!(" {value} ")),
        "@lt" => parse_number(value, 0) < parse_number(&expected, 0),
        _ => false,
    };
    if negated { !matched } else { matched }
}

fn expand_operator_pattern(pattern: &str, tx: &HashMap<String, String>) -> String {
    let mut expanded = pattern.to_string();
    for (key, value) in tx {
        expanded = expanded.replace(&format!("%{{tx.{key}}}"), value);
        expanded = expanded.replace(&format!("%{{TX.{key}}}"), value);
    }
    expanded
}

fn apply_transforms(mut value: String, transforms: &[String]) -> String {
    static WHITESPACE: OnceLock<Regex> = OnceLock::new();
    static COMMENTS: OnceLock<Regex> = OnceLock::new();
    let whitespace =
        WHITESPACE.get_or_init(|| Regex::new(r"\s+").expect("static whitespace regex"));
    let comments =
        COMMENTS.get_or_init(|| Regex::new(r"(?s)/\*.*?\*/").expect("static comment regex"));
    for transform in transforms {
        match transform.as_str() {
            "cssDecode" | "jsDecode" | "urlDecodeUni" => {
                for (encoded, decoded) in [
                    ("%27", "'"),
                    ("%22", "\""),
                    ("%20", " "),
                    ("%3d", "="),
                    ("%3D", "="),
                    ("%3c", "<"),
                    ("%3C", "<"),
                    ("%3e", ">"),
                    ("%3E", ">"),
                    ("+", " "),
                ] {
                    value = value.replace(encoded, decoded);
                }
            }
            "removeNulls" => value = value.replace('\0', ""),
            "removeWhitespace" => {
                value = whitespace.replace_all(&value, "").into_owned();
            }
            "replaceComments" => {
                value = comments.replace_all(&value, " ").into_owned();
            }
            "lowercase" => value.make_ascii_lowercase(),
            _ => {}
        }
    }
    value
}

fn detect_sqli(value: &str) -> bool {
    let text = value.to_ascii_lowercase();
    (text.contains(" union ") && text.contains("select"))
        || text.contains("' or '")
        || text.contains("'or 1=1")
        || text.contains(" or 1=1")
        || text.contains("sleep(")
        || text.contains("benchmark(")
        || text.contains("information_schema")
}

fn parse_number(value: &str, fallback: i64) -> i64 {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        fallback
    } else {
        value.parse().unwrap_or(fallback)
    }
}
