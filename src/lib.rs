use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum SieveError {
    #[error("proposal JSON is invalid: {0}")]
    ProposalJson(#[from] serde_json::Error),
    #[error("policy TOML is invalid: {0}")]
    PolicyToml(#[from] toml::de::Error),
    #[error("policy version {0} is unsupported; expected 1")]
    PolicyVersion(u32),
    #[error("policy rule '{0}' has no hosts")]
    EmptyHosts(String),
    #[error("policy contains duplicate rule id '{0}'")]
    DuplicateRule(String),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub proposal_id: String,
    pub endpoints: Vec<Endpoint>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub id: String,
    pub url: String,
    pub method: String,
    pub purpose: String,
    #[serde(default)]
    pub body_bytes: u64,
    #[serde(default)]
    pub redirect_chain: Vec<String>,
    #[serde(default)]
    pub inspected: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Defaults {
    pub require_inspection: bool,
    pub allow_ip_literals: bool,
    pub allow_private_ips: bool,
    pub allow_cross_origin_redirects: bool,
    pub max_redirects: usize,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            require_inspection: true,
            allow_ip_literals: false,
            allow_private_ips: false,
            allow_cross_origin_redirects: false,
            max_redirects: 3,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub hosts: Vec<String>,
    #[serde(default = "default_schemes")]
    pub schemes: Vec<String>,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    pub max_body_bytes: Option<u64>,
}

fn default_schemes() -> Vec<String> {
    vec!["https".to_string()]
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Finding {
    pub code: String,
    pub endpoint_id: String,
    pub target: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AuditedEndpoint {
    pub endpoint_id: String,
    pub normalized_url: String,
    pub redirect_hops: usize,
    pub rule_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub proposal_id: String,
    pub proposal_digest: String,
    pub allowed: bool,
    pub endpoint_count: usize,
    pub audited_target_count: usize,
    pub audited_endpoints: Vec<AuditedEndpoint>,
    pub findings: Vec<Finding>,
}

impl Proposal {
    pub fn from_json(input: &str) -> Result<Self, SieveError> {
        Ok(serde_json::from_str(input)?)
    }
}

impl Policy {
    pub fn from_toml(input: &str) -> Result<Self, SieveError> {
        let policy: Self = toml::from_str(input)?;
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> Result<(), SieveError> {
        if self.version != 1 {
            return Err(SieveError::PolicyVersion(self.version));
        }
        let mut ids = HashSet::new();
        for rule in &self.rules {
            if rule.hosts.is_empty() {
                return Err(SieveError::EmptyHosts(rule.id.clone()));
            }
            if !ids.insert(rule.id.clone()) {
                return Err(SieveError::DuplicateRule(rule.id.clone()));
            }
        }
        Ok(())
    }
}

pub fn audit(proposal: &Proposal, policy: &Policy) -> Report {
    let mut findings = Vec::new();
    let mut audited_endpoints = Vec::new();
    let mut ids = HashSet::new();
    let mut audited_target_count = 0;

    if proposal.endpoints.is_empty() {
        findings.push(finding(
            "proposal-empty",
            "-",
            "-",
            "proposal must declare at least one endpoint",
        ));
    }

    for endpoint in &proposal.endpoints {
        if endpoint.id.trim().is_empty() {
            findings.push(finding(
                "endpoint-id-empty",
                "-",
                &endpoint.url,
                "endpoint id must not be empty",
            ));
        } else if !ids.insert(endpoint.id.clone()) {
            findings.push(finding(
                "endpoint-id-duplicate",
                &endpoint.id,
                &endpoint.url,
                "endpoint ids must be unique within a proposal",
            ));
        }
        if endpoint.purpose.trim().is_empty() {
            findings.push(finding(
                "purpose-empty",
                &endpoint.id,
                &endpoint.url,
                "endpoint purpose must not be empty",
            ));
        }
        if policy.defaults.require_inspection && !endpoint.inspected {
            findings.push(finding(
                "endpoint-uninspected",
                &endpoint.id,
                &endpoint.url,
                "policy requires every proposed endpoint to be inspected",
            ));
        }
        if endpoint.redirect_chain.len() > policy.defaults.max_redirects {
            findings.push(finding(
                "redirect-limit-exceeded",
                &endpoint.id,
                &endpoint.url,
                &format!(
                    "{} redirect hops exceed policy maximum {}",
                    endpoint.redirect_chain.len(),
                    policy.defaults.max_redirects
                ),
            ));
        }

        let mut targets = Vec::with_capacity(endpoint.redirect_chain.len() + 1);
        targets.push(endpoint.url.as_str());
        targets.extend(endpoint.redirect_chain.iter().map(String::as_str));
        let mut parsed_targets: Vec<Option<Url>> = Vec::with_capacity(targets.len());
        let mut matched_rule_ids = BTreeSet::new();

        for target in &targets {
            audited_target_count += 1;
            match Url::parse(target) {
                Ok(url) => {
                    audit_url(
                        endpoint,
                        &url,
                        target,
                        policy,
                        &mut findings,
                        &mut matched_rule_ids,
                    );
                    parsed_targets.push(Some(url));
                }
                Err(error) => {
                    findings.push(finding(
                        "url-invalid",
                        &endpoint.id,
                        target,
                        &format!("URL could not be parsed: {error}"),
                    ));
                    parsed_targets.push(None);
                }
            }
        }

        for pair in parsed_targets.windows(2) {
            if let [Some(from), Some(to)] = pair {
                if from.scheme() == "https" && to.scheme() == "http" {
                    findings.push(finding(
                        "redirect-tls-downgrade",
                        &endpoint.id,
                        to.as_str(),
                        "redirect chain downgrades HTTPS to HTTP",
                    ));
                }
                if !policy.defaults.allow_cross_origin_redirects && origin(from) != origin(to) {
                    findings.push(finding(
                        "redirect-cross-origin",
                        &endpoint.id,
                        to.as_str(),
                        "redirect changes origin but policy forbids cross-origin redirects",
                    ));
                }
            }
        }

        let normalized_url = parsed_targets
            .first()
            .and_then(Option::as_ref)
            .map(normalize_url)
            .unwrap_or_else(|| endpoint.url.clone());
        audited_endpoints.push(AuditedEndpoint {
            endpoint_id: endpoint.id.clone(),
            normalized_url,
            redirect_hops: endpoint.redirect_chain.len(),
            rule_ids: matched_rule_ids.into_iter().collect(),
        });
    }

    findings.sort_by(|a, b| {
        (&a.endpoint_id, &a.code, &a.target).cmp(&(&b.endpoint_id, &b.code, &b.target))
    });
    audited_endpoints.sort_by(|a, b| a.endpoint_id.cmp(&b.endpoint_id));

    Report {
        proposal_id: proposal.proposal_id.clone(),
        proposal_digest: proposal_digest(proposal),
        allowed: findings.is_empty(),
        endpoint_count: proposal.endpoints.len(),
        audited_target_count,
        audited_endpoints,
        findings,
    }
}

fn audit_url(
    endpoint: &Endpoint,
    url: &Url,
    raw_target: &str,
    policy: &Policy,
    findings: &mut Vec<Finding>,
    matched_rule_ids: &mut BTreeSet<String>,
) {
    if !url.username().is_empty() || url.password().is_some() {
        findings.push(finding(
            "url-credentials",
            &endpoint.id,
            raw_target,
            "embedded URL credentials are forbidden",
        ));
    }
    if url.fragment().is_some() {
        findings.push(finding(
            "url-fragment",
            &endpoint.id,
            raw_target,
            "URL fragments are not sent to the server and are forbidden in endpoint declarations",
        ));
    }

    let Some(host) = url.host_str() else {
        findings.push(finding(
            "host-missing",
            &endpoint.id,
            raw_target,
            "URL must contain a host",
        ));
        return;
    };
    let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !policy.defaults.allow_ip_literals {
            findings.push(finding(
                "ip-literal-forbidden",
                &endpoint.id,
                raw_target,
                "IP-literal endpoints are disabled by policy",
            ));
        }
        if !policy.defaults.allow_private_ips && is_non_public_ip(ip) {
            findings.push(finding(
                "private-ip-forbidden",
                &endpoint.id,
                raw_target,
                "private, loopback, link-local, multicast, or unspecified IP is disabled by policy",
            ));
        }
    }

    let method = endpoint.method.to_ascii_uppercase();
    let matches: Vec<&Rule> = policy
        .rules
        .iter()
        .filter(|rule| rule_matches(rule, url, &host, &method, endpoint.body_bytes))
        .collect();
    if matches.is_empty() {
        findings.push(finding(
            "endpoint-not-allowed",
            &endpoint.id,
            raw_target,
            "no policy rule allows this scheme, host, port, path, method, and body size",
        ));
    } else {
        for rule in matches {
            matched_rule_ids.insert(rule.id.clone());
        }
    }
}

fn rule_matches(rule: &Rule, url: &Url, host: &str, method: &str, body_bytes: u64) -> bool {
    let port = effective_port(url);
    rule.schemes
        .iter()
        .any(|scheme| scheme.eq_ignore_ascii_case(url.scheme()))
        && rule.hosts.iter().any(|pattern| host_matches(pattern, host))
        && (rule.ports.is_empty() || port.is_some_and(|value| rule.ports.contains(&value)))
        && (rule.path_prefixes.is_empty()
            || rule
                .path_prefixes
                .iter()
                .any(|prefix| url.path().starts_with(prefix)))
        && (rule.methods.is_empty()
            || rule
                .methods
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(method)))
        && rule.max_body_bytes.is_none_or(|limit| body_bytes <= limit)
}

fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}"))
    } else {
        host == pattern
    }
}

fn effective_port(url: &Url) -> Option<u16> {
    url.port_or_known_default()
}

fn origin(url: &Url) -> (String, String, Option<u16>) {
    (
        url.scheme().to_ascii_lowercase(),
        url.host_str().unwrap_or_default().to_ascii_lowercase(),
        effective_port(url),
    )
}

fn normalize_url(url: &Url) -> String {
    let mut normalized = url.clone();
    normalized.set_fragment(None);
    if matches!(
        (normalized.scheme(), normalized.port()),
        ("https", Some(443)) | ("http", Some(80))
    ) {
        let _ = normalized.set_port(None);
    }
    normalized.to_string()
}

fn is_non_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_non_public_v4(ip),
        IpAddr::V6(ip) => is_non_public_v6(ip),
    }
}

fn is_non_public_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_unspecified()
        || octets[0] == 0
        || octets[0] >= 240
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
}

fn is_non_public_v6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
}

fn proposal_digest(proposal: &Proposal) -> String {
    let mut normalized = proposal.clone();
    normalized.endpoints.sort_by(|a, b| a.id.cmp(&b.id));
    let bytes = serde_json::to_vec(&normalized).expect("serializing Proposal cannot fail");
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn finding(code: &str, endpoint_id: &str, target: &str, message: &str) -> Finding {
    Finding {
        code: code.to_string(),
        endpoint_id: endpoint_id.to_string(),
        target: target.to_string(),
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy::from_toml(
            r#"
version = 1
[defaults]
max_redirects = 2
[[rules]]
id = "api"
hosts = ["api.example.com", "*.trusted.example"]
schemes = ["https"]
ports = [443]
path_prefixes = ["/v1/"]
methods = ["GET", "POST"]
max_body_bytes = 1024
"#,
        )
        .unwrap()
    }

    fn endpoint(url: &str) -> Endpoint {
        Endpoint {
            id: "lookup".into(),
            url: url.into(),
            method: "GET".into(),
            purpose: "retrieve fixture".into(),
            body_bytes: 0,
            redirect_chain: vec![],
            inspected: true,
        }
    }

    fn run(endpoint: Endpoint) -> Report {
        audit(
            &Proposal {
                proposal_id: "p-1".into(),
                endpoints: vec![endpoint],
            },
            &policy(),
        )
    }

    #[test]
    fn allows_exact_host() {
        assert!(run(endpoint("https://api.example.com/v1/items")).allowed);
    }

    #[test]
    fn wildcard_requires_a_subdomain() {
        assert!(run(endpoint("https://a.trusted.example/v1/items")).allowed);
        assert!(!run(endpoint("https://trusted.example/v1/items")).allowed);
    }

    #[test]
    fn rejects_credentials_and_fragment() {
        let report = run(endpoint("https://user:pass@api.example.com/v1/items#token"));
        let codes: Vec<_> = report.findings.iter().map(|f| f.code.as_str()).collect();
        assert!(codes.contains(&"url-credentials"));
        assert!(codes.contains(&"url-fragment"));
    }

    #[test]
    fn rejects_private_ip_even_when_rule_matches() {
        let mut policy = policy();
        policy.rules[0].hosts = vec!["127.0.0.1".into()];
        let proposal = Proposal {
            proposal_id: "p".into(),
            endpoints: vec![endpoint("https://127.0.0.1/v1/items")],
        };
        let report = audit(&proposal, &policy);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.code == "ip-literal-forbidden")
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.code == "private-ip-forbidden")
        );
    }

    #[test]
    fn rejects_uninspected_endpoint() {
        let mut value = endpoint("https://api.example.com/v1/items");
        value.inspected = false;
        assert!(
            run(value)
                .findings
                .iter()
                .any(|f| f.code == "endpoint-uninspected")
        );
    }

    #[test]
    fn rejects_body_over_rule_limit() {
        let mut value = endpoint("https://api.example.com/v1/items");
        value.method = "POST".into();
        value.body_bytes = 1025;
        assert!(
            run(value)
                .findings
                .iter()
                .any(|f| f.code == "endpoint-not-allowed")
        );
    }

    #[test]
    fn rejects_cross_origin_redirect() {
        let mut value = endpoint("https://api.example.com/v1/items");
        value.redirect_chain = vec!["https://cdn.trusted.example/v1/items".into()];
        assert!(
            run(value)
                .findings
                .iter()
                .any(|f| f.code == "redirect-cross-origin")
        );
    }

    #[test]
    fn digest_is_independent_of_endpoint_order() {
        let first = endpoint("https://api.example.com/v1/a");
        let mut second = endpoint("https://api.example.com/v1/b");
        second.id = "second".into();
        let a = Proposal {
            proposal_id: "p".into(),
            endpoints: vec![first.clone(), second.clone()],
        };
        let b = Proposal {
            proposal_id: "p".into(),
            endpoints: vec![second, first],
        };
        assert_eq!(proposal_digest(&a), proposal_digest(&b));
    }

    #[test]
    fn policy_rejects_duplicate_rule_ids() {
        let result = Policy::from_toml(
            r#"
version = 1
[[rules]]
id = "same"
hosts = ["one.example"]
[[rules]]
id = "same"
hosts = ["two.example"]
"#,
        );
        assert!(matches!(result, Err(SieveError::DuplicateRule(_))));
    }
}
