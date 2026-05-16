use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HostInfo {
    pub ip_str: Option<String>,
    pub ipv6: Option<String>,
    pub hostnames: Option<Vec<String>>,
    pub city: Option<String>,
    pub country_name: Option<String>,
    pub country_code: Option<String>,
    pub org: Option<String>,
    pub isp: Option<String>,
    pub os: Option<String>,
    pub last_update: Option<String>,
    pub ports: Option<Vec<u16>>,
    pub vulns: Option<Vec<String>>,
    pub data: Option<Vec<Banner>>,
    pub asn: Option<String>,
    pub region_code: Option<String>,
    pub postal_code: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Banner {
    pub port: u16,
    pub transport: Option<String>,
    pub timestamp: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub data: Option<String>,
    pub http: Option<HttpInfo>,
    pub ssl: Option<SslInfo>,
    pub placeholder: Option<bool>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HttpInfo {
    pub title: Option<String>,
    pub status: Option<u16>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SslInfo {
    pub cert: Option<CertInfo>,
    pub versions: Option<Vec<String>>,
    pub dhparams: Option<DhParams>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CertInfo {
    pub issuer: Option<HashMap<String, String>>,
    pub subject: Option<HashMap<String, String>>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DhParams {
    pub bits: Option<u32>,
    pub generator: Option<String>,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SearchResult {
    pub matches: Vec<Value>,
    pub total: u64,
    pub facets: Option<HashMap<String, Vec<FacetValue>>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FacetValue {
    pub value: Value,
    pub count: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CountResult {
    pub total: u64,
    pub facets: Option<HashMap<String, Vec<FacetValue>>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ApiInfo {
    pub scan_credits: i64,
    pub usage_limits: UsageLimits,
    pub plan: String,
    pub unlocked: bool,
    pub query_credits: i64,
    pub monitored_ips: Option<i64>,
    pub unlocked_left: i64,
    pub telnet: bool,
    pub https: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UsageLimits {
    pub scan_credits: i64,
    pub query_credits: i64,
    pub monitored_ips: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScanResult {
    pub id: String,
    pub count: u32,
    pub credits_left: i32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScanStatus {
    pub id: String,
    pub count: Option<u32>,
    pub created: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Alert {
    pub id: String,
    pub name: String,
    pub filters: AlertFilters,
    pub expires: Option<i64>,
    pub created: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AlertFilters {
    pub ip: Value,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DnsDomain {
    pub domain: String,
    pub tags: Option<Vec<String>>,
    pub data: Vec<DnsRecord>,
    pub subdomains: Vec<String>,
    pub more: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DnsRecord {
    pub subdomain: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub value: String,
    pub last_seen: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Dataset {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DataFile {
    pub name: String,
    pub url: String,
    pub size: u64,
    pub timestamp: Option<String>,
}
