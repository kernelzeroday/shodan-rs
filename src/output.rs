use colored::Colorize;
use serde_json::Value;

use crate::api::types::{Banner, HostInfo};

pub fn print_host(host: &HostInfo, history: bool) {
    let ip = host
        .ipv6
        .as_deref()
        .or(host.ip_str.as_deref())
        .unwrap_or("unknown");
    println!("{}", ip.green());

    if let Some(names) = &host.hostnames {
        if !names.is_empty() {
            println!("{:25}{}", "Hostnames:", names.join(";"));
        }
    }
    if let Some(tags) = &host.tags {
        if !tags.is_empty() {
            println!("{:25}{}", "Tags:", tags.join(";"));
        }
    }
    if let Some(city) = &host.city {
        println!("{:25}{}", "City:", city);
    }
    if let Some(country) = &host.country_name {
        println!("{:25}{}", "Country:", country);
    }
    if let Some(os) = &host.os {
        println!("{:25}{}", "Operating System:", os);
    }
    if let Some(org) = &host.org {
        println!("{:25}{}", "Organization:", org);
    }
    if let Some(ts) = &host.last_update {
        println!("{:25}{}", "Updated:", ts);
    }
    if let Some(ports) = &host.ports {
        println!("{:25}{}", "Number of open ports:", ports.len());
    }
    if let Some(vulns) = &host.vulns {
        let visible: Vec<String> = vulns
            .iter()
            .filter(|v| !v.starts_with('!'))
            .map(|v| {
                if v.to_uppercase() == "CVE-2014-0160" {
                    "Heartbleed".red().to_string()
                } else {
                    v.red().to_string()
                }
            })
            .collect();
        if !visible.is_empty() {
            print!("{:25}", "Vulnerabilities:");
            for v in &visible {
                print!("{}\t", v);
            }
            println!();
        }
    }
    println!();

    if let Some(data) = &host.data {
        let mut banners = data.clone();
        // Fill in placeholder banners for ports with no visible data
        if let Some(ports) = &host.ports {
            if ports.len() != banners.len() {
                let visible_ports: std::collections::HashSet<u16> =
                    banners.iter().map(|b| b.port).collect();
                let last_ts = banners.last().and_then(|b| b.timestamp.clone());
                for &p in ports {
                    if !visible_ports.contains(&p) {
                        banners.push(Banner {
                            port: p,
                            transport: Some("tcp".to_string()),
                            timestamp: last_ts.clone(),
                            product: None,
                            version: None,
                            data: None,
                            http: None,
                            ssl: None,
                            placeholder: Some(true),
                            extra: Default::default(),
                        });
                    }
                }
            }
        }

        banners.sort_by_key(|b| b.port);
        println!("Ports:");
        for banner in &banners {
            let product = banner.product.as_deref().unwrap_or("");
            let version = banner
                .version
                .as_ref()
                .map(|v| format!("({})", v))
                .unwrap_or_default();
            let transport = banner.transport.as_deref().unwrap_or("tcp");

            print!("{}", format!("{:>7}", banner.port).cyan());
            print!("/{} ", transport.yellow());
            print!("{} {}", product, version);

            if history {
                let date = banner
                    .timestamp
                    .as_deref()
                    .map(|t| &t[..10.min(t.len())])
                    .unwrap_or("");
                print!("{}", format!("\t\t({})", date).dimmed());
            }
            println!();

            if let Some(http) = &banner.http {
                if let Some(title) = &http.title {
                    println!("\t|-- HTTP title: {}", title);
                }
            }
            if let Some(ssl) = &banner.ssl {
                if let Some(cert) = &ssl.cert {
                    if let Some(issuer) = &cert.issuer {
                        let s: Vec<String> = issuer
                            .iter()
                            .map(|(k, v)| format!("{}={}", k, v))
                            .collect();
                        println!("\t|-- Cert Issuer: {}", s.join(", "));
                    }
                    if let Some(subject) = &cert.subject {
                        let s: Vec<String> = subject
                            .iter()
                            .map(|(k, v)| format!("{}={}", k, v))
                            .collect();
                        println!("\t|-- Cert Subject: {}", s.join(", "));
                    }
                }
                if let Some(versions) = &ssl.versions {
                    let pos: Vec<&str> = versions
                        .iter()
                        .filter(|v| !v.starts_with('-'))
                        .map(|v| v.as_str())
                        .collect();
                    if !pos.is_empty() {
                        let mut sorted = pos.clone();
                        sorted.sort_unstable();
                        println!("\t|-- SSL Versions: {}", sorted.join(", "));
                    }
                }
                if let Some(dh) = &ssl.dhparams {
                    println!("\t|-- Diffie-Hellman Parameters:");
                    if let Some(bits) = dh.bits {
                        println!("\t\t{:15}{}", "Bits:", bits);
                    }
                    if let Some(r#gen) = &dh.generator {
                        println!("\t\t{:15}{}", "Generator:", r#gen);
                    }
                    if let Some(fp) = &dh.fingerprint {
                        println!("\t\t{:15}{}", "Fingerprint:", fp);
                    }
                }
            }
        }
    }
}

pub fn print_banner_fields(banner: &Value, fields: &[&str], separator: &str, color: bool) {
    let parts: Vec<String> = fields
        .iter()
        .map(|f| get_field(banner, f, color))
        .collect();
    println!("{}", parts.join(separator));
}

fn get_field(val: &Value, field: &str, color: bool) -> String {
    let segments: Vec<&str> = field.split('.').collect();
    let mut current = val;
    for seg in &segments {
        match current.get(seg) {
            Some(v) => current = v,
            None => return String::new(),
        }
    }
    format_value(current, field, color)
}

fn format_value(val: &Value, field: &str, color: bool) -> String {
    let s = match val {
        Value::String(s) => escape_data(s),
        Value::Array(arr) => arr
            .iter()
            .map(|v| v.as_str().unwrap_or("").to_string())
            .collect::<Vec<_>>()
            .join(","),
        other => other.to_string(),
    };
    if !color {
        return s;
    }
    match field {
        "ip_str" => s.green().to_string(),
        "port" => s.yellow().to_string(),
        "data" => s.white().to_string(),
        "hostnames" => s.magenta().to_string(),
        "org" => s.cyan().to_string(),
        "vulns" => s.red().to_string(),
        _ => s,
    }
}

pub fn escape_data(s: &str) -> String {
    s.replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

pub fn humanize_bytes(bytes: u64) -> String {
    if bytes == 1 {
        return "1 byte".to_string();
    }
    if bytes < 1024 {
        return format!("{} bytes", bytes);
    }
    let suffixes = ["KB", "MB", "GB", "TB", "PB"];
    let mut b = bytes as f64;
    for suffix in &suffixes {
        b /= 1024.0;
        if b < 1024.0 {
            return format!("{:.1} {}", b, suffix);
        }
    }
    format!("{:.1} {}", b, suffixes.last().unwrap())
}

pub fn humanize_plan(plan: &str) -> &str {
    match plan {
        "oss" => "Free",
        "dev" => "Membership",
        "basic" => "Freelancer API",
        "plus" => "Small Business API",
        "corp" => "Corporate API",
        "stream-100" => "Enterprise",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_humanize_bytes() {
        assert_eq!(humanize_bytes(1), "1 byte");
        assert_eq!(humanize_bytes(512), "512 bytes");
        assert_eq!(humanize_bytes(1024), "1.0 KB");
        assert_eq!(humanize_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(humanize_bytes(1024 * 1024 * 1024), "1.0 GB");
    }

    #[test]
    fn test_escape_data() {
        assert_eq!(escape_data("hello\nworld"), "hello\\nworld");
        assert_eq!(escape_data("tab\there"), "tab\\there");
        assert_eq!(escape_data("cr\rend"), "cr\\rend");
    }

    #[test]
    fn test_humanize_plan() {
        assert_eq!(humanize_plan("dev"), "Membership");
        assert_eq!(humanize_plan("corp"), "Corporate API");
        assert_eq!(humanize_plan("unknown"), "unknown");
    }

    #[test]
    fn test_get_field_nested() {
        let v = serde_json::json!({"http": {"title": "Test Page"}});
        assert_eq!(get_field(&v, "http.title", false), "Test Page");
    }

    #[test]
    fn test_get_field_missing() {
        let v = serde_json::json!({"ip_str": "1.2.3.4"});
        assert_eq!(get_field(&v, "missing", false), "");
    }
}
