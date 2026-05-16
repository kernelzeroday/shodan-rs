use anyhow::Result;
use std::fs::OpenOptions;
use std::io::Write;

use crate::api::ShodanClient;
use crate::output::print_banner_fields;

pub async fn run_search(
    client: &ShodanClient,
    query: &str,
    fields: &str,
    limit: u32,
    separator: &str,
    color: bool,
) -> Result<()> {
    if limit > 1000 {
        anyhow::bail!("Too many results requested, maximum is 1,000");
    }
    let field_list: Vec<&str> = fields.split(',').map(|s| s.trim()).collect();
    if field_list.is_empty() {
        anyhow::bail!("Please define at least one property to show");
    }

    // Single API call with limit — mutually exclusive with page param
    let result = client
        .search_limit(query, limit, None, Some(fields), false)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    if result.total == 0 {
        anyhow::bail!("No search results found");
    }

    for banner in &result.matches {
        print_banner_fields(banner, &field_list, separator, color);
    }
    Ok(())
}

pub async fn run_count(client: &ShodanClient, query: &str, facets: Option<&str>) -> Result<()> {
    let result = client
        .count(query, facets)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("{}", result.total);
    Ok(())
}

pub async fn run_stats(
    client: &ShodanClient,
    query: &str,
    facets: &str,
    limit: u32,
    output_file: Option<&str>,
) -> Result<()> {
    // Use limit=1 to get total + facets with minimal result payload
    let result = client
        .search_limit(query, 1, Some(facets), None, true)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("Total results:\t{}", result.total);

    let facet_data = match &result.facets {
        Some(f) => f,
        None => return Ok(()),
    };

    let mut csv_out: Option<Box<dyn Write>> = output_file.map(|f| -> Box<dyn Write> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(f)
            .expect("Cannot open output file");
        Box::new(file)
    });

    for (facet_name, values) in facet_data {
        println!("\nTop {} {}:", limit, facet_name);
        for entry in values.iter().take(limit as usize) {
            let val = entry
                .value
                .as_str()
                .map(|s| s.to_string())
                .unwrap_or_else(|| entry.value.to_string());
            println!("{:20} {}", entry.count, val);
            if let Some(ref mut w) = csv_out {
                writeln!(w, "{},{},{}", facet_name, val, entry.count)?;
            }
        }
    }
    Ok(())
}

pub async fn run_download(
    client: &ShodanClient,
    query: &str,
    filename: &str,
    limit: i64,
    fields: Option<&str>,
) -> Result<()> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use indicatif::{ProgressBar, ProgressStyle};

    // Get total count and API info for summary display (matching Python CLI)
    let total_available = client
        .count(query, None)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?
        .total;

    let api_info = client
        .api_info()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let total_limit = if limit <= 0 {
        total_available
    } else {
        (limit as u64).min(total_available)
    };

    eprintln!("Search query:\t\t\t{}", query);
    eprintln!("Total number of results:\t{}", total_available);
    eprintln!("Query credits left:\t\t{}", api_info.unlocked_left);
    eprintln!("Output file:\t\t\t{}", filename);

    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(filename)?;
    let mut gz = GzEncoder::new(file, Compression::new(9));

    let bar = ProgressBar::new(total_limit);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40} {pos}/{len} ({percent}%)")?
            .progress_chars("=> "),
    );

    let mut fetched = 0u64;
    let mut page = 1u32;

    // Page-based cursor — no limit param per call, 100 results per page
    loop {
        let result = client
            .search_page(query, page, None, fields, false)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        for banner in &result.matches {
            if fetched >= total_limit {
                break;
            }
            let line = serde_json::to_string(banner)? + "\n";
            gz.write_all(line.as_bytes())?;
            fetched += 1;
            bar.inc(1);
        }

        if result.matches.is_empty() || fetched >= total_limit {
            break;
        }
        page += 1;
    }

    gz.finish()?;
    bar.finish_and_clear();

    if fetched < total_limit {
        eprintln!("Notice: fewer results were saved than requested");
    }
    eprintln!("Saved {} results into file {}", fetched, filename);
    Ok(())
}

pub fn run_parse(
    filenames: &[String],
    fields: &str,
    filters: &[String],
    output_file: Option<&str>,
    separator: &str,
    color: bool,
) -> Result<()> {
    use flate2::read::GzDecoder;
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let field_list: Vec<&str> = fields.split(',').collect();
    let mut out: Option<Box<dyn Write>> = output_file.map(|f| -> Box<dyn Write> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(f)
            .expect("Cannot open output file");
        Box::new(file)
    });

    for filename in filenames {
        let reader: Box<dyn BufRead> = if filename.ends_with(".gz") {
            Box::new(BufReader::new(GzDecoder::new(File::open(filename)?)))
        } else {
            Box::new(BufReader::new(File::open(filename)?))
        };

        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }
            let banner: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => continue,
            };

            if !matches_filters(&banner, filters) {
                continue;
            }

            if let Some(ref mut w) = out {
                let parts: Vec<String> = field_list
                    .iter()
                    .map(|f| get_nested_field(&banner, f))
                    .collect();
                writeln!(w, "{}", parts.join(separator))?;
            } else {
                print_banner_fields(&banner, &field_list, separator, color);
            }
        }
    }
    Ok(())
}

fn get_nested_field(val: &serde_json::Value, field: &str) -> String {
    let mut current = val;
    for seg in field.split('.') {
        match current.get(seg) {
            Some(v) => current = v,
            None => return String::new(),
        }
    }
    match current {
        serde_json::Value::String(s) => crate::output::escape_data(s),
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join(","),
        other => other.to_string(),
    }
}

fn matches_filters(banner: &serde_json::Value, filters: &[String]) -> bool {
    for filter in filters {
        let (field, check) = match filter.split_once(':') {
            Some(pair) => pair,
            None => continue,
        };

        if field == "net" {
            if !matches_net(banner, check) {
                return false;
            }
            continue;
        }

        let value = get_nested_field(banner, field);
        if value.is_empty() {
            return false;
        }
        if !value.contains(check) {
            return false;
        }
    }
    true
}

fn matches_net(banner: &serde_json::Value, cidr: &str) -> bool {
    let ip_val = banner
        .get("ip_str")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if ip_val.is_empty() {
        return false;
    }
    // Simple CIDR check using string prefix for IPv4 /8, /16, /24 or exact
    // A full implementation would use a CIDR library; this covers the common cases.
    if let Ok(network) = cidr.parse::<std::net::IpAddr>() {
        return ip_val.parse::<std::net::IpAddr>().ok() == Some(network);
    }
    if let Some((net_ip, prefix)) = cidr.split_once('/') {
        let prefix: u8 = prefix.parse().unwrap_or(32);
        let ip: std::net::Ipv4Addr = match ip_val.parse() {
            Ok(ip) => ip,
            Err(_) => return false,
        };
        let net: std::net::Ipv4Addr = match net_ip.parse() {
            Ok(n) => n,
            Err(_) => return false,
        };
        let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
        let ip_u: u32 = u32::from(ip);
        let net_u: u32 = u32::from(net);
        return (ip_u & mask) == (net_u & mask);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_net_cidr() {
        let banner = serde_json::json!({"ip_str": "10.0.1.5"});
        assert!(matches_net(&banner, "10.0.0.0/8"));
        assert!(!matches_net(&banner, "192.168.0.0/16"));
    }

    #[test]
    fn test_matches_filters_field() {
        let banner = serde_json::json!({"org": "Acme Corp", "port": 443});
        assert!(matches_filters(&banner, &["org:Acme".to_string()]));
        assert!(!matches_filters(&banner, &["org:Google".to_string()]));
    }

    #[test]
    fn test_get_nested_field() {
        let v = serde_json::json!({"http": {"title": "Admin Panel"}});
        assert_eq!(get_nested_field(&v, "http.title"), "Admin Panel");
        assert_eq!(get_nested_field(&v, "http.missing"), "");
    }
}
