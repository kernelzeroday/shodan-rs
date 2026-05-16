use anyhow::Result;

use crate::api::ShodanClient;

pub async fn run_submit(client: &ShodanClient, ips: &[String]) -> Result<()> {
    let ip_refs: Vec<&str> = ips.iter().map(|s| s.as_str()).collect();
    let result = client
        .scan_submit(&ip_refs)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("Scan ID: {}", result.id);
    println!("IPs:     {}", result.count);
    println!("Credits: {}", result.credits_left);
    Ok(())
}

pub async fn run_status(client: &ShodanClient, scan_id: &str) -> Result<()> {
    let status = client
        .scan_status(scan_id)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("Scan ID: {}", status.id);
    if let Some(s) = &status.status {
        println!("Status:  {}", s);
    }
    if let Some(ts) = &status.created {
        println!("Created: {}", ts);
    }
    Ok(())
}
