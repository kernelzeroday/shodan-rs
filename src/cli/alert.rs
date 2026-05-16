use anyhow::Result;
use serde_json::Value;

use crate::api::ShodanClient;

pub async fn run_list(client: &ShodanClient) -> Result<()> {
    let alerts = client
        .alerts()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    if alerts.is_empty() {
        println!("No alerts found.");
        return Ok(());
    }
    for alert in &alerts {
        let ip = match &alert.filters.ip {
            Value::String(s) => s.clone(),
            Value::Array(arr) => arr
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            other => other.to_string(),
        };
        println!("{:30} {} ({})", alert.name, ip, alert.id);
    }
    Ok(())
}

pub async fn run_create(
    client: &ShodanClient,
    name: &str,
    ip: &str,
    expires: i64,
) -> Result<()> {
    let alert = client
        .create_alert(name, Value::String(ip.to_string()), expires)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("Successfully created network alert!");
    println!("  Alert ID: {}", alert.id);
    Ok(())
}

pub async fn run_delete(client: &ShodanClient, aid: &str) -> Result<()> {
    client
        .delete_alert(aid)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("Alert {} deleted.", aid);
    Ok(())
}

pub async fn run_triggers(client: &ShodanClient) -> Result<()> {
    let triggers = client
        .alert_triggers()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    if let Some(arr) = triggers.as_array() {
        for t in arr {
            let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let desc = t.get("description").and_then(|v| v.as_str()).unwrap_or("");
            println!("{:30} {}", name, desc);
        }
    }
    Ok(())
}

pub async fn run_enable_trigger(
    client: &ShodanClient,
    aid: &str,
    trigger: &str,
) -> Result<()> {
    client
        .enable_alert_trigger(aid, trigger)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("Trigger '{}' enabled on alert {}.", trigger, aid);
    Ok(())
}

pub async fn run_disable_trigger(
    client: &ShodanClient,
    aid: &str,
    trigger: &str,
) -> Result<()> {
    client
        .disable_alert_trigger(aid, trigger)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("Trigger '{}' disabled on alert {}.", trigger, aid);
    Ok(())
}
