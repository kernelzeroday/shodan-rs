use anyhow::Result;
use serde_json::Value;

use crate::api::ShodanClient;

fn format_ips(value: &Value) -> String {
    match value {
        Value::String(ip) => ip.clone(),
        Value::Array(ips) => ips
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", "),
        other => other.to_string(),
    }
}

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
        println!(
            "{:30} {} ({})",
            alert.name,
            format_ips(&alert.filters.ip),
            alert.id
        );
    }
    Ok(())
}

pub async fn run_info(client: &ShodanClient, aid: &str) -> Result<()> {
    let alert = client
        .alert_info(aid)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("{}", alert.name);
    println!("Alert ID: {}", alert.id);
    if let Some(created) = alert.created {
        println!("Created:  {}", created);
    }
    if let Some(expires) = alert.expires {
        println!(
            "Expires:  {}",
            if expires == 0 {
                "never".to_string()
            } else {
                expires.to_string()
            }
        );
    }
    println!("Networks: {}", format_ips(&alert.filters.ip));
    Ok(())
}

pub async fn run_create(
    client: &ShodanClient,
    name: &str,
    ips: &[String],
    expires: i64,
) -> Result<()> {
    let alert = client
        .create_alert(name, ips, expires)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("Successfully created network alert!");
    println!("  Alert ID: {}", alert.id);
    Ok(())
}

pub async fn run_update(client: &ShodanClient, aid: &str, ips: &[String]) -> Result<()> {
    client
        .update_alert(aid, ips)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("Alert {} updated.", aid);
    Ok(())
}

pub async fn run_clear(client: &ShodanClient) -> Result<()> {
    let alerts = client
        .alerts()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    if alerts.is_empty() {
        println!("No alerts found.");
        return Ok(());
    }

    let count = alerts.len();
    for alert in alerts {
        println!("Deleting {} ({})", alert.name, alert.id);
        client
            .delete_alert(&alert.id)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;
    }
    println!("Deleted {} alert(s).", count);
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

pub async fn run_enable_trigger(client: &ShodanClient, aid: &str, trigger: &str) -> Result<()> {
    client
        .enable_alert_trigger(aid, trigger)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("Trigger '{}' enabled on alert {}.", trigger, aid);
    Ok(())
}

pub async fn run_disable_trigger(client: &ShodanClient, aid: &str, trigger: &str) -> Result<()> {
    client
        .disable_alert_trigger(aid, trigger)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("Trigger '{}' disabled on alert {}.", trigger, aid);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    #[tokio::test]
    async fn clear_deletes_every_alert() {
        let mut server = Server::new_async().await;
        let list = server
            .mock("GET", "/shodan/alert/info")
            .match_query(mockito::Matcher::UrlEncoded("key".into(), "testkey".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"[{"id":"one","name":"first","filters":{"ip":["1.2.3.4"]}},{"id":"two","name":"second","filters":{"ip":["10.0.0.0/24"]}}]"#,
            )
            .create_async()
            .await;
        let delete_one = server
            .mock("DELETE", "/shodan/alert/one")
            .match_query(mockito::Matcher::UrlEncoded("key".into(), "testkey".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{}"#)
            .create_async()
            .await;
        let delete_two = server
            .mock("DELETE", "/shodan/alert/two")
            .match_query(mockito::Matcher::UrlEncoded("key".into(), "testkey".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let client = ShodanClient::with_base_url("testkey", server.url());
        run_clear(&client).await.unwrap();

        list.assert_async().await;
        delete_one.assert_async().await;
        delete_two.assert_async().await;
    }
}
