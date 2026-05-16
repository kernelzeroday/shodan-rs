use anyhow::Result;

use crate::api::ShodanClient;
use crate::output::humanize_bytes;

pub async fn run_list(client: &ShodanClient) -> Result<()> {
    let datasets = client
        .list_datasets()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    if datasets.is_empty() {
        println!("No datasets available.");
        return Ok(());
    }
    for ds in &datasets {
        let desc = ds.description.as_deref().unwrap_or("");
        println!("{:30} {}", ds.name, desc);
    }
    Ok(())
}

pub async fn run_files(client: &ShodanClient, dataset: &str) -> Result<()> {
    let files = client
        .list_dataset_files(dataset)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    if files.is_empty() {
        println!("No files in dataset '{}'.", dataset);
        return Ok(());
    }
    for f in &files {
        let ts = f.timestamp.as_deref().unwrap_or("");
        println!(
            "{:15} {:25} {}",
            humanize_bytes(f.size),
            ts,
            f.name
        );
    }
    Ok(())
}
