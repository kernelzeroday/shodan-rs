use anyhow::Result;

use crate::api::ShodanClient;
use crate::output::print_host;

pub async fn run(
    client: &ShodanClient,
    ip: &str,
    history: bool,
    minify: bool,
) -> Result<()> {
    let host = client
        .host_info(ip, history, minify)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    print_host(&host, history);
    Ok(())
}
