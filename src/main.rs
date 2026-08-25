use anyhow::Result;
use clap::{Parser, Subcommand};

mod api;
mod cli;
mod config;
mod output;

use api::ShodanClient;

#[derive(Parser)]
#[command(name = "shodan", version, about = "The official command-line client for Shodan")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize the Shodan CLI with your API key
    Init {
        #[arg(help = "Your Shodan API key")]
        key: String,
    },

    /// Show information about the current API key
    Info,

    /// Show your current IP address
    Myip,

    /// Get all available information for an IP address
    Host {
        #[arg(help = "IP address to look up")]
        ip: String,
        #[arg(long, help = "Show complete history of the host")]
        history: bool,
        #[arg(long, help = "Only return ports and general host info")]
        minify: bool,
    },

    /// Search the Shodan database
    Search {
        #[arg(help = "Search query", num_args = 1..)]
        query: Vec<String>,
        #[arg(long, default_value = "ip_str,port,hostnames,data",
              help = "Comma-separated list of fields to display")]
        fields: String,
        #[arg(long, default_value = "100",
              help = "Number of results to return (0 for all, max 1000 otherwise)")]
        limit: u32,
        #[arg(long, default_value = "\t", help = "Field separator")]
        separator: String,
        #[arg(long = "no-color", default_value = "false", help = "Disable colored output")]
        no_color: bool,
    },

    /// Count the number of results for a search query
    Count {
        #[arg(help = "Search query", num_args = 1..)]
        query: Vec<String>,
    },

    /// Show facet statistics for a search query
    Stats {
        #[arg(help = "Search query", num_args = 1..)]
        query: Vec<String>,
        #[arg(long, default_value = "country,org", help = "Comma-separated list of facets")]
        facets: String,
        #[arg(long, default_value = "10", help = "Number of top values to show per facet")]
        limit: u32,
        #[arg(short = 'O', long, help = "Save results to a CSV file")]
        filename: Option<String>,
    },

    /// Download search results as a compressed JSON file
    Download {
        #[arg(help = "Output filename (will add .json.gz if not present)")]
        filename: String,
        #[arg(help = "Search query", num_args = 1..)]
        query: Vec<String>,
        #[arg(long, default_value = "1000",
              help = "Number of results to download (-1 for all)")]
        limit: i64,
        #[arg(long, help = "Comma-separated list of fields to download")]
        fields: Option<String>,
    },

    /// Parse a local Shodan data file
    Parse {
        #[arg(help = "One or more .json.gz files to parse", num_args = 1..)]
        filenames: Vec<String>,
        #[arg(long, default_value = "ip_str,port,hostnames,data")]
        fields: String,
        #[arg(short = 'f', long, help = "Filter key:value (can be repeated)", action = clap::ArgAction::Append)]
        filters: Vec<String>,
        #[arg(short = 'O', long)]
        filename: Option<String>,
        #[arg(long, default_value = "\t")]
        separator: String,
        #[arg(long = "no-color", default_value = "false")]
        no_color: bool,
    },

    /// Look up a domain's DNS information
    Domain {
        #[arg(help = "Domain name to query")]
        domain: String,
        #[arg(short = 'H', long, help = "Include historical DNS data")]
        history: bool,
        #[arg(short = 'T', long, help = "Only return records of this type")]
        r#type: Option<String>,
    },

    /// Check if an IP is a honeypot
    Honeyscore {
        #[arg(help = "IP address to check")]
        ip: String,
    },

    /// Print the version
    Version,

    /// Manage network alerts
    Alert {
        #[command(subcommand)]
        subcommand: AlertCommand,
    },

    /// Manage and download data from the Shodan datasets
    Data {
        #[command(subcommand)]
        subcommand: DataCommand,
    },

    /// Submit and manage scan requests
    Scan {
        #[command(subcommand)]
        subcommand: ScanCommand,
    },
}

#[derive(Subcommand)]
enum AlertCommand {
    /// List all active alerts
    List,
    /// Create a new alert for an IP or network range
    Create {
        #[arg(help = "Name of the alert")]
        name: String,
        #[arg(help = "IP address or CIDR range to monitor")]
        ip: String,
        #[arg(long, default_value = "0", help = "Seconds until the alert expires (0 = never)")]
        expires: i64,
    },
    /// Delete an alert
    Delete {
        #[arg(help = "Alert ID")]
        id: String,
    },
    /// List available alert triggers
    Triggers,
    /// Enable a trigger on an alert
    Enable {
        #[arg(help = "Alert ID")]
        id: String,
        #[arg(help = "Trigger name")]
        trigger: String,
    },
    /// Disable a trigger on an alert
    Disable {
        #[arg(help = "Alert ID")]
        id: String,
        #[arg(help = "Trigger name")]
        trigger: String,
    },
}

#[derive(Subcommand)]
enum DataCommand {
    /// List available datasets
    List,
    /// List files in a dataset
    Files {
        #[arg(help = "Dataset name")]
        dataset: String,
    },
}

#[derive(Subcommand)]
enum ScanCommand {
    /// Submit IPs for scanning
    Submit {
        #[arg(help = "IP addresses or CIDR ranges to scan", num_args = 1..)]
        ips: Vec<String>,
    },
    /// Check the status of a scan
    Status {
        #[arg(help = "Scan ID")]
        id: String,
    },
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Init { key } => {
            config::save_api_key(&key)?;
            let client = ShodanClient::new(&key);
            let info = client
                .api_info()
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!(
                "Successfully initialized with API key.\nPlan: {}",
                output::humanize_plan(&info.plan)
            );
        }

        Command::Info => {
            let key = config::load_api_key()?;
            let client = ShodanClient::new(&key);
            let info = client
                .api_info()
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            println!("Plan:          {}", output::humanize_plan(&info.plan));
            println!("HTTPS:         {}", info.https);
            println!("Unlocked:      {}", info.unlocked);
            println!("Query Credits: {}", info.query_credits);
            println!("Scan Credits:  {}", info.scan_credits);
            if let Some(m) = info.monitored_ips {
                println!("Monitored IPs: {}", m);
            }
        }

        Command::Myip => {
            let key = config::load_api_key()?;
            let client = ShodanClient::new(&key);
            let ip = client
                .myip()
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("{}", ip);
        }

        Command::Host { ip, history, minify } => {
            let key = config::load_api_key()?;
            let client = ShodanClient::new(&key);
            cli::host::run(&client, &ip, history, minify).await?;
        }

        Command::Search { query, fields, limit, separator, no_color } => {
            let key = config::load_api_key()?;
            let client = ShodanClient::new(&key);
            let q = query.join(" ");
            cli::search::run_search(&client, &q, &fields, limit, &separator, !no_color).await?;
        }

        Command::Count { query } => {
            let key = config::load_api_key()?;
            let client = ShodanClient::new(&key);
            let q = query.join(" ");
            cli::search::run_count(&client, &q, None).await?;
        }

        Command::Stats { query, facets, limit, filename } => {
            let key = config::load_api_key()?;
            let client = ShodanClient::new(&key);
            let q = query.join(" ");
            cli::search::run_stats(&client, &q, &facets, limit, filename.as_deref()).await?;
        }

        Command::Download { filename, query, limit, fields } => {
            let key = config::load_api_key()?;
            let client = ShodanClient::new(&key);
            let q = query.join(" ");
            let fname = if filename.ends_with(".json.gz") {
                filename
            } else {
                format!("{}.json.gz", filename)
            };
            cli::search::run_download(&client, &q, &fname, limit, fields.as_deref()).await?;
        }

        Command::Parse { filenames, fields, filters, filename, separator, no_color } => {
            cli::search::run_parse(&filenames, &fields, &filters, filename.as_deref(), &separator, !no_color)?;
        }

        Command::Domain { domain, history, r#type } => {
            let key = config::load_api_key()?;
            let client = ShodanClient::new(&key);
            let result = client
                .dns_domain(&domain, history, r#type.as_deref(), 1)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            println!("{}", result.domain);
            if let Some(tags) = &result.tags {
                if !tags.is_empty() {
                    println!("Tags: {}", tags.join(", "));
                }
            }
            println!("\nSubdomains:");
            for sub in &result.subdomains {
                println!("  {}.{}", sub, result.domain);
            }
            println!("\nDNS Records:");
            for rec in &result.data {
                println!(
                    "  {:30} {:8} {}",
                    format!("{}.{}", rec.subdomain, result.domain),
                    rec.record_type,
                    rec.value
                );
            }
        }

        Command::Honeyscore { ip } => {
            let key = config::load_api_key()?;
            let client = ShodanClient::new(&key);
            let score = client
                .honeyscore(&ip)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Honeypot probability: {:.1}%", score * 100.0);
        }

        Command::Version => {
            println!("{}", env!("CARGO_PKG_VERSION"));
        }

        Command::Alert { subcommand } => {
            let key = config::load_api_key()?;
            let client = ShodanClient::new(&key);
            match subcommand {
                AlertCommand::List => cli::alert::run_list(&client).await?,
                AlertCommand::Create { name, ip, expires } => {
                    cli::alert::run_create(&client, &name, &ip, expires).await?
                }
                AlertCommand::Delete { id } => cli::alert::run_delete(&client, &id).await?,
                AlertCommand::Triggers => cli::alert::run_triggers(&client).await?,
                AlertCommand::Enable { id, trigger } => {
                    cli::alert::run_enable_trigger(&client, &id, &trigger).await?
                }
                AlertCommand::Disable { id, trigger } => {
                    cli::alert::run_disable_trigger(&client, &id, &trigger).await?
                }
            }
        }

        Command::Data { subcommand } => {
            let key = config::load_api_key()?;
            let client = ShodanClient::new(&key);
            match subcommand {
                DataCommand::List => cli::data::run_list(&client).await?,
                DataCommand::Files { dataset } => {
                    cli::data::run_files(&client, &dataset).await?
                }
            }
        }

        Command::Scan { subcommand } => {
            let key = config::load_api_key()?;
            let client = ShodanClient::new(&key);
            match subcommand {
                ScanCommand::Submit { ips } => cli::scan::run_submit(&client, &ips).await?,
                ScanCommand::Status { id } => cli::scan::run_status(&client, &id).await?,
            }
        }
    }

    Ok(())
}
