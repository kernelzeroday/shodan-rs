use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;

mod api;
mod cli;
mod config;
mod output;

use api::ShodanClient;

#[derive(Parser)]
#[command(
    name = "shodan-rs",
    version,
    about = "The official command-line client for Shodan"
)]
struct Cli {
    /// API key to use instead of the configured key; repeat or comma-separate to rotate keys
    #[arg(long = "key", global = true, value_name = "KEY", value_delimiter = ',')]
    keys: Vec<String>,

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
        #[arg(
            long,
            default_value = "ip_str,port,hostnames,data",
            help = "Comma-separated list of fields to display"
        )]
        fields: String,
        #[arg(
            long,
            default_value = "100",
            help = "Number of results to return (0 for all, max 1000 otherwise)"
        )]
        limit: u32,
        #[arg(long, default_value = "\t", help = "Field separator")]
        separator: String,
        #[arg(
            long = "no-color",
            default_value = "false",
            help = "Disable colored output"
        )]
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
        #[arg(
            long,
            default_value = "country,org",
            help = "Comma-separated list of facets"
        )]
        facets: String,
        #[arg(
            long,
            default_value = "10",
            help = "Number of top values to show per facet"
        )]
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
        #[arg(
            long,
            default_value = "1000",
            help = "Number of results to download (-1 for all)"
        )]
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
    /// Check whether Shodan tagged an IP as a honeypot
    Honeyscore {
        #[arg(help = "IP address to check")]
        ip: String,
    },

    /// Print the version
    Version,

    /// Manage monitored networks and alert triggers
    #[command(alias = "monitor")]
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
    /// List all network alerts
    List,
    /// Show a network alert
    Info {
        #[arg(help = "Alert ID")]
        id: String,
    },
    /// Create a network alert for one or more IPs or network ranges
    Create {
        #[arg(help = "Name of the alert")]
        name: String,
        #[arg(help = "IP addresses or CIDR ranges to monitor", num_args = 1..)]
        ips: Vec<String>,
        #[arg(
            long,
            default_value = "0",
            help = "Seconds until the alert expires (0 = never)"
        )]
        expires: i64,
    },
    /// Replace the IPs and network ranges monitored by an alert
    Update {
        #[arg(help = "Alert ID")]
        id: String,
        #[arg(help = "IP addresses or CIDR ranges to monitor", num_args = 1..)]
        ips: Vec<String>,
    },
    /// Delete an alert
    Delete {
        #[arg(help = "Alert ID")]
        id: String,
    },
    /// Delete all alerts
    Clear,
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

fn client_from_keys(keys: Vec<String>) -> Result<ShodanClient> {
    if keys.is_empty() {
        Ok(ShodanClient::new(config::load_api_key()?))
    } else {
        Ok(ShodanClient::with_keys(keys))
    }
}

async fn run() -> Result<()> {
    let Cli { keys, command } = Cli::parse();

    match command {
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
            let client = client_from_keys(keys)?;
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
            let client = client_from_keys(keys)?;
            let ip = client.myip().await.map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("{}", ip);
        }

        Command::Host {
            ip,
            history,
            minify,
        } => {
            let client = client_from_keys(keys)?;
            cli::host::run(&client, &ip, history, minify).await?;
        }

        Command::Search {
            query,
            fields,
            limit,
            separator,
            no_color,
        } => {
            let client = client_from_keys(keys)?;
            let q = query.join(" ");
            cli::search::run_search(&client, &q, &fields, limit, &separator, !no_color).await?;
        }

        Command::Count { query } => {
            let client = client_from_keys(keys)?;
            let q = query.join(" ");
            cli::search::run_count(&client, &q, None).await?;
        }

        Command::Stats {
            query,
            facets,
            limit,
            filename,
        } => {
            let client = client_from_keys(keys)?;
            let q = query.join(" ");
            cli::search::run_stats(&client, &q, &facets, limit, filename.as_deref()).await?;
        }

        Command::Download {
            filename,
            query,
            limit,
            fields,
        } => {
            let client = client_from_keys(keys)?;
            let q = query.join(" ");
            let fname = if filename.ends_with(".json.gz") {
                filename
            } else {
                format!("{}.json.gz", filename)
            };
            cli::search::run_download(&client, &q, &fname, limit, fields.as_deref()).await?;
        }

        Command::Parse {
            filenames,
            fields,
            filters,
            filename,
            separator,
            no_color,
        } => {
            cli::search::run_parse(
                &filenames,
                &fields,
                &filters,
                filename.as_deref(),
                &separator,
                !no_color,
            )?;
        }

        Command::Domain {
            domain,
            history,
            r#type,
        } => {
            let client = client_from_keys(keys)?;
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
            let client = client_from_keys(keys)?;
            let host = client
                .host_info(&ip, false, true)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            let is_honeypot = host
                .tags
                .as_deref()
                .unwrap_or_default()
                .iter()
                .any(|tag| tag == "honeypot");
            if is_honeypot {
                println!("{}", "Honeypot tag detected".red());
            } else {
                println!("{}", "No honeypot tag found".green());
            }
        }

        Command::Version => {
            println!("{}", env!("CARGO_PKG_VERSION"));
        }

        Command::Alert { subcommand } => {
            let client = client_from_keys(keys)?;
            match subcommand {
                AlertCommand::List => cli::alert::run_list(&client).await?,
                AlertCommand::Info { id } => cli::alert::run_info(&client, &id).await?,
                AlertCommand::Create { name, ips, expires } => {
                    cli::alert::run_create(&client, &name, &ips, expires).await?
                }
                AlertCommand::Update { id, ips } => {
                    cli::alert::run_update(&client, &id, &ips).await?
                }
                AlertCommand::Delete { id } => cli::alert::run_delete(&client, &id).await?,
                AlertCommand::Clear => cli::alert::run_clear(&client).await?,
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
            let client = client_from_keys(keys)?;
            match subcommand {
                DataCommand::List => cli::data::run_list(&client).await?,
                DataCommand::Files { dataset } => cli::data::run_files(&client, &dataset).await?,
            }
        }

        Command::Scan { subcommand } => {
            let client = client_from_keys(keys)?;
            match subcommand {
                ScanCommand::Submit { ips } => cli::scan::run_submit(&client, &ips).await?,
                ScanCommand::Status { id } => cli::scan::run_status(&client, &id).await?,
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_one_explicit_api_key() {
        let cli = Cli::try_parse_from(["shodan-rs", "info", "--key", "specific"]).unwrap();

        assert_eq!(cli.keys, ["specific"]);
    }

    #[test]
    fn parses_repeated_and_comma_separated_api_keys() {
        let cli = Cli::try_parse_from([
            "shodan-rs",
            "info",
            "--key",
            "first,second",
            "--key",
            "third",
        ])
        .unwrap();

        assert_eq!(cli.keys, ["first", "second", "third"]);
    }

    #[test]
    fn monitor_alias_parses_multiple_networks() {
        let cli = Cli::try_parse_from([
            "shodan-rs",
            "monitor",
            "create",
            "production",
            "1.2.3.4",
            "10.0.0.0/24",
            "--expires",
            "60",
        ])
        .unwrap();

        match cli.command {
            Command::Alert {
                subcommand: AlertCommand::Create { name, ips, expires },
            } => {
                assert_eq!(name, "production");
                assert_eq!(ips, ["1.2.3.4", "10.0.0.0/24"]);
                assert_eq!(expires, 60);
            }
            _ => panic!("expected alert create command"),
        }
    }

    #[test]
    fn alert_clear_parses() {
        let cli = Cli::try_parse_from(["shodan-rs", "alert", "clear"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Alert {
                subcommand: AlertCommand::Clear
            }
        ));
    }
}
