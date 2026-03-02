mod api;
mod config;
mod crypto;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use config::{read_config, resolve_config_path};

#[derive(Parser)]
#[command(about)]
struct Args {
    /// Keep the config file after reading (default: delete)
    #[arg(short, long, default_value_t = false)]
    keep_config: bool,

    /// Path to the config file (absolute or relative)
    config_path: PathBuf,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = Args::parse();

    let resolved = match resolve_config_path(&args.config_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error resolving config path: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let delete_after = !args.keep_config;
    match read_config(&resolved, delete_after).await {
        Ok(config) => {
            if let Err(e) = api::run_server(config).await {
                eprintln!("Server error: {}", e);
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error reading config: {}", e);
            ExitCode::FAILURE
        }
    }
}
