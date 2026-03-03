mod api;
mod config;
mod crypto;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use config::{read_config, read_config_from_env, resolve_config_path, unset_env_var};

#[derive(Parser)]
#[command(about)]
struct Args {
    /// Path to the config file (absolute or relative)
    #[arg(required_unless_present = "config_env")]
    config_path: Option<PathBuf>,

    /// Environment variable containing base64-encoded JSON config
    #[arg(long, conflicts_with = "config_path")]
    config_env: Option<String>,

    /// Port to listen on (overrides server_port from config)
    #[arg(short, long)]
    port: Option<u16>,

    /// Keep the config source (file or env var) after reading (default: delete/unset)
    #[arg(short, long, default_value_t = false)]
    keep_config: bool,

    /// Also unset this environment variable after reading config
    #[arg(long)]
    delete_env: Option<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = Args::parse();

    let config = if let Some(path) = &args.config_path {
        let resolved = match resolve_config_path(path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Error resolving config path: {}", e);
                return ExitCode::FAILURE;
            }
        };
        let delete_after = !args.keep_config;
        match read_config(&resolved, delete_after).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error reading config: {}", e);
                return ExitCode::FAILURE;
            }
        }
    } else if let Some(ref env_var) = args.config_env {
        let delete_after = !args.keep_config;
        match read_config_from_env(env_var, delete_after) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error reading config from env: {}", e);
                return ExitCode::FAILURE;
            }
        }
    } else {
        eprintln!("Error: must specify either config path or --config-env");
        return ExitCode::FAILURE;
    };

    if let Some(ref env_var) = args.delete_env {
        unset_env_var(env_var);
    }

    match api::run_server(config, args.port).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Server error: {}", e);
            ExitCode::FAILURE
        }
    }
}
