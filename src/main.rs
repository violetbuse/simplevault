use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    simplevault::run_cli().await
}
