#[tokio::main]
async fn main() -> std::process::ExitCode {
    kletka_cli::cli::run().await
}
