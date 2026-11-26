use clap::{Parser, Subcommand};
use kletka_control::k8s::K8sProvisioner;
use kletka_control::state::{AppState, Config};
use kletka_control::{db, router};
use std::sync::Arc;

#[derive(Debug, Parser)]
#[command(name = "kletka-control", about = "Kletka hosted control-plane")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve,
    ResetPassword {
        #[arg(long)]
        email: String,
        #[arg(long)]
        password: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    tracing::info!(
        version = option_env!("KLETKA_VERSION").unwrap_or("dev"),
        "kletka-control starting"
    );

    let cli = Cli::parse();
    let config = Config::from_env();
    if let Err(err) = config.auth.validate() {
        eprintln!("invalid auth configuration: {err}");
        return Err(err.into());
    }
    let db = db::connect(&config.database_url).await?;

    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => {
            let gate = kletka_control::leader::LeaderGate::start(db.clone());
            let provisioner = K8sProvisioner::connect(config.k8s.clone())
                .await
                .map_err(|e| format!("k8s provisioner: {e}"))?;
            let provisioner = Arc::new(provisioner);
            provisioner.clone().spawn_observer(db.clone(), gate.clone());
            kletka_control::audit::spawn_retention(db.clone(), gate.clone());
            let state = AppState::new(
                db,
                provisioner,
                config.admin_token.clone(),
                config.rate_limits.clone(),
                config.namespaces.clone(),
                config.auth.clone(),
            );
            kletka_control::idle::spawn(state.clone(), gate);

            let app = router(state);
            let listener = tokio::net::TcpListener::bind(config.bind).await?;
            tracing::info!(addr = %config.bind, "kletka-control listening");
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal())
            .await?;
        }
        Command::ResetPassword { email, password } => {
            let password = match password {
                Some(password) if !password.is_empty() => password,
                _ => rpassword_prompt()?,
            };
            let id = kletka_control::routes::auth::set_password(&db, email.trim(), &password)
                .await
                .map_err(|e| e.to_string())?;
            println!("password reset for {id}");
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => sigterm.recv().await,
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate => {}
    }
}

fn rpassword_prompt() -> Result<String, Box<dyn std::error::Error>> {
    use std::io::Write as _;
    eprint!("New password: ");
    std::io::stderr().flush()?;
    let restore = stty_echo(false);
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    restore();
    eprintln!();
    Ok(line.trim().to_string())
}

fn stty_echo(on: bool) -> impl FnOnce() {
    use std::process::Stdio;
    let had_tty = std::process::Command::new("stty")
        .arg(if on { "echo" } else { "-echo" })
        .stdin(Stdio::inherit())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    move || {
        if had_tty {
            let _ = std::process::Command::new("stty")
                .arg("echo")
                .stdin(Stdio::inherit())
                .status();
        }
    }
}
