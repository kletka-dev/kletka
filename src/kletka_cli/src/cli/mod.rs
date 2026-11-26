use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use clap_complete::Shell;

mod commands;

pub const VERSION: &str = match option_env!("KLETKA_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Debug, Parser)]
#[command(
    name = "kletka",
    version = VERSION,
    about = "Instant sandbox VMs on the kletka control plane",
    subcommand_required = true,
    arg_required_else_help = true
)]
pub struct Cli {
    #[arg(long, global = true)]
    pub control_url: Option<String>,

    #[arg(long, global = true)]
    pub json: bool,

    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[arg(short = 'N', long, global = true, value_name = "NAMESPACE")]
    pub namespace: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(alias = "ls")]
    List {
        #[arg(long, value_enum)]
        state: Option<VmStateFilter>,
    },

    Create {
        name: Option<String>,

        #[arg(short, long, default_value = "default")]
        image: String,

        #[arg(long, default_value_t = 2)]
        vcpu: usize,

        #[arg(short, long, default_value_t = 1024)]
        memory: usize,

        #[arg(long, value_parser = parse_disk_size)]
        disk: Option<usize>,

        #[arg(long)]
        no_nat: bool,

        #[arg(long, value_name = "PATH", conflicts_with = "no_nat")]
        wireguard_config: Option<PathBuf>,

        #[arg(long = "ssh-key", value_name = "PATH")]
        ssh_keys: Vec<PathBuf>,

        #[arg(long, value_name = "DURATION", value_parser = parse_idle_timeout)]
        idle_timeout: Option<IdleTimeout>,
    },

    Exec {
        #[arg(short = 'n', long)]
        name: Option<String>,

        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },

    #[command(alias = "c")]
    Console {
        #[arg(short = 'n', long)]
        name: Option<String>,

        #[arg(long)]
        serial: bool,
    },

    Start {
        #[arg(short = 'n', long)]
        name: Option<String>,
    },

    Stop {
        #[arg(short = 'n', long)]
        name: Option<String>,
    },

    Configure {
        #[arg(short = 'n', long)]
        name: Option<String>,

        #[arg(long, value_name = "DURATION", value_parser = parse_idle_timeout)]
        idle_timeout: Option<IdleTimeout>,
    },

    Wireguard {
        #[arg(short = 'n', long)]
        name: Option<String>,

        #[arg(long, value_name = "PATH", required_unless_present = "clear")]
        config: Option<PathBuf>,

        #[arg(long, conflicts_with = "config")]
        clear: bool,
    },

    Resize {
        #[arg(short = 'n', long)]
        name: Option<String>,

        #[arg(long)]
        vcpu: Option<usize>,

        #[arg(short, long, value_parser = parse_disk_size)]
        memory: Option<usize>,

        #[arg(long, value_parser = parse_disk_size)]
        disk: Option<usize>,

        #[arg(long)]
        restart: bool,
    },

    #[command(alias = "fork")]
    Clone {
        #[arg(short = 'n', long)]
        name: Option<String>,

        new_name: Option<String>,
    },

    Rebase {
        #[arg(short = 'n', long)]
        name: Option<String>,

        #[arg(short, long)]
        image: Option<String>,
    },

    #[command(alias = "rm")]
    Destroy {
        #[arg(short = 'n', long)]
        name: Option<String>,

        #[arg(short, long)]
        force: bool,
    },

    Images,

    #[command(alias = "usage")]
    Quota,

    #[command(alias = "f")]
    File {
        #[arg(short = 'n', long, global = true)]
        name: Option<String>,
        #[command(subcommand)]
        command: FileCommand,
    },

    #[command(alias = "p")]
    Proxy {
        #[arg(short = 'n', long)]
        name: Option<String>,

        #[arg(long, default_value = "127.0.0.1")]
        bind: Ipv4Addr,

        #[arg(required = true)]
        specs: Vec<String>,
    },

    Snapshot {
        #[arg(short = 'n', long, global = true)]
        name: Option<String>,
        #[command(subcommand)]
        command: SnapshotCommand,
    },

    Login {
        #[arg(long)]
        control: Option<String>,

        #[arg(long)]
        email: Option<String>,

        #[arg(long)]
        password: Option<String>,

        #[arg(long, conflicts_with_all = ["email", "password"])]
        oauth: bool,

        #[arg(long, value_name = "PROVIDER")]
        provider: Option<String>,

        #[arg(long = "no-browser")]
        no_browser: bool,
    },

    Logout,

    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum SnapshotCommand {
    Create {
        snapshot: String,

        #[arg(long, hide = true)]
        memory: bool,
    },
    List,
    Delete {
        snapshot: String,
    },
    Rollback {
        snapshot: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum FileCommand {
    #[command(alias = "put")]
    Push {
        #[arg(short, long)]
        src: PathBuf,
        #[arg(short, long)]
        dst: String,
        #[arg(long)]
        sudo: bool,
    },
    #[command(alias = "get")]
    Pull {
        #[arg(short, long)]
        src: String,
        #[arg(short, long)]
        dst: PathBuf,
        #[arg(long)]
        sudo: bool,
    },
    Edit {
        path: String,
        #[arg(long)]
        create: bool,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        editor: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum VmStateFilter {
    Pending,
    Rebasing,
    Cloning,
    Running,
    Stopped,
    Failed,
    All,
}

impl VmStateFilter {
    pub(crate) fn matches(self, status: &kletka_types::VmStatus) -> bool {
        use kletka_types::VmStatus;
        match self {
            Self::All => true,
            Self::Pending => *status == VmStatus::Pending,
            Self::Rebasing => *status == VmStatus::Rebasing,
            Self::Cloning => *status == VmStatus::Cloning,
            Self::Running => *status == VmStatus::Running,
            Self::Stopped => *status == VmStatus::Stopped,
            Self::Failed => *status == VmStatus::Failed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleTimeout {
    Default,
    Secs(u64),
}

impl IdleTimeout {
    pub fn secs(self) -> Option<u64> {
        match self {
            Self::Default => None,
            Self::Secs(secs) => Some(secs),
        }
    }
}

pub(crate) fn parse_idle_timeout(raw: &str) -> Result<IdleTimeout, String> {
    let raw = raw.trim().to_ascii_lowercase();
    match raw.as_str() {
        "default" => return Ok(IdleTimeout::Default),
        "off" | "never" | "none" | "0" => return Ok(IdleTimeout::Secs(0)),
        _ => {}
    }
    let (digits, unit) = match raw.chars().last() {
        Some('s') => (&raw[..raw.len() - 1], 1),
        Some('m') => (&raw[..raw.len() - 1], 60),
        Some('h') => (&raw[..raw.len() - 1], 3600),
        Some('d') => (&raw[..raw.len() - 1], 86_400),
        _ => (raw.as_str(), 1),
    };
    digits
        .trim()
        .parse::<u64>()
        .ok()
        .and_then(|value| value.checked_mul(unit))
        .map(IdleTimeout::Secs)
        .ok_or_else(|| {
            format!("invalid duration '{raw}': use e.g. `30m`, `8h`, `2d`, `off` or `default`")
        })
}

pub(crate) fn format_duration(secs: u64) -> String {
    match secs {
        0 => "off".to_string(),
        s if s % 86_400 == 0 => format!("{}d", s / 86_400),
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

pub(crate) fn parse_disk_size(raw: &str) -> Result<usize, String> {
    const MIB: u64 = 1024 * 1024;
    let raw = raw.trim();
    let (digits, multiplier) = match raw.chars().last() {
        Some('k' | 'K') => (&raw[..raw.len() - 1], 1024),
        Some('m' | 'M') => (&raw[..raw.len() - 1], MIB),
        Some('g' | 'G') => (&raw[..raw.len() - 1], 1024 * MIB),
        Some('t' | 'T') => (&raw[..raw.len() - 1], 1024 * 1024 * MIB),
        Some(_) => (raw, MIB),
        None => return Err("disk size cannot be empty".to_string()),
    };
    let value: u64 = digits
        .trim()
        .parse()
        .map_err(|_| format!("invalid disk size '{raw}' (expected e.g. '20G' or '512M')"))?;
    let mib = value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("disk size '{raw}' is too large"))?
        / MIB;
    if mib == 0 {
        return Err(format!("disk size '{raw}' is smaller than 1M"));
    }
    usize::try_from(mib).map_err(|_| format!("disk size '{raw}' is too large"))
}

pub async fn run() -> ExitCode {
    let cli = Cli::parse();

    let filter = if cli.verbose {
        "kletka_cli=debug,warn"
    } else {
        "kletka_cli=warn,off"
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_writer(std::io::stderr)
        .without_time()
        .with_target(false)
        .try_init();

    match commands::dispatch(&cli).await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{}", err.render(cli.verbose));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn idle_timeouts_parse_and_print() {
        use super::{IdleTimeout, format_duration, parse_idle_timeout};
        assert_eq!(parse_idle_timeout("8h"), Ok(IdleTimeout::Secs(28_800)));
        assert_eq!(parse_idle_timeout("30m"), Ok(IdleTimeout::Secs(1800)));
        assert_eq!(parse_idle_timeout("2D"), Ok(IdleTimeout::Secs(172_800)));
        assert_eq!(parse_idle_timeout("90"), Ok(IdleTimeout::Secs(90)));
        assert_eq!(parse_idle_timeout("off"), Ok(IdleTimeout::Secs(0)));
        assert_eq!(parse_idle_timeout("default"), Ok(IdleTimeout::Default));
        assert!(parse_idle_timeout("soon").is_err());
        assert!(parse_idle_timeout("5w").is_err());
        assert_eq!(format_duration(28_800), "8h");
        assert_eq!(format_duration(5400), "90m");
        assert_eq!(format_duration(0), "off");
    }

    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn clap_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn namespace_flag_is_global() {
        let cli = Cli::try_parse_from(["kletka", "-N", "acme", "ls"]).unwrap();
        assert_eq!(cli.namespace.as_deref(), Some("acme"));
        let cli =
            Cli::try_parse_from(["kletka", "stop", "-n", "web", "--namespace", "acme"]).unwrap();
        assert_eq!(cli.namespace.as_deref(), Some("acme"));
    }

    #[test]
    fn disk_sizes_parse() {
        assert_eq!(parse_disk_size("20G").unwrap(), 20 * 1024);
        assert_eq!(parse_disk_size("512m").unwrap(), 512);
        assert_eq!(parse_disk_size("300").unwrap(), 300);
        assert_eq!(parse_disk_size("1T").unwrap(), 1024 * 1024);
        assert!(parse_disk_size("512K").is_err());
        assert!(parse_disk_size("").is_err());
        assert!(parse_disk_size("big").is_err());
    }

    #[test]
    fn wireguard_requires_config_or_clear() {
        let parse = |args: &[&str]| {
            Cli::try_parse_from([&["kletka", "wireguard", "-n", "vm"], args].concat())
        };
        assert!(parse(&["--config", "wg0.conf"]).is_ok());
        assert!(parse(&["--clear"]).is_ok());
        assert!(parse(&[]).is_err());
        assert!(parse(&["--clear", "--config", "x"]).is_err());
    }

    #[test]
    fn create_refuses_wireguard_without_nat() {
        let parsed = Cli::try_parse_from([
            "kletka",
            "create",
            "--no-nat",
            "--wireguard-config",
            "wg0.conf",
        ]);
        assert!(parsed.is_err());
    }

    #[test]
    fn snapshot_subcommands_take_the_vm_from_n() {
        let cli = Cli::try_parse_from(["kletka", "snapshot", "rollback", "-n", "my-vm", "clean"])
            .unwrap();
        let Command::Snapshot { name, command } = cli.command else {
            panic!("snapshot command expected");
        };
        assert_eq!(name.as_deref(), Some("my-vm"));
        assert!(matches!(command, SnapshotCommand::Rollback { snapshot } if snapshot == "clean"));
    }

    #[test]
    fn state_filter_matches_server_statuses() {
        use kletka_types::VmStatus;
        assert!(VmStateFilter::Running.matches(&VmStatus::Running));
        assert!(VmStateFilter::Failed.matches(&VmStatus::Failed));
        assert!(!VmStateFilter::Stopped.matches(&VmStatus::Running));
        assert!(VmStateFilter::All.matches(&VmStatus::Pending));
        assert!(VmStateFilter::Cloning.matches(&VmStatus::Cloning));
    }
}
