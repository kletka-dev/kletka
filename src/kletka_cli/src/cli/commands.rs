use std::io::IsTerminal as _;
use std::path::Path;
use std::process::ExitCode;

use kletka_types::SnapshotInfo;

use super::{
    Cli, Command, FileCommand, IdleTimeout, SnapshotCommand, VmStateFilter, format_duration,
};
use crate::client::{self, Client};
use crate::error::{CliError, CliResult, ErrorKind, io_error};
use crate::{config, session};
use kletka_types::{AccountInfo, CreateVmRequest, Vm, VmStatus};

pub(super) async fn dispatch(cli: &Cli) -> CliResult<ExitCode> {
    match &cli.command {
        Command::Login {
            control,
            email,
            password,
            oauth,
            provider,
            no_browser,
        } => {
            let url = config::control_url(control.as_deref().or(cli.control_url.as_deref()));
            return login(&url, email.as_deref(), password.as_deref(), *oauth, provider.as_deref(), *no_browser).await;
        }
        Command::Logout => {
            let message = if config::clear_credentials()? {
                "logged out"
            } else {
                "not logged in"
            };
            println!("{message}");
            return Ok(ExitCode::SUCCESS);
        }
        Command::Completions { shell } => {
            use clap::CommandFactory as _;
            clap_complete::generate(
                *shell,
                &mut Cli::command(),
                "kletka",
                &mut std::io::stdout(),
            );
            return Ok(ExitCode::SUCCESS);
        }
        _ => {}
    }

    let ctx = Ctx {
        client: Client::new(
            config::control_url(cli.control_url.as_deref()),
            config::token()?,
        )
        .with_namespace(config::namespace(cli.namespace.as_deref())),
        json: cli.json,
    };
    match &cli.command {
        Command::List { state } => ctx.list(*state).await,
        Command::Create {
            name,
            image,
            vcpu,
            memory,
            disk,
            no_nat,
            wireguard_config,
            ssh_keys,
            idle_timeout,
        } => {
            let name = name.clone().filter(|name| !name.trim().is_empty());
            if let Some(ref given) = name {
                kletka_types::validate_vm_name(given).map_err(CliError::new)?;
            }
            let request = CreateVmRequest {
                name,
                image: Some(image.clone()),
                vcpu: Some(*vcpu),
                memory_mib: Some(*memory),
                disk_mib: Some(disk.unwrap_or(0)),
                nat: Some(!no_nat),
                wireguard_config: wireguard_config
                    .as_deref()
                    .map(read_wireguard_config)
                    .transpose()?,
                ssh_keys: ssh_keys
                    .iter()
                    .map(|path| read_ssh_key(path))
                    .collect::<Result<Vec<_>, _>>()?,
                idle_timeout_secs: idle_timeout.and_then(IdleTimeout::secs),
            };
            ctx.create(&request).await
        }
        Command::Exec { name, command } => ctx.exec(name.clone(), command).await,
        Command::Console { name, serial } => {
            let vm = ctx.running(name.clone()).await?;
            session::console(&ctx.client, &vm.name, &vm.id, *serial).await?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Start { name } => ctx.start(name.clone()).await,
        Command::Stop { name } => ctx.stop(name.clone()).await,
        Command::Configure { name, idle_timeout } => {
            ctx.configure(name.clone(), *idle_timeout).await
        }
        Command::Wireguard {
            name,
            config,
            clear,
        } => {
            let config = if *clear {
                None
            } else {
                config.as_deref().map(read_wireguard_config).transpose()?
            };
            ctx.wireguard(name.clone(), config).await
        }
        Command::Resize {
            name,
            vcpu,
            memory,
            disk,
            restart,
        } => {
            ctx.resize(name.clone(), *vcpu, *memory, *disk, *restart)
                .await
        }
        Command::Clone { name, new_name } => ctx.clone_vm(name.clone(), new_name.clone()).await,
        Command::Rebase { name, image } => ctx.rebase(name.clone(), image.as_deref()).await,
        Command::Destroy { name, force } => ctx.destroy(name.clone(), *force).await,
        Command::Images => ctx.images().await,
        Command::Quota => ctx.quota().await,
        Command::File { name, command } => ctx.file(name.clone(), command).await,
        Command::Proxy { name, bind, specs } => ctx.proxy(name.clone(), *bind, specs).await,
        Command::Snapshot { name, command } => ctx.snapshot(name.clone(), command).await,
        Command::Login { .. } | Command::Logout | Command::Completions { .. } => unreachable!(),
    }
}

async fn login(
    url: &str,
    email: Option<&str>,
    password: Option<&str>,
    oauth: bool,
    provider: Option<&str>,
    no_browser: bool,
) -> CliResult<ExitCode> {
    let methods = client::auth_methods(url).await?;
    match oauth_choice(&methods, oauth, provider, email, password)? {
        Some(provider) => {
            let outcome = crate::oauth::sign_in(url, &provider, no_browser).await?;
            config::save_credentials(url, &outcome.token)?;
            println!("logged in with {} ({url})", crate::oauth::label(&provider));
            Ok(ExitCode::SUCCESS)
        }
        None => login_password(url, email, password).await,
    }
}

fn oauth_choice(
    methods: &kletka_types::AuthMethods,
    oauth: bool,
    provider: Option<&str>,
    email: Option<&str>,
    password: Option<&str>,
) -> CliResult<Option<String>> {
    let interactive = std::io::stdin().is_terminal();
    if let Some(provider) = provider {
        let provider = methods
            .oauth
            .iter()
            .find(|enabled| enabled.eq_ignore_ascii_case(provider.trim()))
            .ok_or_else(|| {
                CliError::new(format!(
                    "the OAuth provider '{provider}' is not enabled on this control plane"
                ))
                .hint(match methods.oauth.is_empty() {
                    true => "this deployment has no OAuth providers enabled",
                    false => "enabled providers are listed by `kletka login --oauth`",
                })
            })?;
        return Ok(Some(provider.clone()));
    }
    if oauth {
        return pick_provider(methods, interactive).map(Some);
    }
    if !methods.password {
        if email.is_some() || password.is_some() {
            return Err(CliError::new(
                "email/password sign-in is disabled on this control plane",
            )
            .hint("sign in with an OAuth provider instead (`kletka login --oauth`)"));
        }
        return pick_provider(methods, interactive).map(Some);
    }
    if (email.is_none() && password.is_none() && interactive) && !methods.oauth.is_empty() {
        let mut choices = vec!["Email and password".to_string()];
        choices.extend(methods.oauth.iter().map(|p| crate::oauth::label(p)));
        let picked = inquire::Select::new("Sign in with", choices)
            .raw_prompt()
            .map_err(prompt_error)?;
        if picked.index > 0 {
            return Ok(Some(methods.oauth[picked.index - 1].clone()));
        }
    }
    Ok(None)
}

fn pick_provider(methods: &kletka_types::AuthMethods, interactive: bool) -> CliResult<String> {
    match methods.oauth.len() {
        0 => Err(CliError::new(
            "this control plane has no OAuth providers enabled",
        )
        .hint(if methods.password {
            "log in with an email and password"
        } else {
            "ask the operator to enable a sign-in method"
        })),
        1 => Ok(methods.oauth[0].clone()),
        _ if interactive => {
            let choices = methods.oauth.iter().map(|p| crate::oauth::label(p));
            let picked = inquire::Select::new("Sign in with", choices.collect())
                .raw_prompt()
                .map_err(prompt_error)?;
            Ok(methods.oauth[picked.index].clone())
        }
        _ => Err(CliError::new("several OAuth providers are enabled")
            .hint("pick one with `--provider github|gitlab|steam`")),
    }
}

async fn login_password(url: &str, email: Option<&str>, password: Option<&str>) -> CliResult<ExitCode> {
    let interactive = std::io::stdin().is_terminal();
    let email = match email.map(str::trim).filter(|email| !email.is_empty()) {
        Some(email) => email.to_string(),
        None if interactive => inquire::Text::new("Email:")
            .prompt()
            .map_err(prompt_error)?,
        None => {
            return Err(
                CliError::new("no email given").hint("pass `--email <address>`"),
            );
        }
    };
    let password: Option<String> = password
        .filter(|password| !password.is_empty())
        .map(str::to_string)
        .or_else(|| {
            std::env::var("KLETKA_PASSWORD")
                .ok()
                .filter(|p| !p.is_empty())
        });

    let password = match password {
        Some(password) => password,
        None if interactive => inquire::Password::new("Password:")
            .without_confirmation()
            .prompt()
            .map_err(prompt_error)?,
        None => {
            return Err(
                CliError::new("no password given").hint("pass `--password` or set KLETKA_PASSWORD")
            );
        }
    };
    let email = email.trim();
    let outcome = crate::client::login(url, email, &password).await?;
    config::save_credentials(url, &outcome.token)?;
    if outcome.signed_up {
        println!("created a new account for {email}");
    }
    println!("logged in as {email} ({url})");
    tracing::debug!(user_id = %outcome.user_id, "login stored");
    Ok(ExitCode::SUCCESS)
}

fn prompt_error(err: inquire::InquireError) -> CliError {
    use inquire::InquireError;
    match err {
        InquireError::OperationCanceled | InquireError::OperationInterrupted => {
            CliError::new("cancelled")
        }
        other => CliError::new("cannot prompt for input").detail(other),
    }
}

fn read_wireguard_config(path: &Path) -> CliResult<String> {
    std::fs::read_to_string(path).map_err(|err| {
        io_error(
            format!("cannot read WireGuard config '{}'", path.display()),
            err,
        )
    })
}

fn read_ssh_key(path: &Path) -> CliResult<String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|err| io_error(format!("cannot read ssh key '{}'", path.display()), err))?;
    let key = raw.trim();
    if key.is_empty() {
        return Err(CliError::new(format!("'{}' is empty", path.display()))
            .hint("pass an openssh *public* key (the .pub file)"));
    }
    if let Err(err) = kletka_types::validate_ssh_key(key) {
        return Err(
            CliError::new(format!("'{}' is not one public key", path.display()))
                .hint("pass an openssh *public* key file (one line, e.g. id_ed25519.pub)")
                .detail(err),
        );
    }
    Ok(key.to_string())
}

struct TempFile(std::path::PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn print_json(value: &impl serde::Serialize) -> CliResult<ExitCode> {
    let encoded = serde_json::to_string_pretty(value).expect("CLI output serializes");
    println!("{encoded}");
    Ok(ExitCode::SUCCESS)
}

fn child_exit_code(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

struct Ctx {
    client: Client,
    json: bool,
}

impl Ctx {
    fn output(&self, json: &impl serde::Serialize, text: impl FnOnce()) -> CliResult<ExitCode> {
        if self.json {
            return print_json(json);
        }
        text();
        Ok(ExitCode::SUCCESS)
    }

    async fn resolve(&self, name: Option<String>) -> CliResult<Vm> {
        if let Some(key) = name {
            return self.client.show(&key).await.map_err(|err| {
                if err.is_not_found() {
                    CliError::new(format!("no VM named '{key}'"))
                        .kind(ErrorKind::NotFound)
                        .hint("see your VMs with `kletka list`")
                } else {
                    err
                }
            });
        }

        let mut vms = self.client.list().await?;
        match vms.len() {
            0 => Err(CliError::new("you have no VMs").hint("create one with `kletka create`")),
            _ if !std::io::stdin().is_terminal() => {
                Err(CliError::new("no VM given").hint("choose one with `-n <name>`"))
            }
            _ => {
                let names: Vec<String> = vms.iter().map(|vm| vm.name.clone()).collect();
                let picked = inquire::Select::new("Select a VM", names)
                    .raw_prompt()
                    .map_err(prompt_error)?;
                Ok(vms.remove(picked.index))
            }
        }
    }

    async fn running(&self, name: Option<String>) -> CliResult<Vm> {
        let vm = self.resolve(name).await?;
        self.client.ensure_running(&vm).await
    }

    async fn list(&self, state: Option<VmStateFilter>) -> CliResult<ExitCode> {
        let mut vms = self.client.list().await?;
        if let Some(state) = state {
            vms.retain(|vm| state.matches(&vm.status));
        }
        self.output(&vms, || {
            if vms.is_empty() {
                println!("No VMs found. Create one with `kletka create <name>`.");
            } else {
                print!("{}", render_vms(&vms));
            }
        })
    }

    async fn create(&self, request: &CreateVmRequest) -> CliResult<ExitCode> {
        let vm = self.client.create(request).await?;
        self.output(&vm, || println!("created VM '{}'", vm.name))
    }

    async fn start(&self, name: Option<String>) -> CliResult<ExitCode> {
        let vm = self.resolve(name).await?;
        if vm.status == VmStatus::Running {
            return self.output(&vm, || println!("VM '{}' is already running", vm.name));
        }
        let vm = self.client.ensure_running(&vm).await?;
        self.output(&vm, || println!("started VM '{}'", vm.name))
    }

    async fn stop(&self, name: Option<String>) -> CliResult<ExitCode> {
        let vm = self.resolve(name).await?;
        self.client.stop(&vm).await?;
        self.output(&serde_json::json!({ "stopped": vm.name }), || {
            println!("stopped VM '{}'", vm.name)
        })
    }

    async fn configure(
        &self,
        name: Option<String>,
        idle_timeout: Option<IdleTimeout>,
    ) -> CliResult<ExitCode> {
        let Some(idle_timeout) = idle_timeout else {
            return Err(
                CliError::new("nothing to change").hint("pass a setting, e.g. `--idle-timeout 2h`")
            );
        };
        let vm = self.resolve(name).await?;
        let vm = self
            .client
            .set_idle_timeout(&vm, idle_timeout.secs())
            .await?;
        self.output(&vm, || {
            println!(
                "VM '{}' now stops after {}",
                vm.name,
                describe_idle_timeout(&vm)
            )
        })
    }

    async fn wireguard(&self, name: Option<String>, config: Option<String>) -> CliResult<ExitCode> {
        let vm = self.resolve(name).await?;
        let cleared = config.is_none();
        let vm = self.client.configure_wireguard(&vm, config).await?;
        self.output(&vm, || {
            let verb = if cleared { "cleared" } else { "updated" };
            println!("{verb} the WireGuard configuration of VM '{}'", vm.name);
        })
    }

    async fn resize(
        &self,
        name: Option<String>,
        vcpu: Option<usize>,
        memory_mib: Option<usize>,
        disk_mib: Option<usize>,
        restart: bool,
    ) -> CliResult<ExitCode> {
        if vcpu.is_none() && memory_mib.is_none() && disk_mib.is_none() {
            return Err(CliError::new("nothing to resize")
                .hint("pass `--vcpu <N>`, `--memory <SIZE>` and/or `--disk <SIZE>`"));
        }
        let vm = self.resolve(name).await?;
        if let Some(disk) = disk_mib
            && vm.disk_mib != 0
            && disk < vm.disk_mib
        {
            return Err(CliError::new(format!(
                "VM '{}' has a {} MiB disk; disks can only grow (asked for {disk} MiB)",
                vm.name, vm.disk_mib
            ))
            .hint("resize above the current size, or create a new VM"));
        }
        let was_up = matches!(vm.status, VmStatus::Running | VmStatus::Pending);
        if was_up && !restart {
            return Err(
                CliError::new(format!("VM '{}' is {}", vm.name, vm.status.as_str())).hint(format!(
                    "stop it first (`kletka stop -n {0}`), or pass `--restart` to stop, \
                     resize and start it in one go",
                    vm.name
                )),
            );
        }
        if was_up {
            self.client.stop(&vm).await?;
        }
        let mut vm = self.client.resize(&vm, vcpu, memory_mib, disk_mib).await?;
        if was_up {
            vm = self.client.start(&vm).await?;
        }
        self.output(&vm, || {
            println!(
                "VM '{}' now has {} vCPU{} and {} MiB of memory{}",
                vm.name,
                vm.vcpu,
                if vm.vcpu == 1 { "" } else { "s" },
                vm.memory_mib,
                if was_up { "" } else { " (from its next start)" }
            );
            if let Some(disk) = disk_mib {
                println!(
                    "disk: {} MiB{}",
                    disk,
                    if was_up { "" } else { " (from its next start)" }
                );
            }
        })
    }

    async fn rebase(&self, name: Option<String>, image: Option<&str>) -> CliResult<ExitCode> {
        let vm = self.resolve(name).await?;
        let vm = self.client.rebase(&vm, image).await?;
        self.output(&vm, || {
            println!("rebased VM '{}' onto image '{}'", vm.name, vm.image)
        })
    }

    async fn clone_vm(
        &self,
        name: Option<String>,
        new_name: Option<String>,
    ) -> CliResult<ExitCode> {
        let vm = self.resolve(name).await?;
        let new_name = new_name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty());
        if let Some(given) = new_name {
            kletka_types::validate_vm_name(given).map_err(|err| {
                CliError::new(err).detail(format!(
                    "kletka clone -n {} <new-name>; leave the new name out to generate one",
                    vm.name
                ))
            })?;
        }
        if !matches!(vm.status, VmStatus::Stopped) {
            if vm.status == VmStatus::Cloning {
                return Err(CliError::new(format!(
                    "VM '{}' is the target of a running clone; wait for it to finish",
                    vm.name
                ))
                .hint("check `kletka list`"));
            }
            return Err(
                CliError::new(format!("VM '{}' is {}", vm.name, vm.status.as_str())).hint(format!(
                    "stop it first (`kletka stop -n {0}`), then clone it",
                    vm.name
                )),
            );
        }
        let created = self.client.clone_vm(&vm, new_name).await?;
        self.output(&created, || match created.status {
            VmStatus::Cloning => println!(
                "clone '{}' of VM '{}' is still copying; check `kletka list`",
                created.name, vm.name
            ),
            _ => println!(
                "cloned VM '{}' into '{}' (stopped; it boots on first use)",
                vm.name, created.name
            ),
        })
    }

    async fn destroy(&self, name: Option<String>, force: bool) -> CliResult<ExitCode> {
        let vm = self.resolve(name).await?;
        if !force {
            if !std::io::stdin().is_terminal() {
                return Err(CliError::new(format!(
                    "refusing to destroy VM '{}' without confirmation",
                    vm.name
                ))
                .hint("pass `--force` to destroy without a prompt"));
            }
            let confirmed =
                inquire::Confirm::new(&format!("Destroy VM '{}' and its disk?", vm.name))
                    .with_default(false)
                    .prompt()
                    .map_err(prompt_error)?;
            if !confirmed {
                return Ok(ExitCode::SUCCESS);
            }
        }
        let finished = self.client.destroy(&vm).await?;
        self.output(&serde_json::json!({ "deleted": vm.name }), || {
            if finished {
                println!("destroyed VM '{}'", vm.name)
            } else {
                println!("destroying VM '{}'; teardown is still in progress", vm.name)
            }
        })
    }

    async fn images(&self) -> CliResult<ExitCode> {
        let images = self.client.images().await?;
        self.output(&images, || {
            if images.is_empty() {
                println!("the control plane offers no images");
                return;
            }
            println!("{:<12} REF", "NAME");
            for image in &images {
                println!("{:<12} {}", image.name, image.reference);
            }
        })
    }

    async fn quota(&self) -> CliResult<ExitCode> {
        let account = self.client.account().await?;
        self.output(&account, || print!("{}", render_quota(&account)))
    }

    async fn exec(&self, name: Option<String>, command: &[String]) -> CliResult<ExitCode> {
        let vm = self.running(name).await?;
        let code = if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
            session::exec_pty(&self.client, &vm.id, command).await?
        } else {
            session::exec(
                &self.client,
                &vm.id,
                command,
                session::stdin_reader(64 * 1024),
            )
            .await?
        };
        Ok(child_exit_code(code))
    }

    async fn file(&self, name: Option<String>, command: &FileCommand) -> CliResult<ExitCode> {
        let vm = self.running(name).await?;
        match command {
            FileCommand::Push { src, dst, sudo } => {
                self.client.file_push(&vm, src, dst, *sudo).await?;
                println!("copied '{}' to {}:{dst}", src.display(), vm.name);
            }
            FileCommand::Pull { src, dst, sudo } => {
                self.client.file_pull(&vm, src, dst, *sudo).await?;
                println!("copied {}:{src} to '{}'", vm.name, dst.display());
            }
            FileCommand::Edit {
                path,
                create,
                force,
                editor,
            } => {
                self.file_edit(&vm, path, *create, *force, editor.clone())
                    .await?
            }
        }
        Ok(ExitCode::SUCCESS)
    }

    async fn file_edit(
        &self,
        vm: &Vm,
        path: &str,
        create: bool,
        force: bool,
        editor: Option<String>,
    ) -> CliResult<()> {
        let base = Path::new(path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".to_string());
        let temp = TempFile(
            std::env::temp_dir().join(format!("kletka-edit-{}-{base}", uuid::Uuid::new_v4())),
        );
        let temp_err = |err| io_error("cannot use a temporary file", err);

        match self.client.file_pull(vm, path, &temp.0, false).await {
            Ok(()) => {}
            Err(err) if create && err.is_not_found() => {
                std::fs::write(&temp.0, b"").map_err(temp_err)?
            }
            Err(err) if err.is_not_found() => {
                return Err(
                    CliError::new(format!("'{path}' does not exist in VM '{}'", vm.name))
                        .hint("pass `--create` to create it")
                        .detail(err.message),
                );
            }
            Err(err) => return Err(err),
        }

        let original = std::fs::read(&temp.0).map_err(temp_err)?;
        if original.contains(&0) && !force {
            return Err(CliError::new(format!("'{path}' looks like a binary file"))
                .hint("pass `--force` to edit it anyway"));
        }

        let editor = editor
            .or_else(|| std::env::var("KLETKA_EDITOR").ok())
            .or_else(|| std::env::var("VISUAL").ok())
            .or_else(|| std::env::var("EDITOR").ok())
            .unwrap_or_else(|| "vi".to_string());
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(r#"exec $0 "$1""#)
            .arg(&editor)
            .arg(&temp.0)
            .status()
            .map_err(|err| io_error(format!("cannot run editor '{editor}'"), err))?;
        if !status.success() {
            return Err(CliError::new(format!(
                "editor '{editor}' exited with an error; '{path}' was not changed"
            )));
        }

        if std::fs::read(&temp.0).map_err(temp_err)? == original {
            println!("no changes");
            return Ok(());
        }
        self.client.file_push(vm, &temp.0, path, false).await?;
        println!("saved {}:{path}", vm.name);
        Ok(())
    }

    async fn proxy(
        &self,
        name: Option<String>,
        bind: std::net::Ipv4Addr,
        specs: &[String],
    ) -> CliResult<ExitCode> {
        let forwards = specs
            .iter()
            .map(|spec| parse_forward(spec))
            .collect::<Result<Vec<_>, _>>()?;
        let vm = self.running(name).await?;
        for (local, remote) in &forwards {
            println!("{bind}:{local} → {}:{remote}", vm.name);
        }
        println!("forwarding; press Ctrl-C to stop");
        session::serve_proxy(&self.client, vm.id, bind, &forwards).await?;
        Ok(ExitCode::SUCCESS)
    }

    async fn snapshot(
        &self,
        name: Option<String>,
        command: &SnapshotCommand,
    ) -> CliResult<ExitCode> {
        let vm = self.resolve(name).await?;
        match command {
            SnapshotCommand::Create { snapshot, memory } => {
                let created = self.client.snapshot_create(&vm, snapshot, *memory).await?;
                self.output(&created, || {
                    println!("created snapshot '{snapshot}' of VM '{}'", vm.name)
                })
            }
            SnapshotCommand::List => {
                let snapshots = self.client.snapshot_list(&vm).await?;
                self.output(&snapshots, || {
                    if snapshots.is_empty() {
                        println!("VM '{}' has no snapshots", vm.name);
                    } else {
                        print!("{}", render_snapshots(&snapshots));
                    }
                })
            }
            SnapshotCommand::Delete { snapshot } => {
                self.client.snapshot_delete(&vm, snapshot).await?;
                self.output(&serde_json::json!({ "deleted": snapshot }), || {
                    println!("deleted snapshot '{snapshot}'")
                })
            }
            SnapshotCommand::Rollback { snapshot } => {
                self.client.snapshot_rollback(&vm, snapshot).await?;
                self.output(&serde_json::json!({ "rolled_back": snapshot }), || {
                    println!("rolled VM '{}' back to snapshot '{snapshot}'", vm.name)
                })
            }
        }
    }
}

fn parse_forward(spec: &str) -> CliResult<(u16, u16)> {
    let (local, remote) = spec.split_once(':').unwrap_or((spec, spec));
    let port = |value: &str| {
        value
            .parse::<u16>()
            .ok()
            .filter(|port| *port > 0)
            .ok_or_else(|| {
                CliError::new(format!("invalid port '{value}' in '{spec}'"))
                    .hint("use `<port>` or `<local>:<remote>` with ports 1-65535, e.g. `8080:80`")
            })
    };
    Ok((port(local)?, port(remote)?))
}

fn format_size(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.1}G", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.0}M", bytes as f64 / MIB as f64)
    } else {
        format!("{}K", bytes / 1024)
    }
}

fn render_quota(account: &AccountInfo) -> String {
    let mib = |v: usize| {
        if v >= 1024 {
            format_size(v as u64 * 1024 * 1024)
        } else {
            format!("{v}M")
        }
    };
    format!(
        "{:<9} {}\n{:<9} {}\n{:<9} {} of {} used\n{:<9} {} of {} used\n{:<9} {} of {} used\n",
        "ACCOUNT",
        account.email,
        "NAMESPACE",
        account.namespace.as_deref().unwrap_or("-"),
        "VMS",
        account.usage.vms,
        account.quotas.max_vms,
        "VCPU",
        account.usage.vcpu,
        account.quotas.max_vcpu,
        "MEMORY",
        mib(account.usage.mem_mib),
        mib(account.quotas.max_mem_mib),
    )
}

fn describe_idle_timeout(vm: &Vm) -> String {
    match vm.idle_timeout_secs {
        0 => "never".to_string(),
        secs if vm.idle_timeout_default => {
            format!("{} idle (default)", format_duration(secs))
        }
        secs => format!("{} idle", format_duration(secs)),
    }
}

fn render_vms(vms: &[Vm]) -> String {
    let mut table = format!(
        "{:<20} {:<10} {:<12} {:<6} {:<8} {:<8} {:<6} {}\n",
        "NAME", "STATE", "IMAGE", "VCPU", "MEM", "DISK", "IDLE", "ID"
    );
    for vm in vms {
        let disk = match vm.disk_mib {
            0 => "-".to_string(),
            mib => format_size(mib as u64 * 1024 * 1024),
        };
        let idle = describe_idle_timeout(vm);
        table.push_str(&format!(
            "{:<20} {:<10} {:<12} {:<6} {:<8} {:<8} {:<6} {}\n",
            vm.name,
            vm.status.as_str(),
            vm.image,
            vm.vcpu,
            format!("{}M", vm.memory_mib),
            disk,
            idle,
            vm.id
        ));
    }
    table
}

fn render_snapshots(snapshots: &[SnapshotInfo]) -> String {
    let mut table = format!("{:<20} {:<10} {}\n", "NAME", "SIZE", "CREATED");
    for snapshot in snapshots {
        table.push_str(&format!(
            "{:<20} {:<10} {}\n",
            snapshot.name,
            format_size(snapshot.size_bytes),
            kletka_types::time::display(snapshot.created_at),
        ));
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm(name: &str, status: VmStatus) -> Vm {
        Vm {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            image: "default".into(),
            vcpu: 2,
            memory_mib: 512,
            disk_mib: 2048,
            nat: true,
            status,
            assigned_node: None,
            idle_timeout_secs: 28_800,
            idle_timeout_default: true,
            last_active_at: None,
        }
    }

    #[test]
    fn vm_table_renders_rows() {
        let table = render_vms(&[
            vm("calm-fox", VmStatus::Running),
            vm("bold-ox", VmStatus::Stopped),
        ]);
        assert!(table.starts_with("NAME"));
        assert!(table.contains("calm-fox") && table.contains("running"));
        assert!(table.contains("bold-ox") && table.contains("stopped"));
        assert!(table.contains("512M") && table.contains("2.0G"));
        assert_eq!(table.lines().count(), 3);
    }

    #[test]
    fn snapshot_table_renders_size_and_date() {
        let table = render_snapshots(&[SnapshotInfo {
            name: "clean".into(),
            created_at: kletka_types::time::from_unix(1_700_000_000),
            size_bytes: 3 * 1024 * 1024,
            with_memory: false,
        }]);
        assert!(table.contains("clean"));
        assert!(table.contains("3M"), "{table}");
        assert!(table.contains("2023-11-14 22:13 UTC"), "{table}");
    }

    #[test]
    #[test]
    fn oauth_choice_respects_flags_and_enabled_methods() {
        let methods = |password: bool, oauth: &[&str]| kletka_types::AuthMethods {
            password,
            oauth: oauth.iter().map(|p| p.to_string()).collect(),
        };
        assert_eq!(
            oauth_choice(&methods(true, &["github"]), false, Some("github"), None, None)
                .unwrap()
                .as_deref(),
            Some("github")
        );
        assert!(
            oauth_choice(&methods(true, &[]), false, Some("steam"), None, None).is_err(),
            "unknown providers are rejected"
        );
        assert_eq!(
            oauth_choice(&methods(false, &["gitlab"]), false, None, None, None)
                .unwrap()
                .as_deref(),
            Some("gitlab")
        );
        assert!(oauth_choice(&methods(false, &[]), false, None, None, None).is_err());
        assert!(
            oauth_choice(
                &methods(false, &["github"]),
                false,
                None,
                Some("a@example.com"),
                None
            )
            .is_err(),
            "email flags against a password-disabled deployment are rejected"
        );
        assert_eq!(
            oauth_choice(
                &methods(true, &["github"]),
                false,
                None,
                Some("a@example.com"),
                Some("pw")
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn forward_specs_parse() {
        assert_eq!(parse_forward("3000").unwrap(), (3000, 3000));
        assert_eq!(parse_forward("8080:80").unwrap(), (8080, 80));
        assert!(parse_forward("0").is_err());
        assert!(parse_forward("80:http").is_err());
        assert!(parse_forward("70000").is_err());
    }

    #[test]
    fn sizes_format_compactly() {
        assert_eq!(format_size(4096), "4K");
        assert_eq!(format_size(3 * 1024 * 1024), "3M");
        assert_eq!(format_size(5 * 1024 * 1024 * 1024 / 2), "2.5G");
    }

    #[test]
    fn quota_table_shows_usage_against_limits() {
        let account = AccountInfo {
            user_id: uuid::Uuid::nil(),
            email: "user@example.com".into(),
            quotas: kletka_types::QuotaInfo {
                max_vms: 5,
                max_vcpu: 8,
                max_mem_mib: 8192,
            },
            usage: kletka_types::UsageInfo {
                vms: 2,
                vcpu: 4,
                mem_mib: 4096,
            },
            namespace: Some("acme".into()),
            platform_admin: false,
        };
        let table = render_quota(&account);
        assert!(table.contains("user@example.com"), "{table}");
        assert!(table.contains("NAMESPACE acme"), "{table}");
        assert!(table.contains("VMS       2 of 5 used"), "{table}");
        assert!(table.contains("VCPU      4 of 8 used"), "{table}");
        assert!(table.contains("MEMORY    4.0G of 8.0G used"), "{table}");

        let zeroed = AccountInfo {
            usage: kletka_types::UsageInfo {
                vms: 0,
                vcpu: 0,
                mem_mib: 0,
            },
            ..account
        };
        assert!(render_quota(&zeroed).contains("MEMORY    0M of 8.0G used"));
    }
}
