//! WSL-specific implementation of [`RemoteTransport`].
//!
//! [`WslTransport`] runs the Linux remote server inside a WSL distribution through `wsl.exe`,
//! mirroring how VS Code's Remote-WSL runs its server inside the guest: the binary check, install
//! and `remote-server-proxy` launch all execute in the distribution, and the proxy's stdio becomes
//! the protocol channel.
use std::fmt;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::process::{Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use futures::AsyncWriteExt as _;
use remote_server::auth::RemoteServerAuthContext;
use remote_server::client::RemoteServerClient;
use remote_server::manager::RemoteServerExitStatus;
use remote_server::setup::{PreinstallCheckResult, RemotePlatform, parse_uname_output};
use remote_server::transport::{
    Connection, ControlPath, Error, InstallOutcome, InstallSource, RemoteTransport,
};
use warpui::r#async::FutureExt as _;
use warpui::r#async::executor;

use super::ssh_transport::installation::scp_fallback;

/// The program used to enter a WSL distribution from the Windows host.
const WSL_PROGRAM: &str = "wsl";

/// Exit code of the install script when the guest's OS or architecture is unsupported, which no
/// other download source can fix.
const INSTALL_SCRIPT_UNSUPPORTED_PLATFORM_EXIT_CODE: i32 = 2;

/// WSL transport: runs the remote server inside the WSL distribution `distro`.
#[derive(Clone)]
pub struct WslTransport {
    distro: String,
    auth_context: Arc<RemoteServerAuthContext>,
}

impl fmt::Debug for WslTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WslTransport")
            .field("distro", &self.distro)
            .finish_non_exhaustive()
    }
}

impl WslTransport {
    pub fn new(distro: String, auth_context: Arc<RemoteServerAuthContext>) -> Self {
        Self {
            distro,
            auth_context,
        }
    }

    pub fn distro(&self) -> &str {
        &self.distro
    }

    /// The shell command that execs the proxy. `exec` keeps the proxy as the direct child of
    /// `wsl.exe`, so killing `wsl.exe` on teardown closes the proxy's stdio.
    fn remote_proxy_command(&self) -> String {
        let binary = remote_server::setup::remote_server_binary();
        let identity_key = self.auth_context.remote_server_identity_key();
        let quoted_identity_key = shell_words::quote(&identity_key);
        format!("exec {binary} remote-server-proxy --identity-key {quoted_identity_key}")
    }
}

/// Builds the `wsl.exe` arguments that run `command` with `/bin/sh -c` inside `distro`.
///
/// A shell is required because the setup commands use `~`-relative paths, which `wsl.exe --exec`
/// would otherwise pass through unexpanded.
fn wsl_shell_command_args(distro: &str, command: &str) -> Vec<String> {
    vec![
        "--distribution".to_string(),
        distro.to_string(),
        "--exec".to_string(),
        "/bin/sh".to_string(),
        "-c".to_string(),
        command.to_string(),
    ]
}

/// Builds the `wsl.exe` arguments that run a script read from stdin with `bash -s` inside `distro`.
fn wsl_script_args(distro: &str) -> Vec<String> {
    vec![
        "--distribution".to_string(),
        distro.to_string(),
        "--exec".to_string(),
        "bash".to_string(),
        "-s".to_string(),
    ]
}

/// Runs `command` inside `distro`. `Err` is a transport-level failure (spawn failure or timeout);
/// callers inspect `Ok(output).status` for the command's own exit code.
async fn run_wsl_command(distro: &str, command: &str, timeout: Duration) -> Result<Output, Error> {
    let args = wsl_shell_command_args(distro, command);
    async {
        command::r#async::Command::new(WSL_PROGRAM)
            .args(&args)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output()
            .await
    }
    .with_timeout(timeout)
    .await
    .map_err(|_| Error::TimedOut)?
    .map_err(|err| Error::Other(anyhow!("Failed to run wsl.exe: {err}")))
}

/// Pipes `stdin` into `args` run through `wsl.exe` and waits for it to exit.
async fn run_wsl_with_stdin(
    args: &[String],
    stdin: &[u8],
    timeout: Duration,
) -> Result<Output, Error> {
    async {
        let mut child = command::r#async::Command::new(WSL_PROGRAM)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|err| Error::Other(anyhow!("Failed to spawn wsl.exe: {err}")))?;
        if let Some(mut child_stdin) = child.stdin.take() {
            child_stdin
                .write_all(stdin)
                .await
                .map_err(|err| Error::Other(anyhow!("Failed to write to wsl.exe stdin: {err}")))?;
            // Closing stdin lets the guest process see EOF and exit.
            drop(child_stdin);
        }
        child
            .output()
            .await
            .map_err(|err| Error::Other(anyhow!("wsl.exe I/O error: {err}")))
    }
    .with_timeout(timeout)
    .await
    .map_err(|_| Error::TimedOut)?
}

/// Runs `script` with `bash -s` inside `distro`.
async fn run_wsl_script(distro: &str, script: &str, timeout: Duration) -> Result<Output, Error> {
    run_wsl_with_stdin(&wsl_script_args(distro), script.as_bytes(), timeout).await
}

/// Converts a finished command into `Ok(())` on success or a [`Error::ScriptFailed`] otherwise.
fn ensure_success(output: Output) -> Result<(), Error> {
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::ScriptFailed {
            exit_code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

async fn detect_wsl_platform(distro: &str) -> Result<RemotePlatform, Error> {
    let output = run_wsl_command(distro, "uname -sm", remote_server::setup::CHECK_TIMEOUT).await?;
    if output.status.success() {
        parse_uname_output(&String::from_utf8_lossy(&output.stdout))
    } else {
        let code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(Error::Other(anyhow!(
            "uname -sm exited with code {code}: {stderr}"
        )))
    }
}

/// Installs the binary the way VS Code installs its WSL server: download the tarball on the
/// Windows host, where it is cached across distributions and sessions, and stream it into the
/// distribution, falling back to downloading inside the distribution when the host can't fetch
/// it. Each of [`remote_server::setup::download_channels`] is tried in turn.
async fn install_wsl_binary(distro: &str) -> InstallOutcome {
    let binary_path = remote_server::setup::remote_server_binary();
    log::info!("Installing remote server binary to {binary_path} in WSL distribution {distro}");

    let mut outcome = InstallOutcome {
        source: None,
        result: Err(Error::Other(anyhow!("no remote server download channel"))),
    };
    for &download_channel in remote_server::setup::download_channels() {
        outcome = install_from_channel(distro, download_channel).await;
        match &outcome.result {
            Ok(()) => break,
            Err(Error::ScriptFailed { exit_code, .. })
                if *exit_code == INSTALL_SCRIPT_UNSUPPORTED_PLATFORM_EXIT_CODE =>
            {
                break;
            }
            Err(err) => log::info!(
                "Installing the remote server from the {download_channel} channel failed: {err}"
            ),
        }
    }

    if outcome.result.is_ok() {
        let verify = run_wsl_command(
            distro,
            &remote_server::setup::binary_check_command(),
            remote_server::setup::CHECK_TIMEOUT,
        )
        .await
        .and_then(ensure_success);
        if let Err(err) = verify {
            outcome.result = Err(Error::Other(anyhow!(
                "Post-install verification failed for {binary_path}: {err}"
            )));
        }
    }

    outcome
}

async fn install_from_channel(distro: &str, download_channel: &str) -> InstallOutcome {
    match install_from_host_tarball(distro, download_channel).await {
        Ok(()) => InstallOutcome {
            source: Some(InstallSource::Client),
            result: Ok(()),
        },
        Err(err @ Error::ScriptFailed { exit_code, .. })
            if exit_code == INSTALL_SCRIPT_UNSUPPORTED_PLATFORM_EXIT_CODE =>
        {
            InstallOutcome {
                source: Some(InstallSource::Client),
                result: Err(err),
            }
        }
        Err(host_err) => {
            log::info!(
                "Host-side remote server download failed ({host_err}); downloading inside WSL"
            );
            let result = run_wsl_script(
                distro,
                &remote_server::setup::install_script_from_channel(None, download_channel),
                remote_server::setup::INSTALL_TIMEOUT,
            )
            .await
            .and_then(ensure_success);
            InstallOutcome {
                source: Some(InstallSource::Server),
                result,
            }
        }
    }
}

async fn install_from_host_tarball(distro: &str, download_channel: &str) -> Result<(), Error> {
    let platform = detect_wsl_platform(distro).await?;
    let tarball_path = scp_fallback::cached_remote_server_tarball(&platform, download_channel)
        .await
        .map_err(Error::Other)?;

    let install_dir = remote_server::setup::remote_server_dir();
    let staged_tarball_path = format!("{install_dir}/oz-upload-{}.tar.gz", uuid::Uuid::new_v4());
    let upload_command = format!("mkdir -p {install_dir} && cat > {staged_tarball_path}");
    upload_file_to_wsl(
        &wsl_shell_command_args(distro, &upload_command),
        &tarball_path,
        remote_server::setup::SCP_INSTALL_TIMEOUT,
    )
    .await?;

    run_wsl_script(
        distro,
        &remote_server::setup::install_script_from_channel(
            Some(&staged_tarball_path),
            download_channel,
        ),
        remote_server::setup::SCP_INSTALL_TIMEOUT,
    )
    .await
    .and_then(ensure_success)
}

/// Streams the host file at `path` into the stdin of `args` run through `wsl.exe`.
async fn upload_file_to_wsl(args: &[String], path: &Path, timeout: Duration) -> Result<(), Error> {
    async {
        let mut file = async_fs::File::open(path)
            .await
            .map_err(|err| Error::Other(anyhow!("Failed to open cached tarball: {err}")))?;
        let mut child = command::r#async::Command::new(WSL_PROGRAM)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|err| Error::Other(anyhow!("Failed to spawn wsl.exe: {err}")))?;
        if let Some(mut child_stdin) = child.stdin.take() {
            futures::io::copy(&mut file, &mut child_stdin)
                .await
                .map_err(|err| Error::Other(anyhow!("Failed to stream the tarball: {err}")))?;
            // Closing stdin lets `cat` see EOF and exit.
            drop(child_stdin);
        }
        let output = child
            .output()
            .await
            .map_err(|err| Error::Other(anyhow!("wsl.exe I/O error: {err}")))?;
        ensure_success(output)
    }
    .with_timeout(timeout)
    .await
    .map_err(|_| Error::TimedOut)?
}

impl RemoteTransport for WslTransport {
    fn detect_platform(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<RemotePlatform, Error>> + Send>> {
        let distro = self.distro.clone();
        Box::pin(async move { detect_wsl_platform(&distro).await })
    }

    fn run_preinstall_check(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<PreinstallCheckResult, Error>> + Send>> {
        let distro = self.distro.clone();
        Box::pin(async move {
            let output = run_wsl_script(
                &distro,
                remote_server::setup::PREINSTALL_CHECK_SCRIPT,
                remote_server::setup::CHECK_TIMEOUT,
            )
            .await?;
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            ensure_success(output)?;
            Ok(PreinstallCheckResult::parse(&stdout))
        })
    }

    fn check_binary(&self) -> Pin<Box<dyn Future<Output = Result<bool, Error>> + Send>> {
        let distro = self.distro.clone();
        Box::pin(async move {
            let output = run_wsl_command(
                &distro,
                &remote_server::setup::binary_check_command(),
                remote_server::setup::CHECK_TIMEOUT,
            )
            .await?;
            // Same contract as the SSH check: 127 means not found and 126 means not executable.
            match output.status.code() {
                Some(0) => Ok(true),
                Some(126) | Some(127) => Ok(false),
                Some(code) => Err(Error::Other(anyhow!(
                    "binary check exited with code {code}: {}",
                    String::from_utf8_lossy(&output.stderr)
                ))),
                None => Err(Error::Other(anyhow!("binary check terminated by signal"))),
            }
        })
    }

    fn check_has_old_binary(&self) -> Pin<Box<dyn Future<Output = Result<bool>> + Send>> {
        let distro = self.distro.clone();
        Box::pin(async move {
            let command = format!("test -d {}", remote_server::setup::remote_server_dir());
            let output =
                run_wsl_command(&distro, &command, remote_server::setup::CHECK_TIMEOUT).await?;
            match output.status.code() {
                Some(0) => Ok(true),
                Some(1) => Ok(false),
                code => Err(anyhow!(
                    "remote-server dir check exited with {code:?}: {}",
                    String::from_utf8_lossy(&output.stderr)
                )),
            }
        })
    }

    fn install_binary(&self) -> Pin<Box<dyn Future<Output = InstallOutcome> + Send>> {
        let distro = self.distro.clone();
        Box::pin(async move { install_wsl_binary(&distro).await })
    }

    fn connect(
        &self,
        executor: Arc<executor::Background>,
    ) -> Pin<Box<dyn Future<Output = Result<Connection>> + Send>> {
        let args = wsl_shell_command_args(&self.distro, &self.remote_proxy_command());
        Box::pin(async move {
            // The manager owns the returned `Child`; dropping it on teardown kills `wsl.exe`,
            // which closes the proxy's stdio and lets it exit.
            let mut child = command::r#async::Command::new(WSL_PROGRAM)
                .args(&args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()?;

            let stdin = child
                .stdin
                .take()
                .ok_or_else(|| anyhow!("Failed to capture wsl.exe stdin"))?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| anyhow!("Failed to capture wsl.exe stdout"))?;
            let stderr = child
                .stderr
                .take()
                .ok_or_else(|| anyhow!("Failed to capture wsl.exe stderr"))?;

            let (client, event_rx, failure_rx, host_response_rx, stderr_tail) =
                RemoteServerClient::from_child_streams(stdin, stdout, stderr, &executor);
            Ok(Connection {
                client,
                event_rx,
                failure_rx,
                host_response_rx,
                child,
                control_path: ControlPath::None,
                stderr_tail,
            })
        })
    }

    fn remove_remote_server_binary(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        let distro = self.distro.clone();
        Box::pin(async move {
            let output = run_wsl_command(
                &distro,
                &remote_server::setup::remote_server_removal_command(),
                remote_server::setup::CHECK_TIMEOUT,
            )
            .await?;
            ensure_success(output).map_err(anyhow::Error::from)
        })
    }

    /// Unlike SSH's exit code 255, `wsl.exe` has no exit code that marks the connection itself as
    /// dead, so any exit other than a deliberate kill is worth a reconnect attempt.
    fn is_reconnectable(&self, exit_status: Option<&RemoteServerExitStatus>) -> bool {
        exit_status.is_none_or(|status| !status.signal_killed)
    }
}

#[cfg(test)]
#[path = "wsl_transport_tests.rs"]
mod tests;
