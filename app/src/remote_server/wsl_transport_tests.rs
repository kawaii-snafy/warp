use warpui::r#async::BoxFuture;

use super::*;

fn static_auth_context() -> Arc<RemoteServerAuthContext> {
    Arc::new(RemoteServerAuthContext::new(
        || -> BoxFuture<'static, Option<String>> { Box::pin(async { None }) },
        || "user id/with spaces".to_string(),
        String::new(),
        String::new(),
        true,
    ))
}

#[test]
fn shell_command_args_target_the_distribution_through_sh() {
    assert_eq!(
        wsl_shell_command_args("Ubuntu-24.04", "test -d ~/.warp"),
        vec![
            "--distribution",
            "Ubuntu-24.04",
            "--exec",
            "/bin/sh",
            "-c",
            "test -d ~/.warp",
        ]
    );
}

#[test]
fn script_args_read_the_script_from_stdin() {
    assert_eq!(
        wsl_script_args("Debian"),
        vec!["--distribution", "Debian", "--exec", "bash", "-s"]
    );
}

#[test]
fn remote_proxy_command_execs_the_proxy_with_a_quoted_identity_key() {
    let transport = WslTransport::new("Ubuntu".to_string(), static_auth_context());

    let command = transport.remote_proxy_command();

    assert!(command.starts_with("exec "));
    assert!(command.contains("remote-server-proxy --identity-key"));
    assert!(command.contains("'user id/with spaces'"));
}

#[test]
fn signal_killed_proxy_is_not_reconnectable() {
    let transport = WslTransport::new("Ubuntu".to_string(), static_auth_context());

    assert!(transport.is_reconnectable(None));
    assert!(transport.is_reconnectable(Some(&RemoteServerExitStatus {
        code: Some(1),
        signal_killed: false,
    })));
    assert!(!transport.is_reconnectable(Some(&RemoteServerExitStatus {
        code: None,
        signal_killed: true,
    })));
}
