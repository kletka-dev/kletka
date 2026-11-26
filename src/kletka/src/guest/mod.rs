use std::path::Path;

pub fn ssh_common_args(
    key: &Path,
    port: u16,
    connect_timeout_secs: u32,
    attempts: u32,
) -> Vec<String> {
    [
        "-i".to_string(),
        key.display().to_string(),
        "-p".to_string(),
        port.to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        "-o".to_string(),
        "LogLevel=ERROR".to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        format!("ConnectTimeout={connect_timeout_secs}"),
        "-o".to_string(),
        format!("ConnectionAttempts={attempts}"),
    ]
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carries_the_key_port_and_two_lease_flags() {
        let args = ssh_common_args("/kvm/ssh_key".as_ref(), 2222, 5, 3);
        assert_eq!(args[0], "-i");
        assert_eq!(args[1], "/kvm/ssh_key");
        assert_eq!(args[2], "-p");
        assert_eq!(args[3], "2222");
        assert!(
            args.windows(2)
                .any(|w| w[0] == "-o" && w[1] == "BatchMode=yes")
        );
        assert!(
            args.windows(2)
                .any(|w| w[0] == "-o" && w[1] == "ConnectTimeout=5")
        );
        assert!(
            args.windows(2)
                .any(|w| w[0] == "-o" && w[1] == "ConnectionAttempts=3")
        );
    }
}
