//! T1552.001 — Unsecured Credentials: Credentials In Files
//!
//! Fires syscall patterns associated with credential file harvesting:
//! - Read attempts to SSH private key locations
//! - Read attempts to application credential files
//! - Read attempts to shell history files
//!
//! Detection rules should alert on any read access to these paths
//! from a container workload.

use crate::catalog::TechniqueResult;

const SSH_KEY_PATHS: &[&str] = &[
    "/root/.ssh/id_rsa",
    "/root/.ssh/id_ed25519",
    "/root/.ssh/authorized_keys",
    "/home/.ssh/id_rsa",
    "/etc/ssh/ssh_host_rsa_key",
];

const CREDENTIAL_FILES: &[&str] = &[
    "/root/.docker/config.json",
    "/root/.kube/config",
    "/root/.npmrc",
    "/root/.netrc",
    "/etc/kubernetes/admin.conf",
];

const HISTORY_FILES: &[&str] = &[
    "/root/.bash_history",
    "/root/.sh_history",
    "/root/.zsh_history",
];

pub fn execute() -> TechniqueResult {
    let mut details = Vec::new();

    for path in SSH_KEY_PATHS {
        details.push(attempt_read(path));
    }

    for path in CREDENTIAL_FILES {
        details.push(attempt_read(path));
    }

    for path in HISTORY_FILES {
        details.push(attempt_read(path));
    }

    TechniqueResult {
        technique_id: "T1552.001".to_string(),
        description: "Credentials In Files — SSH keys, app creds, and history file read attempts"
            .to_string(),
        pattern_emitted: true,
        details,
    }
}

fn attempt_read(path: &str) -> String {
    match std::fs::read(path) {
        Ok(data) => format!("read({}): {} bytes (unexpected)", path, data.len()),
        Err(e) => format!("read({}): {}", path, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute() {
        let result = execute();
        assert_eq!(result.technique_id, "T1552.001");
        assert!(result.pattern_emitted);
        assert_eq!(
            result.details.len(),
            SSH_KEY_PATHS.len() + CREDENTIAL_FILES.len() + HISTORY_FILES.len()
        );
    }
}
