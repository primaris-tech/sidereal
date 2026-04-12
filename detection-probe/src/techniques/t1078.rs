//! T1078.001 — Valid Accounts: Default Accounts
//!
//! Fires syscall patterns associated with default account abuse:
//! - Read /etc/passwd and /etc/shadow to enumerate accounts
//! - Attempt to read well-known default credential locations
//! - Attempt to su/sudo as root
//!
//! In a properly sandboxed container these paths should be absent
//! or inaccessible. Detection rules should alert on the access pattern.

use crate::catalog::TechniqueResult;
use std::ffi::CString;

const ACCOUNT_FILES: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
];

const ESCALATION_BINARIES: &[&str] = &[
    "/usr/bin/sudo",
    "/bin/su",
    "/usr/bin/pkexec",
];

pub fn execute() -> TechniqueResult {
    let mut details = Vec::new();

    for path in ACCOUNT_FILES {
        details.push(attempt_read(path));
    }

    for path in ESCALATION_BINARIES {
        details.push(attempt_exec(path));
    }

    TechniqueResult {
        technique_id: "T1078.001".to_string(),
        description: "Default Accounts — account file reads and escalation binary exec attempts"
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

fn attempt_exec(path: &str) -> String {
    use nix::sys::wait::waitpid;
    use nix::unistd::{fork, ForkResult};

    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            let c_path = match CString::new(path) {
                Ok(p) => p,
                Err(_) => std::process::exit(1),
            };
            let _ = nix::unistd::execve::<CString, CString>(&c_path, &[], &[]);
            std::process::exit(1);
        }
        Ok(ForkResult::Parent { child }) => match waitpid(child, None) {
            Ok(status) => format!("execve({}): child exited with {:?}", path, status),
            Err(e) => format!("execve({}): waitpid error ({})", path, e),
        },
        Err(e) => format!("execve({}): fork failed ({})", path, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute() {
        let result = execute();
        assert_eq!(result.technique_id, "T1078.001");
        assert!(result.pattern_emitted);
        assert_eq!(
            result.details.len(),
            ACCOUNT_FILES.len() + ESCALATION_BINARIES.len()
        );
    }
}
