//! T1053.007 — Scheduled Task/Job: Container Orchestration Job
//!
//! Fires syscall patterns associated with unauthorized job scheduling:
//! - Write attempts to cron directories (/etc/cron.d/, /var/spool/cron/)
//! - Attempt to execute scheduling binaries (at, crontab)
//!
//! These operations should be impossible in a properly sandboxed probe
//! container (read-only filesystem, no cron binaries). The detection layer
//! should alert on the file access and execve attempts.

use crate::catalog::TechniqueResult;
use std::ffi::CString;

const CRON_PATHS: &[&str] = &[
    "/etc/cron.d/backdoor",
    "/var/spool/cron/crontabs/root",
    "/etc/crontab",
];

const SCHEDULER_BINARIES: &[&str] = &[
    "/usr/bin/at",
    "/usr/bin/crontab",
    "/usr/bin/batch",
];

pub fn execute() -> TechniqueResult {
    let mut details = Vec::new();

    for path in CRON_PATHS {
        details.push(attempt_cron_write(path));
    }

    for path in SCHEDULER_BINARIES {
        details.push(attempt_exec(path));
    }

    TechniqueResult {
        technique_id: "T1053.007".to_string(),
        description: "Container Orchestration Job — cron write and scheduler exec attempts"
            .to_string(),
        pattern_emitted: true,
        details,
    }
}

fn attempt_cron_write(path: &str) -> String {
    use std::fs::OpenOptions;
    match OpenOptions::new().write(true).create(true).truncate(true).open(path) {
        Ok(_) => format!("write({}): opened for write (unexpected)", path),
        Err(e) => format!("write({}): {}", path, e),
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
        assert_eq!(result.technique_id, "T1053.007");
        assert!(result.pattern_emitted);
        assert_eq!(
            result.details.len(),
            CRON_PATHS.len() + SCHEDULER_BINARIES.len()
        );
    }
}
