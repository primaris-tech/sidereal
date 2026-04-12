//! T1059.004 — Command and Scripting Interpreter: Unix Shell
//!
//! Fires syscall patterns associated with unauthorized command execution:
//! - `execve()` of known-bad interpreter paths (/bin/sh, /bin/bash, etc.)
//!
//! In a scratch/distroless container, these binaries don't exist, so execve
//! will fail with ENOENT. The detection layer should alert on the execve
//! attempt regardless of success.
//!
//! We use nix::unistd::execve which is a direct syscall wrapper. In a real
//! container this would replace the current process, so we fork first.

use crate::catalog::TechniqueResult;
use std::ffi::CString;

/// Known-bad interpreter paths that should trigger detection alerts.
const BAD_PATHS: &[&str] = &[
    "/bin/sh",
    "/bin/bash",
    "/bin/dash",
    "/usr/bin/python3",
    "/usr/bin/curl",
];

/// Execute the T1059 command execution syscall pattern.
pub fn execute() -> TechniqueResult {
    let mut details = Vec::new();

    for path in BAD_PATHS {
        details.push(attempt_execve(path));
    }

    TechniqueResult {
        technique_id: "T1059.004".to_string(),
        description: "Command Execution — execve() of known-bad interpreter paths".to_string(),
        pattern_emitted: true,
        details,
    }
}

/// Attempt execve() of a known-bad path in a forked child process.
/// The child calls execve and exits; the parent observes the result.
/// Expected to fail with ENOENT in scratch/distroless containers.
fn attempt_execve(path: &str) -> String {
    use nix::sys::wait::waitpid;
    use nix::unistd::{fork, ForkResult};

    // Safety: we fork before execve so the parent process survives.
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            // In child: attempt execve. If it succeeds, the child becomes
            // the new binary. If it fails, we exit with code 1.
            let c_path = match CString::new(path) {
                Ok(p) => p,
                Err(_) => std::process::exit(1),
            };
            // execve with no args and empty environment.
            let _ = nix::unistd::execve::<CString, CString>(&c_path, &[], &[]);
            // If we get here, execve failed (expected).
            std::process::exit(1);
        }
        Ok(ForkResult::Parent { child }) => {
            // Wait for child to exit.
            match waitpid(child, None) {
                Ok(status) => {
                    format!("execve({}): child exited with {:?}", path, status)
                }
                Err(e) => {
                    format!("execve({}): waitpid error ({})", path, e)
                }
            }
        }
        Err(e) => {
            format!("execve({}): fork failed ({})", path, e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_returns_result() {
        let result = execute();
        assert_eq!(result.technique_id, "T1059.004");
        assert!(result.pattern_emitted);
        assert_eq!(result.details.len(), BAD_PATHS.len());
    }

    #[test]
    fn test_details_contain_paths() {
        let result = execute();
        for (i, path) in BAD_PATHS.iter().enumerate() {
            assert!(
                result.details[i].contains(path),
                "detail {} should contain path {}",
                i,
                path
            );
        }
    }
}
