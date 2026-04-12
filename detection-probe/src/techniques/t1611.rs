//! T1611 — Escape to Host
//!
//! Fires syscall patterns associated with container escape techniques:
//! - `unshare(CLONE_NEWNS)` — attempt to create a new mount namespace
//! - `mount()` — attempt to mount the host filesystem
//!
//! These syscalls are expected to fail in a properly sandboxed container
//! (seccomp, capabilities dropped, non-root). The detection layer should
//! alert on the attempt regardless of success.
//!
//! Note: The actual syscall wrappers are Linux-only. On macOS (development),
//! stub implementations report that the syscalls are not available.

use crate::catalog::TechniqueResult;

/// Execute the T1611 Escape to Host syscall pattern.
pub fn execute() -> TechniqueResult {
    let mut details = Vec::new();

    details.push(attempt_unshare());
    details.push(attempt_mount());

    TechniqueResult {
        technique_id: "T1611".to_string(),
        description: "Escape to Host — unshare(CLONE_NEWNS) and mount() attempts".to_string(),
        pattern_emitted: true,
        details,
    }
}

/// Attempt unshare(CLONE_NEWNS) to create a new mount namespace.
/// Expected to fail with EPERM in a sandboxed container.
#[cfg(target_os = "linux")]
fn attempt_unshare() -> String {
    use nix::sched::{unshare, CloneFlags};

    match unshare(CloneFlags::CLONE_NEWNS) {
        Ok(()) => "unshare(CLONE_NEWNS): succeeded (unexpected in sandboxed container)".to_string(),
        Err(e) => format!("unshare(CLONE_NEWNS): failed as expected ({})", e),
    }
}

#[cfg(not(target_os = "linux"))]
fn attempt_unshare() -> String {
    "unshare(CLONE_NEWNS): skipped (not available on this platform)".to_string()
}

/// Attempt to mount procfs at a temporary path.
/// Expected to fail with EPERM in a sandboxed container.
#[cfg(target_os = "linux")]
fn attempt_mount() -> String {
    use nix::mount::{mount, umount, MsFlags};

    let result = mount(
        Some("proc"),
        "/tmp/sidereal-probe-mount",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    );

    match result {
        Ok(()) => {
            let _ = umount("/tmp/sidereal-probe-mount");
            "mount(proc): succeeded (unexpected in sandboxed container)".to_string()
        }
        Err(e) => format!("mount(proc, /tmp/sidereal-probe-mount): failed as expected ({})", e),
    }
}

#[cfg(not(target_os = "linux"))]
fn attempt_mount() -> String {
    "mount(proc): skipped (not available on this platform)".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_returns_result() {
        let result = execute();
        assert_eq!(result.technique_id, "T1611");
        assert!(result.pattern_emitted);
        assert_eq!(result.details.len(), 2);
    }

    #[test]
    fn test_details_contain_syscall_names() {
        let result = execute();
        assert!(result.details[0].contains("unshare"));
        assert!(result.details[1].contains("mount"));
    }
}
