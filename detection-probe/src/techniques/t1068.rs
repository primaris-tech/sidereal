//! T1068 — Exploitation for Privilege Escalation
//!
//! Fires syscall patterns associated with privilege escalation attempts:
//! - `setuid(0)` — attempt to elevate to root
//! - `setgid(0)` — attempt to elevate group to root
//! - `prctl(PR_SET_NO_NEW_PRIVS, 0)` — attempt to disable no-new-privs
//!
//! All of these should fail in a properly sandboxed container (non-root,
//! capabilities dropped). The detection layer should alert on the attempt.

use crate::catalog::TechniqueResult;

pub fn execute() -> TechniqueResult {
    let details = vec![
        attempt_setuid(),
        attempt_setgid(),
        attempt_prctl_no_new_privs(),
    ];

    TechniqueResult {
        technique_id: "T1068".to_string(),
        description: "Privilege Escalation — setuid(0), setgid(0), prctl attempts".to_string(),
        pattern_emitted: true,
        details,
    }
}

fn attempt_setuid() -> String {
    match nix::unistd::setuid(nix::unistd::Uid::from_raw(0)) {
        Ok(()) => "setuid(0): succeeded (unexpected — container is running as root)".to_string(),
        Err(e) => format!("setuid(0): {}", e),
    }
}

fn attempt_setgid() -> String {
    match nix::unistd::setgid(nix::unistd::Gid::from_raw(0)) {
        Ok(()) => "setgid(0): succeeded (unexpected)".to_string(),
        Err(e) => format!("setgid(0): {}", e),
    }
}

fn attempt_prctl_no_new_privs() -> String {
    // prctl(PR_SET_NO_NEW_PRIVS, 0) attempts to CLEAR the no-new-privs bit.
    // This should fail if no-new-privs is already set (which it should be).
    #[cfg(target_os = "linux")]
    {
        const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
        let ret = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0) };
        if ret == 0 {
            "prctl(PR_SET_NO_NEW_PRIVS, 0): succeeded (unexpected)".to_string()
        } else {
            let err = std::io::Error::last_os_error();
            format!("prctl(PR_SET_NO_NEW_PRIVS, 0): {}", err)
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        "prctl(PR_SET_NO_NEW_PRIVS, 0): not available on this platform".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute() {
        let result = execute();
        assert_eq!(result.technique_id, "T1068");
        assert!(result.pattern_emitted);
        assert_eq!(result.details.len(), 3);
    }
}
