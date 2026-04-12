//! T1613 — Container and Resource Discovery
//!
//! Fires syscall patterns associated with container environment enumeration:
//! - Read /proc/1/cgroup to determine container runtime
//! - Read /proc/self/mountinfo to enumerate mount points
//! - Read container runtime socket paths
//! - Read /proc/self/status for capability information
//!
//! Detection rules should alert on process introspection from
//! within a container, especially reading cgroup and mount information.

use crate::catalog::TechniqueResult;

const PROC_PATHS: &[&str] = &[
    "/proc/1/cgroup",
    "/proc/self/cgroup",
    "/proc/self/mountinfo",
    "/proc/self/status",
    "/proc/self/environ",
    "/proc/1/cmdline",
];

const RUNTIME_SOCKET_PATHS: &[&str] = &[
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/run/crio/crio.sock",
];

const METADATA_PATHS: &[&str] = &[
    "/etc/hostname",
    "/etc/resolv.conf",
    "/proc/version",
];

pub fn execute() -> TechniqueResult {
    let mut details = Vec::new();

    for path in PROC_PATHS {
        details.push(attempt_read(path));
    }

    for path in RUNTIME_SOCKET_PATHS {
        details.push(attempt_stat(path));
    }

    for path in METADATA_PATHS {
        details.push(attempt_read(path));
    }

    TechniqueResult {
        technique_id: "T1613".to_string(),
        description:
            "Container Discovery — proc introspection, runtime socket probing, metadata reads"
                .to_string(),
        pattern_emitted: true,
        details,
    }
}

fn attempt_read(path: &str) -> String {
    match std::fs::read_to_string(path) {
        Ok(data) => {
            let preview: String = data.chars().take(80).collect();
            format!("read({}): {} bytes [{}...]", path, data.len(), preview.trim())
        }
        Err(e) => format!("read({}): {}", path, e),
    }
}

fn attempt_stat(path: &str) -> String {
    match std::fs::metadata(path) {
        Ok(meta) => format!(
            "stat({}): exists, type={}, len={}",
            path,
            if meta.is_file() {
                "file"
            } else if meta.is_dir() {
                "dir"
            } else {
                "other"
            },
            meta.len()
        ),
        Err(e) => format!("stat({}): {}", path, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute() {
        let result = execute();
        assert_eq!(result.technique_id, "T1613");
        assert!(result.pattern_emitted);
        assert_eq!(
            result.details.len(),
            PROC_PATHS.len() + RUNTIME_SOCKET_PATHS.len() + METADATA_PATHS.len()
        );
    }
}
