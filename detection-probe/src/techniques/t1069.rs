//! T1069.003 — Permission Groups Discovery: Cloud Groups
//!
//! Fires syscall patterns associated with cloud identity enumeration:
//! - Read attempts to cloud metadata endpoints via filesystem paths
//! - Read attempts to Kubernetes ServiceAccount token paths
//! - Read attempts to cloud credential files
//!
//! The probe does not make network calls (it has no network access).
//! It attempts to read local filesystem paths that would contain
//! cloud identity information. Detection rules should alert on
//! access to these sensitive paths.

use crate::catalog::TechniqueResult;

const METADATA_PATHS: &[&str] = &[
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    "/run/secrets/kubernetes.io/serviceaccount/token",
];

const CLOUD_CREDENTIAL_PATHS: &[&str] = &[
    "/root/.aws/credentials",
    "/root/.azure/accessTokens.json",
    "/root/.config/gcloud/credentials.db",
    "/home/.aws/credentials",
];

pub fn execute() -> TechniqueResult {
    let mut details = Vec::new();

    for path in METADATA_PATHS {
        details.push(attempt_read(path));
    }

    for path in CLOUD_CREDENTIAL_PATHS {
        details.push(attempt_read(path));
    }

    TechniqueResult {
        technique_id: "T1069.003".to_string(),
        description: "Cloud Groups Discovery — SA token and cloud credential read attempts"
            .to_string(),
        pattern_emitted: true,
        details,
    }
}

fn attempt_read(path: &str) -> String {
    match std::fs::read(path) {
        Ok(data) => format!("read({}): {} bytes read (unexpected)", path, data.len()),
        Err(e) => format!("read({}): {}", path, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute() {
        let result = execute();
        assert_eq!(result.technique_id, "T1069.003");
        assert!(result.pattern_emitted);
        assert_eq!(
            result.details.len(),
            METADATA_PATHS.len() + CLOUD_CREDENTIAL_PATHS.len()
        );
    }
}
