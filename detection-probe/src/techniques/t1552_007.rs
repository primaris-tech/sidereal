//! T1552.007 — Unsecured Credentials: Container API
//!
//! Fires syscall patterns associated with Kubernetes API access from within
//! a container:
//! - Read the ServiceAccount token from the projected volume
//! - Attempt to connect to the Kubernetes API server endpoint
//! - Read environment variables that expose API server details
//!
//! The probe has no network access, so connect() calls will fail.
//! Detection rules should alert on the token read and connection attempt.

use crate::catalog::TechniqueResult;

const TOKEN_PATHS: &[&str] = &[
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/run/secrets/kubernetes.io/serviceaccount/token",
];

const API_ENDPOINTS: &[(&str, u16)] = &[
    ("10.96.0.1", 443),       // Default ClusterIP for kubernetes.default
    ("kubernetes.default", 443),
];

pub fn execute() -> TechniqueResult {
    let mut details = Vec::new();

    // Attempt to read SA token.
    for path in TOKEN_PATHS {
        details.push(attempt_read(path));
    }

    // Read API server environment variables.
    details.push(read_env("KUBERNETES_SERVICE_HOST"));
    details.push(read_env("KUBERNETES_SERVICE_PORT"));

    // Attempt TCP connect to API server.
    for (host, port) in API_ENDPOINTS {
        details.push(attempt_connect(host, *port));
    }

    TechniqueResult {
        technique_id: "T1552.007".to_string(),
        description: "Container API — SA token read and API server connect attempts".to_string(),
        pattern_emitted: true,
        details,
    }
}

fn attempt_read(path: &str) -> String {
    match std::fs::read(path) {
        Ok(data) => format!("read({}): {} bytes (unexpected in probe container)", path, data.len()),
        Err(e) => format!("read({}): {}", path, e),
    }
}

fn read_env(var: &str) -> String {
    match std::env::var(var) {
        Ok(val) => format!("env({}): {}", var, val),
        Err(_) => format!("env({}): not set", var),
    }
}

fn attempt_connect(host: &str, port: u16) -> String {
    use std::net::TcpStream;
    use std::time::Duration;

    let addr = format!("{}:{}", host, port);
    match TcpStream::connect_timeout(
        &addr.parse().unwrap_or_else(|_| {
            // If hostname can't be parsed as SocketAddr, use a dummy.
            "0.0.0.0:0".parse().unwrap()
        }),
        Duration::from_millis(500),
    ) {
        Ok(_) => format!("connect({}): connected (unexpected — probe should have no network)", addr),
        Err(e) => format!("connect({}): {}", addr, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute() {
        let result = execute();
        assert_eq!(result.technique_id, "T1552.007");
        assert!(result.pattern_emitted);
        // TOKEN_PATHS + 2 env vars + API_ENDPOINTS
        assert!(result.details.len() >= 4);
    }
}
