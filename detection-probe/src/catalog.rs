//! Technique catalog — maps MITRE ATT&CK technique IDs to syscall execution functions.
//!
//! Each technique module exposes an `execute()` function that fires a synthetic
//! syscall pattern. The detection probe does not care whether the syscall succeeds
//! or fails — it only cares that the pattern is emitted for the detection layer
//! (Falco/Tetragon) to observe.

use crate::techniques;

/// Result of executing a technique's syscall pattern.
#[derive(Debug, serde::Serialize)]
pub struct TechniqueResult {
    /// The MITRE ATT&CK technique ID.
    pub technique_id: String,
    /// Human-readable description of what was attempted.
    pub description: String,
    /// Whether the syscall pattern was emitted (not whether it "succeeded").
    pub pattern_emitted: bool,
    /// Details about individual syscall attempts.
    pub details: Vec<String>,
}

/// Execute the syscall pattern for the given MITRE ATT&CK technique ID.
///
/// Returns `Some(TechniqueResult)` if the technique is in the catalog,
/// `None` if the technique ID is not recognized.
pub fn execute(technique_id: &str) -> Option<TechniqueResult> {
    match technique_id {
        "T1053" | "T1053.007" => Some(techniques::t1053::execute()),
        "T1059" | "T1059.004" => Some(techniques::t1059::execute()),
        "T1068" => Some(techniques::t1068::execute()),
        "T1069" | "T1069.003" => Some(techniques::t1069::execute()),
        "T1078" | "T1078.001" => Some(techniques::t1078::execute()),
        "T1552.001" => Some(techniques::t1552_001::execute()),
        "T1552.007" => Some(techniques::t1552_007::execute()),
        "T1611" => Some(techniques::t1611::execute()),
        "T1613" => Some(techniques::t1613::execute()),
        _ => None,
    }
}

/// Returns a list of all supported technique IDs and their descriptions.
pub fn list_techniques() -> Vec<(&'static str, &'static str)> {
    vec![
        ("T1053.007", "Container Orchestration Job — cron write and scheduler exec attempts"),
        ("T1059.004", "Command and Scripting Interpreter: Unix Shell — execve() of known-bad paths"),
        ("T1068", "Exploitation for Privilege Escalation — setuid(0), setgid(0), prctl attempts"),
        ("T1069.003", "Cloud Groups Discovery — SA token and cloud credential read attempts"),
        ("T1078.001", "Default Accounts — account file reads and escalation binary exec attempts"),
        ("T1552.001", "Credentials In Files — SSH keys, app creds, and history file read attempts"),
        ("T1552.007", "Container API — SA token read and API server connect attempts"),
        ("T1611", "Escape to Host — unshare(CLONE_NEWNS), mount() attempts"),
        ("T1613", "Container and Resource Discovery — proc introspection and runtime socket probing"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_techniques_execute() {
        let techniques = list_techniques();
        for (id, _desc) in &techniques {
            let result = execute(id);
            assert!(result.is_some(), "technique {} should be in catalog", id);
            let r = result.unwrap();
            assert_eq!(r.technique_id, *id);
            assert!(r.pattern_emitted);
            assert!(!r.details.is_empty(), "technique {} should have details", id);
        }
    }

    #[test]
    fn test_unknown_technique() {
        let result = execute("T9999");
        assert!(result.is_none());
    }

    #[test]
    fn test_parent_id_aliases() {
        // Parent technique IDs should resolve to subtechnique implementations.
        assert!(execute("T1053").is_some());
        assert!(execute("T1059").is_some());
        assert!(execute("T1069").is_some());
        assert!(execute("T1078").is_some());
    }

    #[test]
    fn test_catalog_has_nine_techniques() {
        let techniques = list_techniques();
        assert_eq!(techniques.len(), 9);
    }
}
