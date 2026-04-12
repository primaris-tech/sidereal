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
        "T1611" => Some(techniques::t1611::execute()),
        "T1059" | "T1059.004" => Some(techniques::t1059::execute()),
        _ => None,
    }
}

/// Returns a list of all supported technique IDs and their descriptions.
pub fn list_techniques() -> Vec<(&'static str, &'static str)> {
    vec![
        ("T1611", "Escape to Host — unshare(CLONE_NEWNS), mount() attempts"),
        ("T1059.004", "Command and Scripting Interpreter: Unix Shell — execve() of known-bad paths"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_technique() {
        let result = execute("T1611");
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.technique_id, "T1611");
        assert!(r.pattern_emitted);
    }

    #[test]
    fn test_unknown_technique() {
        let result = execute("T9999");
        assert!(result.is_none());
    }

    #[test]
    fn test_t1059_alias() {
        // Both T1059 and T1059.004 should resolve.
        assert!(execute("T1059").is_some());
        assert!(execute("T1059.004").is_some());
    }

    #[test]
    fn test_list_techniques() {
        let techniques = list_techniques();
        assert!(techniques.len() >= 2);
        assert!(techniques.iter().any(|(id, _)| *id == "T1611"));
        assert!(techniques.iter().any(|(id, _)| *id == "T1059.004"));
    }
}
