// Sidereal Detection Probe
//
// Fires adversarial syscall patterns for detection pipeline validation.
// This binary has NO network access, NO volume mounts, and NO Kubernetes API access.
// It emits a syscall pattern and exits. The controller independently queries
// the detection backend to determine the outcome.
//
// Environment variables:
//   TECHNIQUE_ID — MITRE ATT&CK technique ID to execute (e.g., "T1611")
//   PROBE_ID     — Probe execution ID for correlation

mod catalog;
mod techniques;

fn main() {
    let technique_id = std::env::var("TECHNIQUE_ID").unwrap_or_default();
    let probe_id = std::env::var("PROBE_ID").unwrap_or_default();

    if technique_id.is_empty() {
        eprintln!("fatal: TECHNIQUE_ID environment variable is required");
        std::process::exit(1);
    }

    if probe_id.is_empty() {
        eprintln!("fatal: PROBE_ID environment variable is required");
        std::process::exit(1);
    }

    eprintln!(
        "sidereal-detection-probe: technique={} probe={}",
        technique_id, probe_id
    );

    // FIPS self-test (when compiled with --features fips).
    #[cfg(feature = "fips")]
    {
        // aws-lc-rs runs FIPS KAT self-tests at first use.
        // Force initialization to fail fast if KATs don't pass.
        let _ = aws_lc_rs::digest::digest(
            &aws_lc_rs::digest::SHA256,
            b"fips-kat-init",
        );
        eprintln!("FIPS: aws-lc-rs KAT self-test passed");
    }

    match catalog::execute(&technique_id) {
        Some(result) => {
            // Emit structured result to stdout for logging/debugging.
            // The controller does NOT read this — it queries the detection backend.
            match serde_json::to_string_pretty(&result) {
                Ok(json) => println!("{}", json),
                Err(e) => eprintln!("warning: failed to serialize result: {}", e),
            }

            eprintln!(
                "sidereal-detection-probe: technique={} pattern_emitted={} details={}",
                result.technique_id,
                result.pattern_emitted,
                result.details.len()
            );
        }
        None => {
            eprintln!(
                "fatal: unknown technique ID: {} (supported: {:?})",
                technique_id,
                catalog::list_techniques()
                    .iter()
                    .map(|(id, _)| *id)
                    .collect::<Vec<_>>()
            );
            std::process::exit(1);
        }
    }

    // Exit cleanly. The controller will independently verify detection.
    eprintln!("sidereal-detection-probe: complete");
}
