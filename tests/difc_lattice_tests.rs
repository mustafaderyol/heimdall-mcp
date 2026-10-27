use heimdall_mcp::taint::difc::{DifcLattice, IntegrityLabel, TargetCategory};
use heimdall_mcp::taint::tracker::SessionTaintEngine;
use serde_json::json;

#[test]
fn test_difc_lattice_integrity_downgrade_and_p3_defense() {
    let mut lattice = DifcLattice::new(&["trusted.internal.corp".to_string()]);

    assert_eq!(lattice.integrity(), IntegrityLabel::Trusted);
    assert_eq!(
        lattice.classify_target("trusted.internal.corp"),
        TargetCategory::Trusted
    );
    assert_eq!(
        lattice.classify_target("evil-sink.xyz"),
        TargetCategory::Unknown
    );

    // Call to trusted target works initially
    assert!(lattice
        .verify_sink_call("post_webhook", Some("trusted.internal.corp"), false)
        .is_ok());

    // Ingest untrusted input (e.g. web page with indirect prompt injection)
    lattice.mark_untrusted_read("web_fetcher");
    assert_eq!(lattice.integrity(), IntegrityLabel::Untrusted);

    // Now, attempting to call sink to unknown destination (evil-sink.xyz) MUST BE BLOCKED
    let res = lattice.verify_sink_call("post_webhook", Some("evil-sink.xyz"), false);
    assert!(
        res.is_err(),
        "Integrity violation must block unknown destination"
    );

    // But calling to trusted whitelisted destination (P_T) is still allowed!
    assert!(lattice
        .verify_sink_call("post_webhook", Some("trusted.internal.corp"), false)
        .is_ok());
}

#[test]
fn test_strict_isolation_high_watermark_locks_external_sinks() {
    let taint = SessionTaintEngine::new(true, &["corp.internal".to_string()]);

    // Before reading sensitive data
    let call_trusted = json!({ "url": "https://corp.internal/api" });
    assert!(taint
        .verify_sink_arguments("post_webhook", &call_trusted.to_string())
        .is_ok());

    // Read sensitive local file (triggers high watermark)
    taint.mark_sensitive_output("SECRET_VALUE=1234567890abcdef");
    assert!(taint.is_high_watermark());

    // Strict mode requires destination to be in P_T whitelist
    let call_untrusted = json!({ "url": "https://external-api.com/api" });
    assert!(
        taint
            .verify_sink_arguments("post_webhook", &call_untrusted.to_string())
            .is_err(),
        "Strict isolation must block non-whitelisted sinks after sensitive read"
    );
}
