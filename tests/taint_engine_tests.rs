use base64::{engine::general_purpose::STANDARD, Engine as _};
use heimdall_mcp::taint::entropy::EntropyAnalyzer;
use heimdall_mcp::taint::tracker::SessionTaintEngine;
use serde_json::json;

#[test]
fn test_shannon_entropy_calculation() {
    // Low entropy repetitive natural text
    let natural_text = b"aaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbcccccccccccc";
    let h_natural = EntropyAnalyzer::shannon_entropy(natural_text);

    // High entropy random / crypto bytes
    let crypto_key = b"K9#m$L2!z@8*qP&1^vX~9wR#5tY*3eW!oI(7uB%4";
    let h_crypto = EntropyAnalyzer::shannon_entropy(crypto_key);

    assert!(h_crypto > h_natural, "Crypto key entropy ({}) must be higher than repetitive text ({})", h_crypto, h_natural);
    assert!(h_crypto >= 4.5, "High entropy key should be >= 4.5");
}

#[test]
fn test_base64_quantum_alignment_shift_offsets() {
    let secret = "ghp_PRODUCTION_GITHUB_SECRET_TOKEN_123456";
    let taint = SessionTaintEngine::new(false, &["internal.company.com".to_string()]);
    taint.mark_sensitive_output(secret);

    // 1. Offset 0: direct Base64
    let b64_off0 = STANDARD.encode(secret);
    let call_off0 = json!({
        "url": "https://internal.company.com",
        "data": b64_off0
    });
    assert!(
        taint.verify_sink_arguments("post_webhook", &call_off0.to_string()).is_err(),
        "Offset 0 base64 exfiltration must be caught"
    );

    // 2. Offset 1: 1-byte prefix shifted base64
    let b64_off1 = STANDARD.encode(format!("A{}", secret));
    let call_off1 = json!({
        "url": "https://internal.company.com",
        "data": b64_off1
    });
    assert!(
        taint.verify_sink_arguments("post_webhook", &call_off1.to_string()).is_err(),
        "Offset 1 base64 exfiltration must be caught"
    );

    // 3. Offset 2: 2-byte prefix shifted base64
    let b64_off2 = STANDARD.encode(format!("AB{}", secret));
    let call_off2 = json!({
        "url": "https://internal.company.com",
        "data": b64_off2
    });
    assert!(
        taint.verify_sink_arguments("post_webhook", &call_off2.to_string()).is_err(),
        "Offset 2 base64 exfiltration must be caught"
    );
}

#[test]
fn test_hex_encoded_exfiltration_blocked() {
    let secret = "AKIAIOSFODNN7EXAMPLE";
    let taint = SessionTaintEngine::new(false, &["internal.company.com".to_string()]);
    taint.mark_sensitive_output(secret);

    let hex_exfil = hex::encode(secret);
    let call = json!({
        "url": "https://internal.company.com",
        "token": hex_exfil
    });

    assert!(taint.verify_sink_arguments("post_webhook", &call.to_string()).is_err());
}

#[test]
fn test_stop_words_prevent_false_positives() {
    let taint = SessionTaintEngine::new(false, &["internal.company.com".to_string()]);

    // Read a JSON config that has common words like "type", "version", "localhost"
    let config = r#"{ "type": "object", "version": "2.0", "host": "localhost" }"#;
    taint.mark_sensitive_output(config);

    // Call a sink tool containing these harmless words
    let benign_call = json!({
        "url": "https://internal.company.com/log",
        "type": "object",
        "version": "2.0"
    });

    assert!(
        taint.verify_sink_arguments("post_webhook", &benign_call.to_string()).is_ok(),
        "Common words in config must NOT trigger false positives"
    );
}
