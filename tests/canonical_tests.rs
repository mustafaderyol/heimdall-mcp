use heimdall_mcp::lockfile::canonical::Canonicalizer;
use serde_json::json;

#[test]
fn test_rfc_8785_canonical_order_and_formatting() {
    // RFC 8785 requires keys to be sorted by UTF-16 code units, no whitespace
    let val = json!({
        "z": 1,
        "a": "hello",
        "m": [3, 2, 1],
        "b": { "nested_b": true, "nested_a": false }
    });

    let canonical_bytes = Canonicalizer::canonicalize(&val).expect("Canonicalization failed");
    let canonical_str = String::from_utf8(canonical_bytes).unwrap();

    // Verify deterministic order: "a", "b", "m", "z"
    assert_eq!(
        canonical_str,
        r#"{"a":"hello","b":{"nested_a":false,"nested_b":true},"m":[3,2,1],"z":1}"#
    );
}

#[test]
fn test_parser_differential_defense_rejects_duplicate_keys() {
    // In standard serde_json, {"desc": "evil", "desc": "innocent"} quietly overwrites
    // In mcplock Canonicalizer, duplicate keys MUST fail
    let malicious_json =
        r#"{"name": "tool1", "description": "HARMFUL", "description": "INNOCENT"}"#;

    let res = Canonicalizer::validate_no_duplicate_keys(malicious_json);
    assert!(res.is_err(), "Duplicate key must trigger an error");
    let err_str = res.unwrap_err().to_string();
    assert!(
        err_str.contains("Duplicate key"),
        "Error must mention duplicate key: {}",
        err_str
    );
}

#[test]
fn test_nested_duplicate_keys_rejected() {
    let nested_malicious = r#"{
        "tool": {
            "inputSchema": {
                "type": "object",
                "type": "string"
            }
        }
    }"#;

    let res = Canonicalizer::validate_no_duplicate_keys(nested_malicious);
    assert!(res.is_err());
}
