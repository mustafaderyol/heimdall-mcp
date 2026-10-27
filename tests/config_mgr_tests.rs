use heimdall_mcp::config_mgr::ConfigManager;
use serde_json::json;
use std::fs;
use tempfile::NamedTempFile;

#[test]
fn test_wrap_and_unwrap_roundtrip() {
    let initial_config = json!({
        "mcpServers": {
            "test_server": {
                "command": "node",
                "args": ["server.js"]
            }
        }
    });

    let temp = NamedTempFile::new().unwrap();
    let path = temp.path().to_path_buf();
    fs::write(
        &path,
        serde_json::to_string_pretty(&initial_config).unwrap(),
    )
    .unwrap();

    // 1. Audit before wrap: Should be vulnerable (Grade F / C)
    let audit_before = ConfigManager::audit_config(&path).unwrap();
    assert!(!audit_before.servers[0].is_protected);

    // 2. Wrap config
    let (wrapped_count, backup) = ConfigManager::wrap_config(&path, Some("heimdall")).unwrap();
    assert_eq!(wrapped_count, 1);
    assert!(backup.exists());

    // 3. Verify wrapped contents
    let wrapped_raw = fs::read_to_string(&path).unwrap();
    let wrapped_json: serde_json::Value = serde_json::from_str(&wrapped_raw).unwrap();
    let s = &wrapped_json["mcpServers"]["test_server"];
    assert_eq!(s["command"], "heimdall");
    let args = s["args"].as_array().unwrap();
    assert_eq!(args[0], "proxy");

    // 4. Audit after wrap: Should be protected
    let audit_after = ConfigManager::audit_config(&path).unwrap();
    assert!(audit_after.servers[0].is_protected);

    // 5. Unwrap / restore
    let restored_from = ConfigManager::unwrap_config(&path).unwrap();
    assert_eq!(restored_from, backup);

    let restored_raw = fs::read_to_string(&path).unwrap();
    let restored_json: serde_json::Value = serde_json::from_str(&restored_raw).unwrap();
    assert_eq!(
        restored_json["mcpServers"]["test_server"]["command"],
        "node"
    );
}
