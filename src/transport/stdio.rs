use crate::error::{McpLockError, Result, SecurityViolation};
use crate::lockfile::manifest::{Manifest, ToolClassification, ToolVerificationResult};
use crate::sanitizer::schema_strip::{SanitizeMode, SchemaSanitizer};
use crate::taint::tracker::SessionTaintEngine;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::process::Stdio;
use std::sync::Arc;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RugPullPolicy {
    /// Abort connection immediately on 1-bit schema discrepancy
    FailClosed,
    /// Apply Context Compiler & Schema Sanitizer to quarantine/prune the altered tools
    SanitizeAndQuarantine,
}

pub struct StdioProxy {
    manifest: Option<Manifest>,
    taint_engine: Arc<SessionTaintEngine>,
    rug_pull_policy: RugPullPolicy,
    sanitize_mode: SanitizeMode,
    pending_tool_calls: Arc<Mutex<HashMap<Value, String>>>, // Request ID -> Tool Name
}

impl StdioProxy {
    pub fn new(
        manifest: Option<Manifest>,
        taint_engine: Arc<SessionTaintEngine>,
        rug_pull_policy: RugPullPolicy,
        sanitize_mode: SanitizeMode,
    ) -> Self {
        Self {
            manifest,
            taint_engine,
            rug_pull_policy,
            sanitize_mode,
            pending_tool_calls: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Spawns the MCP server child process with environment variable isolation
    pub fn spawn_child(
        command: &str,
        args: &[String],
        allowed_envs: &[String],
    ) -> std::io::Result<Child> {
        let mut cmd = Command::new(command);
        cmd.args(args);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::inherit());

        // Environment Variable Isolation: Clear sensitive parent env vars
        // (AWS_*, GITHUB_*, OPENAI_*, SSH_*, etc.) unless explicitly allowed
        let allowed_set: HashSet<String> = allowed_envs.iter().cloned().collect();
        for (k, _v) in std::env::vars() {
            let upper = k.to_uppercase();
            if (upper.contains("SECRET")
                || upper.contains("KEY")
                || upper.contains("TOKEN")
                || upper.contains("PASSWORD")
                || upper.contains("AUTH")
                || upper.starts_with("AWS_")
                || upper.starts_with("GITHUB_"))
                && !allowed_set.contains(&k)
            {
                cmd.env_remove(&k);
            }
        }

        cmd.spawn()
    }

    /// Processes an incoming JSON-RPC message from Client (Agent/Host) to Server
    pub async fn handle_client_to_server(&self, raw_line: &str) -> Result<Option<String>> {
        let parsed: Value = match serde_json::from_str(raw_line) {
            Ok(v) => v,
            Err(_) => return Ok(Some(raw_line.to_string())), // Pass through non-JSON
        };

        let method = parsed.get("method").and_then(|v| v.as_str());
        let id = parsed.get("id").cloned();

        if let Some("tools/call") = method {
            if let Some(params) = parsed.get("params") {
                let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let args_val = params.get("arguments").unwrap_or(&Value::Null);
                let args_json = serde_json::to_string(args_val)?;

                // Save pending request ID for response taint tracking
                if let Some(req_id) = id.clone() {
                    self.pending_tool_calls
                        .lock()
                        .await
                        .insert(req_id, tool_name.to_string());
                }

                // Determine classification
                let classification = self.get_tool_classification(tool_name);

                // If calling an external sink, run taint engine verification
                if classification == ToolClassification::SinkExternal {
                    if let Err(e) = self
                        .taint_engine
                        .verify_sink_arguments(tool_name, &args_json)
                    {
                        warn!("mcp-lock FIREWALL BLOCKED tools/call: {}", e);
                        // Return JSON-RPC error response directly to client
                        let err_resp = json!({
                            "jsonrpc": "2.0",
                            "id": id.unwrap_or(Value::Null),
                            "error": {
                                "code": -32001,
                                "message": e.to_string(),
                                "data": {
                                    "blocked_by": "heimdall",
                                    "tool": tool_name
                                }
                            }
                        });
                        return Ok(Some(serde_json::to_string(&err_resp)?));
                    }
                }
            }
        }

        Ok(Some(serde_json::to_string(&parsed)?))
    }

    /// Processes an incoming JSON-RPC message from Server to Client (Agent/Host)
    pub async fn handle_server_to_client(&self, raw_line: &str) -> Result<Option<String>> {
        let mut parsed: Value = match serde_json::from_str(raw_line) {
            Ok(v) => v,
            Err(_) => return Ok(Some(raw_line.to_string())),
        };

        // Check if this is a response to tools/call
        if let Some(id) = parsed.get("id") {
            let pending_tool = self.pending_tool_calls.lock().await.remove(id);
            if let Some(tool_name) = pending_tool {
                let classification = self.get_tool_classification(&tool_name);
                if let Some(result) = parsed.get("result") {
                    let result_str = serde_json::to_string(result)?;

                    match classification {
                        ToolClassification::SourceSensitive => {
                            info!("Tainting sensitive output from tool '{}'", tool_name);
                            self.taint_engine.mark_sensitive_output(&result_str);
                        }
                        ToolClassification::SourceUntrusted => {
                            info!(
                                "Dropping session integrity from untrusted tool '{}'",
                                tool_name
                            );
                            self.taint_engine.mark_untrusted_output(&tool_name);
                        }
                        _ => {}
                    }
                }
            }
        }

        // Check if this is a tools/list response
        if let Some(result) = parsed.get_mut("result") {
            if let Some(tools_arr) = result.get_mut("tools").and_then(|v| v.as_array_mut()) {
                if let Some(ref manifest) = self.manifest {
                    let verification_results = manifest.verify_tools_list(tools_arr);
                    let mut has_rug_pull = false;

                    for r in &verification_results {
                        if let ToolVerificationResult::RugPull {
                            tool_name,
                            field,
                            expected,
                            actual,
                        } = r
                        {
                            has_rug_pull = true;
                            warn!(
                                "RUG PULL DETECTED: tool '{}', field '{}' mismatch. Expected: {}, Actual: {}",
                                tool_name, field, expected, actual
                            );
                        }
                    }

                    if has_rug_pull {
                        match self.rug_pull_policy {
                            RugPullPolicy::FailClosed => {
                                return Err(McpLockError::Violation(
                                    SecurityViolation::RugPullDetected {
                                        tool_name: "multiple".into(),
                                        field: "schema/description".into(),
                                        expected: "pinned manifest".into(),
                                        actual: "modified dynamically".into(),
                                    },
                                ));
                            }
                            RugPullPolicy::SanitizeAndQuarantine => {
                                info!("Applying Context Compiler & Schema Sanitizer to quarantine modified tools");
                                let known_tools: HashSet<String> =
                                    manifest.payload.tools.keys().cloned().collect();
                                let sanitizer =
                                    SchemaSanitizer::new(self.sanitize_mode, known_tools);
                                for tool in tools_arr.iter_mut() {
                                    sanitizer.sanitize_tool(tool);
                                }
                            }
                        }
                    } else {
                        // Apply context compiler to strip invisible zero-width chars and imperative triggers
                        let known_tools: HashSet<String> =
                            manifest.payload.tools.keys().cloned().collect();
                        let sanitizer = SchemaSanitizer::new(self.sanitize_mode, known_tools);
                        for tool in tools_arr.iter_mut() {
                            sanitizer.sanitize_tool(tool);
                        }
                    }
                }
            }
        }

        Ok(Some(serde_json::to_string(&parsed)?))
    }

    fn get_tool_classification(&self, tool_name: &str) -> ToolClassification {
        if let Some(ref m) = self.manifest {
            if let Some(t) = m.payload.tools.get(tool_name) {
                return t.classification;
            }
        }
        // Fallback heuristic classification
        let lower = tool_name.to_lowercase();
        if lower.contains("read")
            || lower.contains("file")
            || lower.contains("secret")
            || lower.contains("env")
        {
            ToolClassification::SourceSensitive
        } else if lower.contains("send")
            || lower.contains("post")
            || lower.contains("webhook")
            || lower.contains("mail")
        {
            ToolClassification::SinkExternal
        } else if lower.contains("fetch") || lower.contains("scrape") {
            ToolClassification::SourceUntrusted
        } else {
            ToolClassification::PureCompute
        }
    }
}
