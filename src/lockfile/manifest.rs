use crate::error::{McpLockError, Result, SecurityViolation};
use crate::lockfile::canonical::Canonicalizer;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolClassification {
    /// Reads sensitive local resources (files, env, database, ssh keys)
    SourceSensitive,
    /// Writes or exfiltrates to external network / destinations (HTTP, email, webhook)
    SinkExternal,
    /// Fetches untrusted external input (web scraping, PR titles, issues)
    SourceUntrusted,
    /// Pure local calculation without side-effects (math, string formatting)
    PureCompute,
}

impl Default for ToolClassification {
    fn default() -> Self {
        ToolClassification::PureCompute
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedProcess {
    pub command: String,
    pub args: Vec<String>,
    pub env_keys: Vec<String>,
    pub process_hash: String,
}

impl LockedProcess {
    pub fn new(command: String, args: Vec<String>, env_keys: Vec<String>) -> Result<Self> {
        let canonical_rep = json!({
            "command": &command,
            "args": &args,
            "env_keys": &env_keys,
        });
        let process_hash = Canonicalizer::canonical_sha256(&canonical_rep)?;
        Ok(Self {
            command,
            args,
            env_keys,
            process_hash,
        })
    }

    pub fn verify(&self, command: &str, args: &[String], env_keys: &[String]) -> Result<()> {
        let canonical_rep = json!({
            "command": command,
            "args": args,
            "env_keys": env_keys,
        });
        let actual_hash = Canonicalizer::canonical_sha256(&canonical_rep)?;
        if self.process_hash != actual_hash {
            return Err(McpLockError::Violation(SecurityViolation::ProcessTamperingDetected {
                server_id: "unknown".to_string(),
                reason: format!(
                    "CVE-2025-54136 Defense: Process spawn vector mismatch. Locked hash: {}, Current hash: {}",
                    self.process_hash, actual_hash
                ),
            }));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedTool {
    pub name: String,
    pub description: String,
    pub input_schema_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Value>,
    pub classification: ToolClassification,
    pub composite_digest: String,
}

impl LockedTool {
    pub fn compute_composite_digest(
        name: &str,
        description: &str,
        input_schema_hash: &str,
        output_schema_hash: Option<&str>,
        annotations: Option<&Value>,
    ) -> Result<String> {
        let rep = json!({
            "name": name,
            "description": description,
            "input_schema_hash": input_schema_hash,
            "output_schema_hash": output_schema_hash,
            "annotations": annotations,
        });
        Canonicalizer::canonical_sha256(&rep)
    }

    pub fn from_tool_definition(
        tool: &Value,
        classification: Option<ToolClassification>,
    ) -> Result<Self> {
        let name = tool
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpLockError::InvalidConfiguration("Tool definition missing 'name'".into()))?
            .to_string();

        let description = tool
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let input_schema = tool.get("inputSchema").unwrap_or(&Value::Null);
        let input_schema_hash = Canonicalizer::canonical_sha256(input_schema)?;

        let output_schema_hash = match tool.get("outputSchema") {
            Some(v) if !v.is_null() => Some(Canonicalizer::canonical_sha256(v)?),
            _ => None,
        };

        let annotations = tool.get("annotations").cloned();

        let derived_class = classification.unwrap_or_else(|| Self::heuristic_classify(&name, &description, tool));

        let composite_digest = Self::compute_composite_digest(
            &name,
            &description,
            &input_schema_hash,
            output_schema_hash.as_deref(),
            annotations.as_ref(),
        )?;

        Ok(Self {
            name,
            description,
            input_schema_hash,
            output_schema_hash,
            annotations,
            classification: derived_class,
            composite_digest,
        })
    }

    /// Conservative heuristic classifier when no explicit classification is provided
    pub fn heuristic_classify(name: &str, description: &str, tool: &Value) -> ToolClassification {
        let lower_name = name.to_lowercase();
        let lower_desc = description.to_lowercase();

        // 1. Check annotations if present
        if let Some(ann) = tool.get("annotations") {
            if let Some(open_world) = ann.get("openWorldHint").and_then(|v| v.as_bool()) {
                if open_world {
                    return ToolClassification::SinkExternal;
                }
            }
        }

        // 2. Sensitive source patterns (filesystem, db, secrets, env)
        if lower_name.contains("read")
            || lower_name.contains("file")
            || lower_name.contains("get_secret")
            || lower_name.contains("sql")
            || lower_name.contains("query")
            || lower_name.contains("env")
            || lower_name.contains("ssh")
            || lower_desc.contains("read file")
            || lower_desc.contains("database query")
            || lower_desc.contains("credentials")
        {
            return ToolClassification::SourceSensitive;
        }

        // 3. Untrusted source patterns (web scraping, external fetch, email receive)
        if lower_name.contains("fetch")
            || lower_name.contains("scrape")
            || lower_name.contains("curl")
            || lower_name.contains("pull_request")
            || lower_desc.contains("fetch web")
            || lower_desc.contains("untrusted content")
        {
            return ToolClassification::SourceUntrusted;
        }

        // 4. External sink patterns (post, send, webhook, email, http request)
        if lower_name.contains("send")
            || lower_name.contains("post")
            || lower_name.contains("upload")
            || lower_name.contains("webhook")
            || lower_name.contains("mail")
            || lower_name.contains("slack")
            || lower_desc.contains("send email")
            || lower_desc.contains("post request")
            || lower_desc.contains("exfiltrate")
        {
            return ToolClassification::SinkExternal;
        }

        ToolClassification::PureCompute
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestPayload {
    pub server_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<LockedProcess>,
    pub tools: BTreeMap<String, LockedTool>,
    pub whitelist_targets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: String,
    pub generated_at: String,
    pub public_key: String,
    pub signature: String,
    pub payload: ManifestPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolVerificationResult {
    Verified,
    RugPull {
        tool_name: String,
        field: String,
        expected: String,
        actual: String,
    },
    UnrecognizedTool {
        tool_name: String,
    },
}

impl Manifest {
    pub fn new(
        server_id: String,
        process: Option<LockedProcess>,
        tools: Vec<LockedTool>,
        whitelist_targets: Vec<String>,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        let mut tool_map = BTreeMap::new();
        for t in tools {
            tool_map.insert(t.name.clone(), t);
        }

        let payload = ManifestPayload {
            server_id,
            process,
            tools: tool_map,
            whitelist_targets,
        };

        let payload_val = serde_json::to_value(&payload)?;
        let canonical_payload = Canonicalizer::canonicalize(&payload_val)?;

        let signature = signing_key.sign(&canonical_payload);
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        Ok(Self {
            version: "1.0.0".to_string(),
            generated_at: "2026-10-28T00:00:00Z".to_string(),
            public_key: hex::encode(verifying_key.as_bytes()),
            signature: hex::encode(signature.to_bytes()),
            payload,
        })
    }

    /// Verifies the cryptographic Ed25519 signature over the manifest payload.
    pub fn verify_signature(&self) -> Result<()> {
        let pubkey_bytes = hex::decode(&self.public_key)
            .map_err(|e| McpLockError::InvalidSignature(format!("Invalid public key hex: {}", e)))?;
        let pubkey_arr: [u8; 32] = pubkey_bytes
            .try_into()
            .map_err(|_| McpLockError::InvalidSignature("Public key must be 32 bytes".into()))?;

        let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)
            .map_err(|e| McpLockError::InvalidSignature(format!("Ed25519 key error: {}", e)))?;

        let sig_bytes = hex::decode(&self.signature)
            .map_err(|e| McpLockError::InvalidSignature(format!("Invalid signature hex: {}", e)))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| McpLockError::InvalidSignature("Signature must be 64 bytes".into()))?;

        let signature = Signature::from_bytes(&sig_arr);

        let payload_val = serde_json::to_value(&self.payload)?;
        let canonical_payload = Canonicalizer::canonicalize(&payload_val)?;

        verifying_key
            .verify(&canonical_payload, &signature)
            .map_err(|e| McpLockError::InvalidSignature(format!("Verification failed: {}", e)))?;

        Ok(())
    }

    /// Verifies incoming `tools/list` response from MCP server against locked tools.
    /// Detects dynamic Rug Pulls (1-bit modifications to descriptions, schemas, or annotations).
    pub fn verify_tools_list(&self, incoming_tools: &[Value]) -> Vec<ToolVerificationResult> {
        let mut results = Vec::new();
        let mut seen_incoming_names = HashSet::new();

        for tool_val in incoming_tools {
            let Some(name) = tool_val.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            seen_incoming_names.insert(name.to_string());

            let Some(locked) = self.payload.tools.get(name) else {
                results.push(ToolVerificationResult::UnrecognizedTool {
                    tool_name: name.to_string(),
                });
                continue;
            };

            // Check description
            let curr_desc = tool_val.get("description").and_then(|v| v.as_str()).unwrap_or("");
            if curr_desc != locked.description {
                results.push(ToolVerificationResult::RugPull {
                    tool_name: name.to_string(),
                    field: "description".to_string(),
                    expected: locked.description.clone(),
                    actual: curr_desc.to_string(),
                });
                continue;
            }

            // Check inputSchema hash
            let curr_input = tool_val.get("inputSchema").unwrap_or(&Value::Null);
            let curr_input_hash = Canonicalizer::canonical_sha256(curr_input).unwrap_or_default();
            if curr_input_hash != locked.input_schema_hash {
                results.push(ToolVerificationResult::RugPull {
                    tool_name: name.to_string(),
                    field: "inputSchema".to_string(),
                    expected: locked.input_schema_hash.clone(),
                    actual: curr_input_hash,
                });
                continue;
            }

            // Check composite digest
            let curr_output_hash = match tool_val.get("outputSchema") {
                Some(v) if !v.is_null() => Canonicalizer::canonical_sha256(v).ok(),
                _ => None,
            };
            let curr_annotations = tool_val.get("annotations");

            let composite = LockedTool::compute_composite_digest(
                name,
                curr_desc,
                &curr_input_hash,
                curr_output_hash.as_deref(),
                curr_annotations,
            ).unwrap_or_default();

            if composite != locked.composite_digest {
                results.push(ToolVerificationResult::RugPull {
                    tool_name: name.to_string(),
                    field: "composite_digest".to_string(),
                    expected: locked.composite_digest.clone(),
                    actual: composite,
                });
                continue;
            }

            results.push(ToolVerificationResult::Verified);
        }

        results
    }

    /// Verifies process execution arguments against CVE-2025-54136
    pub fn verify_process(&self, command: &str, args: &[String], env_keys: &[String]) -> Result<()> {
        if let Some(ref proc) = self.payload.process {
            proc.verify(command, args, env_keys)?;
        }
        Ok(())
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_ref = path.as_ref();
        if !path_ref.exists() {
            return Err(McpLockError::LockfileNotFound(path_ref.to_string_lossy().into()));
        }
        let raw = std::fs::read_to_string(path_ref)?;
        Canonicalizer::validate_no_duplicate_keys(&raw)?;
        let manifest: Manifest = serde_json::from_str(&raw)?;
        manifest.verify_signature()?;
        Ok(manifest)
    }

    pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }
}
