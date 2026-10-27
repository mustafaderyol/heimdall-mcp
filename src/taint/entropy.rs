use std::collections::HashSet;

pub struct EntropyAnalyzer;

impl EntropyAnalyzer {
    /// Computes Shannon entropy in bits per byte (0.0 to 8.0).
    #[inline]
    pub fn shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut counts = [0u32; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        let len = data.len() as f64;
        let mut entropy = 0.0;
        for &count in &counts {
            if count > 0 {
                let p = (count as f64) / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Checks if a string resembles a cryptographic credential, API key, or private key.
    pub fn is_credential_shape(token: &str) -> bool {
        let trimmed = token.trim();
        if trimmed.len() < 8 {
            return false;
        }

        // Known high-risk credential prefixes
        let prefixes = [
            "sk-", "sk_live_", "ghp_", "gho_", "ghs_", "ghu_", "glpat-",
            "AKIA", "ASIA", "xoxb-", "xoxp-", "sq0atp-", "ya29.", "AIza",
            "-----BEGIN", "bearer ", "token ", "eyJh", // JWT header '{"a'
        ];

        for &p in &prefixes {
            if trimmed.starts_with(p) {
                return true;
            }
        }

        // High entropy check for random tokens (hex, base64, url-safe)
        if trimmed.len() >= 16 {
            let entropy = Self::shannon_entropy(trimmed.as_bytes());
            if entropy >= 4.2 {
                return true;
            }
        }

        false
    }

    /// Set of common benign keys/words that should never be tainted
    pub fn stop_words() -> HashSet<&'static str> {
        [
            "type", "version", "id", "status", "name", "description",
            "properties", "required", "items", "title", "format",
            "localhost", "127.0.0.1", "true", "false", "null",
            "object", "string", "number", "integer", "boolean", "array",
            "application/json", "text/plain", "application/octet-stream",
            "utf-8", "success", "error", "message", "ok", "result",
            "tools", "params", "method", "jsonrpc", "content", "text",
        ]
        .iter()
        .copied()
        .collect()
    }

    /// Extracts leaf values from structured output (JSON / Key-Value / free text).
    /// Prevents false positive collapse from marking JSON keys like "type": "object".
    pub fn extract_candidate_secrets(raw_output: &str) -> Vec<String> {
        let stop_set = Self::stop_words();
        let mut candidates = HashSet::new();

        // 1. Try parsing as JSON first to extract pure leaf scalar values
        if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(raw_output) {
            Self::collect_json_leaves(&json_val, &stop_set, &mut candidates);
        } else {
            // 2. Not JSON: parse line-by-line and token-by-token
            for line in raw_output.lines() {
                let trimmed_line = line.trim();
                if trimmed_line.is_empty() {
                    continue;
                }

                // If line is KEY=VALUE (like .env or bash export)
                if let Some((_k, val)) = trimmed_line.split_once('=') {
                    let clean_val = val.trim_matches(|c| c == '"' || c == '\'' || c == ' ');
                    if clean_val.len() >= 8 && !stop_set.contains(clean_val.to_lowercase().as_str()) {
                        candidates.insert(clean_val.to_string());
                    }
                }

                // Split line into word tokens
                for token in trimmed_line.split(|c: char| {
                    c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | '{' | '}' | '[' | ']' | '(' | ')')
                }) {
                    let trimmed_token = token.trim();
                    if trimmed_token.len() < 8 {
                        continue;
                    }

                    if stop_set.contains(trimmed_token.to_lowercase().as_str()) {
                        continue;
                    }

                    // Candidate if it matches credential shape or has high entropy
                    if Self::is_credential_shape(trimmed_token) {
                        candidates.insert(trimmed_token.to_string());
                    } else if trimmed_token.len() >= 16 && Self::shannon_entropy(trimmed_token.as_bytes()) >= 4.2 {
                        candidates.insert(trimmed_token.to_string());
                    }
                }
            }
        }

        candidates.into_iter().collect()
    }

    fn collect_json_leaves(
        val: &serde_json::Value,
        stop_set: &HashSet<&'static str>,
        out: &mut HashSet<String>,
    ) {
        match val {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    // Do not taint keys, recurse into values
                    if k.to_lowercase().contains("secret")
                        || k.to_lowercase().contains("token")
                        || k.to_lowercase().contains("password")
                        || k.to_lowercase().contains("key")
                    {
                        if let Some(s) = v.as_str() {
                            if s.len() >= 8 {
                                out.insert(s.to_string());
                            }
                        }
                    }
                    Self::collect_json_leaves(v, stop_set, out);
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    Self::collect_json_leaves(item, stop_set, out);
                }
            }
            serde_json::Value::String(s) => {
                let trimmed = s.trim();
                if trimmed.len() >= 8 && !stop_set.contains(trimmed.to_lowercase().as_str()) {
                    if Self::is_credential_shape(trimmed)
                        || (trimmed.len() >= 12 && Self::shannon_entropy(trimmed.as_bytes()) >= 4.2)
                    {
                        out.insert(trimmed.to_string());
                    }
                }
            }
            _ => {}
        }
    }
}
