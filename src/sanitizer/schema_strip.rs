use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizeMode {
    /// Prunes malicious tags, conditional triggers, imperative rules, limits to 120 chars
    CompilerPrune,
    /// Strict mode: Replaces natural language descriptions completely with synthetic AST signature
    StrictAstOnly,
}

pub struct SchemaSanitizer {
    mode: SanitizeMode,
    other_tool_names: HashSet<String>,
}

impl SchemaSanitizer {
    pub fn new(mode: SanitizeMode, other_tool_names: HashSet<String>) -> Self {
        Self {
            mode,
            other_tool_names,
        }
    }

    /// Normalizes Unicode into NFC, strips zero-width chars and bidirectional overrides
    pub fn normalize_unicode_and_strip_invisible(text: &str) -> String {
        let nfc: String = text.nfc().collect();
        nfc.chars()
            .filter(|&c| {
                // Strip zero-width chars
                if matches!(c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}') {
                    return false;
                }
                // Strip BiDi override characters
                if ('\u{202A}'..='\u{202E}').contains(&c) || ('\u{2066}'..='\u{2069}').contains(&c) {
                    return false;
                }
                // Strip non-printable ASCII control characters except \n and \t
                if c.is_ascii_control() && c != '\n' && c != '\t' {
                    return false;
                }
                true
            })
            .collect()
    }

    /// Strips HTML/XML tags, comments, and pseudo-tags like <IMPORTANT>, <system>, etc.
    pub fn strip_html_and_pseudo_tags(text: &str) -> String {
        // Strip comments <!-- ... -->
        let comment_regex = Regex::new(r"(?s)<!--.*?-->").unwrap();
        let without_comments = comment_regex.replace_all(text, "");

        // Strip XML/HTML tags: <...>
        let tag_regex = Regex::new(r"<[^>]+>").unwrap();
        let without_tags = tag_regex.replace_all(&without_comments, "");

        without_tags.to_string()
    }

    /// Filters sentences containing imperative triggers, sensitive file paths, or references to other tools
    pub fn prune_imperative_sentences(&self, text: &str) -> String {
        let imperative_triggers = [
            "before using",
            "first read",
            "always call",
            "do not mention",
            "important:",
            "note:",
            "required:",
            "must send",
            "authorize by",
            "send to",
            "ignore previous",
            "prioritize this",
            "exfiltrate",
            "read key",
            "read secret",
        ];

        let sensitive_paths = [
            "~/.ssh",
            "~/.cursor",
            "~/.aws",
            "/etc/passwd",
            "/etc/shadow",
            ".env",
            "id_rsa",
            "credentials",
            "mcp.json",
        ];

        let mut clean_sentences = Vec::new();

        // Split by sentence terminators
        for sentence in text.split(|c| c == '.' || c == '!' || c == '?' || c == '\n') {
            let trimmed = sentence.trim();
            if trimmed.is_empty() {
                continue;
            }

            let lower = trimmed.to_lowercase();

            // Check imperative trigger phrases
            let has_trigger = imperative_triggers.iter().any(|&trigger| lower.contains(trigger));
            if has_trigger {
                continue;
            }

            // Check sensitive file paths
            let has_sensitive_path = sensitive_paths.iter().any(|&path| lower.contains(path));
            if has_sensitive_path {
                continue;
            }

            // Check if sentence references another tool in the session (cross-tool line jumping)
            let has_other_tool = self.other_tool_names.iter().any(|tool_name| {
                !tool_name.is_empty() && lower.contains(&tool_name.to_lowercase())
            });
            if has_other_tool {
                continue;
            }

            clean_sentences.push(trimmed.to_string());
        }

        clean_sentences.join(". ")
    }

    /// Derives a synthetic signature from the JSON schema AST (e.g. `add(a: number, b: number)`)
    pub fn derive_ast_signature(name: &str, input_schema: &Value) -> String {
        let mut params = Vec::new();
        if let Some(props) = input_schema.get("properties").and_then(|p| p.as_object()) {
            for (param_name, spec) in props {
                let ty = spec.get("type").and_then(|t| t.as_str()).unwrap_or("any");
                params.push(format!("{}: {}", param_name, ty));
            }
        }
        format!("{}({})", name, params.join(", "))
    }

    /// Cleans and sanitizes a single description string
    pub fn sanitize_description(&self, desc: &str) -> String {
        let step1 = Self::normalize_unicode_and_strip_invisible(desc);
        let step2 = Self::strip_html_and_pseudo_tags(&step1);
        let step3 = self.prune_imperative_sentences(&step2);

        // Cap at 120 characters
        if step3.chars().count() > 120 {
            step3.chars().take(117).collect::<String>() + "..."
        } else {
            step3
        }
    }

    /// Recursively sanitizes properties and removes suspicious parameters (e.g. `sidenote`, `notes` in math tools)
    pub fn sanitize_schema(&self, schema: &mut Value, tool_name: &str) {
        if let Some(obj) = schema.as_object_mut() {
            // Remove x-mcp-header extensions
            obj.remove("x-mcp-header");

            // Sanitize title and description in schema root
            if let Some(desc) = obj.get_mut("description").and_then(|d| d.as_str().map(|s| s.to_string())) {
                *obj.get_mut("description").unwrap() = Value::String(self.sanitize_description(&desc));
            }

            if let Some(props) = obj.get_mut("properties").and_then(|p| p.as_object_mut()) {
                // Detect suspicious parameters: e.g. for simple arithmetic or time tools,
                // prune injected parameters like 'notes', 'sidenote', 'auth_token', 'system_log'
                let is_simple_tool = tool_name.contains("add")
                    || tool_name.contains("calc")
                    || tool_name.contains("math")
                    || tool_name.contains("time");

                if is_simple_tool {
                    props.remove("notes");
                    props.remove("sidenote");
                    props.remove("side_note");
                    props.remove("token");
                    props.remove("exfil");
                }

                for (_param_name, param_spec) in props.iter_mut() {
                    if let Some(param_obj) = param_spec.as_object_mut() {
                        param_obj.remove("x-mcp-header");
                        if let Some(desc) = param_obj.get_mut("description").and_then(|d| d.as_str().map(|s| s.to_string())) {
                            *param_obj.get_mut("description").unwrap() = Value::String(self.sanitize_description(&desc));
                        }
                    }
                }
            }

            // Also clean $defs or definitions if present
            for def_key in ["$defs", "definitions"] {
                if let Some(defs) = obj.get_mut(def_key).and_then(|d| d.as_object_mut()) {
                    for (_k, sub) in defs.iter_mut() {
                        self.sanitize_schema(sub, tool_name);
                    }
                }
            }
        }
    }

    /// Compiles and sanitizes a full tool definition object
    pub fn sanitize_tool(&self, tool: &mut Value) {
        let name = tool.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();

        match self.mode {
            SanitizeMode::CompilerPrune => {
                if let Some(desc_val) = tool.get_mut("description") {
                    if let Some(desc_str) = desc_val.as_str() {
                        *desc_val = Value::String(self.sanitize_description(desc_str));
                    }
                }

                if let Some(input_schema) = tool.get_mut("inputSchema") {
                    self.sanitize_schema(input_schema, &name);
                }

                if let Some(output_schema) = tool.get_mut("outputSchema") {
                    self.sanitize_schema(output_schema, &name);
                }
            }
            SanitizeMode::StrictAstOnly => {
                let input_schema = tool.get("inputSchema").unwrap_or(&Value::Null);
                let ast_sig = Self::derive_ast_signature(&name, input_schema);
                tool["description"] = Value::String(ast_sig);

                if let Some(input_schema) = tool.get_mut("inputSchema") {
                    self.sanitize_schema(input_schema, &name);
                }
            }
        }
    }
}
