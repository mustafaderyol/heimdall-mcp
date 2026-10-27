use crate::error::{McpLockError, Result, SecurityViolation};
use crate::taint::difc::{ConfidentialityLabel, DifcLattice, IntegrityLabel};
use crate::taint::encoders::SecretEncoder;
use crate::taint::entropy::EntropyAnalyzer;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::RwLock;

pub struct SessionTaintEngine {
    raw_patterns: RwLock<Vec<Vec<u8>>>,
    pattern_set: RwLock<HashSet<Vec<u8>>>,
    automaton: RwLock<Option<AhoCorasick>>,
    taint_high_watermark: RwLock<bool>,
    strict_isolation_mode: bool,
    difc_lattice: RwLock<DifcLattice>,
}

impl SessionTaintEngine {
    pub fn new(strict_isolation_mode: bool, trusted_targets: &[String]) -> Self {
        Self {
            raw_patterns: RwLock::new(Vec::new()),
            pattern_set: RwLock::new(HashSet::new()),
            automaton: RwLock::new(None),
            taint_high_watermark: RwLock::new(false),
            strict_isolation_mode,
            difc_lattice: RwLock::new(DifcLattice::new(trusted_targets)),
        }
    }

    pub fn is_high_watermark(&self) -> bool {
        *self.taint_high_watermark.read().unwrap()
    }

    pub fn confidentiality(&self) -> ConfidentialityLabel {
        self.difc_lattice.read().unwrap().confidentiality()
    }

    pub fn integrity(&self) -> IntegrityLabel {
        self.difc_lattice.read().unwrap().integrity()
    }

    /// Records output from a SOURCE_UNTRUSTED tool (e.g. web scraper), dropping integrity
    pub fn mark_untrusted_output(&self, source_tool: &str) {
        self.difc_lattice
            .write()
            .unwrap()
            .mark_untrusted_read(source_tool);
    }

    /// Parses SOURCE_SENSITIVE output, extracts high-entropy secrets, generates 3-offset
    /// Base64 and Hex evasion variants, and atomically compiles the Aho-Corasick automaton.
    pub fn mark_sensitive_output(&self, raw_output: &str) {
        *self.taint_high_watermark.write().unwrap() = true;
        self.difc_lattice.write().unwrap().mark_sensitive_read();

        let candidate_strings = EntropyAnalyzer::extract_candidate_secrets(raw_output);
        let mut new_entries = Vec::new();

        for cand in candidate_strings {
            let cand_bytes = cand.as_bytes();
            let variants = SecretEncoder::generate_all_variants(cand_bytes);
            new_entries.extend(variants);
        }

        let mut set_guard = self.pattern_set.write().unwrap();
        let mut vec_guard = self.raw_patterns.write().unwrap();
        let mut added = false;

        for entry in new_entries {
            if entry.len() >= 8 && set_guard.insert(entry.clone()) {
                vec_guard.push(entry);
                added = true;
            }
        }

        if added {
            let ac = AhoCorasickBuilder::new()
                .match_kind(MatchKind::LeftmostFirst)
                .ascii_case_insensitive(true)
                .prefilter(true)
                .build(&*vec_guard)
                .expect("Failed to build Aho-Corasick automaton");

            *self.automaton.write().unwrap() = Some(ac);
        }
    }

    /// Inspects and extracts destination target (URL/domain/email) from tool call arguments
    pub fn extract_destination(args_json: &str) -> Option<String> {
        let Ok(parsed) = serde_json::from_str::<Value>(args_json) else {
            return None;
        };

        if let Some(obj) = parsed.as_object() {
            // Check common destination fields
            for key in [
                "url",
                "to",
                "recipient",
                "email",
                "host",
                "endpoint",
                "destination",
                "target",
            ] {
                if let Some(val) = obj.get(key).and_then(|v| v.as_str()) {
                    // If URL, extract host
                    if let Ok(parsed_url) = url::Url::parse(val) {
                        if let Some(host) = parsed_url.host_str() {
                            return Some(host.to_string());
                        }
                    }
                    return Some(val.to_string());
                }
            }
        }
        None
    }

    /// Verifies SINK_EXTERNAL arguments using O(n) Aho-Corasick automaton,
    /// normalized scanning, and DIFC lattice destination verification.
    pub fn verify_sink_arguments(&self, sink_tool: &str, args_json: &str) -> Result<()> {
        // 1. Destination / DIFC lattice verification
        let destination = Self::extract_destination(args_json);
        self.difc_lattice.read().unwrap().verify_sink_call(
            sink_tool,
            destination.as_deref(),
            self.strict_isolation_mode,
        )?;

        // 2. Strict isolation high-watermark check
        if self.strict_isolation_mode
            && *self.taint_high_watermark.read().unwrap()
            && destination.is_none()
        {
            return Err(McpLockError::Violation(
                SecurityViolation::StrictIsolationPolicyViolation {
                    sink_tool: sink_tool.to_string(),
                    reason: "Strict isolation active: Cannot call external sink without verifiable trusted destination".into(),
                },
            ));
        }

        let ac_guard = self.automaton.read().unwrap();
        let Some(ref ac) = *ac_guard else {
            return Ok(());
        };

        // 3. O(n) SIMD/DFA scan on raw argument bytes
        if let Some(mat) = ac.find(args_json.as_bytes()) {
            let matched_bytes = &args_json.as_bytes()[mat.start()..mat.end()];
            let sample = String::from_utf8_lossy(matched_bytes).to_string();
            return Err(McpLockError::Violation(
                SecurityViolation::TaintedDataExfiltrationBlocked {
                    matched_pattern_id: mat.pattern().as_usize(),
                    sample,
                    sink_tool: sink_tool.to_string(),
                },
            ));
        }

        // 4. Normalized scan: strip JSON escape characters and whitespaces
        let normalized: String = args_json
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '\\')
            .collect();

        if let Some(mat) = ac.find(normalized.as_bytes()) {
            let matched_bytes = &normalized.as_bytes()[mat.start()..mat.end()];
            let sample = String::from_utf8_lossy(matched_bytes).to_string();
            return Err(McpLockError::Violation(
                SecurityViolation::TaintedDataExfiltrationBlocked {
                    matched_pattern_id: mat.pattern().as_usize(),
                    sample,
                    sink_tool: sink_tool.to_string(),
                },
            ));
        }

        // 5. Opportunistic URL-decode scan for escaped payloads
        let decoded_str = url::form_urlencoded::parse(args_json.as_bytes())
            .into_owned()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        if !decoded_str.is_empty() {
            if let Some(mat) = ac.find(decoded_str.as_bytes()) {
                let matched_bytes = &decoded_str.as_bytes()[mat.start()..mat.end()];
                let sample = String::from_utf8_lossy(matched_bytes).to_string();
                return Err(McpLockError::Violation(
                    SecurityViolation::TaintedDataExfiltrationBlocked {
                        matched_pattern_id: mat.pattern().as_usize(),
                        sample,
                        sink_tool: sink_tool.to_string(),
                    },
                ));
            }
        }

        Ok(())
    }

    pub fn pattern_count(&self) -> usize {
        self.raw_patterns.read().unwrap().len()
    }
}
