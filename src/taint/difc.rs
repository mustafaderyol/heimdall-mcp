use crate::error::{McpLockError, Result, SecurityViolation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ConfidentialityLabel {
    /// Public information, can be freely communicated
    Public,
    /// Sensitive secret information (source: filesystem, env, db, ssh)
    Sensitive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IntegrityLabel {
    /// Tainted by untrusted input (web scraping, PR titles, issue comments)
    Untrusted,
    /// Trusted system or user instructions
    Trusted,
}

#[derive(Debug, Clone)]
pub struct DifcLattice {
    confidentiality: ConfidentialityLabel,
    integrity: IntegrityLabel,
    trusted_targets: HashSet<String>,   // P_T
    untrusted_targets: HashSet<String>, // P_U
    last_untrusted_source: Option<String>,
}

impl DifcLattice {
    pub fn new(trusted_targets: &[String]) -> Self {
        let p_t: HashSet<String> = trusted_targets.iter().map(|s| s.to_lowercase()).collect();
        Self {
            confidentiality: ConfidentialityLabel::Public,
            integrity: IntegrityLabel::Trusted,
            trusted_targets: p_t,
            untrusted_targets: HashSet::new(),
            last_untrusted_source: None,
        }
    }

    pub fn confidentiality(&self) -> ConfidentialityLabel {
        self.confidentiality
    }

    pub fn integrity(&self) -> IntegrityLabel {
        self.integrity
    }

    /// Called when SOURCE_SENSITIVE tool produces output
    pub fn mark_sensitive_read(&mut self) {
        self.confidentiality = ConfidentialityLabel::Sensitive;
    }

    /// Called when SOURCE_UNTRUSTED tool produces output
    pub fn mark_untrusted_read(&mut self, source_tool: &str) {
        self.integrity = IntegrityLabel::Untrusted;
        self.last_untrusted_source = Some(source_tool.to_string());
    }

    /// Classifies an external target into P_T, P_U, or P_?
    pub fn classify_target(&self, target: &str) -> TargetCategory {
        let clean = target.trim().to_lowercase();
        if self.untrusted_targets.contains(&clean) {
            TargetCategory::Untrusted
        } else if self.trusted_targets.is_empty() {
            TargetCategory::Unknown
        } else if self.trusted_targets.iter().any(|t| clean == *t || clean.ends_with(&format!(".{}", t)) || clean.contains(t)) {
            TargetCategory::Trusted
        } else {
            TargetCategory::Unknown
        }
    }

    /// Enforces DIFC policy when a SINK_EXTERNAL tool is called
    pub fn verify_sink_call(
        &self,
        sink_tool: &str,
        destination_target: Option<&str>,
        strict_isolation: bool,
    ) -> Result<()> {
        let dest = destination_target.unwrap_or("unknown_destination");
        let category = self.classify_target(dest);

        // 1. Strict Isolation check: If high watermark sensitive data is read,
        // sink call is blocked unless target is strictly in P_T
        if strict_isolation && self.confidentiality == ConfidentialityLabel::Sensitive {
            if category != TargetCategory::Trusted {
                return Err(McpLockError::Violation(
                    SecurityViolation::StrictIsolationPolicyViolation {
                        sink_tool: sink_tool.to_string(),
                        reason: format!(
                            "High-watermark taint active. External sink call to '{}' rejected because target is not in P_T whitelist.",
                            dest
                        ),
                    },
                ));
            }
        }

        // 2. Integrity Lattice Check: If session integrity is dropped to UNTRUSTED
        // by untrusted inputs (e.g. web scraping / PR comments),
        // SINK_EXTERNAL to unknown (P_?) or untrusted (P_U) is blocked.
        // This stops P3 Parameter Manipulation attacks!
        if self.integrity == IntegrityLabel::Untrusted {
            if category != TargetCategory::Trusted {
                return Err(McpLockError::Violation(
                    SecurityViolation::IntegrityPolicyViolation {
                        source_untrusted: self.last_untrusted_source.clone().unwrap_or_else(|| "untrusted_input".into()),
                        target_sink: sink_tool.to_string(),
                        destination: dest.to_string(),
                        reason: "Integrity dropped to UNTRUSTED. Calling external sink with non-whitelisted target is blocked by DIFC lattice.".to_string(),
                    },
                ));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetCategory {
    /// Whitelisted destination (P_T)
    Trusted,
    /// Known untrusted destination (P_U)
    Untrusted,
    /// Unclassified destination (P_?)
    Unknown,
}
