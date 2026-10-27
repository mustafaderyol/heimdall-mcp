use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityViolation {
    TaintedDataExfiltrationBlocked {
        matched_pattern_id: usize,
        sample: String,
        sink_tool: String,
    },
    StrictIsolationPolicyViolation {
        sink_tool: String,
        reason: String,
    },
    IntegrityPolicyViolation {
        source_untrusted: String,
        target_sink: String,
        destination: String,
        reason: String,
    },
    RugPullDetected {
        tool_name: String,
        field: String,
        expected: String,
        actual: String,
    },
    ProcessTamperingDetected {
        server_id: String,
        reason: String,
    },
}

impl fmt::Display for SecurityViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityViolation::TaintedDataExfiltrationBlocked {
                matched_pattern_id,
                sample,
                sink_tool,
            } => write!(
                f,
                "SECURITY BLOCK: Exfiltration attempt blocked on sink '{}'. Matched pattern #{}: '{}'",
                sink_tool, matched_pattern_id, sample
            ),
            SecurityViolation::StrictIsolationPolicyViolation { sink_tool, reason } => write!(
                f,
                "SECURITY BLOCK: Strict isolation violation on sink '{}': {}",
                sink_tool, reason
            ),
            SecurityViolation::IntegrityPolicyViolation {
                source_untrusted,
                target_sink,
                destination,
                reason,
            } => write!(
                f,
                "SECURITY BLOCK: DIFC Integrity violation from untrusted source '{}' to sink '{}' destination '{}': {}",
                source_untrusted, target_sink, destination, reason
            ),
            SecurityViolation::RugPullDetected {
                tool_name,
                field,
                expected,
                actual,
            } => write!(
                f,
                "SECURITY BLOCK: Rug Pull detected on tool '{}'. Field '{}' digest mismatch. Expected: {}, Actual: {}",
                tool_name, field, expected, actual
            ),
            SecurityViolation::ProcessTamperingDetected { server_id, reason } => write!(
                f,
                "SECURITY BLOCK: Process spawn tampering detected for server '{}': {}",
                server_id, reason
            ),
        }
    }
}

impl std::error::Error for SecurityViolation {}

#[derive(Debug)]
pub enum HeimdallError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Canonicalization(String),
    DuplicateKey(String),
    LockfileNotFound(String),
    InvalidSignature(String),
    DigestMismatch {
        target: String,
        expected: String,
        actual: String,
    },
    Violation(SecurityViolation),
    InvalidConfiguration(String),
    Transport(String),
}

pub type McpLockError = HeimdallError;

impl fmt::Display for HeimdallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeimdallError::Io(e) => write!(f, "IO error: {}", e),
            HeimdallError::Json(e) => write!(f, "JSON error: {}", e),
            HeimdallError::Canonicalization(msg) => {
                write!(f, "RFC 8785 Canonicalization error: {}", msg)
            }
            HeimdallError::DuplicateKey(k) => write!(
                f,
                "Parser differential defense: Duplicate key detected in JSON: '{}'",
                k
            ),
            HeimdallError::LockfileNotFound(path) => {
                write!(f, "heimdall-lock.json not found at: {}", path)
            }
            HeimdallError::InvalidSignature(msg) => write!(f, "Ed25519 signature invalid: {}", msg),
            HeimdallError::DigestMismatch {
                target,
                expected,
                actual,
            } => write!(
                f,
                "Digest mismatch for '{}'. Expected: {}, Actual: {}",
                target, expected, actual
            ),
            HeimdallError::Violation(v) => write!(f, "{}", v),
            HeimdallError::InvalidConfiguration(msg) => write!(f, "Configuration error: {}", msg),
            HeimdallError::Transport(msg) => write!(f, "Transport error: {}", msg),
        }
    }
}

impl std::error::Error for HeimdallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HeimdallError::Io(e) => Some(e),
            HeimdallError::Json(e) => Some(e),
            HeimdallError::Violation(v) => Some(v),
            _ => None,
        }
    }
}

impl From<std::io::Error> for HeimdallError {
    fn from(e: std::io::Error) -> Self {
        HeimdallError::Io(e)
    }
}

impl From<serde_json::Error> for HeimdallError {
    fn from(e: serde_json::Error) -> Self {
        HeimdallError::Json(e)
    }
}

impl From<SecurityViolation> for HeimdallError {
    fn from(v: SecurityViolation) -> Self {
        HeimdallError::Violation(v)
    }
}

pub type Result<T> = std::result::Result<T, HeimdallError>;
