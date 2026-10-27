pub mod config_mgr;
pub mod error;
pub mod lockfile;
pub mod sanitizer;
pub mod taint;
pub mod test_app;
pub mod transport;

pub use config_mgr::{AuditReport, ConfigManager, DetectedHostConfig, RiskSeverity, ServerRisk};
pub use error::{HeimdallError, McpLockError, Result, SecurityViolation};
pub use lockfile::{
    Canonicalizer, LockedProcess, LockedTool, Manifest, ManifestPayload, ToolClassification,
    ToolVerificationResult,
};
pub use sanitizer::{SanitizeMode, SchemaSanitizer};
pub use taint::{
    ConfidentialityLabel, DifcLattice, EntropyAnalyzer, IntegrityLabel, SecretEncoder,
    SessionTaintEngine, TargetCategory,
};
pub use test_app::{
    AgentSimulator, BenchmarkResult, LlmBackend, MicroBenchResult, MockMcpServer,
    PerformanceBenchmark, TestHarness,
};
pub use transport::{
    RugPullPolicy, SandboxManager, SandboxProfile, StdioProxy, StreamableHttpServer,
};
