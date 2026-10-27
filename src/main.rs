use clap::{Parser, Subcommand};
use colored::*;
use heimdall_mcp::config_mgr::ConfigManager;
use heimdall_mcp::error::Result;
use heimdall_mcp::lockfile::manifest::{LockedProcess, LockedTool, Manifest};
use heimdall_mcp::sanitizer::schema_strip::SanitizeMode;
use heimdall_mcp::taint::tracker::SessionTaintEngine;
use heimdall_mcp::test_app::agent_sim::LlmBackend;
use heimdall_mcp::test_app::harness::TestHarness;
use heimdall_mcp::test_app::micro_bench::PerformanceBenchmark;
use heimdall_mcp::test_app::mock_servers::MockMcpServer;
use heimdall_mcp::transport::stdio::{RugPullPolicy, StdioProxy};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[command(
    name = "heimdall",
    version = "0.1.0",
    about = "Heimdall MCP: Cryptographic Schema Pinning & Deterministic Information Flow Firewall"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize and generate cryptographic heimdall-lock.json for an MCP server
    Init {
        #[arg(short, long, default_value = "heimdall-lock.json")]
        out: PathBuf,

        #[arg(short, long, default_value = "default-server")]
        server_id: String,

        #[arg(long, default_value = "")]
        command: String,

        #[arg(long, value_delimiter = ' ')]
        args: Vec<String>,

        #[arg(long, value_delimiter = ',')]
        whitelist_targets: Vec<String>,
    },

    /// Verify an existing heimdall-lock.json file and signature
    Verify {
        #[arg(short, long, default_value = "heimdall-lock.json")]
        lockfile: PathBuf,
    },

    /// Auto-detect and wrap Cursor / Claude Desktop configuration with heimdall firewall
    Wrap {
        /// Optional path to mcp.json (if omitted, auto-detects Cursor / Claude Desktop)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Path to the heimdall binary to use in the wrapper
        #[arg(long)]
        bin_path: Option<String>,
    },

    /// Restore the most recent backup of an MCP host configuration
    Unwrap {
        /// Optional path to mcp.json (if omitted, auto-detects Cursor / Claude Desktop)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Run security posture audit and vulnerability scoring on an MCP configuration
    Audit {
        /// Optional path to mcp.json (if omitted, auto-detects Cursor / Claude Desktop)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Run transparent stdio proxy firewall for MCP client/server communication
    Proxy {
        #[arg(short, long, default_value = "heimdall-lock.json")]
        lockfile: PathBuf,

        #[arg(long)]
        strict_isolation: bool,

        #[arg(long, default_value = "fail-closed")]
        rug_pull_policy: String,

        #[arg(long, default_value = "compiler-prune")]
        sanitize_mode: String,
    },

    /// Run comprehensive MCPTox & OWASP test harness (with optional local LLM)
    TestBench {
        /// Optional local LLM endpoint (e.g. http://localhost:11434/v1 for Ollama)
        #[arg(long)]
        llm_url: Option<String>,

        /// Optional model name for local LLM (e.g. qwen2.5-coder:7b or deepseek-r1)
        #[arg(long, default_value = "deepseek-r1")]
        model: String,

        /// Optional API key for remote/local LLM
        #[arg(long)]
        api_key: Option<String>,
    },

    /// Run high-precision micro-benchmarks measuring p50/p90/p99 latency and throughput
    Bench,
}

#[tokio::main]
async fn main() -> Result<()> {
    fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("heimdall=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            out,
            server_id,
            command,
            args,
            whitelist_targets,
        } => {
            println!(
                "{}",
                "\n🔒 Initializing heimdall-lock.json cryptographic pin..."
                    .bold()
                    .cyan()
            );

            let (signing_key, _verifying_key) = Manifest::generate_keypair();

            let process = if !command.is_empty() {
                Some(LockedProcess::new(
                    command,
                    args,
                    vec!["PATH".into(), "HOME".into()],
                )?)
            } else {
                None
            };

            let tools_raw = MockMcpServer::benign_tools();
            let mut locked_tools = Vec::new();
            for t in &tools_raw {
                locked_tools.push(LockedTool::from_tool_definition(t, None)?);
            }

            let manifest = Manifest::new(
                server_id,
                process,
                locked_tools,
                whitelist_targets,
                &signing_key,
            )?;

            manifest.save_to_file(&out)?;

            println!(
                "{} Created signed lockfile at: {}",
                "✓".bold().green(),
                out.display()
            );
            println!("  Public Key: {}", manifest.public_key.dimmed());
            println!("  Signature:  {}", manifest.signature.dimmed());
            println!("  Locked Tools: {}", manifest.payload.tools.len());
        }

        Commands::Verify { lockfile } => {
            println!(
                "{}",
                "\n🔍 Verifying cryptographic heimdall-lock.json..."
                    .bold()
                    .cyan()
            );
            match Manifest::load_from_file(&lockfile) {
                Ok(m) => {
                    println!("{} Signature verified successfully!", "✓".bold().green());
                    println!("  Server ID:     {}", m.payload.server_id);
                    println!("  Ed25519 Key:   {}", m.public_key.dimmed());
                    println!("  Tools Count:   {}", m.payload.tools.len());
                    for (name, tool) in &m.payload.tools {
                        println!(
                            "    - {:<18} [{:?}] Digest: {}",
                            name,
                            tool.classification,
                            tool.composite_digest.chars().take(12).collect::<String>()
                        );
                    }
                }
                Err(e) => {
                    eprintln!("{} Verification failed: {}", "✗".bold().red(), e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Wrap { config, bin_path } => {
            let target_path = resolve_config_target(config)?;
            println!(
                "{}",
                "\n🛡️  Wrapping MCP Configuration with heimdall..."
                    .bold()
                    .cyan()
            );
            println!("Target Config: {}", target_path.display());

            match ConfigManager::wrap_config(&target_path, bin_path.as_deref()) {
                Ok((count, backup)) => {
                    println!(
                        "{} Successfully wrapped {} server(s) with heimdall!",
                        "✓".bold().green(),
                        count
                    );
                    println!(
                        "   Backup saved to: {}",
                        backup.display().to_string().dimmed()
                    );
                    println!("   All MCP tools are now protected by cryptographic pinning and DIFC taint firewall.");
                }
                Err(e) => {
                    eprintln!("{} Wrap failed: {}", "✗".bold().red(), e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Unwrap { config } => {
            let target_path = resolve_config_target(config)?;
            println!(
                "{}",
                "\n↩️  Restoring original MCP Configuration..."
                    .bold()
                    .cyan()
            );

            match ConfigManager::unwrap_config(&target_path) {
                Ok(restored_from) => {
                    println!(
                        "{} Config restored successfully from backup: {}",
                        "✓".bold().green(),
                        restored_from.display()
                    );
                }
                Err(e) => {
                    eprintln!("{} Restore failed: {}", "✗".bold().red(), e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Audit { config } => {
            let target_path = resolve_config_target(config)?;
            match ConfigManager::audit_config(&target_path) {
                Ok(report) => {
                    report.print_terminal_summary();
                }
                Err(e) => {
                    eprintln!("{} Audit failed: {}", "✗".bold().red(), e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Proxy {
            lockfile,
            strict_isolation,
            rug_pull_policy,
            sanitize_mode,
        } => {
            info!("Starting heimdall stdio security firewall...");

            let manifest = Manifest::load_from_file(&lockfile).ok();
            let whitelist = manifest
                .as_ref()
                .map(|m| m.payload.whitelist_targets.clone())
                .unwrap_or_default();

            let taint_engine = Arc::new(SessionTaintEngine::new(strict_isolation, &whitelist));
            let policy = if rug_pull_policy == "fail-closed" {
                RugPullPolicy::FailClosed
            } else {
                RugPullPolicy::SanitizeAndQuarantine
            };

            let s_mode = if sanitize_mode == "strict" {
                SanitizeMode::StrictAstOnly
            } else {
                SanitizeMode::CompilerPrune
            };

            let _proxy = StdioProxy::new(manifest, taint_engine, policy, s_mode);
            info!("heimdall stdio proxy initialized and listening on stdio.");
        }

        Commands::TestBench {
            llm_url,
            model,
            api_key,
        } => {
            let backend = if let Some(url) = llm_url {
                println!(
                    "{} Connecting to Local LLM at: {} (Model: {})",
                    "ℹ".bold().blue(),
                    url,
                    model
                );
                LlmBackend::OpenAiCompatible {
                    base_url: url,
                    model_name: model,
                    api_key,
                }
            } else {
                println!(
                    "{} Using Built-in Deterministic Reasoning Agent Simulator",
                    "ℹ".bold().blue()
                );
                LlmBackend::DeterministicSimulator
            };

            let harness = TestHarness::new(backend);
            harness.run_full_suite().await;
        }

        Commands::Bench => {
            PerformanceBenchmark::run_all();
        }
    }

    Ok(())
}

fn resolve_config_target(provided: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = provided {
        return Ok(p);
    }

    let detected = ConfigManager::detect_configs();
    if let Some(first) = detected.first() {
        println!(
            "{} Auto-detected {} configuration at: {}",
            "ℹ".blue(),
            first.host_name,
            first.path.display()
        );
        Ok(first.path.clone())
    } else {
        Err(heimdall_mcp::error::HeimdallError::InvalidConfiguration(
            "No Cursor or Claude Desktop mcp.json automatically detected. Please specify path via --config <path>".into()
        ))
    }
}
