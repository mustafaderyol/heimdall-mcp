use crate::error::{McpLockError, Result};
use crate::lockfile::manifest::Manifest;
use colored::*;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct DetectedHostConfig {
    pub host_name: &'static str,
    pub path: PathBuf,
}

pub struct ConfigManager;

impl ConfigManager {
    /// Detects known MCP host configuration files on the current system (Cursor, Claude Desktop)
    pub fn detect_configs() -> Vec<DetectedHostConfig> {
        let mut configs = Vec::new();
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        let home_path = Path::new(&home);

        // 1. Cursor config locations
        let cursor_paths = [
            home_path.join(".cursor").join("mcp.json"),
            home_path.join(".cursor").join("rules").join("mcp.json"),
            home_path.join("Library").join("Application Support").join("Cursor").join("User").join("globalStorage").join("cursor.mcp.json"),
        ];

        for p in &cursor_paths {
            if p.exists() {
                configs.push(DetectedHostConfig {
                    host_name: "Cursor",
                    path: p.clone(),
                });
                break;
            }
        }

        // 2. Claude Desktop config locations
        let claude_paths = [
            home_path.join("Library").join("Application Support").join("Claude").join("claude_desktop_config.json"),
            home_path.join(".config").join("Claude").join("claude_desktop_config.json"),
            home_path.join("AppData").join("Roaming").join("Claude").join("claude_desktop_config.json"),
        ];

        for p in &claude_paths {
            if p.exists() {
                configs.push(DetectedHostConfig {
                    host_name: "Claude Desktop",
                    path: p.clone(),
                });
                break;
            }
        }

        configs
    }

    /// Backs up a configuration file before modifying it
    pub fn backup_config<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
        let path_ref = path.as_ref();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let backup_path = path_ref.with_extension(format!("backup.{}.json", timestamp));
        fs::copy(path_ref, &backup_path)?;
        Ok(backup_path)
    }

    /// Wraps an MCP host configuration so that all servers are executed through mcp-lock proxy
    pub fn wrap_config<P: AsRef<Path>>(config_path: P, mcplock_bin_path: Option<&str>) -> Result<(usize, PathBuf)> {
        let path_ref = config_path.as_ref();
        if !path_ref.exists() {
            return Err(McpLockError::InvalidConfiguration(format!(
                "Config file not found at: {}",
                path_ref.display()
            )));
        }

        let backup = Self::backup_config(path_ref)?;
        let raw = fs::read_to_string(path_ref)?;
        let mut parsed: Value = serde_json::from_str(&raw)?;

        let bin_name = mcplock_bin_path.unwrap_or("heimdall");

        let mut wrapped_count = 0;

        if let Some(servers) = parsed.get_mut("mcpServers").and_then(|s| s.as_object_mut()) {
            for (server_id, server_cfg) in servers.iter_mut() {
                if let Some(cfg_obj) = server_cfg.as_object_mut() {
                    let curr_command = cfg_obj.get("command").and_then(|v| v.as_str()).unwrap_or("");

                    // Check if already wrapped
                    if curr_command == bin_name || curr_command.ends_with("/heimdall") || curr_command.ends_with("/heimdall-mcp") {
                        continue;
                    }

                    let orig_command = curr_command.to_string();
                    let orig_args: Vec<String> = cfg_obj
                        .get("args")
                        .and_then(|a| a.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();

                    // Generate lockfile path for this server
                    let lockfile_name = format!("heimdall-lock.{}.json", server_id);
                    let lockfile_path = path_ref.parent().unwrap_or_else(|| Path::new(".")).join(&lockfile_name);

                    // Create lockfile manifest if not existing
                    if !lockfile_path.exists() {
                        let (signing_key, _) = Manifest::generate_keypair();
                        let dummy_manifest = Manifest::new(
                            server_id.clone(),
                            None,
                            Vec::new(),
                            vec!["localhost".into(), "127.0.0.1".into()],
                            &signing_key,
                        )?;
                        dummy_manifest.save_to_file(&lockfile_path)?;
                    }

                    // Build wrapped command arguments:
                    // heimdall proxy --lockfile <path> -- <orig_cmd> <orig_args>
                    let mut new_args = vec![
                        "proxy".to_string(),
                        "--lockfile".to_string(),
                        lockfile_path.to_string_lossy().to_string(),
                        "--".to_string(),
                        orig_command,
                    ];
                    new_args.extend(orig_args);

                    cfg_obj.insert("command".to_string(), Value::String(bin_name.to_string()));
                    cfg_obj.insert(
                        "args".to_string(),
                        Value::Array(new_args.into_iter().map(Value::String).collect()),
                    );

                    wrapped_count += 1;
                }
            }
        }

        let updated_raw = serde_json::to_string_pretty(&parsed)?;
        fs::write(path_ref, updated_raw)?;

        Ok((wrapped_count, backup))
    }

    /// Restores the most recent backup of a configuration file
    pub fn unwrap_config<P: AsRef<Path>>(config_path: P) -> Result<PathBuf> {
        let path_ref = config_path.as_ref();
        let parent = path_ref.parent().unwrap_or_else(|| Path::new("."));
        let file_stem = path_ref.file_stem().and_then(|s| s.to_str()).unwrap_or("mcp");

        // Find backups matching file_stem.backup.*.json
        let mut backups = Vec::new();
        if let Ok(entries) = fs::read_dir(parent) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with(&format!("{}.backup.", file_stem)) && name.ends_with(".json") {
                    backups.push(entry.path());
                }
            }
        }

        backups.sort();
        let latest_backup = backups.last().ok_or_else(|| {
            McpLockError::InvalidConfiguration("No backup file found to restore from.".into())
        })?;

        fs::copy(latest_backup, path_ref)?;
        Ok(latest_backup.clone())
    }

    /// Audits an MCP host configuration and produces a security score and risk report
    pub fn audit_config<P: AsRef<Path>>(config_path: P) -> Result<AuditReport> {
        let path_ref = config_path.as_ref();
        let raw = fs::read_to_string(path_ref)?;
        let parsed: Value = serde_json::from_str(&raw)?;

        let mut server_audits = Vec::new();
        let mut overall_score: u32 = 100;

        if let Some(servers) = parsed.get("mcpServers").and_then(|s| s.as_object()) {
            for (server_id, server_cfg) in servers {
                let cmd = server_cfg.get("command").and_then(|v| v.as_str()).unwrap_or("");
                let args: Vec<String> = server_cfg
                    .get("args")
                    .and_then(|a| a.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default();

                let is_protected = cmd.contains("heimdall");

                let mut risks = Vec::new();

                if !is_protected {
                    risks.push(ServerRisk {
                        severity: RiskSeverity::Critical,
                        title: "Unprotected MCP Server Execution".to_string(),
                        description: "Running raw binary without cryptographic schema pinning or DIFC taint firewall.".to_string(),
                        remediation: "Run 'heimdall wrap' to enforce cryptographic pinning and exfiltration firewall.".to_string(),
                    });
                    overall_score = overall_score.saturating_sub(25);
                }

                // Check dangerous commands
                if cmd == "bash" || cmd == "sh" || cmd == "zsh" || cmd == "cmd" || cmd == "powershell" {
                    risks.push(ServerRisk {
                        severity: RiskSeverity::High,
                        title: "Raw Shell Execution Primitive".to_string(),
                        description: format!("Server runs via direct shell '{}', vulnerable to command injection.", cmd),
                        remediation: "Execute precompiled binaries directly instead of wrapping with raw shell.".to_string(),
                    });
                    overall_score = overall_score.saturating_sub(15);
                }

                // Check sensitive environment inheritance
                if let Some(env) = server_cfg.get("env").and_then(|e| e.as_object()) {
                    for key in env.keys() {
                        let upper = key.to_uppercase();
                        if upper.contains("SECRET") || upper.contains("KEY") || upper.contains("TOKEN") {
                            risks.push(ServerRisk {
                                severity: RiskSeverity::Medium,
                                title: format!("Plaintext Secret in Configuration ({})", key),
                                description: "Sensitive API tokens stored in unencrypted configuration file.".to_string(),
                                remediation: "Pass secrets via OS keychain or scoped environment variables.".to_string(),
                            });
                            overall_score = overall_score.saturating_sub(5);
                        }
                    }
                }

                server_audits.push(ServerAudit {
                    server_id: server_id.clone(),
                    command: cmd.to_string(),
                    args,
                    is_protected,
                    risks,
                });
            }
        }

        let grade = match overall_score {
            90..=100 => "A",
            75..=89 => "B",
            50..=74 => "C",
            _ => "F",
        };

        Ok(AuditReport {
            config_path: path_ref.to_string_lossy().to_string(),
            overall_score,
            grade: grade.to_string(),
            servers: server_audits,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone)]
pub struct ServerRisk {
    pub severity: RiskSeverity,
    pub title: String,
    pub description: String,
    pub remediation: String,
}

#[derive(Debug, Clone)]
pub struct ServerAudit {
    pub server_id: String,
    pub command: String,
    pub args: Vec<String>,
    pub is_protected: bool,
    pub risks: Vec<ServerRisk>,
}

#[derive(Debug, Clone)]
pub struct AuditReport {
    pub config_path: String,
    pub overall_score: u32,
    pub grade: String,
    pub servers: Vec<ServerAudit>,
}

impl AuditReport {
    pub fn print_terminal_summary(&self) {
        println!("{}", "\n================================================================================".cyan());
        println!("       Heimdall MCP SECURITY AUDIT & POSTURE REPORT: Grade {}", self.grade.bold());
        println!("{}", "================================================================================\n".cyan());

        let score_colored = if self.overall_score >= 80 {
            format!("{}/100", self.overall_score).bold().green()
        } else if self.overall_score >= 50 {
            format!("{}/100", self.overall_score).bold().yellow()
        } else {
            format!("{}/100", self.overall_score).bold().red()
        };

        println!("Config Target: {}", self.config_path.bold());
        println!("Security Posture Score: {}\n", score_colored);

        for s in &self.servers {
            let status = if s.is_protected {
                "PROTECTED".bold().green()
            } else {
                "VULNERABLE (UNPROTECTED)".bold().red()
            };

            println!("Server [{}]: {}", s.server_id.bold(), status);
            println!("  Command: {} {}", s.command, s.args.join(" "));

            if s.risks.is_empty() {
                println!("  {} No security risks detected.", "✓".green());
            } else {
                for r in &s.risks {
                    let sev_badge = match r.severity {
                        RiskSeverity::Critical => "[CRITICAL]".bold().red(),
                        RiskSeverity::High => "[HIGH]".bold().red(),
                        RiskSeverity::Medium => "[MEDIUM]".bold().yellow(),
                        RiskSeverity::Low => "[LOW]".bold().blue(),
                    };
                    println!("  {} {} - {}", sev_badge, r.title.bold(), r.description);
                    println!("     Remediation: {}", r.remediation.dimmed());
                }
            }
            println!();
        }
    }
}
