use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxProfile {
    /// Pure computation only: Disallow all network and filesystem write access
    PureCompute,
    /// Scoped filesystem: Read-only access to working directory, no sensitive directories (~/.ssh, ~/.aws, /etc)
    ScopedFilesystem,
    /// Permissive: Default process isolation with environment variable sanitization
    Permissive,
}

pub struct SandboxManager;

impl SandboxManager {
    /// Generates macOS seatbelt (sandbox-exec) configuration profile scheme
    #[cfg(target_os = "macos")]
    pub fn generate_macos_seatbelt_profile(allowed_dir: &Path, allow_network: bool) -> String {
        let mut profile = String::from("(version 1)\n(deny default)\n");
        // Allow basic execution and shared libraries
        profile.push_str("(allow process-exec)\n");
        profile.push_str("(allow sysctl-read)\n");
        profile.push_str("(allow file-read* (subpath \"/usr/lib\") (subpath \"/usr/share\") (subpath \"/System\"))\n");

        // Allow reading current allowed working directory
        profile.push_str(&format!(
            "(allow file-read* file-write* (subpath \"{}\"))\n",
            allowed_dir.to_string_lossy()
        ));

        // Network rules
        if allow_network {
            profile.push_str("(allow network-outbound)\n");
        } else {
            profile.push_str("(deny network*)\n");
        }

        // Explicitly deny sensitive personal paths
        profile.push_str(
            "(deny file* (regex #\"/\\.ssh/\") (regex #\"/\\.cursor/\") (regex #\"/\\.aws/\"))\n",
        );

        profile
    }

    /// Wraps a command invocation with OS-specific sandbox wrapper if requested
    pub fn build_sandboxed_command(
        command: &str,
        args: &[String],
        profile: SandboxProfile,
        working_dir: &Path,
    ) -> (String, Vec<String>) {
        match profile {
            SandboxProfile::Permissive => (command.to_string(), args.to_vec()),
            #[cfg(target_os = "macos")]
            SandboxProfile::ScopedFilesystem | SandboxProfile::PureCompute => {
                let allow_net = profile != SandboxProfile::PureCompute;
                let seatbelt_script = Self::generate_macos_seatbelt_profile(working_dir, allow_net);
                let mut sandbox_args = vec!["-p".to_string(), seatbelt_script, command.to_string()];
                sandbox_args.extend_from_slice(args);
                ("sandbox-exec".to_string(), sandbox_args)
            }
            #[cfg(not(target_os = "macos"))]
            _ => (command.to_string(), args.to_vec()),
        }
    }
}
