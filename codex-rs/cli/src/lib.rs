pub(crate) mod debug_sandbox;
mod exit_status;
pub(crate) mod login;

use clap::Args;
use clap::Parser;
use codex_utils_absolute_path::AbsolutePathBuf;
use codex_utils_cli::CliConfigOverrides;
use codex_utils_cli::ProfileV2Name;
use std::path::PathBuf;

pub use debug_sandbox::run_command_under_landlock;
pub use debug_sandbox::run_command_under_seatbelt;
pub use debug_sandbox::run_command_under_windows_sandbox;
pub use login::read_access_token_from_stdin;
pub use login::read_api_key_from_stdin;
pub use login::run_login_status;
pub use login::run_login_with_access_token;
pub use login::run_login_with_api_key;
pub use login::run_login_with_chatgpt;
pub use login::run_login_with_device_code;
pub use login::run_login_with_device_code_fallback_to_browser;
pub use login::run_logout;

#[derive(Debug, Default, Args)]
pub struct SandboxStateArgs {
    /// JSON value from `codex/sandbox-state-meta` to apply directly.
    #[arg(
        long = "sandbox-state-json",
        value_name = "JSON",
        conflicts_with_all = ["permissions_profile", "cwd", "include_managed_config"]
    )]
    pub sandbox_state_json: Option<String>,

    /// Add a readable root to the supplied sandbox state. Repeat for multiple roots.
    #[arg(
        long,
        requires = "sandbox_state_json",
        value_parser = parse_absolute_path
    )]
    pub sandbox_state_readable_root: Vec<AbsolutePathBuf>,

    /// Disable direct network access in the supplied sandbox state.
    #[arg(long, requires = "sandbox_state_json", default_value_t = false)]
    pub sandbox_state_disable_network: bool,
}

// These command structs share common sandbox options, but remain separate
// because each host backend has a slightly different option surface.
#[derive(Debug, Parser)]
pub struct SeatbeltCommand {
    #[command(flatten)]
    pub sandbox_state: SandboxStateArgs,

    /// Named permissions profile to apply from the active configuration stack.
    #[arg(
        long = "permission-profile",
        alias = "permissions-profile",
        short = 'P',
        value_name = "NAME"
    )]
    pub permissions_profile: Option<String>,

    /// Layer $CODEX_HOME/<name>.config.toml on top of the base user config.
    #[arg(long = "profile", short = 'p')]
    pub config_profile: Option<ProfileV2Name>,

    /// Working directory used for profile resolution and command execution.
    #[arg(
        short = 'C',
        long = "cd",
        value_name = "DIR",
        requires = "permissions_profile"
    )]
    pub cwd: Option<PathBuf>,

    /// Include managed requirements while resolving an explicit permissions profile.
    #[arg(
        long = "include-managed-config",
        default_value_t = false,
        requires = "permissions_profile"
    )]
    pub include_managed_config: bool,

    /// Allow the sandboxed command to bind/connect AF_UNIX sockets rooted at this path. Relative paths are resolved against the current directory. Repeat to allow multiple paths.
    #[arg(long = "allow-unix-socket", value_parser = parse_absolute_path)]
    pub allow_unix_sockets: Vec<AbsolutePathBuf>,

    #[command(flatten)]
    pub seatbelt_allowlist: SeatbeltAllowlist,

    /// While the command runs, capture macOS sandbox denials via `log stream` and print them after exit
    #[arg(long = "log-denials", default_value_t = false)]
    pub log_denials: bool,

    #[clap(skip)]
    pub config_overrides: CliConfigOverrides,

    /// Full command args to run under seatbelt.
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,
}

fn parse_absolute_path(raw: &str) -> Result<AbsolutePathBuf, String> {
    AbsolutePathBuf::relative_to_current_dir(raw)
        .map_err(|err| format!("invalid path {raw}: {err}"))
}

/// Bootstrap service names are `name_t` buffers: 128 bytes including the NUL terminator;
/// sysctl MIB names are shorter still.
const MAX_SEATBELT_NAME_LEN: usize = 127;

/// Accepts dotted identifiers only (reverse-DNS service names, sysctl MIB names), so a
/// name can never close the quoted Seatbelt string it is rendered into.
fn parse_seatbelt_name(raw: &str) -> Result<String, String> {
    let valid = !raw.is_empty()
        && raw.len() <= MAX_SEATBELT_NAME_LEN
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
    if valid {
        Ok(raw.to_string())
    } else {
        Err(format!(
            "invalid name {raw:?}: expected 1-{MAX_SEATBELT_NAME_LEN} ASCII letters, digits, '.', '-' or '_'"
        ))
    }
}

/// Named allowances appended to the generated Seatbelt policy after its denies, so the
/// specific rules win: Mach service lookups and registrations, bundled XPC services and
/// sysctl reads.
#[derive(Debug, Default, Args)]
pub struct SeatbeltAllowlist {
    /// Allow the sandboxed command to look up this global Mach service (for example `com.apple.FSEvents`). Repeat to allow multiple services.
    #[arg(
        long = "allow-mach-lookup",
        value_name = "SERVICE",
        value_parser = parse_seatbelt_name
    )]
    pub global_names: Vec<String>,

    /// Allow the sandboxed command to look up every global Mach service under this prefix (for example `org.chromium.`). Repeat to allow multiple prefixes.
    #[arg(
        long = "allow-mach-lookup-prefix",
        value_name = "PREFIX",
        value_parser = parse_seatbelt_name
    )]
    pub global_name_prefixes: Vec<String>,

    /// Allow the sandboxed command to look up this bundled XPC service (for example `com.apple.CoreSimulator.SimLaunchHost-arm64`). Repeat to allow multiple services.
    #[arg(
        long = "allow-xpc-service",
        value_name = "SERVICE",
        value_parser = parse_seatbelt_name
    )]
    pub xpc_services: Vec<String>,

    /// Allow the sandboxed command to register this global Mach service name. Repeat to allow multiple names.
    #[arg(
        long = "allow-mach-register",
        value_name = "SERVICE",
        value_parser = parse_seatbelt_name
    )]
    pub register_names: Vec<String>,

    /// Allow the sandboxed command to register every global Mach service name under this prefix (for example `org.chromium.Chromium.MachPortRendezvousServer.`). Repeat to allow multiple prefixes.
    #[arg(
        long = "allow-mach-register-prefix",
        value_name = "PREFIX",
        value_parser = parse_seatbelt_name
    )]
    pub register_prefixes: Vec<String>,

    /// Allow the sandboxed command to read this sysctl (for example `hw.optional.arm64`). Repeat to allow multiple names.
    #[arg(
        long = "allow-sysctl-read",
        value_name = "NAME",
        value_parser = parse_seatbelt_name
    )]
    pub sysctl_names: Vec<String>,

    /// Allow the sandboxed command to read every sysctl under this prefix (for example `sysctl.oidfmt.`). Repeat to allow multiple prefixes.
    #[arg(
        long = "allow-sysctl-read-prefix",
        value_name = "PREFIX",
        value_parser = parse_seatbelt_name
    )]
    pub sysctl_prefixes: Vec<String>,
}

impl SeatbeltAllowlist {
    /// Seatbelt rules for the allowances; names are validated by the CLI parser, so they
    /// cannot leave the quoted filter string.
    pub fn seatbelt_rules(&self) -> String {
        let rules = [
            (&self.global_names, "mach-lookup", "global-name"),
            (
                &self.global_name_prefixes,
                "mach-lookup",
                "global-name-prefix",
            ),
            (&self.xpc_services, "mach-lookup", "xpc-service-name"),
            (&self.register_names, "mach-register", "global-name"),
            (
                &self.register_prefixes,
                "mach-register",
                "global-name-prefix",
            ),
            (&self.sysctl_names, "sysctl-read", "sysctl-name"),
            (&self.sysctl_prefixes, "sysctl-read", "sysctl-name-prefix"),
        ];
        rules
            .iter()
            .flat_map(|(names, operation, filter)| {
                names
                    .iter()
                    .map(move |name| format!("\n(allow {operation} ({filter} \"{name}\"))"))
            })
            .collect()
    }
}

#[derive(Debug, Parser)]
pub struct LandlockCommand {
    #[command(flatten)]
    pub sandbox_state: SandboxStateArgs,

    /// Named permissions profile to apply from the active configuration stack.
    #[arg(
        long = "permission-profile",
        alias = "permissions-profile",
        short = 'P',
        value_name = "NAME"
    )]
    pub permissions_profile: Option<String>,

    /// Layer $CODEX_HOME/<name>.config.toml on top of the base user config.
    #[arg(long = "profile", short = 'p')]
    pub config_profile: Option<ProfileV2Name>,

    /// Working directory used for profile resolution and command execution.
    #[arg(
        short = 'C',
        long = "cd",
        value_name = "DIR",
        requires = "permissions_profile"
    )]
    pub cwd: Option<PathBuf>,

    /// Include managed requirements while resolving an explicit permissions profile.
    #[arg(
        long = "include-managed-config",
        default_value_t = false,
        requires = "permissions_profile"
    )]
    pub include_managed_config: bool,

    #[clap(skip)]
    pub config_overrides: CliConfigOverrides,

    /// Full command args to run under the Linux sandbox.
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,
}

#[derive(Debug, Parser)]
pub struct WindowsCommand {
    #[command(flatten)]
    pub sandbox_state: SandboxStateArgs,

    /// Named permissions profile to apply from the active configuration stack.
    #[arg(
        long = "permission-profile",
        alias = "permissions-profile",
        short = 'P',
        value_name = "NAME"
    )]
    pub permissions_profile: Option<String>,

    /// Layer $CODEX_HOME/<name>.config.toml on top of the base user config.
    #[arg(long = "profile", short = 'p')]
    pub config_profile: Option<ProfileV2Name>,

    /// Working directory used for profile resolution and command execution.
    #[arg(
        short = 'C',
        long = "cd",
        value_name = "DIR",
        requires = "permissions_profile"
    )]
    pub cwd: Option<PathBuf>,

    /// Include managed requirements while resolving an explicit permissions profile.
    #[arg(
        long = "include-managed-config",
        default_value_t = false,
        requires = "permissions_profile"
    )]
    pub include_managed_config: bool,

    #[clap(skip)]
    pub config_overrides: CliConfigOverrides,

    /// Full command args to run under Windows restricted token sandbox.
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,
}

#[cfg(test)]
#[path = "sandbox_args_tests.rs"]
mod tests;
