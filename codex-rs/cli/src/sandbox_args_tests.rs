use super::SeatbeltAllowlist;
use super::parse_seatbelt_name;
use pretty_assertions::assert_eq;

#[test]
fn seatbelt_names_cannot_escape_the_quoted_filter() {
    let longest = "a".repeat(127);
    for accepted in [
        "com.apple.CoreSimulator.CoreSimulatorService",
        "hw.optional.arm64",
        "sysctl.oidfmt.",
        "org.chromium.Chromium.MachPortRendezvousServer.",
        longest.as_str(),
    ] {
        assert_eq!(parse_seatbelt_name(accepted), Ok(accepted.to_string()));
    }

    let too_long = "a".repeat(128);
    for rejected in [
        "",
        "com.apple.\")) (allow default",
        "com.apple\\x",
        "com apple",
        "com.apple\nx",
        "com.apple(x",
        too_long.as_str(),
    ] {
        assert!(
            parse_seatbelt_name(rejected).is_err(),
            "{rejected:?} must be rejected"
        );
    }
}

#[test]
fn allowlist_renders_one_rule_per_name() {
    assert_eq!(SeatbeltAllowlist::default().seatbelt_rules(), "");

    let allowlist = SeatbeltAllowlist {
        global_names: vec![
            "com.apple.CoreSimulator.CoreSimulatorService".to_string(),
            "com.apple.FSEvents".to_string(),
        ],
        global_name_prefixes: vec!["org.chromium.".to_string()],
        xpc_services: vec!["com.apple.CoreSimulator.SimLaunchHost-arm64".to_string()],
        register_names: vec!["com.example.server".to_string()],
        register_prefixes: vec!["org.chromium.Chromium.MachPortRendezvousServer.".to_string()],
        sysctl_names: vec!["hw.optional.arm64".to_string()],
        sysctl_prefixes: vec!["sysctl.oidfmt.".to_string()],
    };
    assert_eq!(
        allowlist.seatbelt_rules(),
        "\n(allow mach-lookup (global-name \"com.apple.CoreSimulator.CoreSimulatorService\"))\
         \n(allow mach-lookup (global-name \"com.apple.FSEvents\"))\
         \n(allow mach-lookup (global-name-prefix \"org.chromium.\"))\
         \n(allow mach-lookup (xpc-service-name \"com.apple.CoreSimulator.SimLaunchHost-arm64\"))\
         \n(allow mach-register (global-name \"com.example.server\"))\
         \n(allow mach-register (global-name-prefix \"org.chromium.Chromium.MachPortRendezvousServer.\"))\
         \n(allow sysctl-read (sysctl-name \"hw.optional.arm64\"))\
         \n(allow sysctl-read (sysctl-name-prefix \"sysctl.oidfmt.\"))"
    );
}
