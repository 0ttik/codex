use super::MachAllowlist;
use super::parse_mach_service_name;
use pretty_assertions::assert_eq;

#[test]
fn mach_service_names_cannot_escape_the_seatbelt_string() {
    let longest = "a".repeat(127);
    for accepted in [
        "com.apple.CoreSimulator.CoreSimulatorService",
        "com.apple.FSEvents",
        longest.as_str(),
    ] {
        assert_eq!(parse_mach_service_name(accepted), Ok(accepted.to_string()));
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
            parse_mach_service_name(rejected).is_err(),
            "{rejected:?} must be rejected"
        );
    }
}

#[test]
fn mach_allowlist_renders_one_rule_per_service() {
    assert_eq!(MachAllowlist::default().seatbelt_rules(), "");

    let allowlist = MachAllowlist {
        global_names: vec![
            "com.apple.CoreSimulator.CoreSimulatorService".to_string(),
            "com.apple.FSEvents".to_string(),
        ],
        xpc_services: vec!["com.apple.CoreSimulator.SimLaunchHost-arm64".to_string()],
    };
    assert_eq!(
        allowlist.seatbelt_rules(),
        "\n(allow mach-lookup (global-name \"com.apple.CoreSimulator.CoreSimulatorService\"))\
         \n(allow mach-lookup (global-name \"com.apple.FSEvents\"))\
         \n(allow mach-lookup (xpc-service-name \"com.apple.CoreSimulator.SimLaunchHost-arm64\"))"
    );
}
