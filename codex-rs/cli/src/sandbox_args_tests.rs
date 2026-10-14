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
