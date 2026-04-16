#![no_main]

use libfuzzer_sys::fuzz_target;

/// Fuzz the BandwidthRate::parse function.
/// This is a critical input surface as it parses untrusted user input.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Try to parse the string as a bandwidth rate
        // We don't care about the result, just that it doesn't panic
        let _ = oxy::units::BandwidthRate::parse(s);
    }
});
