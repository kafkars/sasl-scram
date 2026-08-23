//! Arbitrary-byte coverage for the server-first parser.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sasl_scram::{ResourceLimits, message::ServerFirst};

fuzz_target!(|input: &[u8]| {
    let _result = ServerFirst::parse(input, &ResourceLimits::default());
});
