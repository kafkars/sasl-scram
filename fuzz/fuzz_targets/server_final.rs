//! Arbitrary-byte coverage for the server-final parser.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sasl_scram::{ResourceLimits, message::ServerFinal};

fuzz_target!(|input: &[u8]| {
    let _result = ServerFinal::parse(input, &ResourceLimits::default());
});
