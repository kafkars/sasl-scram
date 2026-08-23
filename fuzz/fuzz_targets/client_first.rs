//! Arbitrary-byte coverage for the client-first parser.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sasl_scram::{ResourceLimits, message::ClientFirst};

fuzz_target!(|input: &[u8]| {
    let _result = ClientFirst::parse(input, &ResourceLimits::default());
});
