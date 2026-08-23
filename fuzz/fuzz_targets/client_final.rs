//! Arbitrary-byte coverage for the client-final parser.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sasl_scram::{ResourceLimits, message::ClientFinal};

fuzz_target!(|input: &[u8]| {
    let _result = ClientFinal::parse(input, &ResourceLimits::default());
});
