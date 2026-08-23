//! Constant-time equality for fixed-length derived values.

use ctutils::CtEq;

pub(super) fn constant_time_eq(expected: &[u8], received: &[u8]) -> bool {
    expected.ct_eq(received).to_bool()
}
