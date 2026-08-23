//! Exhaustive small-domain properties for SCRAM identity escaping.

use sasl_scram::{
    ChannelBindingMode, PreparedAuthenticationIdentity, ResourceLimits,
    message::{ClientFirst, encode_client_first},
};

#[test]
fn escaping_round_trips_every_small_valid_identity() -> Result<(), sasl_scram::Error> {
    let alphabet = ["a", ",", "=", "é", "\u{0487}"];
    let limits = ResourceLimits::default();
    for first in alphabet {
        assert_round_trip(first, &limits)?;
        for second in alphabet {
            assert_round_trip(&format!("{first}{second}"), &limits)?;
            for third in alphabet {
                assert_round_trip(&format!("{first}{second}{third}"), &limits)?;
            }
        }
    }
    Ok(())
}

fn assert_round_trip(identity: &str, limits: &ResourceLimits) -> Result<(), sasl_scram::Error> {
    let prepared = PreparedAuthenticationIdentity::from_protocol_profile(identity)?;
    let message = encode_client_first(
        &ChannelBindingMode::Unsupported,
        &prepared,
        None,
        b"nonce",
        limits,
    )?;
    let parsed = ClientFirst::parse(message.as_bytes(), limits)?;
    let decoded = parsed.decode_authentication_identity()?;

    assert_eq!(&*decoded, identity);
    Ok(())
}

#[test]
fn invalid_escape_sequences_never_normalize_into_identities() {
    let invalid = [b"=".as_slice(), b"=2c", b"=3d", b"=2D", b"==3D", b"a\0b"];
    let limits = ResourceLimits::default();
    for identity in invalid {
        let mut message = b"n,,n=".to_vec();
        message.extend_from_slice(identity);
        message.extend_from_slice(b",r=nonce");
        assert!(ClientFirst::parse(&message, &limits).is_err());
    }
}
