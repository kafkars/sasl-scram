//! Server verifier generation, import, concealment, and secret ownership.

#![cfg(feature = "sha256")]

use core::num::{NonZeroU32, NonZeroUsize};

use sasl_scram::{
    Algorithm, AsciiProfile, ConcealmentKey, ConcealmentProfile, CredentialResponse, CryptoError,
    Error, IterationCount, NeedCredential, PolicyError, Salt, SaltPolicy, SecretBytes,
    SecretString, Server, ServerConfig, ServerCredential,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[test]
fn rfc7677_password_derivation_produces_storage_ready_verifier_parts() -> Result<(), Error> {
    let salt = hex("5b6d99689d12358eeca04b141236fa81")?;
    let password = AsciiProfile::prepare_password(SecretString::new("pencil"))?;
    let pending = ServerCredential::prepare(
        Algorithm::Sha256,
        password,
        Salt::new(SecretBytes::new(salt))?,
        iterations(4096),
    )?;
    assert_send::<sasl_scram::PendingServerCredential>();
    assert!(format!("{pending:?}").contains("[REDACTED]"));
    let credential = pending.derive()?;

    assert_eq!(
        credential.stored_key().expose_secret(),
        hex("586e5df283e6dceb5c3e791d8b8528ec191e664045ce971792e2e6b5bb13e2a6")?
    );
    assert_eq!(
        credential.server_key().expose_secret(),
        hex("c1f3cbc1c13a9d35a14c0990eed97629ea225863e566a4314ab99f3f00e5d9d5")?
    );
    assert_eq!(credential.iterations(), iterations(4096));
    assert!(format!("{credential:?}").contains("[REDACTED]"));
    Ok(())
}

#[test]
fn imported_verifiers_reject_incoherent_algorithm_key_lengths() -> Result<(), Error> {
    let invalid = ServerCredential::from_verifier_parts(
        Algorithm::Sha256,
        Salt::new(SecretBytes::new(b"0123456789abcdef".as_slice()))?,
        iterations(4096),
        SecretBytes::new([0_u8; 31].as_slice()),
        SecretBytes::new([0_u8; 32].as_slice()),
    );
    assert!(matches!(invalid, Err(PolicyError::InvalidCredential)));

    #[cfg(feature = "sha512")]
    assert!(matches!(
        ServerCredential::from_verifier_parts(
            Algorithm::Sha512,
            Salt::new(SecretBytes::new(b"0123456789abcdef".as_slice()))?,
            iterations(4096),
            SecretBytes::new([0_u8; 32].as_slice()),
            SecretBytes::new([0_u8; 32].as_slice()),
        ),
        Err(PolicyError::InvalidCredential)
    ));
    Ok(())
}

#[test]
fn synthetic_credentials_are_deterministic_identity_bound_and_domain_separated() -> Result<(), Error>
{
    let key = ConcealmentKey::new(SecretBytes::new([7_u8; 32].as_slice()))?;
    let profile = ConcealmentProfile::new(NonZeroUsize::MIN.saturating_add(15), iterations(4096));
    let first = concealed(&need(b"alice")?, &key, profile)?;
    let second = concealed(&need(b"alice")?, &key, profile)?;
    let other = concealed(&need(b"bob")?, &key, profile)?;
    let extended = concealed(
        &need(b"alice")?,
        &key,
        ConcealmentProfile::new(NonZeroUsize::MIN.saturating_add(79), iterations(4096)),
    )?;

    assert_eq!(first.salt().expose_bytes(), second.salt().expose_bytes());
    assert_eq!(
        first.stored_key().expose_secret(),
        second.stored_key().expose_secret()
    );
    assert_eq!(
        first.server_key().expose_secret(),
        second.server_key().expose_secret()
    );
    assert_eq!(
        first.salt().expose_bytes(),
        hex("8d3115e65a01284b08d96533ee648254")?
    );
    assert_eq!(
        first.stored_key().expose_secret(),
        hex("d569d02a71bd76c0eb016876cd57e000925a6a62ec3e730ac3e1952972383806")?
    );
    assert_eq!(
        first.server_key().expose_secret(),
        hex("b704a8e15339145366716f6a5b4c98e303ff7ea21e3b1ad0daf386b605172bb6")?
    );
    assert_eq!(
        other.salt().expose_bytes(),
        hex("404e4ce075e7d348d7198ac9e81408f8")?
    );
    assert_eq!(extended.salt().len(), 80);
    assert_eq!(
        &extended.salt().expose_bytes()[..16],
        first.salt().expose_bytes()
    );
    let blocks_differ = extended.salt().expose_bytes()[..32]
        .iter()
        .zip(&extended.salt().expose_bytes()[32..64])
        .any(|(left, right)| left != right);
    assert!(blocks_differ);
    assert!(format!("{key:?}").contains("[REDACTED]"));
    Ok(())
}

#[test]
fn salts_and_concealment_keys_enforce_security_minimums() -> Result<(), Error> {
    assert!(matches!(
        Salt::new(SecretBytes::new(b"short".as_slice())),
        Err(PolicyError::SaltTooShort {
            length: 5,
            minimum: 16
        })
    ));
    let compatibility = SaltPolicy::new(NonZeroUsize::MIN, NonZeroUsize::MIN.saturating_add(7))?;
    assert_eq!(
        Salt::with_policy(SecretBytes::new(b"short".as_slice()), compatibility)?.len(),
        5
    );
    assert!(matches!(
        ConcealmentKey::new(SecretBytes::new([0_u8; 31].as_slice())),
        Err(PolicyError::ConcealmentKeyTooShort {
            length: 31,
            minimum: 32
        })
    ));
    assert!(matches!(
        Salt::new(SecretBytes::new([0_u8; 1025].as_slice())),
        Err(PolicyError::SaltTooLong {
            length: 1025,
            maximum: 1024
        })
    ));
    Ok(())
}

#[test]
fn server_secret_owners_zeroize_explicitly_and_on_drop() -> Result<(), Error> {
    assert_zeroize_on_drop::<Salt>();
    assert_zeroize_on_drop::<ServerCredential>();
    assert_zeroize_on_drop::<sasl_scram::PendingServerCredential>();
    assert_zeroize_on_drop::<ConcealmentKey>();

    let mut credential = credential("password", 1)?;
    credential.zeroize();
    assert!(
        credential
            .salt()
            .expose_bytes()
            .iter()
            .all(|byte| *byte == 0)
    );
    assert!(
        credential
            .stored_key()
            .expose_secret()
            .iter()
            .all(|byte| *byte == 0)
    );
    assert!(
        credential
            .server_key()
            .expose_secret()
            .iter()
            .all(|byte| *byte == 0)
    );
    Ok(())
}

fn credential(password: &str, count: u32) -> Result<ServerCredential, Error> {
    let password = AsciiProfile::prepare_password(SecretString::new(password))?;
    ServerCredential::prepare(
        Algorithm::Sha256,
        password,
        Salt::new(SecretBytes::new(b"0123456789abcdef".as_slice()))?,
        iterations(count),
    )?
    .derive()
}

fn need(identity: &[u8]) -> Result<NeedCredential, Error> {
    let mut message = b"n,,n=".to_vec();
    message.extend_from_slice(identity);
    message.extend_from_slice(b",r=nonce");
    let received = Server::new(ServerConfig::builder(Algorithm::Sha256).build()?)
        .receive_client_first(&message)?;
    let (authentication_identity, authorization_identity) =
        AsciiProfile::prepare_server_identities(
            received.authentication_identity(),
            received.authorization_identity(),
        )?;
    received.accept_prepared(authentication_identity, authorization_identity)
}

fn concealed(
    need: &NeedCredential,
    key: &ConcealmentKey,
    profile: ConcealmentProfile,
) -> Result<ServerCredential, Error> {
    let CredentialResponse::Concealed { synthetic } = need.conceal::<()>(key, profile)? else {
        return Err(CryptoError::Unavailable.into());
    };
    Ok(synthetic)
}

fn iterations(value: u32) -> IterationCount {
    let count = NonZeroU32::new(value).unwrap_or(NonZeroU32::MIN);
    IterationCount::new(count)
}

fn hex(value: &str) -> Result<Vec<u8>, Error> {
    if !value.len().is_multiple_of(2) {
        return Err(CryptoError::Unavailable.into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let high = nibble(chunk[0])?;
            let low = nibble(chunk[1])?;
            Ok(high << 4 | low)
        })
        .collect()
}

fn nibble(value: u8) -> Result<u8, Error> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(CryptoError::Unavailable.into()),
    }
}

fn assert_send<T: Send>() {}

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
