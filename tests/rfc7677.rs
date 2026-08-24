//! RFC 7677 SCRAM-SHA-256 transcript and intermediate derivation vectors.

#![cfg(feature = "sha256")]

use sasl_scram::{
    Algorithm, AsciiProfile, AuthenticationError, ChannelBindingMode, Client, ClientConfig,
    ClientPolicy, CryptoError, Error, NonceError, NonceSource, SecretString,
};

#[path = "../src/crypto/sha256.rs"]
mod sha256_backend;
#[path = "../src/crypto/verify.rs"]
mod verify;

const CLIENT_FIRST: &[u8] = b"n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
const SERVER_FIRST: &[u8] =
    b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
const CLIENT_FINAL_WITHOUT_PROOF: &[u8] =
    b"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
const CLIENT_FINAL: &[u8] = b"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
const SERVER_FINAL: &[u8] = b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

struct FixedNonce([u8; 15]);

impl NonceSource for FixedNonce {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), NonceError> {
        if output.len() != self.0.len() {
            return Err(NonceError::unavailable());
        }
        output.copy_from_slice(&self.0);
        Ok(())
    }
}

#[test]
fn rfc7677_client_exchange_matches_every_wire_message() -> Result<(), Error> {
    let credentials = AsciiProfile::prepare("user", SecretString::new("pencil"))?;
    let config = ClientConfig::builder(Algorithm::Sha256)
        .credentials(credentials)
        .channel_binding(ChannelBindingMode::Unsupported)
        .policy(ClientPolicy::default())
        .build()?;
    let mut nonce = FixedNonce([
        0xac, 0xea, 0x6b, 0x34, 0x67, 0xf0, 0x11, 0xb7, 0x91, 0x5a, 0x06, 0xcd, 0x12, 0x4a, 0x8e,
    ]);
    let (client, first) = Client::start(config, &mut nonce)?;
    assert_eq!(first.as_bytes(), CLIENT_FIRST);
    let pending = client.receive_server_first(SERVER_FIRST)?;
    let (client, final_message) = pending.derive()?;
    assert_eq!(final_message.as_bytes(), CLIENT_FINAL);
    let authenticated = client.receive_server_final(SERVER_FINAL)?;
    assert_eq!(authenticated.algorithm(), Algorithm::Sha256);
    Ok(())
}

#[test]
fn rfc7677_intermediate_derivations_match_independent_values() -> Result<(), Error> {
    let salt = expected::<16>("5b6d99689d12358eeca04b141236fa81")?;
    let auth_message = [
        CLIENT_FIRST.split_at(3).1,
        b",",
        SERVER_FIRST,
        b",",
        CLIENT_FINAL_WITHOUT_PROOF,
    ]
    .concat();
    let salted = sha256_backend::salted_password(b"pencil", &salt, 4096)?;
    assert_eq!(
        salted.as_ref(),
        &expected::<32>("c4a49510323ab4f952cac1fa99441939e78ea74d6be81ddf7096e87513dc615d")?
    );
    let client_key = sha256_backend::client_key(salted.as_ref())?;
    assert_eq!(
        client_key.as_ref(),
        &expected::<32>("a60fc923d67e8644a92d16b96eda5ef4656b0c725c484374be25535576996e8b")?
    );
    let stored_key = sha256_backend::stored_key(client_key.as_ref());
    assert_eq!(
        stored_key.as_ref(),
        &expected::<32>("586e5df283e6dceb5c3e791d8b8528ec191e664045ce971792e2e6b5bb13e2a6")?
    );
    let client_signature = sha256_backend::client_signature(stored_key.as_ref(), &auth_message)?;
    assert_eq!(
        client_signature.as_ref(),
        &expected::<32>("d27312467c28a40a8a7f05c73c0de33eb3cbfb4a83783b58144cf19ac6be1bdf")?
    );
    let proof = sha256_backend::client_proof(client_key.as_ref(), client_signature.as_ref());
    assert_eq!(
        proof.as_ref(),
        &expected::<32>("747cdb65aa56224e2352137e52d7bdcad6a0f738df30782caa69a2cfb0277554")?
    );
    let server_key = sha256_backend::server_key(salted.as_ref())?;
    assert_eq!(
        server_key.as_ref(),
        &expected::<32>("c1f3cbc1c13a9d35a14c0990eed97629ea225863e566a4314ab99f3f00e5d9d5")?
    );
    let server_signature = sha256_backend::hmac_sha256(server_key.as_ref(), &auth_message)?;
    let expected_signature =
        expected::<32>("eabae24d1062db75a9451ff0b6ea7e98c8546549ff741e672d3251b2397de46e")?;
    assert_eq!(server_signature.as_ref(), &expected_signature);
    let complete = sha256_backend::derive_client(b"pencil", &salt, 4096, &auth_message)?;
    assert_eq!(complete.proof.as_ref(), proof.as_ref());
    assert_eq!(complete.server_signature.as_ref(), &expected_signature);
    let server_credential = sha256_backend::derive_server_credential(b"pencil", &salt, 4096)?;
    assert_eq!(server_credential.stored_key.as_ref(), stored_key.as_ref());
    assert_eq!(server_credential.server_key.as_ref(), server_key.as_ref());
    let verified = sha256_backend::verify_client_proof(
        stored_key.as_ref(),
        server_key.as_ref(),
        &auth_message,
        proof.as_ref(),
    )?;
    assert!(verified.valid);
    assert_eq!(verified.server_signature.as_ref(), &expected_signature);
    for bit in 0..proof.len() * 8 {
        let mut mutated = *proof;
        mutated[bit / 8] ^= 1 << (bit % 8);
        assert!(
            !sha256_backend::verify_client_proof(
                stored_key.as_ref(),
                server_key.as_ref(),
                &auth_message,
                &mutated,
            )?
            .valid
        );
    }
    let synthetic = sha256_backend::derive_synthetic_credential(b"conceal", b"missing", 32)?;
    assert_eq!(
        synthetic.salt.as_slice(),
        &expected::<32>("92ad6c598f21a5b6b91975ba749cc3692f49e2c55ff6db78e88498547b4cbc81")?
    );
    assert_eq!(
        synthetic.stored_key.as_ref(),
        &expected::<32>("a25ffab28fba3766e3cc99161aa1aa3ef7d58d9659dfd7807338f28b83f82055")?
    );
    assert_eq!(
        synthetic.server_key.as_ref(),
        &expected::<32>("deb951d0d990cf520ca47a0a616e7cede70c6da286da3dcb9afe9bb23a1b0c6d")?
    );
    Ok(())
}

#[test]
fn authenticated_transcript_mutation_invalidates_the_rfc_server_verifier() -> Result<(), Error> {
    let credentials = AsciiProfile::prepare("user", SecretString::new("pencil"))?;
    let config = ClientConfig::builder(Algorithm::Sha256)
        .credentials(credentials)
        .channel_binding(ChannelBindingMode::Unsupported)
        .build()?;
    let mut nonce = FixedNonce([
        0xac, 0xea, 0x6b, 0x34, 0x67, 0xf0, 0x11, 0xb7, 0x91, 0x5a, 0x06, 0xcd, 0x12, 0x4a, 0x8e,
    ]);
    let (client, _) = Client::start(config, &mut nonce)?;
    let pending = client.receive_server_first(
        b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,x=kept",
    )?;
    let (client, _final_message) = pending.derive()?;
    assert!(matches!(
        client.receive_server_final(SERVER_FINAL),
        Err(Error::Authentication(
            AuthenticationError::InvalidServerSignature
        ))
    ));
    Ok(())
}

#[test]
fn constant_time_verifier_rejects_every_one_bit_signature_mutation() -> Result<(), Error> {
    let expected_signature =
        expected::<32>("eabae24d1062db75a9451ff0b6ea7e98c8546549ff741e672d3251b2397de46e")?;
    for bit in 0..expected_signature.len() * 8 {
        let mut mutated = expected_signature;
        mutated[bit / 8] ^= 1 << (bit % 8);
        assert!(!verify::constant_time_eq(&expected_signature, &mutated));
    }
    Ok(())
}

#[test]
fn client_proof_fails_after_every_one_bit_transcript_mutation() -> Result<(), Error> {
    let salt = expected::<16>("5b6d99689d12358eeca04b141236fa81")?;
    let auth_message = [
        CLIENT_FIRST.split_at(3).1,
        b",",
        SERVER_FIRST,
        b",",
        CLIENT_FINAL_WITHOUT_PROOF,
    ]
    .concat();
    let client = sha256_backend::derive_client(b"pencil", &salt, 4096, &auth_message)?;
    let server = sha256_backend::derive_server_credential(b"pencil", &salt, 4096)?;
    for bit in 0..auth_message.len() * 8 {
        let mut mutated = auth_message.clone();
        mutated[bit / 8] ^= 1 << (bit % 8);
        assert!(
            !sha256_backend::verify_client_proof(
                server.stored_key.as_ref(),
                server.server_key.as_ref(),
                &mutated,
                client.proof.as_ref(),
            )?
            .valid
        );
    }
    Ok(())
}

#[test]
fn retained_secret_state_is_zeroize_on_drop() {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    assert_zeroize_on_drop::<sha2::Sha256>();
    assert_zeroize_on_drop::<zeroize::Zeroizing<[u8; 32]>>();
}

fn expected<const N: usize>(hex: &str) -> Result<[u8; N], Error> {
    if hex.len() != N * 2 {
        return Err(CryptoError::Unavailable.into());
    }
    let mut output = [0_u8; N];
    for (index, destination) in output.iter_mut().enumerate() {
        let high = nibble(hex.as_bytes()[index * 2])?;
        let low = nibble(hex.as_bytes()[index * 2 + 1])?;
        *destination = high << 4 | low;
    }
    Ok(output)
}

fn nibble(value: u8) -> Result<u8, Error> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(CryptoError::Unavailable.into()),
    }
}
