//! RustCrypto-backed SCRAM-SHA-256 derivation primitives.

extern crate alloc;

use alloc::vec::Vec;

use hmac::{Hmac, KeyInit, Mac};
use pbkdf2::pbkdf2;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::CryptoError;

pub(super) const OUTPUT_LEN: usize = 32;
type SecretOutput = Zeroizing<[u8; OUTPUT_LEN]>;
type HmacSha256 = Hmac<Sha256>;

pub(super) struct DerivedClient {
    pub(super) proof: SecretOutput,
    pub(super) server_signature: SecretOutput,
}

pub(super) struct DerivedServerCredential {
    pub(super) stored_key: SecretOutput,
    pub(super) server_key: SecretOutput,
}

pub(super) struct ClientProofVerification {
    pub(super) valid: bool,
    pub(super) server_signature: SecretOutput,
}

pub(super) struct SyntheticCredential {
    pub(super) salt: Zeroizing<Vec<u8>>,
    pub(super) stored_key: SecretOutput,
    pub(super) server_key: SecretOutput,
}

pub(super) fn derive_client(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    auth_message: &[u8],
) -> Result<DerivedClient, CryptoError> {
    let salted_password = salted_password(password, salt, iterations)?;
    let client_key = client_key(salted_password.as_ref())?;
    let stored_key = stored_key(client_key.as_ref());
    let client_signature = client_signature(stored_key.as_ref(), auth_message)?;
    let proof = client_proof(client_key.as_ref(), client_signature.as_ref());
    let server_key = server_key(salted_password.as_ref())?;
    let server_signature = hmac_sha256(server_key.as_ref(), auth_message)?;
    Ok(DerivedClient {
        proof,
        server_signature,
    })
}

pub(super) fn derive_server_credential(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<DerivedServerCredential, CryptoError> {
    let salted_password = salted_password(password, salt, iterations)?;
    let client_key = client_key(salted_password.as_ref())?;
    let stored_key = stored_key(client_key.as_ref());
    let server_key = server_key(salted_password.as_ref())?;
    Ok(DerivedServerCredential {
        stored_key,
        server_key,
    })
}

pub(super) fn verify_client_proof(
    stored_key: &[u8],
    server_key: &[u8],
    auth_message: &[u8],
    proof: &[u8],
) -> Result<ClientProofVerification, CryptoError> {
    let signature = client_signature(stored_key, auth_message)?;
    let recovered_client_key = client_proof(proof, signature.as_ref());
    let recovered_stored_key = self::stored_key(recovered_client_key.as_ref());
    let server_signature = hmac_sha256(server_key, auth_message)?;
    Ok(ClientProofVerification {
        valid: super::verify::constant_time_eq(stored_key, recovered_stored_key.as_ref()),
        server_signature,
    })
}

pub(super) fn derive_synthetic_credential(
    concealment_key: &[u8],
    authentication_identity: &[u8],
    salt_bytes: usize,
) -> Result<SyntheticCredential, CryptoError> {
    let salt = synthetic_salt(concealment_key, authentication_identity, salt_bytes)?;
    let stored_key = hmac_sha256_parts(
        concealment_key,
        &[
            b"sasl-scram synthetic stored key v2\0SCRAM-SHA-256\0",
            authentication_identity,
        ],
    )?;
    let server_key = hmac_sha256_parts(
        concealment_key,
        &[
            b"sasl-scram synthetic server key v2\0SCRAM-SHA-256\0",
            authentication_identity,
        ],
    )?;
    Ok(SyntheticCredential {
        salt,
        stored_key,
        server_key,
    })
}

fn synthetic_salt(
    key: &[u8],
    identity: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let blocks = length
        .checked_add(OUTPUT_LEN - 1)
        .ok_or(CryptoError::Unavailable)?
        / OUTPUT_LEN;
    if blocks > u32::MAX as usize {
        return Err(CryptoError::Unavailable);
    }
    let mut salt = Zeroizing::new(Vec::with_capacity(length));
    for counter in 0..blocks {
        let counter = u32::try_from(counter)
            .map_err(|_| CryptoError::Unavailable)?
            .to_be_bytes();
        let block = hmac_sha256_parts(
            key,
            &[
                b"sasl-scram synthetic salt v2\0SCRAM-SHA-256\0",
                identity,
                &counter,
            ],
        )?;
        let remaining = length - salt.len();
        salt.extend_from_slice(&block[..remaining.min(OUTPUT_LEN)]);
    }
    Ok(salt)
}

pub(super) fn salted_password(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<SecretOutput, CryptoError> {
    let mut output = Zeroizing::new([0_u8; OUTPUT_LEN]);
    pbkdf2::<HmacSha256>(password, salt, iterations, output.as_mut())
        .map_err(|_| CryptoError::Unavailable)?;
    Ok(output)
}

pub(super) fn client_key(salted_password: &[u8]) -> Result<SecretOutput, CryptoError> {
    hmac_sha256(salted_password, b"Client Key")
}

pub(super) fn stored_key(client_key: &[u8]) -> SecretOutput {
    let mut digest = Sha256::digest(client_key);
    let mut output = Zeroizing::new([0_u8; OUTPUT_LEN]);
    output.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    output
}

pub(super) fn client_signature(
    stored_key: &[u8],
    auth_message: &[u8],
) -> Result<SecretOutput, CryptoError> {
    hmac_sha256(stored_key, auth_message)
}

pub(super) fn client_proof(client_key: &[u8], signature: &[u8]) -> SecretOutput {
    let mut output = Zeroizing::new([0_u8; OUTPUT_LEN]);
    for ((destination, key), signature) in output
        .iter_mut()
        .zip(client_key.iter())
        .zip(signature.iter())
    {
        *destination = key ^ signature;
    }
    output
}

pub(super) fn server_key(salted_password: &[u8]) -> Result<SecretOutput, CryptoError> {
    hmac_sha256(salted_password, b"Server Key")
}

pub(super) fn hmac_sha256(key: &[u8], input: &[u8]) -> Result<SecretOutput, CryptoError> {
    hmac_sha256_parts(key, &[input])
}

fn hmac_sha256_parts(key: &[u8], inputs: &[&[u8]]) -> Result<SecretOutput, CryptoError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| CryptoError::Unavailable)?;
    for input in inputs {
        mac.update(input);
    }
    let tag = mac.finalize();
    let mut bytes = tag.into_bytes();
    let mut output = Zeroizing::new([0_u8; OUTPUT_LEN]);
    output.copy_from_slice(&bytes);
    bytes.as_mut_slice().zeroize();
    Ok(output)
}
