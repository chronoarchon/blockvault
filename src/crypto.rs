use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{bail, Result};
use zeroize::Zeroizing;

pub const SCRYPT_LOG_N: u8 = 14; // N = 16384 (2^14)
pub const SCRYPT_R: u32 = 8;
pub const SCRYPT_P: u32 = 1;

/// Derives a 32-byte AES-256 key using memory-hard Scrypt (N=16384, r=8, p=1).
/// The returned key automatically zeroes its memory when dropped.
pub fn derive_key(seed: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = [0u8; 32];
    let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, 32)
        .map_err(|e| anyhow::anyhow!("Invalid Scrypt parameters: {}", e))?;

    scrypt::scrypt(seed, salt, &params, &mut key)
        .map_err(|e| anyhow::anyhow!("Scrypt key derivation failed: {}", e))?;

    Ok(Zeroizing::new(key))
}

/// Generates a cryptographically secure random 12-byte IV for AES-256-GCM.
pub fn generate_iv() -> Result<[u8; 12]> {
    let mut iv = [0u8; 12];
    getrandom::getrandom(&mut iv)
        .map_err(|e| anyhow::anyhow!("Hardware RNG failure: {}", e))?;
    Ok(iv)
}

/// Generates a cryptographically secure random 32-byte salt for Scrypt.
pub fn generate_salt() -> Result<[u8; 32]> {
    let mut salt = [0u8; 32];
    getrandom::getrandom(&mut salt)
        .map_err(|e| anyhow::anyhow!("Hardware RNG failure: {}", e))?;
    Ok(salt)
}

/// Encrypts plaintext using AES-256-GCM with AAD.
/// Returns (ciphertext, 16-byte authentication tag).
pub fn encrypt_aes_gcm(
    key: &[u8; 32],
    iv: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; 16])> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("Failed to initialize AES-256-GCM cipher: {}", e))?;
    let nonce = Nonce::from_slice(iv);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let mut ciphertext_and_tag = cipher
        .encrypt(nonce, payload)
        .map_err(|e| anyhow::anyhow!("AES-256-GCM encryption failed: {}", e))?;

    if ciphertext_and_tag.len() < 16 {
        bail!("Ciphertext output too short to contain tag");
    }

    let tag_start = ciphertext_and_tag.len() - 16;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ciphertext_and_tag[tag_start..]);
    ciphertext_and_tag.truncate(tag_start);

    Ok((ciphertext_and_tag, tag))
}

/// Decrypts ciphertext and verifies the 16-byte authentication tag with AAD.
pub fn decrypt_aes_gcm(
    key: &[u8; 32],
    iv: &[u8; 12],
    ciphertext: &[u8],
    tag: &[u8; 16],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("Failed to initialize AES-256-GCM cipher: {}", e))?;
    let nonce = Nonce::from_slice(iv);

    let mut payload_bytes = Vec::with_capacity(ciphertext.len() + 16);
    payload_bytes.extend_from_slice(ciphertext);
    payload_bytes.extend_from_slice(tag);

    let payload = Payload {
        msg: &payload_bytes,
        aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| anyhow::anyhow!("Decryption failed: Authentication tag mismatch or invalid seed phrase."))
}
