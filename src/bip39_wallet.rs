use anyhow::{bail, Result};
use bip39::{Language, Mnemonic};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub struct DerivedKeys {
    pub seed: [u8; 64],
    pub wallet_address: String,
}

impl Drop for DerivedKeys {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// Generates a standard BIP-39 mnemonic phrase (12 or 24 words).
pub fn generate_mnemonic(word_count: usize) -> Result<String> {
    let entropy_len = match word_count {
        12 => 16,
        24 => 32,
        n => bail!("Mnemonic must be 12 or 24 words, got {}", n),
    };
    let mut entropy = vec![0u8; entropy_len];
    getrandom::getrandom(&mut entropy)
        .map_err(|e| anyhow::anyhow!("Hardware RNG failure: {}", e))?;

    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|e| anyhow::anyhow!("Failed to generate mnemonic: {}", e))?;
    Ok(mnemonic.to_string())
}

/// Validates a BIP-39 mnemonic phrase and derives the 64-byte seed and EIP-55 wallet address.
pub fn mnemonic_to_keys(phrase: &str, passphrase: &str) -> Result<DerivedKeys> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase.trim())
        .map_err(|e| anyhow::anyhow!("Invalid BIP-39 mnemonic phrase: {}", e))?;

    let seed_slice = mnemonic.to_seed(passphrase);
    let mut seed = [0u8; 64];
    seed.copy_from_slice(&seed_slice);

    // Derive EIP-55 Address from the second 32 bytes of the seed
    let pub_hash = Sha256::digest(&seed[32..64]);
    let raw_addr = hex::encode(&pub_hash[..20]);
    let wallet_address = to_eip55_checksum(&raw_addr);

    Ok(DerivedKeys { seed, wallet_address })
}

/// Formats an Ethereum address into an EIP-55 mixed-case checksum address.
fn to_eip55_checksum(hex_addr: &str) -> String {
    let lower = hex_addr.to_ascii_lowercase();
    let hash = Sha256::digest(lower.as_bytes());
    let hash_hex = hex::encode(&hash);

    let mut checksum = String::with_capacity(42);
    checksum.push_str("0x");

    for (i, c) in lower.chars().enumerate() {
        if c.is_ascii_digit() {
            checksum.push(c);
        } else {
            let nibble = u8::from_str_radix(&hash_hex[i..i + 1], 16).unwrap_or(0);
            if nibble >= 8 {
                checksum.push(c.to_ascii_uppercase());
            } else {
                checksum.push(c);
            }
        }
    }
    checksum
}

mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
