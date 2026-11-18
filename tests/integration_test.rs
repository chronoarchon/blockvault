use std::fs;
use sha2::{Digest, Sha256};

use blockvault::bip39_wallet::{generate_mnemonic, mnemonic_to_keys};
use blockvault::crypto::{derive_key, encrypt_aes_gcm, decrypt_aes_gcm, generate_iv};
use blockvault::merkle::compute_merkle_tree;
use blockvault::vault::{lock_folder, unlock_block, inspect_block, smart_resolve_path, get_user_home};

// =========================================================================
// STAGE 1: BIP-39 Mnemonic Generation & Checksum Validation
// =========================================================================
#[test]
fn stage_1_bip39_generation_and_checksum_validation() {
    // 12-word generation
    let phrase_12 = generate_mnemonic(12).expect("Should generate 12-word mnemonic");
    let words_12: Vec<&str> = phrase_12.split_whitespace().collect();
    assert_eq!(words_12.len(), 12, "12-word phrase must contain exactly 12 words");

    // 24-word generation
    let phrase_24 = generate_mnemonic(24).expect("Should generate 24-word mnemonic");
    let words_24: Vec<&str> = phrase_24.split_whitespace().collect();
    assert_eq!(words_24.len(), 24, "24-word phrase must contain exactly 24 words");

    // Invalid word count rejection
    assert!(generate_mnemonic(16).is_err(), "Must reject non-standard word count");

    // Checksum validation
    let keys = mnemonic_to_keys(&phrase_12, "").expect("Valid phrase must derive keys");
    assert!(!keys.wallet_address.is_empty());
    assert!(keys.wallet_address.starts_with("0x"));

    // Tampered word rejection (corrupting first word)
    let corrupted_phrase = format!("invalidword {}", words_12[1..].join(" "));
    assert!(mnemonic_to_keys(&corrupted_phrase, "").is_err(), "Invalid word must fail");

    // Checksum mismatch rejection (swapping two valid words breaks checksum)
    let swapped_phrase = format!("{} {} {}", words_12[1], words_12[0], words_12[2..].join(" "));
    assert!(mnemonic_to_keys(&swapped_phrase, "").is_err(), "Swapped words must fail checksum");
}

// =========================================================================
// STAGE 2: BIP-39 Passphrase Entropy Isolation (13th/25th Word)
// =========================================================================
#[test]
fn stage_2_passphrase_entropy_isolation() {
    let phrase = "rabbit element survey depth traffic walk battle nuclear quality awkward shrug fault";

    let keys_no_pass = mnemonic_to_keys(phrase, "").unwrap();
    let keys_pass_a = mnemonic_to_keys(phrase, "VaultPass#2026").unwrap();
    let keys_pass_b = mnemonic_to_keys(phrase, "VaultPass#Different").unwrap();

    // All master seeds must be completely distinct
    assert_ne!(keys_no_pass.seed, keys_pass_a.seed, "Passphrase must derive different seed");
    assert_ne!(keys_pass_a.seed, keys_pass_b.seed, "Different passphrases must derive different seeds");

    // Wallet addresses must be distinct
    assert_ne!(keys_no_pass.wallet_address, keys_pass_a.wallet_address);
    assert_ne!(keys_pass_a.wallet_address, keys_pass_b.wallet_address);
}

// =========================================================================
// STAGE 3: Memory-Hard Scrypt Key Derivation (N=16384, r=8, p=1)
// =========================================================================
#[test]
fn stage_3_scrypt_kdf_memory_hardness_and_determinism() {
    let seed = [42u8; 64];
    let salt = [7u8; 32];

    let key1 = derive_key(&seed, &salt).unwrap();
    let key2 = derive_key(&seed, &salt).unwrap();
    assert_eq!(*key1, *key2, "Scrypt must be deterministic for identical inputs");

    // Avalanche effect: 1 bit flip in salt must produce completely distinct key
    let mut alt_salt = salt;
    alt_salt[0] ^= 0x01;
    let key_alt = derive_key(&seed, &alt_salt).unwrap();
    assert_ne!(*key1, *key_alt, "1-bit salt flip must completely change derived key");
}

// =========================================================================
// STAGE 4: AES-256-GCM Authenticated Encryption & AAD Tamper Detection
// =========================================================================
#[test]
fn stage_4_aes_256_gcm_authenticated_encryption() {
    let key = [0x5au8; 32];
    let iv = generate_iv().unwrap();
    let plaintext = b"BlockVault Sovereign Cryptographic Payload";
    let aad = b"BlockHeaderV2:Root=0x1234";

    let (ciphertext, tag) = encrypt_aes_gcm(&key, &iv, plaintext, aad).unwrap();
    assert_ne!(ciphertext, plaintext, "Ciphertext must not match plaintext");

    // Valid decryption
    let decrypted = decrypt_aes_gcm(&key, &iv, &ciphertext, &tag, aad).unwrap();
    assert_eq!(decrypted, plaintext, "Decrypted data must match original plaintext");

    // Tampered AAD rejection
    let tampered_aad = b"BlockHeaderV2:Root=0x9999";
    assert!(
        decrypt_aes_gcm(&key, &iv, &ciphertext, &tag, tampered_aad).is_err(),
        "Tampered AAD must cause authentication failure"
    );

    // Tampered Tag rejection
    let mut tampered_tag = tag;
    tampered_tag[0] ^= 0xff;
    assert!(
        decrypt_aes_gcm(&key, &iv, &ciphertext, &tampered_tag, aad).is_err(),
        "Tampered Tag must cause authentication failure"
    );

    // Tampered Ciphertext rejection
    let mut tampered_cipher = ciphertext.clone();
    tampered_cipher[0] ^= 0xff;
    assert!(
        decrypt_aes_gcm(&key, &iv, &tampered_cipher, &tag, aad).is_err(),
        "Tampered Ciphertext must cause authentication failure"
    );
}

// =========================================================================
// STAGE 5: RFC 6962 Merkle Tree Determinism & Path Normalization
// =========================================================================
#[test]
fn stage_5_merkle_tree_determinism_and_path_normalization() {
    let temp_dir = std::env::temp_dir().join("bv_qa_stage5_merkle");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(temp_dir.join("nested/deep")).unwrap();

    fs::write(temp_dir.join("file_a.txt"), b"Document Alpha").unwrap();
    fs::write(temp_dir.join("nested/file_b.bin"), &[1, 2, 3, 4, 5]).unwrap();
    fs::write(temp_dir.join("nested/deep/file_c.json"), b"{\"key\":\"value\"}").unwrap();

    let tree1 = compute_merkle_tree(&temp_dir).unwrap();
    let tree2 = compute_merkle_tree(&temp_dir).unwrap();
    assert_eq!(tree1.root, tree2.root, "Merkle tree must be strictly deterministic");
    assert_eq!(tree1.files.len(), 3);

    // Verify all relative paths use POSIX forward slash '/'
    for f in &tree1.files {
        assert!(!f.path.contains('\\'), "Paths in Merkle ledger must never contain Windows backslashes");
    }

    // Sensitivity test: 1-byte modification in any file changes the root completely
    fs::write(temp_dir.join("nested/deep/file_c.json"), b"{\"key\":\"valuX\"}").unwrap();
    let tree_tampered = compute_merkle_tree(&temp_dir).unwrap();
    assert_ne!(tree1.root, tree_tampered.root, "1-byte file change must alter Merkle root");

    let _ = fs::remove_dir_all(&temp_dir);
}

// =========================================================================
// STAGE 6: End-to-End Vault Packing, Inspection, and Verification
// =========================================================================
#[test]
fn stage_6_vault_end_to_end_pack_inspect_verify() {
    let temp_dir = std::env::temp_dir().join("bv_qa_stage6_vault");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(temp_dir.join("docs")).unwrap();

    fs::write(temp_dir.join("docs/contract.txt"), b"Sovereign Agreement 2026").unwrap();
    fs::write(temp_dir.join("readme.md"), b"# Welcome to BlockVault").unwrap();

    // Lock folder
    let lock_res = lock_folder(&temp_dir, None, 12, "my-safe-pass", false).unwrap();
    assert!(lock_res.block_path.exists());
    assert_eq!(lock_res.file_count, 2);

    // Inspect without keys
    let (header, total_size) = inspect_block(&lock_res.block_path).unwrap();
    assert_eq!(header.merkle_root, lock_res.merkle_root);
    assert_eq!(header.file_count, 2);
    assert_eq!(header.algorithm, "AES-256-GCM");
    assert!(total_size > 0);

    // Unlock
    let restore_dir = std::env::temp_dir().join("bv_qa_stage6_restored");
    let _ = fs::remove_dir_all(&restore_dir);

    let unlock_res = unlock_block(
        &lock_res.block_path,
        Some(&restore_dir),
        &lock_res.mnemonic,
        "my-safe-pass",
        false,
    ).unwrap();

    assert!(unlock_res.merkle_verified, "Merkle verification must report 100% match");
    assert_eq!(unlock_res.file_count, 2);

    // Verify contents
    let restored_contract = restore_dir.join("bv_qa_stage6_vault/docs/contract.txt");
    assert_eq!(fs::read(restored_contract).unwrap(), b"Sovereign Agreement 2026");

    let _ = fs::remove_dir_all(&temp_dir);
    let _ = fs::remove_file(&lock_res.block_path);
    let _ = fs::remove_dir_all(&restore_dir);
}

// =========================================================================
// STAGE 7: Complex Multi-Megabyte Binary & Deep Hierarchy Payload
// =========================================================================
#[test]
fn stage_7_complex_multi_megabyte_payload() {
    let temp_dir = std::env::temp_dir().join("bv_qa_stage7_large");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(temp_dir.join("a/b/c/d/e")).unwrap();

    // 1MB pseudorandom binary payload
    let mut large_blob = vec![0u8; 1024 * 1024];
    for (i, b) in large_blob.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let expected_hash = format!("{:x}", Sha256::digest(&large_blob));

    fs::write(temp_dir.join("a/b/c/d/e/payload.bin"), &large_blob).unwrap();
    fs::write(temp_dir.join("unicode_⚡_ファイル.txt"), "Unicode UTF-8 content ✓").unwrap();

    let lock_res = lock_folder(&temp_dir, None, 24, "", false).unwrap();

    let restore_dir = std::env::temp_dir().join("bv_qa_stage7_restored");
    let _ = fs::remove_dir_all(&restore_dir);

    let unlock_res = unlock_block(
        &lock_res.block_path,
        Some(&restore_dir),
        &lock_res.mnemonic,
        "",
        false,
    ).unwrap();

    assert!(unlock_res.merkle_verified);
    let restored_blob = fs::read(restore_dir.join("bv_qa_stage7_large/a/b/c/d/e/payload.bin")).unwrap();
    let restored_hash = format!("{:x}", Sha256::digest(&restored_blob));
    assert_eq!(expected_hash, restored_hash, "Binary hash must match across extraction");

    let _ = fs::remove_dir_all(&temp_dir);
    let _ = fs::remove_file(&lock_res.block_path);
    let _ = fs::remove_dir_all(&restore_dir);
}

// =========================================================================
// STAGE 8: Tampered Container & Wrong Seed Rejection
// =========================================================================
#[test]
fn stage_8_tampered_container_and_wrong_seed_rejection() {
    let temp_dir = std::env::temp_dir().join("bv_qa_stage8_tamper");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    fs::write(temp_dir.join("secret.key"), b"private-key-data").unwrap();

    let lock_res = lock_folder(&temp_dir, None, 12, "correct-pass", false).unwrap();
    let restore_dir = std::env::temp_dir().join("bv_qa_stage8_restored");

    // 1. Wrong mnemonic phrase rejection
    let alt_mnemonic = generate_mnemonic(12).unwrap();
    assert!(
        unlock_block(&lock_res.block_path, Some(&restore_dir), &alt_mnemonic, "correct-pass", false).is_err(),
        "Wrong mnemonic must fail decryption"
    );

    // 2. Wrong passphrase rejection
    assert!(
        unlock_block(&lock_res.block_path, Some(&restore_dir), &lock_res.mnemonic, "wrong-pass", false).is_err(),
        "Wrong passphrase must fail decryption"
    );

    // 3. Bit-flip tampering in block file
    let mut block_bytes = fs::read(&lock_res.block_path).unwrap();
    let last_idx = block_bytes.len() - 1;
    block_bytes[last_idx] ^= 0x01; // flip 1 bit in ciphertext
    let tampered_path = temp_dir.join("tampered.block");
    fs::write(&tampered_path, &block_bytes).unwrap();

    assert!(
        unlock_block(&tampered_path, Some(&restore_dir), &lock_res.mnemonic, "correct-pass", false).is_err(),
        "Tampered container bit-flip must be rejected by AES-256-GCM authentication"
    );

    let _ = fs::remove_dir_all(&temp_dir);
    let _ = fs::remove_file(&lock_res.block_path);
    let _ = fs::remove_dir_all(&restore_dir);
}

// =========================================================================
// STAGE 9: In-Place Locker Mode (--replace) Verification
// =========================================================================
#[test]
fn stage_9_replace_and_in_place_locker_mode() {
    let temp_dir = std::env::temp_dir().join("bv_qa_stage9_replace");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    fs::write(temp_dir.join("doc.pdf"), b"%PDF-1.4 sample content").unwrap();

    // Lock with replace = true (deletes source directory)
    let lock_res = lock_folder(&temp_dir, None, 12, "", true).unwrap();
    assert!(!temp_dir.exists(), "Source folder must be securely removed in replace mode");
    assert!(lock_res.block_path.exists(), "Container block file must exist");

    // Unlock with replace = true (deletes .block container)
    let restore_dir = std::env::temp_dir().join("bv_qa_stage9_restored");
    let _ = fs::remove_dir_all(&restore_dir);

    let unlock_res = unlock_block(&lock_res.block_path, Some(&restore_dir), &lock_res.mnemonic, "", true).unwrap();
    assert!(!lock_res.block_path.exists(), "Block file must be removed after replace unlock");
    assert!(unlock_res.extracted_folder.exists(), "Extracted folder must exist");

    let _ = fs::remove_dir_all(&restore_dir);
}

// =========================================================================
// STAGE 10: Cross-Platform Path Resolution & Typo Resilience
// =========================================================================
#[test]
fn stage_10_cross_platform_path_resolver() {
    let home = get_user_home();
    assert!(home.exists(), "User home directory must exist on target platform");

    // Tilde expansion
    let resolved_tilde = smart_resolve_path("~/Documents", "").unwrap();
    assert_eq!(resolved_tilde, home.join("Documents"));

    // Default extension appending
    let resolved_ext = smart_resolve_path("testfile", ".block").unwrap();
    assert!(resolved_ext.to_string_lossy().ends_with(".block"));

    // Root-typo recovery (/Downloads/restored without ~)
    let typo_resolved = smart_resolve_path("/Downloads/my-vault", "").unwrap();
    assert_eq!(typo_resolved, home.join("Downloads/my-vault"));
}
