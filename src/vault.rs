use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use crate::bip39_wallet::{generate_mnemonic, mnemonic_to_keys};
use crate::crypto::{decrypt_aes_gcm, derive_key, encrypt_aes_gcm, generate_iv, generate_salt};
use crate::merkle::{compute_merkle_tree, compute_merkle_tree_with_progress, MerkleFileEntry};

pub const MAGIC: &[u8; 8] = b"BLKVAULT";
pub const VERSION: u16 = 2;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlockHeader {
    pub block_version: u16,
    pub block_height: u64,
    pub timestamp: String,
    pub creator_wallet: String,
    pub folder_name: String,
    pub merkle_root: String,
    pub algorithm: String,
    pub kdf: String,
    pub word_count: usize,
    pub has_passphrase: bool,
    pub salt_hex: String,
    pub iv_hex: String,
    pub auth_tag_hex: String,
    pub payload_size: usize,
    pub file_count: usize,
    pub files: Vec<MerkleFileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockResult {
    pub block_path: PathBuf,
    pub mnemonic: String,
    pub wallet_address: String,
    pub merkle_root: String,
    pub file_count: usize,
    pub payload_size: usize,
    pub total_size: usize,
    pub replaced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockResult {
    pub extracted_folder: PathBuf,
    pub creator_wallet: String,
    pub merkle_root: String,
    pub merkle_verified: bool,
    pub file_count: usize,
}

/// Returns the current user's home directory across Linux, macOS ($HOME) and Windows ($USERPROFILE).
pub fn get_user_home() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(h) = std::env::var("USERPROFILE") {
            return PathBuf::from(h);
        }
    }
    if let Ok(h) = std::env::var("HOME") {
        PathBuf::from(h)
    } else if let Ok(h) = std::env::var("USERPROFILE") {
        PathBuf::from(h)
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    }
}

/// Smart path resolver that handles missing leading slashes, '~' expansion, root-typo redirects (/Downloads -> ~/Downloads),
/// automatic extension appending, and smart search in ~/Downloads and ~/Documents.
pub fn smart_resolve_path(input: &str, default_ext: &str) -> Option<PathBuf> {
    let trimmed = input
        .trim()
        .trim_matches('\'')
        .trim_matches('"')
        .trim();
    if trimmed.is_empty() {
        return None;
    }

    let home_path = get_user_home();
    let home = home_path.to_string_lossy().to_string();

    // 1. Handle common typo: "/Downloads/..." or "/Documents/..." when user accidentally used root "/" instead of "~/"
    let adjusted = if trimmed.starts_with("/Downloads")
        || trimmed.starts_with("/Documents")
        || trimmed.starts_with("/Desktop")
        || trimmed.starts_with("/Music")
        || trimmed.starts_with("/Videos")
        || trimmed.starts_with("/Pictures")
    {
        let p_root = Path::new(trimmed);
        if !p_root.exists() {
            home_path.join(trimmed.trim_start_matches('/')).to_string_lossy().to_string()
        } else {
            trimmed.to_string()
        }
    } else if trimmed.starts_with('~') {
        trimmed.replacen('~', &home, 1)
    } else if trimmed.starts_with("home/") {
        format!("/{}", trimmed)
    } else {
        trimmed.to_string()
    };

    let p = PathBuf::from(&adjusted);

    // If looking for a specific extension (e.g. .block), check with extension first
    if !default_ext.is_empty() && !p.to_string_lossy().ends_with(default_ext) {
        let ext_dot = if default_ext.starts_with('.') {
            default_ext.to_string()
        } else {
            format!(".{}", default_ext)
        };

        // 1. Try direct append (e.g. "song.mp3" -> "song.mp3.block")
        let mut direct_app = p.as_os_str().to_os_string();
        direct_app.push(&ext_dot);
        let direct_p = PathBuf::from(direct_app);
        if direct_p.is_file() {
            return Some(direct_p);
        }

        // 2. Try set_extension (e.g. "folder" -> "folder.block")
        let mut with_ext = p.clone();
        let ext = default_ext.trim_start_matches('.');
        with_ext.set_extension(ext);
        if with_ext.is_file() {
            return Some(with_ext);
        }
    }

    // If path exists as-is, return it
    if p.exists() {
        return Some(p);
    }

    // If relative path and not found in current directory, check in ~/Downloads/ and ~/Documents/
    if !p.is_absolute() {
        if !default_ext.is_empty() {
            let ext_dot = if default_ext.starts_with('.') {
                default_ext.to_string()
            } else {
                format!(".{}", default_ext)
            };

            // 1. Direct append in ~/Downloads
            let mut dl_app = home_path.join("Downloads").join(&p).into_os_string();
            dl_app.push(&ext_dot);
            let dl_app_p = PathBuf::from(dl_app);
            if dl_app_p.is_file() {
                return Some(dl_app_p);
            }

            // 2. Set extension in ~/Downloads
            let mut dl_ext = home_path.join("Downloads").join(&p);
            dl_ext.set_extension(default_ext.trim_start_matches('.'));
            if dl_ext.is_file() {
                return Some(dl_ext);
            }
        }
        let in_downloads = home_path.join("Downloads").join(&p);
        if in_downloads.exists() {
            return Some(in_downloads);
        }

        if !default_ext.is_empty() {
            let ext_dot = if default_ext.starts_with('.') {
                default_ext.to_string()
            } else {
                format!(".{}", default_ext)
            };

            // 1. Direct append in ~/Documents
            let mut doc_app = home_path.join("Documents").join(&p).into_os_string();
            doc_app.push(&ext_dot);
            let doc_app_p = PathBuf::from(doc_app);
            if doc_app_p.is_file() {
                return Some(doc_app_p);
            }

            // 2. Set extension in ~/Documents
            let mut doc_ext = home_path.join("Documents").join(&p);
            doc_ext.set_extension(default_ext.trim_start_matches('.'));
            if doc_ext.is_file() {
                return Some(doc_ext);
            }
        }
        let in_documents = home_path.join("Documents").join(&p);
        if in_documents.exists() {
            return Some(in_documents);
        }
    }

    // Return the expanded path (for destination/output paths that might not exist yet)
    if !default_ext.is_empty() && !p.to_string_lossy().ends_with(default_ext) {
        let mut with_ext = p;
        with_ext.set_extension(default_ext.trim_start_matches('.'));
        Some(with_ext)
    } else {
        Some(p)
    }
}

/// Tar-gzips a directory or a single file into a memory buffer.
fn archive_payload(target_path: &Path) -> Result<Vec<u8>> {
    let name = target_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Target path has no name"))?;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut tar = tar::Builder::new(&mut encoder);
        if target_path.is_file() {
            tar.append_path_with_name(target_path, name)
                .context("Failed to build tar archive of file")?;
        } else {
            tar.append_dir_all(name, target_path)
                .context("Failed to build tar archive of directory")?;
        }
        tar.finish()?;
    }
    encoder.finish().context("Failed to gzip compress payload")
}

/// Extracts a tar-gzip buffer into a destination directory.
fn extract_archive(tar_gz: &[u8], dest_dir: &Path) -> Result<()> {
    let cursor = Cursor::new(tar_gz);
    let decoder = GzDecoder::new(cursor);
    let mut archive = tar::Archive::new(decoder);
    archive
        .unpack(dest_dir)
        .context("Failed to unpack tar archive")?;
    Ok(())
}

#[derive(Debug, Clone)]
pub enum LockProgress<'a> {
    HashingFile { current: usize, total: usize, path: &'a str, bytes: u64 },
    DerivingKeys,
    CompressingPayload,
    EncryptingContainer,
}

#[derive(Debug, Clone, Copy)]
pub enum UnlockProgress {
    InspectingHeader,
    DerivingKeys,
    DecryptingAndUnpacking,
    VerifyingMerkleRoot,
}

pub fn lock_folder(
    folder_path: &Path,
    output_path: Option<&Path>,
    word_count: usize,
    passphrase: &str,
    replace: bool,
) -> Result<LockResult> {
    lock_folder_with_progress(
        folder_path,
        output_path,
        word_count,
        passphrase,
        replace,
        |_| {},
    )
}

pub fn lock_folder_with_progress<F>(
    folder_path: &Path,
    output_path: Option<&Path>,
    word_count: usize,
    passphrase: &str,
    replace: bool,
    mut progress_cb: F,
) -> Result<LockResult>
where
    F: FnMut(LockProgress),
{
    if !folder_path.exists() {
        bail!("Path '{}' does not exist.", folder_path.display());
    }

    let folder_name = folder_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let parent = folder_path
        .parent()
        .unwrap_or_else(|| Path::new("."));

    let out_block = match output_path {
        Some(p) => p.to_path_buf(),
        None => parent.join(format!("{}.block", folder_name)),
    };

    // 1. Compute Merkle Tree
    let merkle = compute_merkle_tree_with_progress(folder_path, |current, total, path, bytes| {
        progress_cb(LockProgress::HashingFile { current, total, path, bytes });
    })?;

    // 2. BIP-39 Mnemonic & Seed + 3. Derive Key via Scrypt
    progress_cb(LockProgress::DerivingKeys);
    let mnemonic = generate_mnemonic(word_count)?;
    let derived = mnemonic_to_keys(&mnemonic, passphrase)?;

    let salt = generate_salt()?;
    let aes_key = derive_key(&derived.seed, &salt)?;
    let iv = generate_iv()?;

    // 4. Archive payload
    progress_cb(LockProgress::CompressingPayload);
    let tar_gz = archive_payload(folder_path)?;

    // 5. Header Pre-Authentication
    progress_cb(LockProgress::EncryptingContainer);
    let now = chrono_timestamp();
    let mut header = BlockHeader {
        block_version: VERSION,
        block_height: 1,
        timestamp: now,
        creator_wallet: derived.wallet_address.clone(),
        folder_name,
        merkle_root: merkle.root.clone(),
        algorithm: "AES-256-GCM".to_string(),
        kdf: "Scrypt-N16384-r8-p1".to_string(),
        word_count,
        has_passphrase: !passphrase.is_empty(),
        salt_hex: hex_encode(&salt),
        iv_hex: hex_encode(&iv),
        auth_tag_hex: String::new(),
        payload_size: tar_gz.len(),
        file_count: merkle.files.len(),
        files: merkle.files,
    };

    let aad = serde_json::to_vec(&header)?;
    let (ciphertext, tag) = encrypt_aes_gcm(&aes_key, &iv, &tar_gz, &aad)?;
    header.auth_tag_hex = hex_encode(&tag);

    let header_bytes = serde_json::to_vec_pretty(&header)?;
    let mut container = Vec::with_capacity(14 + header_bytes.len() + ciphertext.len());

    container.extend_from_slice(MAGIC);
    container.extend_from_slice(&VERSION.to_be_bytes());
    container.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
    container.extend_from_slice(&header_bytes);
    container.extend_from_slice(&ciphertext);

    fs::write(&out_block, &container)
        .context(format!("Failed to write block file '{}'", out_block.display()))?;

    let total_size = container.len();
    if replace {
        if folder_path.is_file() {
            fs::remove_file(folder_path)?;
        } else {
            fs::remove_dir_all(folder_path)?;
        }
    }

    Ok(LockResult {
        block_path: out_block,
        mnemonic,
        wallet_address: derived.wallet_address.clone(),
        merkle_root: merkle.root,
        file_count: header.file_count,
        payload_size: ciphertext.len(),
        total_size,
        replaced: replace,
    })
}

pub fn unlock_block(
    block_path: &Path,
    dest_dir: Option<&Path>,
    phrase: &str,
    passphrase: &str,
    replace: bool,
) -> Result<UnlockResult> {
    unlock_block_with_progress(
        block_path,
        dest_dir,
        phrase,
        passphrase,
        replace,
        |_| {},
    )
}

pub fn unlock_block_with_progress<F>(
    block_path: &Path,
    dest_dir: Option<&Path>,
    phrase: &str,
    passphrase: &str,
    replace: bool,
    mut progress_cb: F,
) -> Result<UnlockResult>
where
    F: FnMut(UnlockProgress),
{
    progress_cb(UnlockProgress::InspectingHeader);
    let data = fs::read(block_path)
        .context(format!("Failed to read block file '{}'", block_path.display()))?;

    if data.len() < 14 || &data[0..8] != MAGIC {
        bail!("File '{}' is not a valid BlockVault container.", block_path.display());
    }

    let version = u16::from_be_bytes([data[8], data[9]]);
    let header_len = u32::from_be_bytes([data[10], data[11], data[12], data[13]]) as usize;

    if data.len() < 14 + header_len {
        bail!("Corrupted container header in '{}'", block_path.display());
    }

    let header_bytes = &data[14..14 + header_len];
    let header: BlockHeader = serde_json::from_slice(header_bytes)
        .context("Failed to parse container JSON header")?;
    let ciphertext = &data[14 + header_len..];

    // Derive Keys from Mnemonic
    progress_cb(UnlockProgress::DerivingKeys);
    let derived = mnemonic_to_keys(phrase, passphrase)?;

    let salt = hex_decode(&header.salt_hex)?;
    let aes_key = derive_key(&derived.seed, &salt)?;
    let iv_bytes = hex_decode(&header.iv_hex)?;
    let tag_bytes = hex_decode(&header.auth_tag_hex)?;

    if iv_bytes.len() != 12 || tag_bytes.len() != 16 {
        bail!("Invalid cryptographic parameter lengths in header");
    }

    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_bytes);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&tag_bytes);

    let mut header_pre = header.clone();
    header_pre.auth_tag_hex = String::new();
    let aad = if version >= 2 {
        serde_json::to_vec(&header_pre)?
    } else {
        Vec::new()
    };

    progress_cb(UnlockProgress::DecryptingAndUnpacking);
    let tar_gz = decrypt_aes_gcm(&aes_key, &iv, ciphertext, &tag, &aad)?;

    let target = match dest_dir {
        Some(d) => d.to_path_buf(),
        None => block_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf(),
    };

    fs::create_dir_all(&target)?;
    extract_archive(&tar_gz, &target)?;

    progress_cb(UnlockProgress::VerifyingMerkleRoot);
    let extracted_folder = target.join(&header.folder_name);
    let verify_merkle = compute_merkle_tree(&extracted_folder)?;
    let merkle_verified = verify_merkle.root == header.merkle_root;

    if replace {
        fs::remove_file(block_path)?;
    }

    Ok(UnlockResult {
        extracted_folder,
        creator_wallet: header.creator_wallet,
        merkle_root: header.merkle_root,
        merkle_verified,
        file_count: header.file_count,
    })
}

pub fn inspect_block(block_path: &Path) -> Result<(BlockHeader, usize)> {
    let data = fs::read(block_path)?;
    if data.len() < 14 || &data[0..8] != MAGIC {
        bail!("File '{}' is not a valid BlockVault container.", block_path.display());
    }

    let header_len = u32::from_be_bytes([data[10], data[11], data[12], data[13]]) as usize;
    let header: BlockHeader = serde_json::from_slice(&data[14..14 + header_len])?;
    Ok((header, data.len()))
}

fn chrono_timestamp() -> String {
    // Generate ISO 8601 UTC timestamp using system time
    let now = std::time::SystemTime::now();
    let duration = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}Z", duration.as_secs(), duration.subsec_millis())
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        bail!("Odd length hex string");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("Invalid hex byte: {}", e))
        })
        .collect()
}
