use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleFileEntry {
    pub path: String,
    pub size: u64,
    pub hash: String,
}

#[derive(Debug)]
pub struct MerkleTreeResult {
    pub root: String,
    pub leaf_count: usize,
    pub depth: usize,
    pub files: Vec<MerkleFileEntry>,
}

/// Recursively scans a directory and collects relative file entries.
pub fn scan_folder_files(base_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut dirs = vec![base_dir.to_path_buf()];

    while let Some(current_dir) = dirs.pop() {
        for entry in fs::read_dir(&current_dir)? {
            let entry = entry?;
            let path = entry.path();
            let ft = entry.file_type()?;
            if ft.is_dir() {
                dirs.push(path);
            } else if ft.is_file() {
                files.push(path);
            }
        }
    }

    files.sort();
    Ok(files)
}

/// Computes a domain-separated binary Merkle Tree (RFC 6962 compliant).
pub fn compute_merkle_tree(folder_path: &Path) -> Result<MerkleTreeResult> {
    let full_files = scan_folder_files(folder_path)?;
    let mut file_entries = Vec::with_capacity(full_files.len());

    for f in &full_files {
        let rel_path = f
            .strip_prefix(folder_path)?
            .to_string_lossy()
            .replace('\\', "/");
        let content = fs::read(f)?;
        let hash = format!("{:x}", Sha256::digest(&content));
        file_entries.push(MerkleFileEntry {
            path: rel_path,
            size: content.len() as u64,
            hash,
        });
    }

    file_entries.sort_by(|a, b| a.path.cmp(&b.path));

    let mut current_layer: Vec<[u8; 32]> = file_entries
        .iter()
        .map(|e| {
            let mut hasher = Sha256::new();
            hasher.update([0x00]); // 0x00 leaf domain prefix
            hasher.update(e.path.as_bytes());
            hasher.update(b":");
            hasher.update(e.hash.as_bytes());
            let out: [u8; 32] = hasher.finalize().into();
            out
        })
        .collect();

    if current_layer.is_empty() {
        let mut hasher = Sha256::new();
        hasher.update([0x00]);
        hasher.update(b"EMPTY_DIRECTORY");
        current_layer.push(hasher.finalize().into());
    }

    let mut depth = 1;
    while current_layer.len() > 1 {
        let mut next_layer = Vec::with_capacity((current_layer.len() + 1) / 2);
        for i in (0..current_layer.len()).step_by(2) {
            let left = current_layer[i];
            let right = if i + 1 < current_layer.len() {
                current_layer[i + 1]
            } else {
                left
            };

            let mut hasher = Sha256::new();
            hasher.update([0x01]); // 0x01 internal node domain prefix
            hasher.update(left);
            hasher.update(right);
            let parent: [u8; 32] = hasher.finalize().into();
            next_layer.push(parent);
        }
        current_layer = next_layer;
        depth += 1;
    }

    let root = current_layer[0]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    Ok(MerkleTreeResult {
        root,
        leaf_count: file_entries.len(),
        depth,
        files: file_entries,
    })
}
