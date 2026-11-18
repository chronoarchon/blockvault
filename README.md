# BlockVault

A sovereign, cryptocurrency-grade folder encryption engine and CLI written in Rust.

BlockVault secures local directories using the same cryptographic primitives that protect decentralized blockchain networks: BIP-39 mnemonic seeds, Scrypt key derivation, AES-256-GCM authenticated encryption, and domain-separated Merkle trees.

---

## Cryptographic Architecture

- **BIP-39 Mnemonic Seed Phrases:** Generates 12-word (128-bit) or 24-word (256-bit) recovery seed phrases using the official 2,048-word BIP-39 dictionary.
- **BIP-39 Optional Passphrase:** Supports the "13th/25th word" feature for plausible deniability.
- **Scrypt Key Derivation:** Employs Ethereum-standard memory-hard Scrypt parameters (`N=16384, r=8, p=1`) to prevent GPU and ASIC cracking attacks.
- **AES-256-GCM Authenticated Encryption:** Uses Galois/Counter Mode with a 128-bit authentication tag and Additional Authenticated Data (AAD) to ensure privacy and tamper detection.
- **Zeroize Memory Hardening:** Securely wipes encryption keys, seeds, and plaintext buffers from RAM on drop to thwart cold-boot and memory dump attacks.
- **Domain-Separated Merkle Trees:** Recursively hashes files via SHA-256 (`0x00` leaf prefix, `0x01` branch prefix, per RFC 6962) to produce an immutable root hash for bit-level integrity verification.
- **EIP-55 Wallet Identity:** Derives a checksummed Ethereum-style creator address from each seed.

---

## Installation

### 1. One-Line cURL Installer (Recommended)

Automatically downloads, compiles, and installs the standalone binary into `~/.local/bin`:

```bash
curl -fsSL https://raw.githubusercontent.com/chronoarchon/blockvault/main/install.sh | bash
```

### 2. Install via Cargo

```bash
cargo install --git https://github.com/chronoarchon/blockvault.git
```

### 3. Build from Source

```bash
git clone https://github.com/chronoarchon/blockvault.git
cd blockvault
cargo build --release
cp target/release/blockvault ~/.local/bin/
```

---

## Usage

### 1. Lock a Folder

```bash
# Standard 12-word encryption
blockvault lock /path/to/folder

# Enterprise 24-word encryption with custom passphrase
blockvault lock /path/to/folder --words 24 --passphrase "my-passphrase"

# In-place encryption (removes unencrypted source folder)
blockvault lock /path/to/folder --replace
```

### 2. Unlock a Block

```bash
# Interactive prompt for seed phrase
blockvault unlock /path/to/folder.block /destination

# Non-interactive unlock
blockvault unlock /path/to/folder.block --phrase "word1 word2 ... word12"

# In-place restore (deletes .block file upon success)
blockvault unlock /path/to/folder.block --replace
```

### 3. Inspect a Block (Public Header)

Inspect the creator wallet, Merkle root, and file inventory without decryption keys:

```bash
blockvault inspect /path/to/folder.block
```

---

## Running Tests

Run the full Rust cryptographic verification and integration test suite:

```bash
cargo test
```

---

## License

MIT License.
