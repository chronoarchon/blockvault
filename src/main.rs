use anyhow::Result;
use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use blockvault::vault::{
    inspect_block, lock_folder, smart_resolve_path, unlock_block, LockResult,
};

#[derive(Parser)]
#[command(
    name = "blockvault",
    author = "chronoarchon <chronoarchon@users.noreply.github.com>",
    version = "2.1.0",
    about = "Sovereign, cryptocurrency-grade folder encryption CLI using BIP-39 mnemonic seeds, Scrypt KDF, AES-256-GCM, and Merkle trees.",
    after_help = "EXAMPLES:
  $ blockvault lock ./my-folder
  $ blockvault lock ~/Documents/projects --words 24 --passphrase \"secret#2026\" --replace
  $ blockvault unlock ~/Documents/projects.block ~/Restored
  $ blockvault inspect ~/Documents/projects.block"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a folder into an immutable, authenticated blockchain vault
    Lock {
        /// Target folder to encrypt
        folder: String,

        /// Custom output file path (.block)
        #[arg(short, long)]
        output: Option<String>,

        /// BIP-39 mnemonic word count (12 or 24)
        #[arg(short, long, default_value_t = 12)]
        words: usize,

        /// Optional BIP-39 passphrase (the 13th / 25th word feature)
        #[arg(short, long, default_value = "")]
        passphrase: String,

        /// Delete unencrypted source folder after locking (in-place locker mode)
        #[arg(short, long)]
        replace: bool,
    },

    /// Decrypt and restore a block vault, mathematically verifying the Merkle root
    Unlock {
        /// Encrypted .block file to unlock
        block: String,

        /// Destination directory for restored files (defaults to current directory)
        #[arg(short, long)]
        dest: Option<String>,

        /// 12 or 24-word BIP-39 recovery seed phrase
        #[arg(long)]
        phrase: Option<String>,

        /// Optional BIP-39 passphrase
        #[arg(short, long, default_value = "")]
        passphrase: String,

        /// Delete the .block file after successful extraction
        #[arg(short, long)]
        replace: bool,
    },

    /// Inspect public block header, creator wallet, and Merkle file ledger without keys
    Inspect {
        /// Encrypted .block file to inspect
        block: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Lock {
            folder,
            output,
            words,
            passphrase,
            replace,
        } => {
            let target_path = smart_resolve_path(&folder, "")
                .unwrap_or_else(|| PathBuf::from(&folder));

            if !target_path.is_dir() {
                eprintln!("\n\x1b[31m\x1b[1m❌ ERROR:\x1b[0m Target path \"{}\" is not a valid directory.", target_path.display());

                // Smart folder suggestion
                let folder_name = target_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_lowercase();
                let home = std::env::var("HOME").unwrap_or_else(|_| "/home/leodarshan".to_string());
                let home_path = Path::new(&home);
                let doc_path = home_path.join("Documents");

                if folder.contains("Downloads/documents") && doc_path.is_dir() {
                    eprintln!("   \x1b[33m💡 Tip: \"~/Downloads/documents\" is an example placeholder. Did you mean \"~/Documents\"?\x1b[0m");
                }

                // Check parent directory
                if let Some(parent) = target_path.parent() {
                    if parent.is_dir() {
                        eprintln!("\n\x1b[36mExisting directories inside \"{}\":\x1b[0m", parent.display());
                        if let Ok(entries) = fs::read_dir(parent) {
                            for e in entries.flatten() {
                                if let Ok(ft) = e.file_type() {
                                    if ft.is_dir() {
                                        let name = e.file_name().to_string_lossy().to_string();
                                        if name.to_lowercase() == folder_name {
                                            eprintln!("  📁 {} \x1b[33m(case mismatch!)\x1b[0m", name);
                                        } else {
                                            eprintln!("  📁 {}", name);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                std::process::exit(1);
            }

            let out_p = output.as_deref().and_then(|o| smart_resolve_path(o, ".block"));

            println!("\n\x1b[36m📦 Initializing BlockVault Genesis Block...\x1b[0m");
            println!("\x1b[2m   Target: {}\x1b[0m", target_path.display());
            println!("\x1b[2m   Security: {}-word BIP-39 + Scrypt (N=16384) + AES-256-GCM\x1b[0m", words);

            let res: LockResult = lock_folder(
                &target_path,
                out_p.as_deref(),
                words,
                &passphrase,
                replace,
            )?;

            print_lock_success(&res, words, !passphrase.is_empty());
        }

        Commands::Unlock {
            block,
            dest,
            phrase,
            passphrase,
            replace,
        } => {
            let block_p = smart_resolve_path(&block, ".block")
                .unwrap_or_else(|| PathBuf::from(&block));

            if !block_p.is_file() {
                eprintln!("\n\x1b[31m\x1b[1m❌ ERROR:\x1b[0m Block file \"{}\" not found.", block_p.display());
                std::process::exit(1);
            }

            let user_phrase = match phrase {
                Some(p) => p,
                None => {
                    print!("\n\x1b[33m🔑 Enter BIP-39 Recovery Seed Phrase (12 or 24 words):\x1b[0m\n> ");
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                    input.trim().to_string()
                }
            };

            let dest_p = dest.as_deref().and_then(|d| smart_resolve_path(d, ""));

            println!("\n\x1b[36m⚙️  Deriving keys via Scrypt (Ethereum Keystore Standard)...\x1b[0m");
            println!("\x1b[36m🔓 Decrypting & Authenticating with AES-256-GCM...\x1b[0m");

            let res = unlock_block(
                &block_p,
                dest_p.as_deref(),
                &user_phrase,
                &passphrase,
                replace,
            )?;

            println!("\n\x1b[32m\x1b[1m✅ DECRYPTION SUCCESSFUL!\x1b[0m");
            println!("   \x1b[1mRestored Folder:\x1b[0m  {}", res.extracted_folder.display());
            println!("   \x1b[1mCreator Wallet:\x1b[0m   {}", res.creator_wallet);
            println!("   \x1b[1mFiles Extracted:\x1b[0m  {} items", res.file_count);
            println!("   \x1b[1mMerkle Root:\x1b[0m      0x{}", res.merkle_root);
            if res.merkle_verified {
                println!("   \x1b[32m\x1b[1m🌲 Merkle Verification: 100% MATCH - Zero bit rot or tampering!\x1b[0m\n");
            } else {
                println!("   \x1b[31m\x1b[1m⚠️ Merkle Mismatch: Files may have been modified after packing.\x1b[0m\n");
            }
        }

        Commands::Inspect { block } => {
            let block_p = smart_resolve_path(&block, ".block")
                .unwrap_or_else(|| PathBuf::from(&block));

            if !block_p.is_file() {
                eprintln!("\n\x1b[31m\x1b[1m❌ ERROR:\x1b[0m Block file \"{}\" not found.", block_p.display());
                std::process::exit(1);
            }

            let (header, total_size) = inspect_block(&block_p)?;

            println!("\n\x1b[38;5;240m╔════════════════════════════════════════════════════════════════════════╗\x1b[0m");
            println!("\x1b[38;5;240m║\x1b[0m \x1b[38;5;220m\x1b[1m🔎 BLOCKVAULT LEDGER INSPECTION\x1b[0m");
            println!("\x1b[38;5;240m╠════════════════════════════════════════════════════════════════════════╣\x1b[0m");
            println!("\x1b[38;5;240m║\x1b[0m \x1b[1mBlock Height:\x1b[0m     #{} (Genesis Block)", header.block_height);
            println!("\x1b[38;5;240m║\x1b[0m \x1b[1mContainer Size:\x1b[0m   {} bytes", total_size);
            println!("\x1b[38;5;240m║\x1b[0m \x1b[1mTimestamp:\x1b[0m        {}", header.timestamp);
            println!("\x1b[38;5;240m║\x1b[0m \x1b[1mCreator Wallet:\x1b[0m   \x1b[36m{}\x1b[0m", header.creator_wallet);
            println!("\x1b[38;5;240m║\x1b[0m \x1b[1mCryptography:\x1b[0m     {} + {}", header.algorithm, header.kdf);
            println!("\x1b[38;5;240m║\x1b[0m \x1b[1mMerkle Root:\x1b[0m      \x1b[32m0x{}\x1b[0m", header.merkle_root);
            println!("\x1b[38;5;240m║\x1b[0m \x1b[1mWord Standard:\x1b[0m    {}-word BIP-39 ({})", 
                header.word_count, 
                if header.has_passphrase { "Passphrase Protected" } else { "Standard" });
            println!("\x1b[38;5;240m╠════════════════════════════════════════════════════════════════════════╣\x1b[0m");
            println!("\x1b[38;5;240m║\x1b[0m \x1b[1mMERKLE TREE LEDGER MANIFEST:\x1b[0m");
            println!("\x1b[38;5;240m╠════════════════════════════════════════════════════════════════════════╣\x1b[0m");
            for f in &header.files {
                println!("   \x1b[36m•\x1b[0m {:<48} \x1b[2m({:>9} B)\x1b[0m  \x1b[2mSHA256:\x1b[0m {}...", 
                    f.path, f.size, &f.hash[..16]);
            }
            println!("\x1b[38;5;240m╚════════════════════════════════════════════════════════════════════════╝\x1b[0m\n");
        }
    }

    Ok(())
}

fn print_lock_success(res: &LockResult, word_count: usize, has_passphrase: bool) {
    println!("\n\x1b[38;5;240m╔════════════════════════════════════════════════════════════════════════╗\x1b[0m");
    println!("\x1b[38;5;240m║\x1b[0m \x1b[38;5;220m\x1b[1m✨ GENESIS BLOCK CREATED SUCCESSFULLY!\x1b[0m");
    println!("\x1b[38;5;240m╠════════════════════════════════════════════════════════════════════════╣\x1b[0m");
    println!("\x1b[38;5;240m║\x1b[0m \x1b[1mBlock File:\x1b[0m     {}", res.block_path.display());
    println!("\x1b[38;5;240m║\x1b[0m \x1b[1mCreator Wallet:\x1b[0m \x1b[36m{}\x1b[0m", res.wallet_address);
    println!("\x1b[38;5;240m║\x1b[0m \x1b[1mMerkle Root:\x1b[0m    \x1b[32m0x{}\x1b[0m", res.merkle_root);
    println!("\x1b[38;5;240m║\x1b[0m \x1b[1mFiles Locked:\x1b[0m   {} items ({} bytes)", res.file_count, res.payload_size);
    if has_passphrase {
        println!("\x1b[38;5;240m║\x1b[0m \x1b[1mPassphrase:\x1b[0m     \x1b[35m[Enabled: 13th/25th Word Protection]\x1b[0m");
    }
    if res.replaced {
        println!("\x1b[38;5;240m║\x1b[0m \x1b[1mMode:\x1b[0m           \x1b[31m[In-Place: Original folder removed]\x1b[0m");
    }
    println!("\x1b[38;5;240m╠════════════════════════════════════════════════════════════════════════╣\x1b[0m");
    println!("\x1b[38;5;240m║\x1b[0m \x1b[38;5;226m\x1b[1m🔑 YOUR {}-WORD RECOVERY SEED PHRASE:\x1b[0m", word_count);
    println!("\x1b[38;5;240m╠════════════════════════════════════════════════════════════════════════╣\x1b[0m");
    println!("\n\x1b[1m\x1b[38;5;220m   {}\x1b[0m\n", res.mnemonic);
    println!("\x1b[38;5;240m╠════════════════════════════════════════════════════════════════════════╣\x1b[0m");
    println!("\x1b[38;5;240m║\x1b[0m \x1b[31m\x1b[1m⚠️  CRITICAL RECOVERY WARNING:\x1b[0m");
    println!("\x1b[38;5;240m║\x1b[0m   Write down these {} words on paper or save them in a password manager.", word_count);
    println!("\x1b[38;5;240m║\x1b[0m   Without these words, \x1b[1mNO ONE ON EARTH\x1b[0m can decrypt this block.");
    println!("\x1b[38;5;240m╚════════════════════════════════════════════════════════════════════════╝\x1b[0m\n");
}
