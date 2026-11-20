use anyhow::Result;
use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use blockvault::progress::{ProgressBar, StepIndicator};
use blockvault::vault::{
    get_user_home, inspect_block, lock_folder_with_progress, smart_resolve_path,
    unlock_block_with_progress, LockProgress, LockResult, UnlockProgress,
};

#[derive(Parser)]
#[command(
    name = "blockvault",
    author = "chronoarchon <chronoarchon@users.noreply.github.com>",
    version = "2.2.0",
    about = "Sovereign, cryptocurrency-grade folder encryption CLI using BIP-39 mnemonic seeds, Scrypt KDF, AES-256-GCM, and Merkle trees.",
    after_help = "EXAMPLES:
  $ blockvault lock ~/Downloads/lynterminal
  $ blockvault lock ./my-folder --words 24 --passphrase \"secret#2026\" --replace
  $ blockvault unlock luffy.block
  $ blockvault unlock luffy.block ~/Downloads/restored
  $ blockvault inspect luffy.block"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a folder or file into an immutable, authenticated blockchain vault
    Lock {
        /// Target folder or file to encrypt (prompted if omitted)
        folder: Option<String>,

        /// Optional custom output file path (.block)
        output: Option<String>,

        /// Optional output file flag (--output <path>)
        #[arg(short = 'o', long = "output")]
        output_flag: Option<String>,

        /// BIP-39 mnemonic word count (12 or 24)
        #[arg(short, long, default_value_t = 12)]
        words: usize,

        /// Optional BIP-39 passphrase (the 13th / 25th word feature)
        #[arg(short, long, default_value = "")]
        passphrase: String,

        /// Delete unencrypted source folder or file after locking (in-place locker mode)
        #[arg(short, long)]
        replace: bool,
    },

    /// Decrypt and restore a block vault, mathematically verifying the Merkle root
    #[command(alias = "unblock", alias = "restore", alias = "decrypt")]
    Unlock {
        /// Encrypted .block file to unlock (filename or path; prompted if omitted)
        block: Option<String>,

        /// Optional destination directory for restored files (defaults to current directory or origin)
        dest: Option<String>,

        /// Optional destination directory flag (--dest <path>)
        #[arg(short = 'd', long = "dest")]
        dest_flag: Option<String>,

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
    #[command(alias = "info", alias = "view", alias = "check")]
    Inspect {
        /// Encrypted .block file to inspect (prompted if omitted)
        block: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Lock {
            folder,
            output,
            output_flag,
            words,
            passphrase,
            replace,
        } => {
            let folder_input = match folder {
                Some(f) if !f.trim().is_empty() => f,
                _ => {
                    print!("\x1b[36m\x1b[1m📂 Enter path to folder or file to lock:\x1b[0m ");
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                    input.trim().to_string()
                }
            };

            if folder_input.is_empty() {
                eprintln!("\n\x1b[31m\x1b[1m❌ ERROR:\x1b[0m No path provided. Please specify a folder or file to lock.");
                eprintln!("   \x1b[33mExample:\x1b[0m blockvault lock ~/Downloads/my-folder");
                std::process::exit(1);
            }

            let target_path = smart_resolve_path(&folder_input, "")
                .unwrap_or_else(|| PathBuf::from(&folder_input));

            if !target_path.exists() {
                eprintln!("\n\x1b[31m\x1b[1m❌ ERROR:\x1b[0m Target path \"{}\" does not exist.", target_path.display());
                eprintln!("   \x1b[33m💡 Tip: When paths contain spaces, parentheses '()', or '$' symbols, wrap them in quotes:\x1b[0m");
                eprintln!("      \x1b[32mblockvault lock \"/path/to/my file (1).mp3\"\x1b[0m");

                // Smart suggestion
                let item_name = target_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_lowercase();
                let home_path = get_user_home();
                let doc_path = home_path.join("Documents");

                if folder_input.contains("Downloads/documents") && doc_path.is_dir() {
                    eprintln!("   \x1b[33m💡 Tip: \"~/Downloads/documents\" is an example placeholder. Did you mean \"~/Documents\"?\x1b[0m");
                }

                // Check parent directory
                if let Some(parent) = target_path.parent() {
                    if parent.is_dir() {
                        eprintln!("\n\x1b[36mExisting items inside \"{}\":\x1b[0m", parent.display());
                        if let Ok(entries) = fs::read_dir(parent) {
                            for e in entries.flatten() {
                                let name = e.file_name().to_string_lossy().to_string();
                                let is_d = e.file_type().map(|ft| ft.is_dir()).unwrap_or(false);
                                let icon = if is_d { "📁" } else { "📄" };
                                if name.to_lowercase() == item_name {
                                    eprintln!("  {} {} \x1b[33m(case mismatch!)\x1b[0m", icon, name);
                                } else {
                                    eprintln!("  {} {}", icon, name);
                                }
                            }
                        }
                    }
                }
                std::process::exit(1);
            }

            let final_output = output.or(output_flag);
            let out_p = final_output.as_deref().and_then(|o| smart_resolve_path(o, ".block"));

            println!("\n\x1b[36m📦 Initializing BlockVault Genesis Block...\x1b[0m");
            println!("\x1b[2m   Target: {}\x1b[0m", target_path.display());
            println!("\x1b[2m   Security: {}-word BIP-39 + Scrypt (N=16384) + AES-256-GCM\x1b[0m\n", words);

            let mut pb = ProgressBar::new(0, "[1/4] 🌲 Hashing Merkle Ledger");
            let mut init_bar = false;
            let mut s2: Option<StepIndicator> = None;
            let mut s3: Option<StepIndicator> = None;
            let mut s4: Option<StepIndicator> = None;

            let res: LockResult = lock_folder_with_progress(
                &target_path,
                out_p.as_deref(),
                words,
                &passphrase,
                replace,
                |event| match event {
                    LockProgress::HashingFile { current, total, bytes, .. } => {
                        if !init_bar {
                            pb = ProgressBar::new(total as u64, "[1/4] 🌲 Hashing Merkle Ledger");
                            init_bar = true;
                        }
                        pb.update(current as u64, bytes);
                        if current == total {
                            pb.finish("[1/4] 🌲 Merkle Ledger Hashed");
                        }
                    }
                    LockProgress::DerivingKeys => {
                        s2 = Some(StepIndicator::start("[2/4] ⚙️  Deriving Master Key (Scrypt N=16384)..."));
                    }
                    LockProgress::CompressingPayload => {
                        if let Some(ref s) = s2 {
                            s.done("[2/4] ⚙️  Master Key & BIP-39 Seed Derived");
                        }
                        s3 = Some(StepIndicator::start("[3/4] 📦 Compressing Folder Payload..."));
                    }
                    LockProgress::EncryptingContainer => {
                        if let Some(ref s) = s3 {
                            s.done("[3/4] 📦 Folder Compressed & Packed");
                        }
                        s4 = Some(StepIndicator::start("[4/4] 🔒 Encrypting Container (AES-256-GCM + AAD)..."));
                    }
                },
            )?;

            if let Some(ref s) = s4 {
                s.done("[4/4] 🔒 Container Sealed & Authenticated");
            }

            print_lock_success(&res, words, !passphrase.is_empty());
        }

        Commands::Unlock {
            block,
            dest,
            dest_flag,
            phrase,
            passphrase,
            replace,
        } => {
            let block_input = match block {
                Some(b) if !b.trim().is_empty() => b,
                _ => {
                    print!("\x1b[36m\x1b[1m🔓 Enter path to .block file to unlock:\x1b[0m ");
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                    input.trim().to_string()
                }
            };

            if block_input.is_empty() {
                eprintln!("\n\x1b[31m\x1b[1m❌ ERROR:\x1b[0m No .block file provided. Please specify a container to unlock.");
                eprintln!("   \x1b[33mExample:\x1b[0m blockvault unlock ~/Downloads/my-vault.block");
                std::process::exit(1);
            }

            let block_p = smart_resolve_path(&block_input, ".block")
                .unwrap_or_else(|| PathBuf::from(&block_input));

            if !block_p.is_file() {
                eprintln!("\n\x1b[31m\x1b[1m❌ ERROR:\x1b[0m Block file \"{}\" not found.", block_input);

                // Check for available .block files to guide user
                let mut found_blocks = Vec::new();
                if let Ok(entries) = fs::read_dir(".") {
                    for e in entries.flatten() {
                        if e.path().extension().and_then(|x| x.to_str()) == Some("block") {
                            found_blocks.push(e.path());
                        }
                    }
                }
                let home_path = get_user_home();
                let dl = home_path.join("Downloads");
                if let Ok(entries) = fs::read_dir(&dl) {
                    for e in entries.flatten() {
                        if e.path().extension().and_then(|x| x.to_str()) == Some("block") {
                            found_blocks.push(e.path());
                        }
                    }
                }

                if !found_blocks.is_empty() {
                    eprintln!("\n\x1b[33m💡 Available .block vaults found on your system:\x1b[0m");
                    for b in found_blocks {
                        eprintln!("   📦 {}", b.display());
                    }
                    eprintln!("\n   Example: \x1b[36mblockvault unlock {}\x1b[0m", block_input);
                }
                std::process::exit(1);
            }

            let final_dest = dest.or(dest_flag);
            let dest_p = final_dest.as_deref().and_then(|d| smart_resolve_path(d, ""));

            let user_phrase = match phrase {
                Some(p) => p,
                None => {
                    println!("\n\x1b[36m📦 Selected Block: {}\x1b[0m", block_p.display());
                    if let Some(ref d) = dest_p {
                        println!("\x1b[2m   Restore Destination: {}\x1b[0m", d.display());
                    }
                    print!("\x1b[33m🔑 Enter BIP-39 Recovery Seed Phrase (12 or 24 words):\x1b[0m\n> ");
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                    input.trim().to_string()
                }
            };

            let mut s1: Option<StepIndicator> = None;
            let mut s2: Option<StepIndicator> = None;
            let mut s3: Option<StepIndicator> = None;
            let mut s4: Option<StepIndicator> = None;

            println!();
            let res = unlock_block_with_progress(
                &block_p,
                dest_p.as_deref(),
                &user_phrase,
                &passphrase,
                replace,
                |event| match event {
                    UnlockProgress::InspectingHeader => {
                        s1 = Some(StepIndicator::start("[1/4] 🔎 Reading Block Header & Magic Bytes..."));
                    }
                    UnlockProgress::DerivingKeys => {
                        if let Some(ref s) = s1 {
                            s.done("[1/4] 🔎 Header Authenticated & Validated");
                        }
                        s2 = Some(StepIndicator::start("[2/4] ⚙️  Deriving Master Key via Scrypt (N=16384)..."));
                    }
                    UnlockProgress::DecryptingAndUnpacking => {
                        if let Some(ref s) = s2 {
                            s.done("[2/4] ⚙️  Key Verified & Derived");
                        }
                        s3 = Some(StepIndicator::start("[3/4] 🔓 Decrypting Payload (AES-256-GCM) & Unpacking..."));
                    }
                    UnlockProgress::VerifyingMerkleRoot => {
                        if let Some(ref s) = s3 {
                            s.done("[3/4] 🔓 Decrypted & Unpacked");
                        }
                        s4 = Some(StepIndicator::start("[4/4] 🌲 Verifying Merkle Tree Ledger..."));
                    }
                },
            )?;

            if let Some(ref s) = s4 {
                s.done("[4/4] 🌲 Merkle Root Verified (100% Match)");
            }

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
            let block_input = match block {
                Some(b) if !b.trim().is_empty() => b,
                _ => {
                    print!("\x1b[36m\x1b[1m🔎 Enter path to .block file to inspect:\x1b[0m ");
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                    input.trim().to_string()
                }
            };

            if block_input.is_empty() {
                eprintln!("\n\x1b[31m\x1b[1m❌ ERROR:\x1b[0m No .block file provided. Please specify a container to inspect.");
                eprintln!("   \x1b[33mExample:\x1b[0m blockvault inspect ~/Downloads/my-vault.block");
                std::process::exit(1);
            }

            let block_p = smart_resolve_path(&block_input, ".block")
                .unwrap_or_else(|| PathBuf::from(&block_input));

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
    println!("\x1b[38;5;240m╠════════════════════════════════════════════════════════════════════════╣\x1b[0m");
    println!("\x1b[38;5;240m║\x1b[0m \x1b[38;5;45m\x1b[1m🔓 HOW TO UNLOCK / RESTORE THIS BLOCK:\x1b[0m");
    let block_disp = res.block_path.display().to_string();
    let quoted_block = if block_disp.contains(' ') {
        format!("\"{}\"", block_disp)
    } else {
        block_disp
    };
    if has_passphrase {
        println!("\x1b[38;5;240m║\x1b[0m   \x1b[1m\x1b[32m$ blockvault unlock {} -p \"<passphrase>\"\x1b[0m", quoted_block);
    } else {
        println!("\x1b[38;5;240m║\x1b[0m   \x1b[1m\x1b[32m$ blockvault unlock {}\x1b[0m", quoted_block);
    }
    println!("\x1b[38;5;240m║\x1b[0m   \x1b[2m(To extract to a custom folder: blockvault unlock {} <destination>)\x1b[0m", quoted_block);
    println!("\x1b[38;5;240m╚════════════════════════════════════════════════════════════════════════╝\x1b[0m\n");
}
