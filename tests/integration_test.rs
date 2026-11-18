use std::fs;
use blockvault::vault::{lock_folder, unlock_block, inspect_block};

#[test]
fn test_rust_lock_and_unlock() {
    let temp_dir = std::env::temp_dir().join("bv_rust_test_suite");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(temp_dir.join("sub")).unwrap();

    fs::write(temp_dir.join("hello.txt"), b"Hello Sovereign World!").unwrap();
    fs::write(temp_dir.join("sub/data.bin"), &[1, 2, 3, 4, 5, 42]).unwrap();

    // Lock folder
    let lock_res = lock_folder(&temp_dir, None, 12, "my-passphrase", false).unwrap();
    assert!(lock_res.block_path.exists());
    assert_eq!(lock_res.file_count, 2);

    // Inspect
    let (header, total_size) = inspect_block(&lock_res.block_path).unwrap();
    assert_eq!(header.merkle_root, lock_res.merkle_root);
    assert_eq!(header.file_count, 2);
    assert!(total_size > 0);

    // Unlock
    let restore_dir = std::env::temp_dir().join("bv_rust_test_restored");
    let _ = fs::remove_dir_all(&restore_dir);

    let unlock_res = unlock_block(
        &lock_res.block_path,
        Some(&restore_dir),
        &lock_res.mnemonic,
        "my-passphrase",
        false,
    ).unwrap();

    assert!(unlock_res.merkle_verified);
    assert_eq!(unlock_res.file_count, 2);

    let restored_file = restore_dir.join("bv_rust_test_suite/hello.txt");
    assert_eq!(fs::read(restored_file).unwrap(), b"Hello Sovereign World!");

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
    let _ = fs::remove_file(&lock_res.block_path);
    let _ = fs::remove_dir_all(&restore_dir);
}
