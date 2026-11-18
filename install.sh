#!/usr/bin/env bash
set -e

# BlockVault One-Line Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/chronoarchon/blockvault/main/install.sh | bash

INSTALL_DIR="${HOME}/.blockvault"
BIN_DIR="${HOME}/.local/bin"
REPO_URL="https://github.com/chronoarchon/blockvault.git"

echo "=== Installing BlockVault (Rust Native Edition) ==="

# Ensure ~/.local/bin exists
mkdir -p "${BIN_DIR}"

# Ensure Cargo/Rust toolchain is installed
if ! command -v cargo >/dev/null 2>&1; then
    echo "Notice: Cargo/Rust toolchain is required to build BlockVault."
    echo "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "${HOME}/.cargo/env"
fi

# Clone or update repository
if [ -d "${INSTALL_DIR}" ]; then
    echo "Updating existing installation in ${INSTALL_DIR}..."
    cd "${INSTALL_DIR}"
    git pull --quiet origin main || true
else
    echo "Downloading BlockVault to ${INSTALL_DIR}..."
    git clone --depth 1 --quiet "${REPO_URL}" "${INSTALL_DIR}"
fi

# Build native release binary
echo "Compiling optimized native binary with Cargo..."
cd "${INSTALL_DIR}"
cargo build --release --quiet

# Install binary to ~/.local/bin
cp -f "${INSTALL_DIR}/target/release/blockvault" "${BIN_DIR}/blockvault"
chmod +x "${BIN_DIR}/blockvault"

# Check PATH
case ":${PATH}:" in
    *:"${BIN_DIR}":*) ;;
    *)
        echo ""
        echo "Notice: ${BIN_DIR} is not in your PATH."
        echo "Add the following line to your shell profile (~/.bashrc or ~/.zshrc):"
        echo "    export PATH=\"\${HOME}/.local/bin:\${PATH}\""
        ;;
esac

echo ""
echo "=== BlockVault installed successfully ==="
echo "Run 'blockvault --help' to get started."
