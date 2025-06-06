#!/bin/bash

set -e

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Map architecture to GoReleaser format
case $ARCH in
    x86_64)
        ARCH="x86_64"
        ;;
    aarch64)
        ARCH="arm64"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Map OS to GoReleaser format
case $OS in
    linux)
        OS="Linux"
        EXT="tar.gz"
        ;;
    darwin)
        OS="Darwin"
        EXT="tar.gz"
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

# Get latest version
LATEST_VERSION=$(curl -s https://api.github.com/repos/prefeitura-rio/idcli/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

# Download URL
DOWNLOAD_URL="https://github.com/prefeitura-rio/idcli/releases/download/${LATEST_VERSION}/idcli_${OS}_${ARCH}.${EXT}"

# Create temp directory
TMP_DIR=$(mktemp -d)
cd $TMP_DIR

echo "Downloading idcli ${LATEST_VERSION} for ${OS} ${ARCH}..."
curl -L -o idcli.${EXT} $DOWNLOAD_URL

# Extract and install
if [ "$EXT" = "tar.gz" ]; then
    tar xzf idcli.${EXT}
else
    unzip idcli.${EXT}
fi

# Install binary
INSTALL_DIR="/usr/local/bin"
if [ ! -w "$INSTALL_DIR" ]; then
    echo "Need sudo to install to $INSTALL_DIR"
    sudo mv idcli $INSTALL_DIR/
else
    mv idcli $INSTALL_DIR/
fi

# Cleanup
cd - > /dev/null
rm -rf $TMP_DIR

echo "idcli ${LATEST_VERSION} has been installed to ${INSTALL_DIR}/idcli"
echo "You can now run 'idcli --help' to get started" 