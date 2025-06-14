#!/bin/bash
set -e

echo "Installing Laravel Log Parser..."

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

if [[ "$ARCH" == "x86_64" ]]; then
    ARCH="amd64"
elif [[ "$ARCH" == "arm64" ]] && [[ "$OS" == "darwin" ]]; then
    ARCH="arm64"
fi

BINARY_NAME="logparse-${OS}-${ARCH}"
if [[ "$OS" == "windows" ]]; then
    BINARY_NAME="${BINARY_NAME}.exe"
fi

echo "Downloading ${BINARY_NAME}..."
curl -L "https://github.com/nickcheek/laravel-log-parser/releases/latest/download/${BINARY_NAME}" -o logparse

echo "Installing to /usr/local/bin..."
sudo mv logparse /usr/local/bin/
sudo chmod +x /usr/local/bin/logparse

echo "Installation complete!"
echo "Try: logparse --help"
EOF