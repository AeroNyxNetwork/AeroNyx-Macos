#!/bin/bash
# Build script for AeroNyx Rust Crypto library

# Set up environment
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Make sure rustup is installed
if ! command -v rustup &> /dev/null; then
    echo "Rustup is required but not found. Please install Rust first."
    exit 1
fi

# Install targets if needed
echo "Checking and installing Rust targets..."
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin

# Build for macOS x86_64
echo "Building for x86_64-apple-darwin..."
cargo build --release --target x86_64-apple-darwin

# Build for macOS arm64 (Apple Silicon)
echo "Building for aarch64-apple-darwin..."
cargo build --release --target aarch64-apple-darwin

# Check if the builds were successful
if [ ! -f "$SCRIPT_DIR/target/x86_64-apple-darwin/release/libaeronyx_crypto.dylib" ]; then
    echo "Error: x86_64 build failed!"
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/target/aarch64-apple-darwin/release/libaeronyx_crypto.dylib" ]; then
    echo "Error: arm64 build failed!"
    exit 1
fi

# Create universal binary
echo "Creating universal binary..."
mkdir -p "$SCRIPT_DIR/target/universal/release"
lipo -create \
  "$SCRIPT_DIR/target/x86_64-apple-darwin/release/libaeronyx_crypto.dylib" \
  "$SCRIPT_DIR/target/aarch64-apple-darwin/release/libaeronyx_crypto.dylib" \
  -output "$SCRIPT_DIR/target/universal/release/libaeronyx_crypto.dylib"

# Copy the library to the app's Resources directory
echo "Copying library to ed25519/Resources directory..."
mkdir -p "$SCRIPT_DIR/../ed25519/Resources"
cp "$SCRIPT_DIR/target/universal/release/libaeronyx_crypto.dylib" "$SCRIPT_DIR/../ed25519/Resources/"

# Create a test file to verify the library works
cat > "$SCRIPT_DIR/../ed25519/LibraryTest.swift" << EOL
import Foundation

class LibraryTest {
    static func runTest() {
        print("Testing AeronyxCrypto library loading...")
        let status = AeronyxCrypto.testLibraryLoading()
        print("Library status: \(status)")
        
        if AeronyxCrypto.isLibraryLoaded {
            print("Library is properly loaded!")
        } else {
            print("Library is NOT properly loaded.")
        }
    }
}
EOL

echo "Build complete!"
