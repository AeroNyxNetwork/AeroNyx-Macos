#!/bin/bash
# Build script for AeroNyx Rust Crypto library

# 设置环境
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# 确保rustup已安装
if ! command -v rustup &> /dev/null; then
    echo "Rustup is required but not found. Please install Rust first."
    exit 1
fi

# 安装必要的目标平台
echo "Checking and installing Rust targets..."
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin

# 为macOS x86_64构建
echo "Building for x86_64-apple-darwin..."
cargo build --release --target x86_64-apple-darwin

# 检查构建是否成功
if [ ! -f "$SCRIPT_DIR/target/x86_64-apple-darwin/release/libaeronyx_crypto.dylib" ]; then
    echo "Error: x86_64 build failed!"
    exit 1
fi

# 为macOS arm64 (Apple Silicon)构建
echo "Building for aarch64-apple-darwin..."
cargo build --release --target aarch64-apple-darwin

# 检查构建是否成功
if [ ! -f "$SCRIPT_DIR/target/aarch64-apple-darwin/release/libaeronyx_crypto.dylib" ]; then
    echo "Error: arm64 build failed!"
    exit 1
fi

# 创建通用二进制文件
echo "Creating universal binary..."
mkdir -p "$SCRIPT_DIR/target/universal/release"
lipo -create \
  "$SCRIPT_DIR/target/x86_64-apple-darwin/release/libaeronyx_crypto.dylib" \
  "$SCRIPT_DIR/target/aarch64-apple-darwin/release/libaeronyx_crypto.dylib" \
  -output "$SCRIPT_DIR/target/universal/release/libaeronyx_crypto.dylib"

# 创建Resources目录
echo "Creating Resources directory..."
mkdir -p "$SCRIPT_DIR/../ed25519/Resources"

# 复制库文件到Resources目录
echo "Copying library to ed25519/Resources directory..."
cp "$SCRIPT_DIR/target/universal/release/libaeronyx_crypto.dylib" "$SCRIPT_DIR/../ed25519/Resources/"

# 检查复制是否成功
if [ ! -f "$SCRIPT_DIR/../ed25519/Resources/libaeronyx_crypto.dylib" ]; then
    echo "Error: Failed to copy the library to Resources directory!"
    exit 1
fi

echo "Build complete!"
echo "Library successfully built and copied to: $SCRIPT_DIR/../ed25519/Resources/libaeronyx_crypto.dylib"
