#!/bin/bash
# Builds the Rust core for Android (arm64 + x86_64 emulator) and the Kotlin bindings.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"
: "${ANDROID_NDK_HOME:=/opt/homebrew/share/android-commandlinetools/ndk/27.2.12479018}"
export ANDROID_NDK_HOME
OUT=${1:-../syncloom-android/app/src/main}
command -v cargo-ndk >/dev/null || cargo install cargo-ndk --locked
cargo ndk -t arm64-v8a -t x86_64 -o "$OUT/jniLibs" build --release --features uniffi --lib
cargo build --features uniffi --lib   # host library, only to read the interface for the bindings
LIBEXT=$(uname | grep -q Darwin && echo dylib || echo so)
cargo run --quiet --features uniffi --bin uniffi-bindgen generate --library target/debug/libsyncloom_core.$LIBEXT --language kotlin --out-dir target/kotlin-bindings
mkdir -p "$OUT/java"
cp -R target/kotlin-bindings/* "$OUT/java/"
echo "Android libraries and bindings written to $OUT"
