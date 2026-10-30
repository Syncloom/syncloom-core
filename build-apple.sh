#!/bin/bash
# Builds SyncloomCore.xcframework (macOS arm64, iOS device, iOS simulator) and the Swift bindings.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"
OUT=${1:-../syncloom-apple/Frameworks}
LIB=libsyncloom_core.a
TARGETS=(aarch64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim)
for t in "${TARGETS[@]}"; do
  IPHONEOS_DEPLOYMENT_TARGET=17.0 MACOSX_DEPLOYMENT_TARGET=14.0 cargo build --release --features uniffi --lib --target "$t"
done
BG=target/apple-bindings
rm -rf "$BG" && mkdir -p "$BG/headers"
cargo run --quiet --features uniffi --bin uniffi-bindgen generate --library target/aarch64-apple-darwin/release/libsyncloom_core.dylib --language swift --out-dir "$BG"
mv "$BG/syncloom_coreFFI.h" "$BG/headers/"
mv "$BG/syncloom_coreFFI.modulemap" "$BG/headers/module.modulemap"
rm -rf "$OUT/SyncloomCore.xcframework" && mkdir -p "$OUT"
xcodebuild -create-xcframework \
  -library target/aarch64-apple-darwin/release/$LIB -headers "$BG/headers" \
  -library target/aarch64-apple-ios/release/$LIB -headers "$BG/headers" \
  -library target/aarch64-apple-ios-sim/release/$LIB -headers "$BG/headers" \
  -output "$OUT/SyncloomCore.xcframework"
mkdir -p "$OUT/../Sources/SyncloomKit/Generated"
cp "$BG/syncloom_core.swift" "$OUT/../Sources/SyncloomKit/Generated/syncloom_core.swift"
echo "built $OUT/SyncloomCore.xcframework"
