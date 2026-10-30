# syncloom-core

The shared Rust crate: wire protocol, chunking, end-to-end encryption (vault and sharing keys), three-way text merge, name normalisation and the sync engine. It is used directly by the server and the Linux client, and through UniFFI (Swift, Kotlin), a C ABI (C#) and WebAssembly (web app).

Part of [Syncloom](https://github.com/Syncloom), a self-hosted, end-to-end encrypted file sync and key/value store. Status: **public preview (0.1)**.

```bash
cargo test --lib                 # unit tests
./build-apple.sh                 # XCFramework + Swift bindings into ../syncloom-apple
./build-android.sh               # JNI libraries + Kotlin bindings into ../syncloom-android
```
Feature flags: `client`, `grpc`, `uniffi`, `wasm`, `capi`.

## Working with the other repositories

The Syncloom repositories reference each other by relative path. Clone the ones you need **side by side in one folder**, for example `syncloom-core`, `syncloom-server` and `syncloom-web` next to each other.

## License

Apache License 2.0, see [LICENSE](LICENSE).
