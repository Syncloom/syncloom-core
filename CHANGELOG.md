# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [semantic versioning](https://semver.org/). Syncloom is a public preview until 1.0.

## [Unreleased]

### Added
- C ABI operations `versions` and `hash_file` (BLAKE3 of a local file, the same hash the versions carry), so a client can tell whether a local file equals a version on the server.
- C ABI operations `upload_version`, `move_to` and `changes`, for the Windows on-demand files engine.

## [0.1.0] - 2026-11-02

First public preview.

### Added
- Protocol types, content-defined chunking and hashing.
- End-to-end encryption: key hierarchy, vault, recovery key, public-key sharing, link keys.
- Three-way text merge with conflict-copy fallback, and name normalisation across operating systems.
- Local state database and sync engine.
- Bindings: UniFFI (Swift, Kotlin), WebAssembly, and a C ABI.

### Known limits
- Share-key rotation on revoke is not implemented.
