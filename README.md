# rustls-rustcrypto

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

[RustCrypto]-based cryptography provider implementation for [rustls], maintained by the RustCrypto organization.

## Version compatibility

This fork builds against a **git dependency** of rustls (here: the `craftls_wasm` fork).

- The effective rustls API is determined by the pinned git commit in `Cargo.lock`, not by a crates.io version.
- Updating/rebasing the rustls fork may require follow-up changes in this provider.

## Notes on this fork (`nickz/api_update`)

Compared to `origin/master`, this branch updates the provider to match a newer rustls API and adjusts tests accordingly. High-level changes:

- **rustls dependency**: switched from `rustls = "0.23.12"` to a git dependency (`craftls_wasm`) and enabled `rustls` features `craft` and `custom-provider`.
- **Provider wiring**: updated `CryptoProvider` construction and related trait wiring to match the newer rustls API (including required fields such as `ticketer_factory` and `fips()` support).
- **Cipher suite structs**: updated TLS 1.3 suite wiring to match the new rustls types/fields (e.g. protocol version field changes).
- **Record-layer adapters**: updated AEAD glue code for the newer rustls message/cipher buffer types and nonce handling.
- **Key exchange**: updated KX group APIs to the newer rustls `StartedKeyExchange` / `ActiveKeyExchange` shape.
- **Signing**:
  - updated signer trait signatures (boxed self signing)
  - implemented RFC 5280 SPKI public key export for RSA / ECDSA / Ed25519 keys, which rustls uses to verify key/cert consistency
  - Ed448 is not implemented in this provider
- **Tests**: updated test helpers to rustls’ new verifier/resolver traits and builder APIs.

## WASM compatibility notes

This crate is `#![no_std]` but requires `alloc`. Whether it is **WASM-compatible** depends on both:

- this crate (RNG + crypto implementations), and
- the rustls implementation you build against (here: `craftls_wasm`)

### Current status (with `craftls_wasm`)

`wasm32-unknown-unknown` **does not build** with the current `craftls_wasm` rustls fork because rustls calls `pki_types::UnixTime::now()` in `ticketer` / `time_provider`, and that API is not available on `wasm32-unknown-unknown` (no `std` time source).

This needs to be fixed in the rustls fork (e.g. by gating `UnixTime::now()` behind `std`, or by using a time provider implementation that works in WASM).

### Additional provider constraints

Even after rustls itself builds for WASM, this provider currently uses `rand_core::OsRng` (via `getrandom`) for:

- `SecureRandom` (`src/lib.rs`)
- key exchange ephemeral key generation (`src/kx.rs`)
- randomized signing (`src/sign.rs`)

On `wasm32-unknown-unknown`, `getrandom` typically requires a JS-backed feature (or a custom hook) to provide randomness.

### TLS 1.2 support

The current rustls fork used here does not expose the historical `tls12` feature flag. This crate still contains some TLS 1.2 code paths behind `cfg(feature = "tls12")`, but that feature is not exposed from `Cargo.toml` in this fork configuration.

## QUIC support

`rustls` has a built-in QUIC integration surface (`rustls::quic`). When using rustls for QUIC, rustls needs cipher-suite-specific code to create:

- packet protection keys (`quic::PacketKey`)
- header protection keys (`quic::HeaderProtectionKey`)

Those are **not “TLS record layer”** primitives; they’re QUIC-specific, defined by QUIC-TLS (RFC 9001).

This crate includes a `quic` module so it can (eventually) act as a complete provider for rustls users that also enable QUIC. This module predates the rustls API upgrade.

- **Not wired into cipher suites**: our TLS 1.3 cipher suites currently set `quic: None` (see `src/lib.rs`), so rustls will not select this provider for QUIC even if you use rustls’ QUIC APIs.
- **Packet protection is implemented**: `src/quic.rs` has a working `quic::PacketKey` implementation (payload encryption/authentication).
- **Header protection is not implemented**: QUIC header protection is currently **explicitly unsupported** and returns a runtime error if called.

## ⚠️USE THIS AT YOUR OWN RISK! DO NOT USE THIS IN PRODUCTION⚠️

Not only that this is incomplete that only few selected TLS suites implemented (it should be well enough to cover 70% of the usage), but the elephant in the room is that neither did rustls nor RustCrypto packages were formally verified and certified with FIPS compliance.

Note that RustCrypto performance is generally inferior than ring, but in exchange you got a pure Rust implementation that theoretically compiles everywhere Rust was ported to. In our case, we need to have `std` but foundational support for future `no_std` expansion is already here.

## Supported Cipher Suites

- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
- TLS13_AES_128_GCM_SHA256
- TLS13_AES_256_GCM_SHA384
- TLS13_CHACHA20_POLY1305_SHA256

## License

Licensed under either of:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

Some code authored by [@ctz](https://github.com/ctz) was adapted from upstream rustls. Licensed as above with permission.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # "badges"
[crate-image]: https://img.shields.io/crates/v/rustls-rustcrypto
[crate-link]: https://crates.io/crates/rustls-rustcrypto
[docs-image]: https://docs.rs/rustls-rustcrypto/badge.svg
[docs-link]: https://docs.rs/rustls-rustcrypto/
[build-image]: https://github.com/RustCrypto/rustls-rustcrypto/actions/workflows/rustls-rustcrypto.yml/badge.svg
[build-link]: https://github.com/RustCrypto/rustls-rustcrypto/actions/workflows/rustls-rustcrypto.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.75+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/434751-TLS
[//]: # "links"
[RustCrypto]: https://github.com/RustCrypto/
[rustls]: https://github.com/rustls/rustls/
