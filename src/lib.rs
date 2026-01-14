#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(
    clippy::alloc_instead_of_core,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::checked_conversions,
    clippy::from_iter_instead_of_collect,
    clippy::missing_errors_doc,
    clippy::mod_module_files,
    clippy::implicit_saturating_sub,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::std_instead_of_alloc,
    clippy::std_instead_of_core,
    clippy::unwrap_used,
    rust_2018_idioms,
    trivial_numeric_casts,
    unused_lifetimes
)]

//! # Usage
//!
//! See [`examples-xsmall`](https://github.com/RustCrypto/rustls-rustcrypto/tree/master/examples-xsmall)
//! for a usage example.

#[cfg(not(feature = "alloc"))]
compile_error!("Rustls currently does not support alloc-less environments");

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, sync::Arc};

use alloc::borrow::Cow;

use rustls::crypto::{
    CipherSuite, CipherSuiteCommon, CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom,
    SigningKey, TicketProducer, TicketerFactory,
};
use rustls::version::TLS13_VERSION;
use rustls::Tls13CipherSuite;

#[derive(Debug)]
pub struct Provider;

pub fn provider() -> CryptoProvider {
    CryptoProvider {
        tls12_cipher_suites: Cow::Borrowed(&[]),
        tls13_cipher_suites: Cow::Borrowed(TLS13_SUITES),
        kx_groups: Cow::Borrowed(kx::ALL_KX_GROUPS),
        signature_verification_algorithms: verify::ALGORITHMS,
        secure_random: &Provider,
        key_provider: &Provider,
        ticketer_factory: &Provider,
    }
}

impl TicketerFactory for Provider {
    fn ticketer(&self) -> Result<Arc<dyn TicketProducer>, rustls::Error> {
        Err(rustls::Error::General("Ticketing not supported".into()))
    }

    fn fips(&self) -> bool {
        false
    }
}

impl SecureRandom for Provider {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), GetRandomFailed> {
        use rand_core::RngCore;
        rand_core::OsRng
            .try_fill_bytes(bytes)
            .map_err(|_| GetRandomFailed)
    }
}

impl KeyProvider for Provider {
    fn load_private_key(
        &self,
        key_der: pki_types::PrivateKeyDer<'static>,
    ) -> Result<Box<dyn SigningKey>, rustls::Error> {
        sign::any_supported_type(&key_der).map(|arc| {
            // Convert Arc to Box - this is safe because we just created the Arc
            let raw = Arc::into_raw(arc);
            // SAFETY: We just created this Arc, so we have unique ownership
            unsafe { Box::from_raw(raw as *mut dyn SigningKey) }
        })
    }
}

pub static TLS13_AES_128_GCM_SHA256: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: hash::SHA256,
        confidentiality_limit: u64::MAX,
    },
    protocol_version: TLS13_VERSION,
    hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(hmac::SHA256),
    aead_alg: &aead::gcm::Tls13Aes128Gcm,
    quic: None,
};

pub static TLS13_AES_256_GCM_SHA384: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
        hash_provider: hash::SHA384,
        confidentiality_limit: u64::MAX,
    },
    protocol_version: TLS13_VERSION,
    hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(hmac::SHA384),
    aead_alg: &aead::gcm::Tls13Aes256Gcm,
    quic: None,
};

pub static TLS13_CHACHA20_POLY1305_SHA256: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: hash::SHA256,
        confidentiality_limit: u64::MAX,
    },
    protocol_version: TLS13_VERSION,
    hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(hmac::SHA256),
    aead_alg: &aead::chacha20::Chacha20Poly1305,
    quic: None,
};

static TLS13_SUITES: &[&Tls13CipherSuite] = &[
    &TLS13_AES_128_GCM_SHA256,
    &TLS13_AES_256_GCM_SHA384,
    &TLS13_CHACHA20_POLY1305_SHA256,
];

mod aead;
mod hash;
mod hmac;
mod kx;
mod misc;
pub mod quic;
pub mod sign;
mod verify;
