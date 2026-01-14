#![allow(clippy::duplicate_mod)]

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use aead::AeadCore;
use chacha20poly1305::{AeadInPlace, KeyInit, KeySizeUser};
use crypto_common::typenum::Unsigned;
use rustls::crypto::cipher::{self, AeadKey, Iv};
use rustls::{quic, Error, Tls13CipherSuite};

/// QUIC header protection is currently not implemented for this provider.
/// The type exists only to satisfy trait bounds; attempts to use it will
/// result in explicit errors rather than panics.
pub struct HeaderProtectionKey(AeadKey);

impl HeaderProtectionKey {
    pub fn new(key: AeadKey) -> Self {
        Self(key)
    }
}

impl quic::HeaderProtectionKey for HeaderProtectionKey {
    fn encrypt_in_place(
        &self,
        _sample: &[u8],
        _first: &mut u8,
        _packet_number: &mut [u8],
    ) -> Result<(), Error> {
        Err(Error::General(
            "QUIC header protection is not supported by rustls-rustcrypto".into(),
        ))
    }

    fn decrypt_in_place(
        &self,
        _sample: &[u8],
        _first: &mut u8,
        _packet_number: &mut [u8],
    ) -> Result<(), Error> {
        Err(Error::General(
            "QUIC header protection is not supported by rustls-rustcrypto".into(),
        ))
    }

    #[inline]
    fn sample_len(&self) -> usize {
        // No valid sample length since header protection is unsupported.
        0
    }
}

pub struct PacketKey {
    /// Computes unique nonces for each packet
    iv: Iv,

    /// The cipher suite used for this packet key
    #[allow(dead_code)]
    suite: &'static Tls13CipherSuite,

    crypto: chacha20poly1305::ChaCha20Poly1305,
}

impl PacketKey {
    pub fn new(suite: &'static Tls13CipherSuite, key: AeadKey, iv: Iv) -> Self {
        Self {
            iv,
            suite,
            crypto: chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                .expect("key should be valid"),
        }
    }
}

impl quic::PacketKey for PacketKey {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        aad: &[u8],
        payload: &mut [u8],
        _key_id: Option<u32>,
    ) -> Result<quic::Tag, Error> {
        let nonce: [u8; 12] = cipher::Nonce::new(&self.iv, packet_number).to_array().expect("nonce length should match");

        let tag = self
            .crypto
            .encrypt_in_place_detached(&nonce.into(), aad, payload)
            .map_err(|_| rustls::Error::EncryptError)?;
        Ok(quic::Tag::from(tag.as_ref()))
    }

    /// Decrypt a QUIC packet
    ///
    /// Takes the packet `header`, which is used as the additional authenticated
    /// data, and the `payload`, which includes the authentication tag.
    ///
    /// If the return value is `Ok`, the decrypted payload can be found in
    /// `payload`, up to the length found in the return value.
    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        aad: &[u8],
        payload: &'a mut [u8],
        _key_id: Option<u32>,
    ) -> Result<&'a [u8], Error> {
        let mut payload_ = payload.to_vec();
        let payload_len = payload_.len();
        let nonce = chacha20poly1305::Nonce::from(cipher::Nonce::new(&self.iv, packet_number).to_array::<12>().expect("nonce length should match"));

        self.crypto
            .decrypt_in_place(&nonce, aad, &mut payload_)
            .map_err(|_| rustls::Error::DecryptError)?;

        // Unfortunately the lifetime bound on decrypt_in_place sucks
        payload.copy_from_slice(&payload_);

        let plain_len = payload_len - self.tag_len();
        Ok(&payload[..plain_len])
    }

    /// Tag length for the underlying AEAD algorithm
    #[inline]
    fn tag_len(&self) -> usize {
        <chacha20poly1305::ChaCha20Poly1305 as AeadCore>::TagSize::to_usize()
    }

    fn integrity_limit(&self) -> u64 {
        1 << 36
    }

    fn confidentiality_limit(&self) -> u64 {
        u64::MAX
    }
}

/// A minimal QUIC algorithm implementation for the Chacha20-Poly1305 suite.
/// Currently, only packet protection is implemented; header protection will
/// return an error at runtime if used.
pub struct KeyBuilder;

impl rustls::quic::Algorithm for KeyBuilder {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        Box::new(PacketKey::new(
            &crate::TLS13_CHACHA20_POLY1305_SHA256,
            key,
            iv,
        ))
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        Box::new(HeaderProtectionKey::new(key))
    }

    fn aead_key_len(&self) -> usize {
        chacha20poly1305::ChaCha20Poly1305::key_size()
    }
}
