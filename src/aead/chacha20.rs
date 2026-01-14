#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use super::{DecryptBufferAdapter, EncryptBufferAdapter};

use chacha20poly1305::{AeadInPlace, KeyInit, KeySizeUser};
use rustls::crypto::cipher::{
    self, AeadKey, EncodedMessage, InboundOpaque, Iv, MessageDecrypter, MessageEncrypter,
    OutboundOpaque, OutboundPlain, Tls13AeadAlgorithm, UnsupportedOperationError,
};
use rustls::enums::{ContentType, ProtocolVersion};
use rustls::ConnectionTrafficSecrets;

#[cfg(feature = "tls12")]
use rustls::crypto::cipher::{KeyBlockShape, Tls12AeadAlgorithm, NONCE_LEN};

pub struct Chacha20Poly1305;

impl Tls13AeadAlgorithm for Chacha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Cipher(
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                .expect("key should be valid"),
            iv,
        ))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Cipher(
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                .expect("key should be valid"),
            iv,
        ))
    }

    fn key_len(&self) -> usize {
        chacha20poly1305::ChaCha20Poly1305::key_size()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}

#[cfg(feature = "tls12")]
impl Tls12AeadAlgorithm for Chacha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        Box::new(Tls12Cipher(
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                .expect("key should be valid"),
            Iv::copy(iv),
        ))
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(Tls12Cipher(
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                .expect("key should be valid"),
            Iv::copy(iv),
        ))
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 32,
            fixed_iv_len: 12,
            explicit_nonce_len: 0,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        // This should always be true because KeyBlockShape and the Iv nonce len are in
        // agreement.
        debug_assert_eq!(NONCE_LEN, iv.len());
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
            key,
            iv: Iv::new(iv[..].try_into().expect("conversion should succeed")),
        })
    }
}

struct Tls13Cipher(chacha20poly1305::ChaCha20Poly1305, Iv);

impl MessageEncrypter for Tls13Cipher {
    fn encrypt(
        &mut self,
        m: EncodedMessage<OutboundPlain<'_>>,
        seq: u64,
    ) -> Result<EncodedMessage<OutboundOpaque>, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = OutboundOpaque::with_capacity(total_len);

        payload.extend_from_chunks(&m.payload);
        payload.extend_from_slice(&m.typ.to_array());

        let nonce: chacha20poly1305::Nonce = cipher::Nonce::new(&self.1, seq).to_array().expect("nonce length should match").into();
        let aad = cipher::make_tls13_aad(total_len);

        self.0
            .encrypt_in_place(&nonce, &aad, &mut EncryptBufferAdapter(&mut payload))
            .map_err(|_| rustls::Error::EncryptError)
            .map(|()| EncodedMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + CHACHAPOLY1305_OVERHEAD
    }
}

impl MessageDecrypter for Tls13Cipher {
    fn decrypt<'a>(
        &mut self,
        mut m: EncodedMessage<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<EncodedMessage<&'a [u8]>, rustls::Error> {
        let payload = &mut m.payload;
        let nonce: chacha20poly1305::Nonce = cipher::Nonce::new(&self.1, seq).to_array().expect("nonce length should match").into();
        let aad = cipher::make_tls13_aad(payload.len());

        self.0
            .decrypt_in_place(&nonce, &aad, &mut DecryptBufferAdapter(payload))
            .map_err(|_| rustls::Error::DecryptError)?;

        m.into_tls13_unpadded_message()
    }
}

#[cfg(feature = "tls12")]
struct Tls12Cipher(chacha20poly1305::ChaCha20Poly1305, Iv);

#[cfg(feature = "tls12")]
impl MessageEncrypter for Tls12Cipher {
    fn encrypt(
        &mut self,
        m: EncodedMessage<OutboundPlain<'_>>,
        seq: u64,
    ) -> Result<EncodedMessage<OutboundOpaque>, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = OutboundOpaque::with_capacity(total_len);

        payload.extend_from_chunks(&m.payload);

        let nonce: chacha20poly1305::Nonce = cipher::Nonce::new(&self.1, seq).to_array().expect("nonce length should match").into();
        let aad = cipher::make_tls12_aad(seq, m.typ, m.version, m.payload.len());

        self.0
            .encrypt_in_place(&nonce, &aad, &mut EncryptBufferAdapter(&mut payload))
            .map_err(|_| rustls::Error::EncryptError)
            .map(|_| EncodedMessage::new(m.typ, m.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + CHACHAPOLY1305_OVERHEAD
    }
}

#[cfg(feature = "tls12")]
impl MessageDecrypter for Tls12Cipher {
    fn decrypt<'a>(
        &mut self,
        mut m: EncodedMessage<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<EncodedMessage<&'a [u8]>, rustls::Error> {
        let payload = &m.payload;
        let nonce: chacha20poly1305::Nonce = cipher::Nonce::new(&self.1, seq).to_array().expect("nonce length should match").into();
        let aad = cipher::make_tls12_aad(
            seq,
            m.typ,
            m.version,
            payload.len() - CHACHAPOLY1305_OVERHEAD,
        );

        let payload = &mut m.payload;
        self.0
            .decrypt_in_place(&nonce, &aad, &mut DecryptBufferAdapter(payload))
            .map_err(|_| rustls::Error::DecryptError)?;

        Ok(m.into_plain_message())
    }
}

const CHACHAPOLY1305_OVERHEAD: usize = 16;
