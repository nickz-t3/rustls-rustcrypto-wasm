use std::sync::Arc;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::SignatureScheme;
use rustls::server::danger::{
    ClientIdentity, ClientVerifier, PeerVerified, SignatureVerificationInput,
};
use rustls::DistinguishedName;
use rustls::Error;

#[derive(Debug)]
pub struct FakeClientCertVerifier {
    pub dn: Arc<[DistinguishedName]>,
}

impl ClientVerifier for FakeClientCertVerifier {
    fn verify_identity(&self, _identity: &ClientIdentity<'_>) -> Result<PeerVerified, Error> {
        Ok(PeerVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn root_hint_subjects(&self) -> Arc<[DistinguishedName]> {
        self.dn.clone()
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }
}
