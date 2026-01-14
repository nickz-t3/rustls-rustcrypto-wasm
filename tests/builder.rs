use std::sync::Arc;

use rustls::ClientConfig as RusTlsClientConfig;
use rustls::DistinguishedName;
use rustls::ServerConfig as RusTlsServerConfig;

use rustls_rustcrypto::provider as rustcrypto_provider;

mod fake_time;
use fake_time::FakeTime;

mod fake_cert_server_verifier;
use fake_cert_server_verifier::FakeServerCertVerifier;

mod fake_cert_client_verifier;
use fake_cert_client_verifier::FakeClientCertVerifier;

mod fake_cert_server_resolver;
use fake_cert_server_resolver::FakeServerCertResolver;

// Test integration between rustls and rustls in Client builder context
#[test]
fn integrate_client_builder_with_details_fake() {
    let provider = rustcrypto_provider();
    let time_provider = FakeTime {};

    let fake_server_cert_verifier = FakeServerCertVerifier {};

    let builder_init =
        RusTlsClientConfig::builder_with_details(Arc::new(provider), Arc::new(time_provider));

    let dangerous_verifier = builder_init
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(fake_server_cert_verifier));

    // Out of scope
    let rustls_client_config = dangerous_verifier
        .with_no_client_auth()
        .expect("Failed to create client config");

    // RustCrypto is not fips
    assert!(!rustls_client_config.fips());
}

// Test integration between rustls and rustls in Server builder context
#[test]
fn integrate_server_builder_with_details_fake() {
    let provider = rustcrypto_provider();
    let time_provider = FakeTime {};

    let builder_init =
        RusTlsServerConfig::builder_with_details(Arc::new(provider), Arc::new(time_provider));

    // A DistinguishedName is a Vec<u8> wrapped in internal types.
    // DER or BER encoded Subject field from RFC 5280 for a single certificate.
    // The Subject field is encoded as an RFC 5280 Name
    let dummy_entry: &[u8] = b"";
    let client_dn: Arc<[DistinguishedName]> =
        Arc::new([DistinguishedName::in_sequence(dummy_entry)]);

    let client_cert_verifier = FakeClientCertVerifier { dn: client_dn };

    let dangerous_verifier =
        builder_init.with_client_cert_verifier(Arc::new(client_cert_verifier));

    let server_cert_resolver = FakeServerCertResolver {};

    // Out of scope
    let rustls_server_config = dangerous_verifier
        .with_server_credential_resolver(Arc::new(server_cert_resolver))
        .expect("Failed to create server config");

    // RustCrypto is not fips
    assert!(!rustls_server_config.fips());
}
