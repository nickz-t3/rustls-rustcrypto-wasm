use rustls::crypto::SelectedCredential;
use rustls::server::{ClientHello, ServerCredentialResolver};
use rustls::Error;

#[derive(Debug)]
pub struct FakeServerCertResolver;

impl ServerCredentialResolver for FakeServerCertResolver {
    fn resolve(&self, _client_hello: &ClientHello<'_>) -> Result<SelectedCredential, Error> {
        Err(Error::General("No certificate available".into()))
    }
}
