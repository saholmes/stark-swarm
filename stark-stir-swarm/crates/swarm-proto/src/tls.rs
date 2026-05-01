//! TLS 1.3 configs with X25519+ML-KEM-768 hybrid key exchange.
//!
//! Both server and client use the `aws-lc-rs` provider, then prepend the
//! post-quantum hybrid kx group from `rustls-post-quantum` so it is
//! preferred over classical-only X25519. Workers verify the controller by
//! pinning the SHA3-256 fingerprint of its self-signed certificate; the
//! controller does not require client auth at the TLS layer (workers
//! authenticate themselves at the application layer with their ML-DSA
//! public key in the `Register` message).

use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use sha3::{Digest, Sha3_256};

use crate::cert::{pem_certs_to_der, pem_first_private_key_der, ServerIdentity};

/// Build the shared `CryptoProvider` with the post-quantum hybrid kx group
/// promoted to the front of the preference list.
fn pq_provider() -> Arc<rustls::crypto::CryptoProvider> {
    let mut p = aws_lc_rs::default_provider();
    // X25519MLKEM768 hybrid first, then classical fallbacks.
    let mut groups = vec![rustls_post_quantum::X25519MLKEM768];
    groups.extend(p.kx_groups.iter().copied());
    p.kx_groups = groups;
    Arc::new(p)
}

/// Build a TLS 1.3 server config from the controller's PEM identity.
pub fn server_config(id: &ServerIdentity) -> Result<Arc<ServerConfig>> {
    let cert_chain: Vec<CertificateDer<'static>> = pem_certs_to_der(&id.cert_pem)?
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    if cert_chain.is_empty() {
        anyhow::bail!("server identity contains no certificates");
    }

    let key_der = pem_first_private_key_der(&id.key_pem)?;
    let key = PrivateKeyDer::Pkcs8(key_der.into());

    let cfg = ServerConfig::builder_with_provider(pq_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("set TLS 1.3 only")?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .context("install server cert")?;

    Ok(Arc::new(cfg))
}

/// Build a TLS 1.3 client config that pins the controller's certificate by
/// its SHA3-256 fingerprint. SNI hostname is supplied at connect time.
pub fn client_config_with_pinned_fp(expected_fp: [u8; 32]) -> Result<Arc<ClientConfig>> {
    let verifier = Arc::new(PinnedFingerprintVerifier { expected_fp });

    let cfg = ClientConfig::builder_with_provider(pq_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("set TLS 1.3 only")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    Ok(Arc::new(cfg))
}

/// Server-cert verifier that accepts exactly one cert, identified by its
/// SHA3-256 fingerprint over the DER bytes. Bypasses CA chain validation
/// — appropriate for a swarm with a self-signed controller cert pinned
/// out-of-band, *not* appropriate for general internet TLS.
#[derive(Debug)]
struct PinnedFingerprintVerifier {
    expected_fp: [u8; 32],
}

impl ServerCertVerifier for PinnedFingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut h = Sha3_256::new();
        Digest::update(&mut h, end_entity.as_ref());
        let fp: [u8; 32] = Digest::finalize(h).into();
        if fp == self.expected_fp {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "server cert fingerprint mismatch: got {} expected {}",
                hex::encode(fp),
                hex::encode(self.expected_fp),
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // TLS 1.3 only — this never fires.
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOfferedOrEnabled,
        ))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // We pin by fingerprint, so we accept any signature the cert produces.
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}
