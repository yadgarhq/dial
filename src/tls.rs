//! Per-service TLS options and their preparation into a [`ClientTlsConfig`].
//!
//! Split out of `lib.rs` by LEDGER 719; nothing here changed.

use std::path::PathBuf;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use tonic::transport::{Certificate, ClientTlsConfig, Identity};

use crate::error::BalanceError;
use crate::CONNECT_TIMEOUT;

/// Per-service TLS: a CA bundle on disk, and the name to verify against.
///
/// **Paths and a name, deliberately — never an issuer-specific resource** (D80).
/// The reference deployment has cert-manager write these files; an operator on
/// EKS assembling a Secret by hand produces something this crate cannot tell
/// apart, and neither can be named here without making one platform a
/// requirement.
///
/// **The verification domain defaults to the host being dialled, and that is the
/// whole point.** `dial` balances across pod ADDRESSES, so a certificate is
/// verified against the Service name the caller asked for rather than against
/// whichever IP the balancer happens to have picked. [`TlsOptions::domain_name`]
/// overrides it for the case where the certificate names something else — a
/// per-namespace FQDN, say — and is not needed otherwise.
///
/// **Mutual TLS is a configuration addition, not a redesign**, and
/// [`TlsOptions::identity`] is it: two more paths, no change to
/// [`connect_tls`]'s signature. It is OFF unless set, so every caller that
/// says nothing about it dials exactly as it did before.
#[derive(Clone, Debug)]
pub struct TlsOptions {
    ca_certificate: PathBuf,
    domain_name: Option<String>,
    identity: Option<ClientIdentity>,
}

/// The certificate a caller presents to prove WHO IT IS, and its private key.
///
/// The two paths live together rather than as two `Option`s because one
/// without the other is not a configuration, it is a mistake — and a shape that
/// cannot express the mistake needs no check for it.
#[derive(Clone, Debug)]
struct ClientIdentity {
    certificate: PathBuf,
    key: PathBuf,
}

impl TlsOptions {
    /// Verify the peer against the certificate authorities in the PEM bundle at
    /// `ca_certificate`.
    ///
    /// The file is read and checked when [`connect_tls`] runs, not here.
    pub fn new(ca_certificate: impl Into<PathBuf>) -> Self {
        Self {
            ca_certificate: ca_certificate.into(),
            domain_name: None,
            identity: None,
        }
    }

    /// Verify the peer's certificate against `domain_name` instead of against
    /// the host passed to [`connect_tls`].
    pub fn domain_name(self, domain_name: impl Into<String>) -> Self {
        Self {
            domain_name: Some(domain_name.into()),
            ..self
        }
    }

    /// Present `certificate`, proved by `key`, so the peer can authenticate
    /// this caller — mutual TLS (ADR-0516).
    ///
    /// **This is the CALLER's identity, and it is a different certificate from
    /// the one the caller SERVES.** Every internal service is both, so the two
    /// are easy to confuse and the consequence of confusing them is not an
    /// error: a serving certificate is issued for `server auth`, a peer
    /// verifies a client chain for `client auth`, and a leaf that names the
    /// wrong purpose is refused at the handshake by a server that trusts its
    /// issuer perfectly well. That separation is what lets one authority issue
    /// both, and `tests/tls.rs` holds it as a property rather than a comment.
    ///
    /// **THE SEPARATION IS BETWEEN NAMED PURPOSES, AND ONLY THOSE.** webpki
    /// checks `client auth` as `required_if_present`, so a leaf carrying no
    /// extended-key-usage extension is accepted — and that is the shape
    /// cert-manager issues when `usages` is omitted. One authority is therefore
    /// safe only while it never issues a leaf without a purpose. `tests/tls.rs`
    /// pins that as an accepted gap rather than a guarantee.
    ///
    /// **Paths, never an issuer-specific resource** (D80), for the reason given
    /// on [`TlsOptions`]. Both files are read when [`connect_tls`] runs.
    ///
    /// NOTHING VERIFIES WHAT THE CERTIFICATE SAYS THE CALLER IS. A peer that
    /// checks a client certificate learns that this deployment issued it, not
    /// which service is on the other end — distinguishing callers needs a check
    /// against the name in the certificate, and no such check exists in this
    /// estate today.
    pub fn identity(self, certificate: impl Into<PathBuf>, key: impl Into<PathBuf>) -> Self {
        Self {
            identity: Some(ClientIdentity {
                certificate: certificate.into(),
                key: key.into(),
            }),
            ..self
        }
    }

    /// Read and CHECK the CA bundle, and settle the verification domain.
    ///
    /// Everything that can be wrong about the configuration is wrong here, once,
    /// before a channel exists — so a bad path is a startup error rather than an
    /// unexplained handshake failure much later, and never a quiet downgrade.
    pub(crate) fn prepare(&self, host: &str) -> Result<ClientTlsConfig, BalanceError> {
        let pem =
            std::fs::read(&self.ca_certificate).map_err(|source| BalanceError::CaUnreadable {
                path: self.ca_certificate.clone(),
                source,
            })?;

        // THE ASSERTION THIS FUNCTION EXISTS FOR. The PEM reader yields nothing
        // — rather than an error — for input that contains no certificate
        // section, so "parsed successfully" can mean "parsed nothing", and a
        // trust store with no roots trusts nobody. Left unchecked that surfaces
        // as a handshake failure against a hostname the operator has never seen,
        // which is among the hardest errors here to diagnose.
        let certificates = CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| BalanceError::CaUnparsable {
                path: self.ca_certificate.clone(),
                source,
            })?;
        if certificates.is_empty() {
            return Err(BalanceError::CaEmpty {
                path: self.ca_certificate.clone(),
            });
        }

        // AND THE ASSERTION A SECTION COUNT CANNOT MAKE. The check above counts
        // PEM SECTIONS. What has to be non-empty is the ROOT STORE, and the two
        // part company for a bundle whose sections decode as PEM and then fail
        // to parse as a trust anchor — a key pasted under a CERTIFICATE header,
        // a truncated DER body. tonic hands exactly these DERs to
        // `add_parsable_certificates` and DISCARDS its `(accepted, rejected)`
        // return with no check after it
        // (`tonic-0.14.6/src/transport/channel/service/tls.rs:104`), so such a
        // bundle yields precisely the rootless trust store this function exists
        // to prevent, and the section count sees a healthy `1`.
        //
        // The store is built HERE, the way tonic will build it, and then
        // dropped: tonic accepts a PEM bundle rather than a store, so what this
        // buys is the answer to "how many roots will that produce", asked before
        // a channel exists instead of never.
        let sections = certificates.len();
        let mut roots = rustls::RootCertStore::empty();
        let (accepted, _rejected) = roots.add_parsable_certificates(certificates);
        if accepted == 0 {
            return Err(BalanceError::CaNoTrustAnchor {
                path: self.ca_certificate.clone(),
                sections,
            });
        }

        let mut configured = ClientTlsConfig::new()
            // The host, NOT the address that gets dialled.
            .domain_name(self.domain_name.as_deref().unwrap_or(host))
            .ca_certificate(Certificate::from_pem(&pem))
            // See `endpoint` for why the handshake needs its own bound.
            .timeout(CONNECT_TIMEOUT);

        // READ HERE, with the bundle, for the same reason: a mount that did not
        // happen is the operator's mistake and is reported as itself, naming
        // the file, rather than as a connection the peer closed without saying
        // why.
        //
        // THERE IS NO EMPTY-FILE CHECK TO MATCH `CaEmpty`, and the asymmetry is
        // deliberate rather than an omission. An empty CA bundle parses to a
        // trust store with no roots and fails much later; an empty client chain
        // is refused where rustls builds the configuration, and reaches the
        // caller as `Tls` from `endpoint` — observed as
        // `NoCertificatesPresented` — before any channel exists. Neither dials.
        // `tests/tls.rs` asserts that VARIANT rather than merely that it fails,
        // so a future tonic that accepted an empty chain and dialled anonymously
        // would be caught rather than pass for the wrong reason.
        if let Some(identity) = &self.identity {
            let certificate = std::fs::read(&identity.certificate).map_err(|source| {
                BalanceError::ClientCertificateUnreadable {
                    path: identity.certificate.clone(),
                    source,
                }
            })?;
            let key = std::fs::read(&identity.key).map_err(|source| {
                BalanceError::ClientKeyUnreadable {
                    path: identity.key.clone(),
                    source,
                }
            })?;
            configured = configured.identity(Identity::from_pem(certificate, key));
        }

        Ok(configured)
        // NOTE the two methods NOT called here: `with_native_roots` and
        // `with_webpki_roots`. Either would add the platform's trust store
        // alongside the bundle, so a CA that failed to load would leave the
        // peer verified against public roots instead — the silent downgrade
        // this change exists to remove, reintroduced one layer up.
    }
}
