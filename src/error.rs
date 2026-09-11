//! The one error type every entry point in this crate returns.
//!
//! Split out of `lib.rs` by LEDGER 719; nothing here changed.

use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum BalanceError {
    #[error(
        "resolving {host} did not finish within {after:?}. This is NOT a name \
         that does not exist — that answers, and answers quickly. It is a \
         resolver that stopped answering at all, and the caller is released \
         rather than left waiting with no end. The lookup itself runs on the \
         blocking pool and cannot be cancelled: that thread stays parked until \
         the resolver replies."
    )]
    DnsTimedOut { host: String, after: Duration },

    #[error(
        "{host} cannot be dialled at all: it does not form a URI authority. This \
         is NOT an upstream that is absent — no resolution will ever fix it — so \
         it is reported before a channel exists rather than deferred to a lazy \
         dial that could never succeed."
    )]
    InvalidHost { host: String },

    #[error("could not resolve {host}")]
    Dns {
        host: String,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "TLS was requested, so a CA certificate bundle that cannot be read is \
         an error rather than a reason to connect in cleartext. The bundle at \
         {path} could not be read"
    )]
    CaUnreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("could not decode the CA certificate bundle at {path}")]
    CaUnparsable {
        path: PathBuf,
        #[source]
        source: rustls_pki_types::pem::Error,
    },

    #[error(
        "the CA certificate bundle at {path} decoded without error but contains \
         no certificate. That is not the same as a missing file: the PEM reader \
         returns an empty list for input with no certificate section, so an \
         empty or truncated bundle would otherwise produce a trust store with \
         no roots — which trusts nobody and fails much later, at the handshake."
    )]
    CaEmpty { path: PathBuf },

    #[error(
        "the CA certificate bundle at {path} holds {sections} PEM certificate \
         section(s) and NONE of them is a usable trust anchor. That is not the \
         same as an empty bundle: the sections are present and they decode as \
         PEM, so counting them says the file is fine. tonic builds its root \
         store with `add_parsable_certificates`, which reports how many it \
         accepted and how many it threw away, and discards that report — so a \
         bundle like this one produces a trust store with no roots and no error, \
         and fails much later, at the handshake."
    )]
    CaNoTrustAnchor { path: PathBuf, sections: usize },

    #[error(
        "a client certificate was configured, so one that cannot be read is an \
         error rather than a reason to connect without presenting one. The \
         certificate at {path} could not be read"
    )]
    ClientCertificateUnreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "a client certificate without its key proves nothing, so a key that \
         cannot be read is an error rather than a reason to connect without \
         presenting one. The key at {path} could not be read"
    )]
    ClientKeyUnreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("TLS could not be configured")]
    Tls {
        #[source]
        source: tonic::transport::Error,
    },
}
