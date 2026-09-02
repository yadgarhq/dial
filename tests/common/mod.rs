//! What both integration suites need to stand a server up, and nothing else.
//!
//! `tests/tls.rs` and `tests/timeout.rs` both need a certificate authority, a
//! server certificate, a CA bundle on disk and a way to wait for a listener.
//! Two copies of that is how two rigs quietly come to disagree — in particular
//! about `localhost`, which resolves to BOTH `::1` and `127.0.0.1` on this
//! machine, so a rig that binds one of them is flaky by construction.
//!
//! The servers themselves are NOT here: one suite serves and the other refuses
//! to, which is the whole difference between them.
//!
//! `allow(dead_code)` because each integration test binary compiles this module
//! separately, so anything only one of them uses looks unused to the other.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};

/// A certificate authority and one certificate it issued.
pub struct Pki {
    pub ca_pem: String,
    pub cert_pem: String,
    pub key_pem: String,
}

/// Mint a CA and a server certificate whose ONLY subject alternative name is
/// `san` — a DNS name, with no IP SAN. The absence is what makes the
/// host-versus-address distinction observable at all: an implementation that
/// verifies against `127.0.0.1` has nothing to match.
///
/// CERTIFICATES ARE MINTED PER RUN. A fixture key committed to the repository is
/// a secret committed to the repository, and it expires on a date nobody is
/// watching.
pub fn pki(san: &str) -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "yadgar-dial test authority");
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![san.to_string()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.distinguished_name.push(DnType::CommonName, san);
    let cert = params.signed_by(&key, &ca).unwrap();

    Pki {
        ca_pem: ca.pem(),
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    }
}

/// A file that deletes itself, so a CA bundle can be handed over as a PATH —
/// which is the only shape `TlsOptions` accepts, and the reason it accepts it.
pub struct TempPem(PathBuf);

impl TempPem {
    pub fn with(contents: &str) -> Self {
        let name = format!(
            "yadgar-dial-{}-{}.pem",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, contents).unwrap();
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempPem {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Wait until the port accepts a TCP connection, rather than sleeping a
/// guessed interval.
pub async fn ready(host: &str, port: u16) {
    for _ in 0..200 {
        if tokio::net::TcpStream::connect((host, port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the test server never accepted a connection on port {port}");
}
