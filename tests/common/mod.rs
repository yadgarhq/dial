//! What both integration suites need to stand a server up, and nothing else.
//!
//! `tests/tls.rs` and `tests/timeout.rs` both need a certificate authority, a
//! server certificate, a CA bundle on disk and a way to wait for a listener.
//! Two copies of that is how two rigs quietly come to disagree — in particular
//! about `localhost`, which resolves to BOTH `::1` and `127.0.0.1` on this
//! machine, so a rig that binds one of them is flaky by construction.
//!
//! The servers themselves are NOT here: one suite serves and the other refuses
//! to, which is the whole difference between them. [`bind_all`] therefore hands
//! back LISTENERS and leaves the serving to the caller.
//!
//! `allow(dead_code)` because each integration test binary compiles this module
//! separately, so anything only one of them uses looks unused to the other.
#![allow(dead_code)]

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use tokio::net::TcpListener;

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};

/// A certificate authority and one certificate it issued.
///
/// The authority is KEPT rather than dropped after that first leaf, because
/// mutual TLS needs a second leaf — the client's — issued by THE SAME
/// authority. Two calls to [`pki`] produce two unrelated roots, which is the
/// right rig for `a_certificate_from_an_untrusted_authority_is_refused` and
/// exactly the wrong one for every mutual-TLS case.
pub struct Pki {
    pub ca_pem: String,
    pub cert_pem: String,
    pub key_pem: String,
    issuer: CertifiedIssuer<'static, KeyPair>,
}

/// A certificate and its private key, issued by an existing [`Pki`].
pub struct Leaf {
    pub cert_pem: String,
    pub key_pem: String,
}

impl Pki {
    /// Issue a further leaf from this authority, valid for `purpose` alone.
    ///
    /// **THE PURPOSE IS A PARAMETER BECAUSE IT IS LOAD-BEARING, not so a test
    /// can vary it.** One authority issues both the serving and the client
    /// certificates in this estate, and what stops a serving certificate being
    /// replayed as a client credential is that rustls verifies a client chain
    /// for `client auth` and a server chain for `server auth`. A rig that
    /// issued every leaf for both purposes would pass against a deployment
    /// with no separation at all.
    pub fn issue(&self, san: &str, purpose: ExtendedKeyUsagePurpose) -> Leaf {
        self.issue_for(san, vec![purpose])
    }

    /// Issue a leaf naming EXACTLY `purposes`, including none at all.
    ///
    /// The empty case is the one this exists for, and it is not a variation on
    /// the above: an empty vector makes rcgen omit the extended-key-usage
    /// extension entirely rather than emit an empty one
    /// (`rcgen-0.14.10/src/certificate.rs:238`), which is what a leaf
    /// issued with no `usages` looks like. See
    /// `a_certificate_naming_no_purpose_at_all_is_accepted` for why that shape
    /// has to be pinned rather than assumed away.
    pub fn issue_for(&self, san: &str, purposes: Vec<ExtendedKeyUsagePurpose>) -> Leaf {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![san.to_string()]).unwrap();
        params.extended_key_usages = purposes;
        params.distinguished_name.push(DnType::CommonName, san);
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        Leaf {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }
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
        issuer: ca,
    }
}

/// A file that deletes itself, so a CA bundle can be handed over as a PATH —
/// which is the only shape `TlsOptions` accepts, and the reason it accepts it.
pub struct TempPem(PathBuf);

/// One reading of the clock per PROCESS, so two runs that the OS gave the same
/// recycled pid do not name the same files. It varies per run and never within
/// one, which is what leaves [`unique_name`] with exactly one varying part.
fn run_id() -> u128 {
    static RUN: OnceLock<u128> = OnceLock::new();
    *RUN.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    })
}

/// The name of one temporary PEM, unique within this process by CONSTRUCTION.
///
/// **THE CLOCK IS NOT A UNIQUENESS SOURCE ACROSS THREADS, and this is measured
/// on this tree rather than assumed.** The name used to be `pid` plus a fresh
/// nanosecond reading. Every test in one binary shares the pid and they run on
/// threads, so two concurrent calls collide whenever both readings land on the
/// same nanosecond — and then one `TempPem`'s `Drop` deletes a path a sibling
/// test is still reading. A clock is a timestamp, not a nonce (ledger 629).
///
/// The counter is the ONLY part that varies within a run, which is what makes
/// the property assertable rather than merely likely. It is asserted in
/// `tests/tls.rs` rather than here: a `#[test]` in this module would be
/// compiled into all three integration binaries and run three times.
pub fn unique_name() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    format!(
        "yadgar-dial-{}-{}-{}.pem",
        std::process::id(),
        run_id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

impl TempPem {
    pub fn with(contents: &str) -> Self {
        let path = std::env::temp_dir().join(unique_name());
        // `create_new`, not `fs::write`. Silence is what made the old collision
        // expensive: two tests shared a path, one deleted it, and the other
        // failed somewhere else entirely — as a missing bundle, or as a key file
        // that had been overwritten with a certificate. If a name is ever
        // reused, this panics and names the file instead.
        let mut file = std::fs::File::options()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap_or_else(|e| panic!("{} already exists or cannot be made: {e}", path.display()));
        file.write_all(contents.as_bytes()).unwrap();
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

/// How many ports to try before giving up on finding one free everywhere.
const BIND_ATTEMPTS: usize = 32;

/// Bind ONE free port on EVERY address `host` resolves to, and hand back the
/// listeners together with that port.
///
/// **Three call sites grew their own copy of this and had already drifted**: one
/// had lost the "resolved to nothing" assertion its siblings kept, and reported
/// a port collision through a bare `unwrap`. It lives here now, which is what
/// this module exists for.
///
/// **THE RACE, and why the retry is not decoration.** A free port is only
/// knowable AFTER the first bind, so between reading it and binding the same
/// port on the name's other addresses another process can take it — and nothing
/// reserves a port across several addresses at once. So the attempt drops
/// everything it holds and asks for a different port. Under a parallel
/// `cargo test` that collision is real rather than theoretical.
pub async fn bind_all(host: &str) -> (Vec<TcpListener>, u16) {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, 0))
        .await
        .unwrap_or_else(|e| panic!("{host} could not be resolved: {e}"))
        .collect();
    assert!(!addrs.is_empty(), "{host} resolved to nothing");

    for _ in 0..BIND_ATTEMPTS {
        if let Some(bound) = bind_once(&addrs).await {
            return bound;
        }
    }
    panic!("no port was free on every address of {host} after {BIND_ATTEMPTS} attempts");
}

/// One attempt: a free port on the first address, then the SAME port on the
/// rest. `None` means somebody else already holds it on one of the others, which
/// is the caller's cue to try a different port.
async fn bind_once(addrs: &[SocketAddr]) -> Option<(Vec<TcpListener>, u16)> {
    let first = TcpListener::bind(addrs[0])
        .await
        .unwrap_or_else(|e| panic!("no free port on {}: {e}", addrs[0]));
    let port = first.local_addr().unwrap().port();

    let mut listeners = vec![first];
    for addr in &addrs[1..] {
        match TcpListener::bind(SocketAddr::new(addr.ip(), port)).await {
            Ok(listener) => listeners.push(listener),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => return None,
            Err(e) => panic!("binding {} on port {port}: {e}", addr.ip()),
        }
    }
    Some((listeners, port))
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
