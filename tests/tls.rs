//! The TLS seam, proved by real handshakes.
//!
//! **A test that only shows "TLS was configured" passes against the broken
//! version of this change**, so nothing here inspects configuration. Every case
//! stands up a gRPC server with a real certificate, dials it through the crate's
//! own public entry points, and asserts on whether a request survived.
//!
//! THE FINDING THE WHOLE CHANGE RESTS ON is that `dial` connects to ADDRESSES
//! while a certificate names a HOST. `the_certificate_is_verified_against_the_
//! host_not_the_dialled_address` is the case that separates a working
//! implementation from one that verifies against the IP — and a broken one
//! fails it with `NotValidForName`, naming both sides.
//!
//! CERTIFICATES ARE MINTED PER RUN. A fixture key committed to the repository is
//! a secret committed to the repository, and it expires on a date nobody is
//! watching. The minting, and the CA bundle on disk, live in `tests/common` so
//! this suite and `tests/timeout.rs` cannot come to disagree about them.
//!
//! NOTE ON `localhost`: it is the one name that resolves without touching
//! `/etc/hosts`, and on this machine it resolves to BOTH `::1` and `127.0.0.1`.
//! `serve` therefore binds every address the name resolves to, on one port, so
//! the balancer never holds an endpoint nothing is listening on. That is a
//! property of the test rig, not of the crate.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::codegen::{http, Service};
use tonic::transport::{Channel, Identity, Server, ServerTlsConfig};
use yadgar_dial::TlsOptions;

mod common;

use common::{pki, ready, Pki, TempPem};

/// The name the test certificates are issued for, and the name the test rig
/// listens on.
const SERVED_NAME: &str = "localhost";

/// Serve gRPC over TLS on every address `SERVED_NAME` resolves to, and return
/// the shared port. `Routes::default()` answers every method with
/// `Unimplemented`, which is all that is needed: the question each test asks is
/// whether a request reached the server at all.
async fn serve(p: &Pki) -> u16 {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((SERVED_NAME, 0))
        .await
        .unwrap()
        .collect();
    assert!(!addrs.is_empty(), "{SERVED_NAME} resolved to nothing");

    let first = TcpListener::bind(addrs[0]).await.unwrap();
    let port = first.local_addr().unwrap().port();
    spawn_tls_server(first, p);

    for addr in &addrs[1..] {
        let listener = TcpListener::bind(SocketAddr::new(addr.ip(), port))
            .await
            .expect("the same free port on a second address of the same name");
        spawn_tls_server(listener, p);
    }

    ready(SERVED_NAME, port).await;
    port
}

/// Serve gRPC in CLEARTEXT, for the case that has to keep working untouched.
async fn serve_cleartext() -> u16 {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((SERVED_NAME, 0))
        .await
        .unwrap()
        .collect();
    let first = TcpListener::bind(addrs[0]).await.unwrap();
    let port = first.local_addr().unwrap().port();
    spawn_cleartext_server(first);
    for addr in &addrs[1..] {
        let listener = TcpListener::bind(SocketAddr::new(addr.ip(), port))
            .await
            .unwrap();
        spawn_cleartext_server(listener);
    }
    ready(SERVED_NAME, port).await;
    port
}

fn spawn_tls_server(listener: TcpListener, p: &Pki) {
    let identity = Identity::from_pem(&p.cert_pem, &p.key_pem);
    let mut builder = Server::builder()
        .tls_config(ServerTlsConfig::new().identity(identity))
        .unwrap();
    let router = builder.add_routes(tonic::service::Routes::default());
    tokio::spawn(async move {
        let _ = router
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await;
    });
}

fn spawn_cleartext_server(listener: TcpListener) {
    let mut builder = Server::builder();
    let router = builder.add_routes(tonic::service::Routes::default());
    tokio::spawn(async move {
        let _ = router
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await;
    });
}

/// Send one gRPC request down the channel and report whether it ARRIVED.
///
/// `Ok` means the transport carried it: the handshake completed and the server
/// answered — with `Unimplemented`, which is a perfectly good answer to this
/// question. `Err` means it never got there.
///
/// The request goes through `poll_ready` first, and that is not a formality:
/// `poll_ready` on a balanced channel reports success even when the only
/// endpoint's handshake has failed, so ASKING THE CHANNEL WHETHER IT IS READY
/// PROVES NOTHING. Only a request does.
async fn request(mut channel: Channel) -> Result<(), String> {
    let req = http::Request::builder()
        .version(http::Version::HTTP_2)
        .method("POST")
        .uri(format!("https://{SERVED_NAME}/yadgar.dial.Probe/Probe"))
        .header("content-type", "application/grpc")
        .body(tonic::body::Body::empty())
        .unwrap();

    std::future::poll_fn(|cx| channel.poll_ready(cx))
        .await
        .map_err(|e| format!("{e}"))?;
    match tokio::time::timeout(Duration::from_secs(10), channel.call(req)).await {
        Err(_) => Err("the request timed out".to_string()),
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!("{e}")),
    }
}

/// THE FINDING. `dial` balances across pod ADDRESSES, so the naive
/// implementation verifies the certificate against `127.0.0.1` — and the
/// certificate here carries no IP SAN, exactly as a real per-Service
/// certificate does not.
///
/// Delete `domain_name` from `TlsOptions::prepare` and this test fails with
/// `NotValidForName { expected: IpAddress(127.0.0.1), presented:
/// [DnsName("localhost")] }`, which is the whole task in one error message.
#[tokio::test]
async fn the_certificate_is_verified_against_the_host_not_the_dialled_address() {
    let p = pki(SERVED_NAME);
    let port = serve(&p).await;
    let ca = TempPem::with(&p.ca_pem);

    let channel = yadgar_dial::connect_tls(SERVED_NAME, port, &TlsOptions::new(ca.path()))
        .await
        .expect("a valid CA bundle and a resolvable host");

    assert_eq!(request(channel).await, Ok(()));
}

/// The host argument has to be the one that reaches the verifier. Dialling the
/// SAME server by its address must fail, because then there is no host — and
/// this is what catches a wiring bug that passes the host's address through in
/// place of the host.
///
/// `127.0.0.1` is used rather than `localhost` because it resolves to exactly
/// one address, so there is no second endpoint for the balancer to succeed on.
#[tokio::test]
async fn dialling_by_address_fails_because_the_address_is_what_gets_verified() {
    let p = pki(SERVED_NAME);
    let port = serve(&p).await;
    let ca = TempPem::with(&p.ca_pem);

    let channel = yadgar_dial::connect_tls("127.0.0.1", port, &TlsOptions::new(ca.path()))
        .await
        .expect("the address resolves and the bundle is valid");

    let outcome = request(channel).await;
    assert!(
        outcome.is_err(),
        "an address has no name for a certificate to match, so this must not connect: {outcome:?}"
    );
}

/// The override, proved with a name the implementation could not have chosen:
/// the certificate is issued for a sentinel, the host dialled is not that
/// sentinel, and only the override can reconcile them.
#[tokio::test]
async fn the_verification_domain_can_be_overridden() {
    const SENTINEL: &str = "dial-pins-this-name.invalid";

    let p = pki(SENTINEL);
    let port = serve(&p).await;
    let ca = TempPem::with(&p.ca_pem);

    let options = TlsOptions::new(ca.path()).domain_name(SENTINEL);
    let channel = yadgar_dial::connect_tls(SERVED_NAME, port, &options)
        .await
        .unwrap();
    assert_eq!(request(channel).await, Ok(()));

    // And without the override the same server is correctly refused: the
    // certificate does not name the host.
    let channel = yadgar_dial::connect_tls(SERVED_NAME, port, &TlsOptions::new(ca.path()))
        .await
        .unwrap();
    assert!(
        request(channel).await.is_err(),
        "a certificate for {SENTINEL} must not satisfy a connection to {SERVED_NAME}"
    );
}

/// Verification has to be REAL. A certificate from an authority the caller does
/// not trust is what an impostor presents, and the bearer token must not go to
/// it. Drop `ca_certificate` from `TlsOptions::prepare`, or add the platform
/// trust store beside it, and this is the test that notices.
#[tokio::test]
async fn a_certificate_from_an_untrusted_authority_is_refused() {
    let served = pki(SERVED_NAME);
    let port = serve(&served).await;

    // A second authority, which issued nothing the server holds.
    let stranger = pki(SERVED_NAME);
    let ca = TempPem::with(&stranger.ca_pem);

    let channel = yadgar_dial::connect_tls(SERVED_NAME, port, &TlsOptions::new(ca.path()))
        .await
        .unwrap();
    assert!(
        request(channel).await.is_err(),
        "a certificate signed by an authority that is not trusted must be refused"
    );
}

/// THE SILENT-DOWNGRADE CASE, in the form the record says it takes: the PEM
/// reader returns an EMPTY LIST rather than an error, so a bundle that decodes
/// to nothing looks like a bundle that decoded fine.
///
/// Each of these must be an error from `connect_tls`, never a channel.
#[tokio::test]
async fn a_ca_bundle_with_no_certificate_in_it_is_an_error() {
    let p = pki(SERVED_NAME);
    let port = serve(&p).await;

    for contents in ["", "   ", "\n", "there is no certificate in this file\n"] {
        let ca = TempPem::with(contents);
        let outcome =
            yadgar_dial::connect_tls(SERVED_NAME, port, &TlsOptions::new(ca.path())).await;
        assert!(
            matches!(outcome, Err(yadgar_dial::BalanceError::CaEmpty { .. })),
            "a bundle containing {contents:?} must be rejected, not connected: {outcome:?}"
        );
    }
}

/// A path that is not there at all. The mistake an operator actually makes is a
/// mount that did not happen, and the answer to it must not be a cleartext
/// channel.
#[tokio::test]
async fn a_ca_bundle_that_cannot_be_read_is_an_error() {
    let p = pki(SERVED_NAME);
    let port = serve(&p).await;

    let missing = std::env::temp_dir().join("yadgar-dial-no-such-bundle-9d3f1a.pem");
    let outcome = yadgar_dial::connect_tls(SERVED_NAME, port, &TlsOptions::new(&missing)).await;
    assert!(
        matches!(outcome, Err(yadgar_dial::BalanceError::CaUnreadable { .. })),
        "a CA path that does not exist must be rejected: {outcome:?}"
    );
}

/// The bundle is checked BEFORE the host is resolved, so an operator who got
/// both wrong is told about the one they can fix from the configuration they
/// just wrote.
#[tokio::test]
async fn the_bundle_is_checked_before_the_host_is_resolved() {
    let missing = std::env::temp_dir().join("yadgar-dial-no-such-bundle-4b7e02.pem");
    let outcome = yadgar_dial::connect_tls(
        "a-host-that-does-not-resolve.invalid",
        50051,
        &TlsOptions::new(&missing),
    )
    .await;
    assert!(
        matches!(outcome, Err(yadgar_dial::BalanceError::CaUnreadable { .. })),
        "the configuration error must win over the DNS failure: {outcome:?}"
    );
}

/// The path that must not have moved. `connect` still speaks cleartext to a
/// cleartext server, and this is what fails if the scheme, the timeouts or the
/// keepalive drift while nobody is looking at them.
#[tokio::test]
async fn the_cleartext_path_still_reaches_a_cleartext_server() {
    let port = serve_cleartext().await;
    let channel = yadgar_dial::connect(SERVED_NAME, port).await.unwrap();
    assert_eq!(request(channel).await, Ok(()));
}

/// And it is still cleartext, which is the other half of "unchanged": a
/// cleartext dial to a TLS server has to fail rather than quietly negotiate
/// something. If `connect` ever started speaking TLS this would begin passing
/// for the wrong reason, so the case above pins the other direction.
#[tokio::test]
async fn the_cleartext_path_cannot_reach_a_tls_server() {
    let p = pki(SERVED_NAME);
    let port = serve(&p).await;
    let channel = yadgar_dial::connect(SERVED_NAME, port).await.unwrap();
    assert!(
        request(channel).await.is_err(),
        "cleartext against a TLS listener must fail"
    );
}
