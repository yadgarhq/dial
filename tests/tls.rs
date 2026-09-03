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
//! `common::bind_all` therefore binds every address the name resolves to, on one
//! port, so the balancer never holds an endpoint nothing is listening on. That is
//! a property of the test rig, not of the crate.

use std::time::Duration;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::codegen::{http, Service};
use tonic::transport::{Channel, Identity, Server, ServerTlsConfig};
use yadgar_dial::TlsOptions;

mod common;

use common::{bind_all, pki, ready, Leaf, Pki, TempPem};
use rcgen::ExtendedKeyUsagePurpose;

/// The name the test certificates are issued for, and the name the test rig
/// listens on.
const SERVED_NAME: &str = "localhost";

/// The name a client certificate is issued for. It is never dialled and never
/// verified — nothing checks a client's name today, which is the gap the
/// deployment records rather than a shortcut taken here — so it exists only to
/// make the certificate a well-formed one.
const CALLER_NAME: &str = "yadgar-dial-test-caller";

/// Bind every address `SERVED_NAME` resolves to, on ONE shared port, hand each
/// listener to `spawn`, and return that port.
///
/// The binding itself lives in `common::bind_all`, which retries because a free
/// port is only knowable after the first bind. `Routes::default()` answers every
/// method with `Unimplemented`, which is all that is needed: the question each
/// test asks is whether a request reached the server at all.
async fn serve_with(spawn: impl Fn(TcpListener)) -> u16 {
    let (listeners, port) = bind_all(SERVED_NAME).await;
    for listener in listeners {
        spawn(listener);
    }
    ready(SERVED_NAME, port).await;
    port
}

/// Serve gRPC over TLS, verifying nothing about the client.
async fn serve(p: &Pki) -> u16 {
    serve_with(|listener| spawn_server(listener, ServerTlsConfig::new().identity(identity(p))))
        .await
}

/// Serve gRPC over MUTUAL TLS: a client that presents no certificate, or one
/// this authority did not issue for `client auth`, is refused at the handshake.
///
/// `client_ca_root` is what the internal services gain in a later car, and it
/// is the whole server side of the seam this suite exercises from the client
/// side.
async fn serve_mtls(p: &Pki) -> u16 {
    serve_with(|listener| {
        spawn_server(
            listener,
            ServerTlsConfig::new()
                .identity(identity(p))
                .client_ca_root(tonic::transport::Certificate::from_pem(&p.ca_pem)),
        )
    })
    .await
}

/// Serve gRPC in CLEARTEXT, for the case that has to keep working untouched.
async fn serve_cleartext() -> u16 {
    serve_with(spawn_cleartext_server).await
}

fn identity(p: &Pki) -> Identity {
    Identity::from_pem(&p.cert_pem, &p.key_pem)
}

fn spawn_server(listener: TcpListener, tls: ServerTlsConfig) {
    let mut builder = Server::builder().tls_config(tls).unwrap();
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

/// Write a leaf's certificate and key to disk, because paths are the only shape
/// [`TlsOptions`] accepts — and the reason it accepts them (D80).
fn on_disk(leaf: &Leaf) -> (TempPem, TempPem) {
    (TempPem::with(&leaf.cert_pem), TempPem::with(&leaf.key_pem))
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

/// THE CASE A SECTION COUNT CANNOT SEE: a bundle that decodes as PEM and yields
/// no trust anchor at all.
///
/// The body here is a real private key's base64 wrapped in CERTIFICATE headers —
/// valid framing, valid base64, and DER that is not a certificate.
/// `CertificateDer`'s PEM reader hands it over without complaint, because it
/// decodes bytes and does not look at them, so a check that counts PEM sections
/// sees a healthy `1`.
///
/// tonic then feeds those same DERs to `add_parsable_certificates`, which throws
/// away what it cannot parse and reports how much — and tonic discards the
/// report with no check after it. The result is the empty root store `CaEmpty`
/// exists to prevent, reached by a path `CaEmpty` never covered.
///
/// The section count is asserted too, not only the variant: `sections: 1` is what
/// makes it this case rather than the empty-file one.
#[tokio::test]
async fn a_ca_bundle_whose_sections_are_not_trust_anchors_is_an_error() {
    let p = pki(SERVED_NAME);
    let port = serve(&p).await;

    let body = p
        .key_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("\n");
    let ca = TempPem::with(&format!(
        "-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"
    ));

    let outcome = yadgar_dial::connect_tls(SERVED_NAME, port, &TlsOptions::new(ca.path())).await;
    assert!(
        matches!(
            outcome,
            Err(yadgar_dial::BalanceError::CaNoTrustAnchor { sections: 1, .. })
        ),
        "a bundle holding one PEM section and no trust anchor must be rejected, not connected: \
         {outcome:?}"
    );
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

/// THE MUTUAL-TLS CASE, and the pair of assertions is the whole test: the same
/// server, dialled twice, differing only in whether a client certificate was
/// configured. One arm alone proves nothing — a channel that never presents a
/// certificate still connects to a server that never asks for one.
///
/// Delete `.identity(...)` from `TlsOptions::prepare` and the first assertion
/// fails, because the server closes the connection on a client that offered
/// nothing.
#[tokio::test]
async fn a_client_certificate_is_presented_when_one_is_configured() {
    let p = pki(SERVED_NAME);
    let port = serve_mtls(&p).await;
    let ca = TempPem::with(&p.ca_pem);

    let client = p.issue(CALLER_NAME, ExtendedKeyUsagePurpose::ClientAuth);
    let (cert, key) = on_disk(&client);
    let options = TlsOptions::new(ca.path()).identity(cert.path(), key.path());
    let channel = yadgar_dial::connect_tls(SERVED_NAME, port, &options)
        .await
        .expect("a valid CA bundle, certificate and key");
    assert_eq!(request(channel).await, Ok(()));

    // The other arm. This is also the proof that presenting a certificate is
    // OPT-IN: `TlsOptions::new` alone is what every caller ships with today,
    // and it reaches a server that does not ask.
    let channel = yadgar_dial::connect_tls(SERVED_NAME, port, &TlsOptions::new(ca.path()))
        .await
        .unwrap();
    assert!(
        request(channel).await.is_err(),
        "a server that requires a client certificate must refuse a client with none"
    );
}

/// THE PROPERTY THAT REPLACES A SECOND CERTIFICATE AUTHORITY, and it is here
/// because the deployment's choice rests on it.
///
/// One authority — `yadgar-internal-ca` — issues both the serving and the
/// client certificates. What stops a stolen SERVING certificate being replayed
/// as a client credential is therefore not a separate issuer but the extended
/// key usage: rustls verifies a client chain for `client auth`, so a leaf
/// carrying `server auth` alone is refused even though the authority is
/// trusted.
///
/// A leaf issued for the wrong purpose is exactly what a serving certificate
/// is when it arrives at the client end of a hop, so this is that attack in
/// miniature. If it ever starts passing, the deployment needs two authorities.
#[tokio::test]
async fn a_certificate_that_is_not_valid_for_client_auth_is_refused() {
    let p = pki(SERVED_NAME);
    let port = serve_mtls(&p).await;
    let ca = TempPem::with(&p.ca_pem);

    let wrong_purpose = p.issue(CALLER_NAME, ExtendedKeyUsagePurpose::ServerAuth);
    let (cert, key) = on_disk(&wrong_purpose);
    let options = TlsOptions::new(ca.path()).identity(cert.path(), key.path());
    let channel = yadgar_dial::connect_tls(SERVED_NAME, port, &options)
        .await
        .expect("the material is well-formed; it is the purpose that is wrong");
    assert!(
        request(channel).await.is_err(),
        "a certificate valid only for `server auth` must not authenticate a client, \
         or one authority for both directions is not safe"
    );
}

/// THE OTHER HALF OF THAT PROPERTY, AND IT DOES NOT HOLD. This case pins an
/// ACCEPTED GAP rather than a guarantee, and it is here so nobody reads the
/// canary above as proving more than it does.
///
/// `a_certificate_that_is_not_valid_for_client_auth_is_refused` covers a leaf
/// that names the WRONG purpose. It says nothing about a leaf that names NO
/// purpose, and the two do not behave alike: webpki's `KeyUsage::client_auth()`
/// is `required_if_present`, not `required`
/// (`rustls-webpki-0.103.15/src/verify_cert.rs:524`), and an absent extension
/// takes the accepting branch of that check (`:578-579`). So a leaf carrying no
/// extended-key-usage extension satisfies a client-auth check. That is not a
/// corner case — it is exactly what cert-manager issues when `usages` is
/// omitted from a Certificate.
///
/// So the wall the single-authority decision rests on separates NAMED purposes
/// and accepts a leaf naming none. Any leaf this authority issues without an
/// extended key usage authenticates a caller, whatever it was meant for. Making
/// this red — by requiring the extension — is a real change with a real cost,
/// and it is not taken here; the assertion is the current behaviour, written
/// down.
#[tokio::test]
async fn a_certificate_naming_no_purpose_at_all_is_accepted() {
    let p = pki(SERVED_NAME);
    let port = serve_mtls(&p).await;
    let ca = TempPem::with(&p.ca_pem);

    let no_purpose = p.issue_for(CALLER_NAME, vec![]);
    let (cert, key) = on_disk(&no_purpose);
    let options = TlsOptions::new(ca.path()).identity(cert.path(), key.path());
    let channel = yadgar_dial::connect_tls(SERVED_NAME, port, &options)
        .await
        .expect("a valid CA bundle, certificate and key");
    assert_eq!(
        request(channel).await,
        Ok(()),
        "a leaf with no extended key usage is accepted for client auth today; \
         if this goes red the gap has been closed and the comment above is stale"
    );
}

/// The mistake an operator actually makes is a mount that did not happen, and
/// the answer to it must name the file rather than surface much later as a
/// handshake the peer closed.
///
/// Both halves, because they are two files and either can be absent alone.
#[tokio::test]
async fn a_client_certificate_that_cannot_be_read_is_an_error() {
    let p = pki(SERVED_NAME);
    let port = serve_mtls(&p).await;
    let ca = TempPem::with(&p.ca_pem);
    let client = p.issue(CALLER_NAME, ExtendedKeyUsagePurpose::ClientAuth);
    let (cert, key) = on_disk(&client);

    let missing = std::env::temp_dir().join("yadgar-dial-no-such-identity-6c02af.pem");

    let options = TlsOptions::new(ca.path()).identity(&missing, key.path());
    let outcome = yadgar_dial::connect_tls(SERVED_NAME, port, &options).await;
    assert!(
        matches!(
            outcome,
            Err(yadgar_dial::BalanceError::ClientCertificateUnreadable { .. })
        ),
        "a client certificate path that does not exist must be rejected: {outcome:?}"
    );

    let options = TlsOptions::new(ca.path()).identity(cert.path(), &missing);
    let outcome = yadgar_dial::connect_tls(SERVED_NAME, port, &options).await;
    assert!(
        matches!(
            outcome,
            Err(yadgar_dial::BalanceError::ClientKeyUnreadable { .. })
        ),
        "a client key path that does not exist must be rejected: {outcome:?}"
    );
}

/// The empty file, which is what a Secret with the wrong key name mounts.
///
/// There is deliberately no `ClientCertificateEmpty` variant to match
/// `CaEmpty`, and the asymmetry has a reason worth pinning: an empty TRUST
/// STORE is silently permissive-looking and fails much later, whereas an empty
/// CLIENT CHAIN is refused by rustls where the configuration is BUILT.
///
/// THE VARIANT IS ASSERTED, NOT MERELY THAT THIS FAILS, and that is the whole
/// value of the case. `Tls` is the error `endpoint` returns when the connector
/// cannot be constructed — observed as `NoCertificatesPresented` — so it says
/// the material was rejected before any channel existed. A bare `is_err` would
/// also be satisfied by a channel that dialled anonymously and was refused by
/// the peer, which is the outcome this asymmetry claims cannot happen. If a
/// future tonic accepts an empty chain, `connect_tls` returns a channel and
/// this goes red, which is the point.
#[tokio::test]
async fn an_empty_client_certificate_is_an_error_rather_than_an_anonymous_dial() {
    let p = pki(SERVED_NAME);
    let port = serve_mtls(&p).await;
    let ca = TempPem::with(&p.ca_pem);
    let client = p.issue(CALLER_NAME, ExtendedKeyUsagePurpose::ClientAuth);
    let (_cert, key) = on_disk(&client);

    let empty = TempPem::with("");
    let options = TlsOptions::new(ca.path()).identity(empty.path(), key.path());
    let outcome = yadgar_dial::connect_tls(SERVED_NAME, port, &options).await;
    assert!(
        matches!(outcome, Err(yadgar_dial::BalanceError::Tls { .. })),
        "an empty client certificate must be refused where the connector is built, \
         not produce a channel that dials anonymously: {outcome:?}"
    );
}
