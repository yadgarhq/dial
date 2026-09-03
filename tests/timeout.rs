//! The per-request bound, proved against a peer that is alive and silent.
//!
//! **A test that only shows "a timeout was configured" passes against the
//! broken version of this change**, so nothing here inspects an `Endpoint`.
//! Every case stands up a real gRPC server whose handler NEVER RESOLVES, dials
//! it through the crate's own public entry points, and measures how long the
//! channel took to give up.
//!
//! THE SHAPE THE BOUND EXISTS FOR is not a peer that vanished. It is a peer
//! that completed its TCP connect, completed its HTTP/2 handshake, answers
//! keepalive pings, and never replies — a `-db` blocked on its engine. That is
//! why the rig is a real `tonic::transport::Server` rather than a bare
//! `TcpListener` that accepts and does nothing: a listener that never speaks
//! HTTP/2 stalls BEFORE the request is dispatched, so the failure comes from
//! `connect_timeout`, which already existed, and the test would pass against a
//! build with no request timeout at all.
//!
//! THE BOUND UNDER TEST IS THE CALLER'S, never the crate's default.
//! `SENTINEL_BOUND` is a value the implementation could not plausibly contain,
//! and every deadline assertion has a ceiling — so a build that ignored the
//! argument and applied its own default fails on the ceiling rather than
//! passing on the floor.
//!
//! NOTE ON `localhost`: it resolves to BOTH `::1` and `127.0.0.1` here, so
//! `common::bind_all` binds every address the name resolves to, on one port. A
//! rig binding one of them leaves the balancer holding an endpoint nothing is
//! listening on.

use std::convert::Infallible;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::body::Body;
use tonic::codegen::{http, Service};
use tonic::server::NamedService;
use tonic::transport::{Channel, Identity, Server, ServerTlsConfig};
use yadgar_dial::TlsOptions;

mod common;

use common::{bind_all, pki, ready, Pki, TempPem};

/// The name the test certificates are issued for, and the name the rig listens
/// on.
const SERVED_NAME: &str = "localhost";

/// The bound the CALLER asks for. Not a number this crate contains anywhere: a
/// build that ignored the argument cannot satisfy the ceilings below by
/// accident.
const SENTINEL_BOUND: Duration = Duration::from_millis(750);

/// A bound so generous that anything finishing under it finished for another
/// reason — used where the point is that something ELSE did the bounding.
const GENEROUS_BOUND: Duration = Duration::from_secs(20);

/// How long a case waits before declaring that NOTHING bounded the request.
///
/// Deliberately far below the crate's own default, so a build that applies its
/// default instead of the caller's argument trips this rather than passing.
const GIVE_UP: Duration = Duration::from_secs(6);

/// A gRPC service that accepts a request and never answers it.
///
/// This is the whole rig. The connection is real, the HTTP/2 handshake
/// completes, the request headers arrive — and the response future is
/// `Pending` forever.
#[derive(Clone, Copy)]
struct NeverAnswers;

impl NamedService for NeverAnswers {
    const NAME: &'static str = "yadgar.dial.NeverAnswers";
}

impl Service<http::Request<Body>> for NeverAnswers {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = std::future::Pending<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // READY, deliberately. A service that reported itself unready would be
        // bounded by the balancer's readiness instead, which is a different
        // layer and a different question.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: http::Request<Body>) -> Self::Future {
        std::future::pending()
    }
}

/// Serve [`NeverAnswers`] on every address `SERVED_NAME` resolves to, over TLS
/// when a `Pki` is given and in cleartext otherwise, and return the shared port.
async fn serve(tls: Option<&Pki>) -> u16 {
    let (listeners, port) = bind_all(SERVED_NAME).await;
    for listener in listeners {
        spawn(listener, tls);
    }
    ready(SERVED_NAME, port).await;
    port
}

fn spawn(listener: TcpListener, tls: Option<&Pki>) {
    let mut builder = match tls {
        None => Server::builder(),
        Some(p) => Server::builder()
            .tls_config(ServerTlsConfig::new().identity(Identity::from_pem(
                p.cert_pem.as_bytes(),
                p.key_pem.as_bytes(),
            )))
            .unwrap(),
    };
    let router = builder.add_routes(tonic::service::Routes::default().add_service(NeverAnswers));
    tokio::spawn(async move {
        let _ = router
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await;
    });
}

/// One request to the route that never answers.
///
/// `caller_deadline` is a `grpc-timeout` header value — the gRPC deadline a
/// caller sets for itself, which is the mechanism this crate's bound has to
/// coexist with.
fn stalling_request(caller_deadline: Option<&str>) -> http::Request<Body> {
    let mut builder = http::Request::builder()
        .version(http::Version::HTTP_2)
        .method("POST")
        .uri(format!("https://{SERVED_NAME}/{}/Wait", NeverAnswers::NAME))
        .header("content-type", "application/grpc");
    if let Some(deadline) = caller_deadline {
        builder = builder.header("grpc-timeout", deadline);
    }
    builder.body(Body::empty()).unwrap()
}

/// Send one request into a peer that will never answer, and report HOW LONG the
/// channel took to give up on it.
///
/// The request goes through `poll_ready` first, and that is not a formality:
/// `poll_ready` on a balanced channel reports success even when the only
/// endpoint's handshake has failed, so ASKING THE CHANNEL WHETHER IT IS READY
/// PROVES NOTHING. Only a request does. The clock starts after it, because
/// establishing the connection is what `connect_timeout` bounds and this is a
/// different measurement.
async fn stalled_for(
    mut channel: Channel,
    caller_deadline: Option<&str>,
) -> Result<Duration, String> {
    std::future::poll_fn(|cx| channel.poll_ready(cx))
        .await
        .map_err(|e| format!("{e}"))?;

    let started = Instant::now();
    match tokio::time::timeout(GIVE_UP, channel.call(stalling_request(caller_deadline))).await {
        Err(_) => Err(format!(
            "NOTHING bounded the request: it was still open after {GIVE_UP:?}"
        )),
        Ok(Ok(response)) => Err(format!(
            "the server answered {} — the rig is wrong, not the crate: the route \
             that never answers was not the one that got the request",
            response.status()
        )),
        Ok(Err(_)) => Ok(started.elapsed()),
    }
}

/// Assert a wait landed on the bound rather than somewhere else.
///
/// BOTH sides matter. The floor rejects a build that failed the request for
/// some other reason — a refused connection, a routing miss — and the ceiling
/// rejects a build that ignored the caller's argument and applied its own
/// number.
fn landed_on(waited: Duration, bound: Duration) {
    assert!(
        waited >= bound,
        "the request failed after {waited:?}, before the {bound:?} bound could have \
         fired — so something other than the bound ended it"
    );
    assert!(
        waited < bound * 3,
        "the request ran {waited:?} against a {bound:?} bound, so the bound that \
         applied was not the one the caller asked for"
    );
}

/// THE FINDING. A peer that is connected, healthy and silent held the caller's
/// handler open for as long as it liked: `connect_timeout` bounds the TCP
/// connect and HTTP/2 keepalive notices a peer that VANISHED, and neither of
/// them is this.
///
/// Delete `.timeout(request_timeout)` from `endpoint` and this fails with
/// "NOTHING bounded the request".
#[tokio::test]
async fn a_peer_that_never_replies_is_cut_off_at_the_bound() {
    let port = serve(None).await;

    let channel = yadgar_dial::connect_with_request_timeout(SERVED_NAME, port, SENTINEL_BOUND)
        .await
        .unwrap();

    landed_on(stalled_for(channel, None).await.unwrap(), SENTINEL_BOUND);
}

/// The SAME bound on the TLS path, because there is one call site and one
/// argument. This is what fails if the two paths are ever allowed to drift.
#[tokio::test]
async fn the_tls_path_carries_the_same_bound() {
    let p = pki(SERVED_NAME);
    let port = serve(Some(&p)).await;
    let ca = TempPem::with(&p.ca_pem);

    let channel = yadgar_dial::connect_tls_with_request_timeout(
        SERVED_NAME,
        port,
        &TlsOptions::new(ca.path()),
        SENTINEL_BOUND,
    )
    .await
    .unwrap();

    landed_on(stalled_for(channel, None).await.unwrap(), SENTINEL_BOUND);
}

/// A BACKSTOP is only a backstop if a caller cannot exceed it. This caller sets
/// a gRPC deadline of ten seconds — longer than the bound, and longer than this
/// suite is willing to wait — and must still be cut off at the bound.
///
/// This is the load-bearing half of the interaction. The case below it passes
/// even with the crate's bound deleted, because the caller's own deadline would
/// end that request anyway; this one does not.
#[tokio::test]
async fn a_callers_longer_deadline_does_not_escape_the_bound() {
    let port = serve(None).await;

    let channel = yadgar_dial::connect_with_request_timeout(SERVED_NAME, port, SENTINEL_BOUND)
        .await
        .unwrap();

    landed_on(
        stalled_for(channel, Some("10S")).await.unwrap(),
        SENTINEL_BOUND,
    );
}

/// And the other direction: a caller that asks for LESS gets less. tonic takes
/// the shorter of the two, so this crate's bound never extends a deadline a
/// caller chose on purpose.
#[tokio::test]
async fn a_callers_shorter_deadline_still_wins() {
    const CALLER: Duration = Duration::from_millis(200);

    let port = serve(None).await;

    let channel = yadgar_dial::connect_with_request_timeout(SERVED_NAME, port, GENEROUS_BOUND)
        .await
        .unwrap();

    let waited = stalled_for(channel, Some("200m")).await.unwrap();
    assert!(
        waited < CALLER * 5,
        "the caller asked for {CALLER:?} and waited {waited:?}: the crate's \
         {GENEROUS_BOUND:?} was applied instead of the shorter of the two"
    );
}

/// The rig itself, and the default with it.
///
/// Every case above proves a bound FIRED. This one proves the server really
/// does stall — that the others are not passing because a request to this route
/// fails immediately for some unrelated reason — and that `connect`, which
/// takes the crate's default rather than an argument, does not cut a request
/// off anywhere near the sentinel.
///
/// It cannot assert the default's actual value without waiting it out, and a
/// test that read the constant back would be asserting the code's own output
/// against the code's own number.
#[tokio::test]
async fn the_default_path_is_still_waiting_long_after_the_sentinel_would_have_fired() {
    let port = serve(None).await;

    let mut channel = yadgar_dial::connect(SERVED_NAME, port).await.unwrap();
    std::future::poll_fn(|cx| channel.poll_ready(cx))
        .await
        .unwrap();

    let outcome =
        tokio::time::timeout(SENTINEL_BOUND * 3, channel.call(stalling_request(None))).await;

    assert!(
        outcome.is_err(),
        "the request ended within {:?} on the DEFAULT bound: either the rig does \
         not actually stall, or the default is far shorter than it claims",
        SENTINEL_BOUND * 3
    );
}
