//! A caller's deadline, carried through a middle hop to the hop behind it
//! (ADR-1019), proved on a real network with three parties:
//!
//! caller -> `Middle` (a tonic server, like `task`) -> `Inner` (like `task-db`)
//!
//! `Inner` never answers. It records the `grpc-timeout` it was sent and sets a
//! flag when its handler future is DROPPED, which is what "cancelled" means for
//! a tonic handler: a pool acquire or a query inside it stops there.
//!
//! "The caller got an error" proves nothing about the inner hop, so every case
//! asserts on what `Inner` saw and on when its work was dropped.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio_stream::wrappers::TcpListenerStream;
use tonic::body::Body;
use tonic::codegen::{http, Service};
use tonic::metadata::MetadataMap;
use tonic::server::NamedService;
use tonic::transport::{Channel, Server};
use yadgar_dial::{Deadline, DEADLINE_MARGIN, GRPC_TIMEOUT};

mod common;

use common::{bind_all, ready};

const SERVED_NAME: &str = "localhost";

/// The middle hop's ceiling where the CALLER'S deadline is meant to bind. Far
/// above anything a case waits, so a pass cannot come from the ceiling.
const GENEROUS_CEILING: Duration = Duration::from_secs(20);

/// The middle hop's ceiling where the CEILING is meant to bind. Not a number
/// the crate contains, so a hidden default cannot satisfy it.
const SENTINEL_CEILING: Duration = Duration::from_millis(750);

/// The caller's own deadline in the cancellation case.
const CALLER: Duration = Duration::from_millis(300);

type BoxFut = Pin<Box<dyn Future<Output = Result<http::Response<Body>, Infallible>> + Send>>;

/// What `Inner` observed.
#[derive(Default)]
struct Seen {
    timeout: Mutex<Option<Option<Duration>>>,
    dropped_at: Mutex<Option<Instant>>,
    arrived: AtomicBool,
}

struct DropFlag(Arc<Seen>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        *self.0.dropped_at.lock().unwrap() = Some(Instant::now());
    }
}

#[derive(Clone)]
struct Inner(Arc<Seen>);

impl NamedService for Inner {
    const NAME: &'static str = "yadgar.dial.Inner";
}

impl Service<http::Request<Body>> for Inner {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = BoxFut;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<Body>) -> Self::Future {
        let seen = self.0.clone();
        let deadline = Deadline::from_metadata(&MetadataMap::from_headers(req.headers().clone()));
        *seen.timeout.lock().unwrap() = Some(deadline.remaining());
        seen.arrived.store(true, Ordering::SeqCst);
        Box::pin(async move {
            let _flag = DropFlag(seen);
            std::future::pending().await
        })
    }
}

/// The hop under test: reads its caller's deadline at entry, stamps the
/// inner request with it, and calls `Inner` through a dial channel whose
/// request timeout is `ceiling`.
#[derive(Clone)]
struct Middle {
    inner: Channel,
    ceiling: Duration,
}

impl NamedService for Middle {
    const NAME: &'static str = "yadgar.dial.Middle";
}

impl Service<http::Request<Body>> for Middle {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = BoxFut;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<Body>) -> Self::Future {
        let deadline = Deadline::from_metadata(&MetadataMap::from_headers(req.headers().clone()));
        let mut channel = self.inner.clone();
        let ceiling = self.ceiling;
        Box::pin(async move {
            let outcome = deadline
                .call(ceiling, tonic::Request::new(()), |outbound| async move {
                    let mut call = request(Inner::NAME, None);
                    call.headers_mut()
                        .extend(outbound.metadata().clone().into_headers());
                    std::future::poll_fn(|cx| channel.poll_ready(cx))
                        .await
                        .unwrap();
                    match channel.call(call).await {
                        Ok(response) => match grpc_status(&response) {
                            Some(0) | None => Ok(()),
                            Some(code) => Err(tonic::Status::new(code.into(), "inner")),
                        },
                        Err(e) => Err(tonic::Status::from_error(Box::new(e))),
                    }
                })
                .await;
            Ok(match outcome {
                Ok(()) => tonic::Status::ok("").into_http(),
                Err(status) => status.into_http(),
            })
        })
    }
}

fn grpc_status(response: &http::Response<Body>) -> Option<i32> {
    response
        .headers()
        .get("grpc-status")?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

fn request(service: &str, grpc_timeout: Option<&str>) -> http::Request<Body> {
    let mut builder = http::Request::builder()
        .version(http::Version::HTTP_2)
        .method("POST")
        .uri(format!("http://{SERVED_NAME}/{service}/Call"))
        .header("content-type", "application/grpc");
    if let Some(value) = grpc_timeout {
        builder = builder.header(GRPC_TIMEOUT, value);
    }
    builder.body(Body::empty()).unwrap()
}

async fn serve<S>(service: S) -> u16
where
    S: Service<http::Request<Body>, Response = http::Response<Body>, Error = Infallible>
        + NamedService
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send + 'static,
{
    let (listeners, port) = bind_all(SERVED_NAME).await;
    for listener in listeners {
        let router = Server::builder()
            .add_routes(tonic::service::Routes::default().add_service(service.clone()));
        tokio::spawn(async move {
            let _ = router
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await;
        });
    }
    ready(SERVED_NAME, port).await;
    port
}

/// Stand up `Inner` behind a `Middle` with `ceiling`, return the caller's
/// channel and what `Inner` sees.
async fn rig(ceiling: Duration) -> (Channel, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let inner_port = serve(Inner(seen.clone())).await;
    let inner = yadgar_dial::connect_with_request_timeout(SERVED_NAME, inner_port, ceiling)
        .await
        .unwrap();
    let middle_port = serve(Middle { inner, ceiling }).await;
    let caller =
        yadgar_dial::connect_with_request_timeout(SERVED_NAME, middle_port, GENEROUS_CEILING)
            .await
            .unwrap();
    (caller, seen)
}

/// Send one call to `Middle` and return how long until the caller had an
/// answer, and the `grpc-status` `Middle` answered with (`None` when the
/// caller saw a transport error instead).
async fn call(mut caller: Channel, grpc_timeout: Option<&str>) -> (Duration, Option<i32>) {
    std::future::poll_fn(|cx| caller.poll_ready(cx))
        .await
        .unwrap();
    let started = Instant::now();
    let outcome = tokio::time::timeout(
        Duration::from_secs(6),
        caller.call(request(Middle::NAME, grpc_timeout)),
    )
    .await;
    let waited = started.elapsed();
    let response = outcome.expect("nothing bounded the call within 6 s");
    (waited, response.ok().as_ref().and_then(grpc_status))
}

/// Wait (bounded) for `Inner`'s handler to be dropped and return when it was.
async fn dropped(seen: &Seen) -> Instant {
    for _ in 0..300 {
        if let Some(at) = *seen.dropped_at.lock().unwrap() {
            return at;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the inner handler was never dropped: its work outlived the caller");
}

fn inner_saw(seen: &Seen) -> Option<Duration> {
    assert!(
        seen.arrived.load(Ordering::SeqCst),
        "no request reached the inner hop"
    );
    seen.timeout.lock().unwrap().expect("recorded")
}

/// `grpc-status` DEADLINE_EXCEEDED.
const DEADLINE_EXCEEDED: i32 = 4;

/// THE FINDING (yaadgaar #337). The caller gives up at 300 ms. The inner hop
/// must be TOLD at most remaining - `DEADLINE_MARGIN`, its work must be
/// dropped then, not at the middle hop's 20 s ceiling, and the middle hop must
/// answer DEADLINE_EXCEEDED itself before its own handler is dropped.
///
/// Delete the `set_timeout` in `apply` and this fails on the header: the
/// inner hop is sent no deadline at all.
#[tokio::test]
async fn an_inner_call_is_cancelled_when_the_callers_deadline_expires() {
    let (caller, seen) = rig(GENEROUS_CEILING).await;
    let started = Instant::now();

    let (waited, status) = call(caller, Some("300m")).await;
    assert!(
        waited < CALLER,
        "caller waited {waited:?}: the middle hop did not answer first"
    );
    assert_eq!(
        status,
        Some(DEADLINE_EXCEEDED),
        "the middle hop did not answer DEADLINE_EXCEEDED itself"
    );

    let told = inner_saw(&seen).expect("the inner hop was sent no deadline");
    assert!(
        told <= CALLER - DEADLINE_MARGIN,
        "the inner hop was given {told:?}, more than the caller's time less the margin"
    );

    let gone = dropped(&seen).await - started;
    assert!(
        gone < CALLER * 3,
        "the inner work was dropped after {gone:?}, long after its caller gave up"
    );
}

/// A caller with no deadline: the inner hop is still bounded, at the middle
/// hop's ceiling (no margin: nothing above will drop the middle handler), and
/// the middle hop reports the cut-off as DEADLINE_EXCEEDED.
#[tokio::test]
async fn a_request_without_a_deadline_falls_back_to_the_ceiling() {
    let (caller, seen) = rig(SENTINEL_CEILING).await;
    let started = Instant::now();

    let (waited, status) = call(caller, None).await;
    assert!(
        waited >= SENTINEL_CEILING && waited < SENTINEL_CEILING * 3,
        "the call ended after {waited:?}, not at the {SENTINEL_CEILING:?} ceiling"
    );
    assert_eq!(status, Some(DEADLINE_EXCEEDED));

    let told = inner_saw(&seen).expect("the inner hop was sent no deadline");
    assert!(
        told <= SENTINEL_CEILING && told > SENTINEL_CEILING - Duration::from_millis(200),
        "the inner hop was given {told:?}, not the {SENTINEL_CEILING:?} ceiling"
    );

    let gone = dropped(&seen).await - started;
    assert!(
        gone < SENTINEL_CEILING * 3,
        "inner work dropped after {gone:?}"
    );
}

/// A caller asking for MORE than the ceiling does not pass that on: the inner
/// hop is told the ceiling, so it never outlives the middle hop.
#[tokio::test]
async fn a_longer_caller_deadline_reaches_the_inner_hop_as_the_ceiling() {
    let (caller, seen) = rig(SENTINEL_CEILING).await;

    call(caller, Some("10S")).await;

    let told = inner_saw(&seen).expect("the inner hop was sent no deadline");
    assert!(
        told <= SENTINEL_CEILING,
        "the inner hop was given {told:?}, above the middle hop's ceiling"
    );
}

/// A caller whose time is already inside the margin gets DEADLINE_EXCEEDED
/// from the middle hop at once, and nothing is sent inward.
#[tokio::test]
async fn a_remaining_time_below_the_margin_sends_nothing_inward() {
    let (caller, seen) = rig(GENEROUS_CEILING).await;

    let (_, status) = call(caller, Some("40m")).await;
    assert_eq!(status, Some(DEADLINE_EXCEEDED));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !seen.arrived.load(Ordering::SeqCst),
        "a request reached the inner hop with no usable time left"
    );
}
