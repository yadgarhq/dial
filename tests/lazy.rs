//! The boot dial, against an upstream that is not there yet.
//!
//! **THE MEASURED DEFECT.** Three of the four internal hops in this estate dial
//! through this crate at boot, and every one of them exited when the upstream's
//! name did not resolve. On a rebuilt cluster `gateway` exited with `could not
//! resolve task:50052` and crash-looped six times before `task`'s Service
//! existed. It self-healed, and that is the problem: the cold start costs
//! exponential backoff, and the restart count that would have shown a real
//! crash is spent on an ordering accident.
//!
//! **WHAT IS ASSERTED HERE IS NOT "connect returns Ok".** That half is one line
//! and passes against a build that hands back a balanced channel holding
//! nothing — which is a WORSE failure than the crash loop, because
//! `Balance::poll_ready` on an empty endpoint set is `Poll::Pending` for ever
//! and no bound in this crate reaches it. Every case below therefore also drives
//! a request through the channel it was given, and the ceiling is what fails.
//!
//! NOTE ON THE NAME: `.invalid` is reserved by RFC 6761 and guaranteed never to
//! resolve, so these cases need no rig and cannot be broken by a wildcard in
//! somebody's search domain. NXDOMAIN also ANSWERS, and answers promptly — which
//! is why the ceilings below are about a hang, never about latency.

use std::time::Duration;

use tonic::body::Body;
use tonic::codegen::{http, Service};
use tonic::transport::Channel;
use yadgar_dial::TlsOptions;

mod common;

use common::{pki, TempPem};

/// An upstream that cannot be reached, ever, from anywhere.
const ABSENT: &str = "an-upstream-that-is-not-there-9f3c.invalid";

/// The port is arbitrary: nothing listens on any of them under `.invalid`.
const PORT: u16 = 50051;

/// How long a case waits before declaring that something HUNG.
///
/// It has to exceed `RESOLVE_TIMEOUT`, which is five seconds: the boot dial
/// still ATTEMPTS a resolution, it merely no longer depends on one, so a
/// resolver that stopped answering costs this much before the channel comes
/// back. Anything at all finishing under it is the assertion; the number itself
/// measures nothing.
const CEILING: Duration = Duration::from_secs(20);

/// One request at a route nothing serves.
fn a_request(host: &str) -> http::Request<Body> {
    http::Request::builder()
        .version(http::Version::HTTP_2)
        .method("POST")
        .uri(format!("https://{host}/yadgar.dial.Absent/Call"))
        .header("content-type", "application/grpc")
        .body(Body::empty())
        .unwrap()
}

/// Drive one request through `channel` and require that it ENDED.
///
/// The readiness poll is the load-bearing half and is not a formality. A
/// balanced channel with no endpoints is `Pending` in `poll_ready` for ever —
/// `REQUEST_TIMEOUT` sits inside a connection and never sees a request that has
/// not been given one — so a build that returned an empty channel fails HERE
/// rather than at the request.
async fn served_something(mut channel: Channel, host: &str) {
    tokio::time::timeout(CEILING, std::future::poll_fn(|cx| channel.poll_ready(cx)))
        .await
        .expect(
            "the channel never became ready: the balancer was given nothing, so every request to \
         it waits for ever — which is a worse failure than the boot exit this change removed",
        )
        .expect("a balanced channel reports readiness even when its only endpoint cannot connect");

    let outcome = tokio::time::timeout(CEILING, channel.call(a_request(host)))
        .await
        .expect("the request never ended: nothing bounded it");

    assert!(
        outcome.is_err(),
        "an upstream that does not resolve cannot have answered: {:?}",
        outcome.map(|r| r.status())
    );
}

/// THE DEFECT. A name that does not resolve was a boot failure, and the process
/// exited.
///
/// Restore `let initial = resolve(host, port).await?;` in `connect_with` and
/// this dies here, on the `Err` — which is the mutation that proves the case
/// tests the change rather than the runtime.
#[tokio::test]
async fn an_upstream_that_does_not_resolve_is_not_a_boot_failure() {
    let outcome = tokio::time::timeout(CEILING, yadgar_dial::connect(ABSENT, PORT))
        .await
        .expect("the boot dial must not hang");

    assert!(
        outcome.is_ok(),
        "an upstream whose Service does not exist yet must not take the caller down with it: \
         {outcome:?}"
    );
}

/// AND THE HALF THAT IS EASY TO LOSE. The channel handed back has to be able to
/// serve, or the crash loop has been traded for a process that starts happily
/// and never answers anything.
///
/// Delete the seed insert from `connect_with` and this dies on the readiness
/// ceiling: the balancer holds nothing, `poll_ready` is `Pending`, and no
/// timeout in this crate is above it.
#[tokio::test]
async fn a_request_dialled_before_anything_resolves_ends_rather_than_hangs() {
    let channel = tokio::time::timeout(CEILING, yadgar_dial::connect(ABSENT, PORT))
        .await
        .expect("the boot dial must not hang")
        .expect("an absent upstream must not fail the dial");

    served_something(channel, ABSENT).await;
}

/// The SAME on the TLS path, because the cut-over turns these hops on one at a
/// time and a hop that is lazy in cleartext and eager in TLS is two behaviours
/// under one name.
///
/// The bundle here is VALID: what is absent is the upstream, not the
/// configuration, and those two must not be conflated — see
/// `a_configuration_mistake_is_still_a_boot_failure`.
#[tokio::test]
async fn the_tls_path_is_lazy_on_the_same_terms() {
    let p = pki(ABSENT);
    let ca = TempPem::with(&p.ca_pem);

    let channel = tokio::time::timeout(
        CEILING,
        yadgar_dial::connect_tls(ABSENT, PORT, &TlsOptions::new(ca.path())),
    )
    .await
    .expect("the boot dial must not hang")
    .expect("an absent upstream must not fail the TLS dial either");

    served_something(channel, ABSENT).await;
}

/// WHAT DID NOT BECOME LAZY, and the reason the change is defensible at all.
///
/// Fail-fast was traded away for an upstream that is merely NOT THERE YET. It
/// was not traded away for a configuration the operator got wrong: a host that
/// cannot form an authority is a mistake in the deployment, no resolution will
/// ever fix it, and it is still an error before a channel exists.
#[tokio::test]
async fn a_configuration_mistake_is_still_a_boot_failure() {
    let outcome = yadgar_dial::connect("not a host name", PORT).await;

    assert!(
        matches!(outcome, Err(yadgar_dial::BalanceError::InvalidHost { .. })),
        "a host that cannot be dialled at all must be reported as itself: {outcome:?}"
    );
}
