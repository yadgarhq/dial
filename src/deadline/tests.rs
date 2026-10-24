//! The deadline arithmetic, on the real clock and without a network.

use std::time::{Duration, Instant};

use tonic::metadata::MetadataMap;
use tonic::Request;

use super::*;

const CEILING: Duration = Duration::from_millis(14_000);

fn metadata(value: &str) -> MetadataMap {
    let mut m = MetadataMap::new();
    m.insert(GRPC_TIMEOUT, value.parse().unwrap());
    m
}

fn stamped<U>(request: &Request<U>) -> Option<Duration> {
    let value = request.metadata().get(GRPC_TIMEOUT)?.to_str().ok()?;
    parse_grpc_timeout(value)
}

#[test]
fn every_unit_the_spec_names_parses() {
    assert_eq!(parse_grpc_timeout("2H"), Some(Duration::from_secs(7_200)));
    assert_eq!(parse_grpc_timeout("3M"), Some(Duration::from_secs(180)));
    assert_eq!(parse_grpc_timeout("10S"), Some(Duration::from_secs(10)));
    assert_eq!(parse_grpc_timeout("250m"), Some(Duration::from_millis(250)));
    assert_eq!(
        parse_grpc_timeout("30000000u"),
        Some(Duration::from_secs(30))
    );
    assert_eq!(
        parse_grpc_timeout("1500n"),
        Some(Duration::from_nanos(1_500))
    );
}

/// A malformed header is treated as absent, which is what tonic's own server
/// does with it: a hop must not invent a deadline its server never enforced.
#[test]
fn a_malformed_value_is_no_deadline() {
    for bad in [
        "",
        "S",
        "10",
        "10s",
        "10X",
        "-1S",
        "123456789S",
        "1.5S",
        " 1S",
    ] {
        assert_eq!(parse_grpc_timeout(bad), None, "{bad:?} parsed");
    }
    assert_eq!(Deadline::from_metadata(&metadata("10X")).remaining(), None);
}

/// What `apply` writes, tonic reads back the same: the header is encoded by
/// `Request::set_timeout`, so this is the round trip every hop depends on.
#[test]
fn tonics_own_encoding_round_trips() {
    let mut request = Request::new(());
    request.set_timeout(Duration::from_secs(30));
    assert_eq!(stamped(&request), Some(Duration::from_secs(30)));
}

#[test]
fn no_header_is_no_deadline_and_bounds_at_the_ceiling() {
    let deadline = Deadline::of(&Request::new(()));
    assert_eq!(deadline, Deadline::none());
    assert_eq!(deadline.remaining(), None);
    assert_eq!(deadline.bound(CEILING), CEILING);
}

/// THE FALLBACK IS STAMPED, not left out. Without a header the next hop would
/// be bounded only by its own ceilings, and a -db acquire would outlive this
/// hop's request timeout.
#[test]
fn a_request_without_a_deadline_is_stamped_with_the_ceiling() {
    let mut outbound = Request::new(());
    Deadline::none().apply(CEILING, &mut outbound).unwrap();
    assert_eq!(stamped(&outbound), Some(CEILING));
}

#[test]
fn a_shorter_caller_deadline_wins_over_the_ceiling() {
    let deadline = Deadline::from_metadata(&metadata("300m"));
    let left = deadline.remaining().unwrap();
    assert!(left <= Duration::from_millis(300) && left > Duration::from_millis(250));
    assert!(deadline.bound(CEILING) <= Duration::from_millis(300) - DEADLINE_MARGIN);
}

/// THE MARGIN (Max, option (b)). The inner call is told at most
/// remaining - DEADLINE_MARGIN, so this hop's own DEADLINE_EXCEEDED path runs
/// before its caller's deadline drops the handler.
#[test]
fn an_inner_call_is_told_the_remaining_time_minus_the_margin() {
    assert_eq!(DEADLINE_MARGIN, Duration::from_millis(50));
    let deadline = Deadline::after(Duration::from_secs(2));
    let mut outbound = Request::new(());
    let stamped_bound = deadline.apply(CEILING, &mut outbound).unwrap();
    let left = deadline.remaining().unwrap();
    // The header is truncated to eight digits of its unit, so it can sit a
    // hair below the bound; never above it.
    let header = stamped(&outbound).unwrap();
    assert!(header <= stamped_bound && stamped_bound - header < Duration::from_millis(1));
    assert!(
        stamped_bound + DEADLINE_MARGIN <= Duration::from_secs(2)
            && stamped_bound + DEADLINE_MARGIN >= left,
        "stamped {stamped_bound:?} with {left:?} left"
    );
}

/// The margin applies to a CALLER's time only. With no caller deadline the
/// ceiling is the bound, and nothing above this hop will drop its handler.
#[test]
fn the_ceiling_fallback_carries_no_margin() {
    assert_eq!(Deadline::none().bound(CEILING), CEILING);
}

/// Remaining time at or below the margin leaves no usable budget: nothing is
/// sent, and the hop answers DEADLINE_EXCEEDED itself.
#[test]
fn a_remaining_time_below_the_margin_sends_nothing() {
    let deadline = Deadline::after(DEADLINE_MARGIN - Duration::from_millis(10));
    let mut outbound = Request::new(());
    let refused = deadline.apply(CEILING, &mut outbound).unwrap_err();
    assert_eq!(refused.code(), tonic::Code::DeadlineExceeded);
    assert!(outbound.metadata().get(GRPC_TIMEOUT).is_none());
}

/// `call` turns the CANCELLED that tonic reports when the stamped bound fires
/// into DEADLINE_EXCEEDED, which is what the hop's caller and its telemetry
/// should see.
///
/// The future BLOCKS past the bound and then is ready with CANCELLED, so the
/// answer reaches `call` before its own timer is looked at: this is the
/// relabel, not the local cut-off below.
#[tokio::test]
async fn a_call_cut_off_at_its_bound_is_deadline_exceeded() {
    let deadline = Deadline::after(Duration::from_millis(200));
    let got: Result<(), _> = deadline
        .call(CEILING, Request::new(()), |r| async move {
            let bound = r.metadata().get(GRPC_TIMEOUT).cloned();
            assert!(bound.is_some(), "call did not stamp the request");
            std::thread::sleep(Duration::from_millis(160));
            Err(tonic::Status::cancelled("Timeout expired"))
        })
        .await;
    assert_eq!(got.unwrap_err().code(), tonic::Code::DeadlineExceeded);
}

/// THE BOUND IS ENFORCED HERE, not only by tonic. tonic's client timer sits
/// inside each connection (`channel/service/connection.rs:73`), so a request
/// still waiting for a ready endpoint, a TCP connect or a TLS handshake is not
/// timed by it. `call` must still end at its bound, before the caller's
/// deadline, or the caller's deadline drops this hop's handler first.
#[tokio::test]
async fn a_call_that_tonic_never_times_is_still_cut_at_its_bound() {
    let caller = Duration::from_millis(300);
    let deadline = Deadline::after(caller);
    let started = Instant::now();
    let got: Result<Result<(), _>, _> = tokio::time::timeout(
        Duration::from_secs(2),
        deadline.call(CEILING, Request::new(()), |_| std::future::pending()),
    )
    .await;
    let waited = started.elapsed();
    let status = got
        .expect("call outlived its bound: nothing but tonic's timer bounds it")
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::DeadlineExceeded);
    assert!(
        waited < caller,
        "call ended after {waited:?}, not before the caller's {caller:?}"
    );
}

/// A relabelled CANCELLED keeps what the peer sent with it: the status
/// details and the trailers.
#[tokio::test]
async fn a_relabelled_status_keeps_its_details_and_metadata() {
    let mut trailers = MetadataMap::new();
    trailers.insert("x-hop", "inner".parse().unwrap());
    let sent = tonic::Status::with_details_and_metadata(
        tonic::Code::Cancelled,
        "Timeout expired",
        b"detail".to_vec().into(),
        trailers,
    );
    let got: Result<(), _> = Deadline::after(Duration::from_millis(100))
        .call(CEILING, Request::new(()), |_| async move {
            std::thread::sleep(Duration::from_millis(80));
            Err(sent)
        })
        .await;
    let status = got.unwrap_err();
    assert_eq!(status.code(), tonic::Code::DeadlineExceeded);
    assert_eq!(status.details(), b"detail");
    assert_eq!(
        status.metadata().get("x-hop").and_then(|v| v.to_str().ok()),
        Some("inner")
    );
}

/// A CANCELLED that arrives BEFORE the bound is someone else's cancel and is
/// passed through unchanged.
#[tokio::test]
async fn an_early_cancel_is_not_relabelled() {
    let deadline = Deadline::after(Duration::from_secs(5));
    let got: Result<(), _> = deadline
        .call(CEILING, Request::new(()), |_| async {
            Err(tonic::Status::cancelled("peer went away"))
        })
        .await;
    assert_eq!(got.unwrap_err().code(), tonic::Code::Cancelled);
}

/// An expired deadline never runs the call at all.
#[tokio::test]
async fn call_with_an_expired_deadline_never_runs() {
    let ran = std::sync::atomic::AtomicBool::new(false);
    let got: Result<(), _> = Deadline::at(Instant::now())
        .call(CEILING, Request::new(()), |_| async {
            ran.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
        .await;
    assert_eq!(got.unwrap_err().code(), tonic::Code::DeadlineExceeded);
    assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
}

#[test]
fn a_longer_caller_deadline_is_cut_to_the_ceiling() {
    let mut outbound = Request::new(());
    Deadline::from_metadata(&metadata("1M"))
        .apply(CEILING, &mut outbound)
        .unwrap();
    assert_eq!(stamped(&outbound), Some(CEILING));
}

/// NO FLOOR. A 10 s caller (the gateway's AUTH_DEADLINE) must hand iam-db
/// less than 10 s, not dial's 14 s chart minimum.
#[test]
fn the_propagated_value_is_never_raised_to_the_chart_floor() {
    let mut outbound = Request::new(());
    Deadline::after(Duration::from_secs(10))
        .apply(crate::min_request_timeout(), &mut outbound)
        .unwrap();
    assert!(stamped(&outbound).unwrap() <= Duration::from_secs(10) - DEADLINE_MARGIN);
}

/// CAPTURED ONCE. iam's login makes two inner calls in sequence; the second
/// must be stamped with what is left, not with the caller's full budget again.
#[test]
fn a_second_inner_call_gets_only_what_is_left() {
    let deadline = Deadline::after(Duration::from_secs(5));
    let mut first = Request::new(());
    deadline.apply(CEILING, &mut first).unwrap();
    std::thread::sleep(Duration::from_millis(60));
    let mut second = Request::new(());
    deadline.apply(CEILING, &mut second).unwrap();

    let (first, second) = (stamped(&first).unwrap(), stamped(&second).unwrap());
    assert!(
        first - second >= Duration::from_millis(50),
        "second call stamped {second:?} after the first's {first:?}"
    );
}

/// A deadline that has passed sends nothing inward: the request is refused
/// here, with the status a gRPC caller expects, and left unstamped.
#[test]
fn an_expired_deadline_sends_nothing() {
    let past = Instant::now() - Duration::from_millis(1);
    let deadline = Deadline::at(past);
    assert_eq!(deadline.remaining(), Some(Duration::ZERO));

    let mut outbound = Request::new(());
    let refused = deadline.apply(CEILING, &mut outbound).unwrap_err();
    assert_eq!(refused.code(), tonic::Code::DeadlineExceeded);
    assert!(outbound.metadata().get(GRPC_TIMEOUT).is_none());
}

/// An apply replaces a header already on the request rather than adding a
/// second one, so a hop that copied metadata cannot forward a stale budget.
#[test]
fn apply_replaces_a_stale_header() {
    let mut outbound = Request::new(());
    outbound
        .metadata_mut()
        .insert(GRPC_TIMEOUT, "1H".parse().unwrap());
    Deadline::after(Duration::from_secs(2))
        .apply(CEILING, &mut outbound)
        .unwrap();
    assert_eq!(outbound.metadata().get_all(GRPC_TIMEOUT).iter().count(), 1);
    assert!(stamped(&outbound).unwrap() <= Duration::from_secs(2));
}
