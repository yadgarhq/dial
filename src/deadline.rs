//! The caller's deadline, carried one hop further in (ADR-1019).
//!
//! A gRPC caller states how long it will wait in the `grpc-timeout` header.
//! tonic already ENFORCES that header on both sides: the server drops a
//! handler whose caller's deadline has passed, and the client cuts a request
//! off at the shorter of the header and the channel's own request timeout.
//! What tonic does not do is PASS IT ON. A handler that calls an inner hop
//! builds a fresh `tonic::Request`, and that request carries no deadline, so
//! the inner hop is bounded only by its own ceilings and keeps working on a
//! request nobody is waiting for. That is the inverted timeout chain of
//! yaadgaar #337.
//!
//! [`Deadline`] is the missing step, and nothing more:
//!
//! 1. Capture it ONCE, at handler entry, with [`Deadline::of`]. The budget is
//!    turned into an [`Instant`] there, so every later call sees the time that
//!    is actually left, not the budget the caller started with.
//! 2. Stamp EVERY outbound request with [`Deadline::apply`], or run the call
//!    through [`Deadline::call`]. It sets `grpc-timeout` to
//!    min(ceiling, remaining - [`DEADLINE_MARGIN`]), where the ceiling is the
//!    per-hop request timeout the consumer already passes to
//!    [`connect_with_request_timeout`](crate::connect_with_request_timeout).
//!    A request with no incoming deadline is stamped with the ceiling, so the
//!    hop after this one is still bounded.
//! 3. The margin is what lets THIS hop answer. The inner call fails 50 ms
//!    before the caller's deadline, so the hop's own `DEADLINE_EXCEEDED` path
//!    runs and records before tonic's server drops its handler. [`Deadline::call`]
//!    turns tonic's `CANCELLED` "Timeout expired" into that `DEADLINE_EXCEEDED`.
//!
//! **NO FLOOR IS APPLIED TO THE PROPAGATED VALUE.**
//! [`min_request_timeout`](crate::min_request_timeout) bounds the CHART
//! ceiling, because a ceiling below keepalive detection makes keepalive
//! pointless. A caller's remaining time is a different thing: clamping it up
//! to 14 s would hand the inner hop more time than its caller has, which is
//! the inversion this module exists to remove.
//!
//! **Time the hop cannot measure is not subtracted.** The clock starts when
//! the handler reads the header, not when the bytes arrived; decode time
//! before that is invisible here and is not guessed at (ADR-1019).

use std::time::{Duration, Instant};

use tonic::metadata::MetadataMap;
use tonic::{Code, Request, Status};

/// The header a gRPC caller states its deadline in (PROTOCOL-HTTP2.md).
pub const GRPC_TIMEOUT: &str = "grpc-timeout";

/// What a hop keeps back from its caller's remaining time (Max, 2026-10-24,
/// option (b) on ADR-1019).
///
/// An inner call is told remaining - this, never the whole remainder. Without
/// it the inner call and the caller's deadline fire together, tonic's server
/// drops this hop's handler first, and the hop records nothing (telemetry
/// `UNRECORDED`, caller sees `CANCELLED`). With it, the inner call fails first
/// and this hop's own `DEADLINE_EXCEEDED` path runs and records.
pub const DEADLINE_MARGIN: Duration = Duration::from_millis(50); // ADR-0569-EXCEPTION(CC): a ruled protocol margin, not a deployment knob.

/// When the caller of this handler stops waiting, if it said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline {
    at: Option<Instant>,
}

impl Deadline {
    /// No caller deadline. [`Deadline::apply`] then stamps the ceiling.
    pub fn none() -> Self {
        Self { at: None }
    }

    /// A deadline at a known instant.
    pub fn at(instant: Instant) -> Self {
        Self { at: Some(instant) }
    }

    /// A deadline `budget` from now. For a caller with no incoming request to
    /// read one from, such as the gateway with its own per-call deadlines.
    ///
    /// A budget too large for the clock to represent is no deadline.
    pub fn after(budget: Duration) -> Self {
        Self {
            at: Instant::now().checked_add(budget),
        }
    }

    /// The deadline of an incoming request, captured now. Call it ONCE, at
    /// handler entry, before the request is consumed.
    pub fn of<T>(request: &Request<T>) -> Self {
        Self::from_metadata(request.metadata())
    }

    /// The deadline a `grpc-timeout` entry in `metadata` states, captured now.
    ///
    /// An absent or malformed value is no deadline: that is how tonic's own
    /// server treats it, and a hop must not enforce a deadline its server
    /// never did.
    pub fn from_metadata(metadata: &MetadataMap) -> Self {
        metadata
            .get(GRPC_TIMEOUT)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_grpc_timeout)
            .map_or_else(Self::none, Self::after)
    }

    /// The time left, or `None` when the caller set no deadline. Zero once the
    /// deadline has passed.
    pub fn remaining(&self) -> Option<Duration> {
        self.at
            .map(|at| at.saturating_duration_since(Instant::now()))
    }

    /// The bound an inner call gets: min(ceiling, remaining - [`DEADLINE_MARGIN`]),
    /// or the ceiling when the caller set no deadline. Zero when the remaining
    /// time is at or below the margin.
    pub fn bound(&self, ceiling: Duration) -> Duration {
        self.remaining().map_or(ceiling, |left| {
            left.saturating_sub(DEADLINE_MARGIN).min(ceiling)
        })
    }

    /// Stamp `request` with [`Deadline::bound`] as its `grpc-timeout`,
    /// replacing any value already there.
    ///
    /// `ceiling` is the request timeout the channel was dialled with. tonic's
    /// client already cuts the call at min(header, channel timeout); stamping
    /// the same minimum is what tells the NEXT hop.
    ///
    /// Returns the bound it stamped.
    ///
    /// # Errors
    ///
    /// `DEADLINE_EXCEEDED` when the remaining time is at or below
    /// [`DEADLINE_MARGIN`]. The request is left unstamped and must not be
    /// sent: its caller is about to give up.
    pub fn apply<U>(
        &self,
        ceiling: Duration,
        request: &mut Request<U>,
    ) -> Result<Duration, Status> {
        let bound = self.bound(ceiling);
        if bound.is_zero() {
            return Err(Status::deadline_exceeded(
                "the caller's deadline leaves no time for an inner call",
            ));
        }
        request.set_timeout(bound);
        Ok(bound)
    }

    /// Run one inner call under this deadline: stamp `request` with
    /// [`Deadline::apply`], run `f`, and report a call cut off at its bound
    /// as `DEADLINE_EXCEEDED`.
    ///
    /// The bound is enforced HERE too, not only by tonic. tonic's client timer
    /// sits inside each connection, so it does not run while a request waits
    /// for a ready endpoint, a TCP connect or a TLS handshake. `call` drops
    /// `f`'s future at the bound wherever it is waiting.
    ///
    /// tonic reports its own timer, on either side of the call, as
    /// `CANCELLED` "Timeout expired". A `CANCELLED` that arrives once the
    /// stamped bound has passed is that timer, so it is relabelled, with its
    /// details and metadata kept; one that arrives earlier is somebody else's
    /// cancel and passes through.
    ///
    /// # Errors
    ///
    /// `DEADLINE_EXCEEDED` without running `f` when [`Deadline::apply`]
    /// refuses; `DEADLINE_EXCEEDED` when the call was cut off at its bound;
    /// otherwise whatever `f` returned.
    pub async fn call<U, T, F, Fut>(
        &self,
        ceiling: Duration,
        mut request: Request<U>,
        f: F,
    ) -> Result<T, Status>
    where
        F: FnOnce(Request<U>) -> Fut,
        Fut: std::future::Future<Output = Result<T, Status>>,
    {
        let bound = self.apply(ceiling, &mut request)?;
        let expires = Instant::now() + bound;
        match tokio::time::timeout(bound, f(request)).await {
            Err(_) => Err(Status::deadline_exceeded(format!(
                "inner call cut off at its {bound:?} bound before it was answered"
            ))),
            Ok(Err(status)) if status.code() == Code::Cancelled && Instant::now() >= expires => {
                Err(Status::with_details_and_metadata(
                    Code::DeadlineExceeded,
                    format!(
                        "inner call cut off at its {bound:?} bound: {}",
                        status.message()
                    ),
                    status.details().to_vec().into(),
                    status.metadata().clone(),
                ))
            }
            Ok(other) => other,
        }
    }
}

/// Parse a `grpc-timeout` value: at most eight ASCII digits and one unit,
/// `H` `M` `S` `m` `u` `n` (PROTOCOL-HTTP2.md). Anything else is `None`.
///
/// Written here because tonic's parser is private to tonic.
pub(crate) fn parse_grpc_timeout(value: &str) -> Option<Duration> {
    let unit = value.chars().last()?;
    let digits = &value[..value.len() - unit.len_utf8()];
    if digits.is_empty() || digits.len() > 8 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = digits.parse().ok()?;
    Some(match unit {
        'H' => Duration::from_secs(n * 60 * 60),
        'M' => Duration::from_secs(n * 60),
        'S' => Duration::from_secs(n),
        'm' => Duration::from_millis(n),
        'u' => Duration::from_micros(n),
        'n' => Duration::from_nanos(n),
        _ => return None,
    })
}

#[cfg(test)]
mod tests;
