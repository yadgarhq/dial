//! The per-request bound, read from the deployment rather than compiled in.
//!
//! ADR-0925 (Q-C1) ruled that the request timeout is a chart value per
//! consuming service, so an operator can tune it per environment without a
//! release. The consumer owns the variable NAME and the chart KEY — naming
//! differs between repositories — and passes both in. What this module owns is
//! what the crate knows and the consumer does not: the bounds a value must sit
//! inside for the crate's other timeouts to keep meaning anything.
//!
//! **THERE IS NO FALLBACK.** An unset variable is a refusal, not
//! [`default_request_timeout`](crate::default_request_timeout) (ADR-0569): a
//! silent default would make the bound whatever happened to be compiled in
//! rather than whatever the chart says, and the chart default is where
//! ADR-0705 puts the number.
//!
//! **WHY THE CHECK LIVES HERE AND NOT ONLY IN EACH CHART'S SCHEMA**, on the
//! precedent of ADR-0859: a chart bound protects only chart installs, and the
//! keepalive invariant below is this crate's, not any chart's.

use std::num::ParseIntError;
use std::time::Duration;

use crate::{KEEPALIVE_INTERVAL, KEEPALIVE_TIMEOUT};

/// The lowest accepted bound: one second above keepalive detection.
///
/// At or below `KEEPALIVE_INTERVAL + KEEPALIVE_TIMEOUT` (13s) the request bound
/// fires before keepalive can notice a peer that VANISHED, which makes
/// keepalive pointless for exactly the peer it exists to catch. The compiled
/// default was pinned against that by a test; a value an operator sets must
/// hold it too. Zero is the degenerate case: every request fails.
const MIN_REQUEST_TIMEOUT: Duration =
    Duration::from_secs(KEEPALIVE_INTERVAL.as_secs() + KEEPALIVE_TIMEOUT.as_secs() + 1); // ADR-0569-EXCEPTION(CC): derived from keepalive, not a knob.

/// The highest accepted bound: one second below the 60s ingress idle timeout.
///
/// At or above it the answer arrives after the ingress — and most HTTP
/// clients — have already given up, so the bound frees nobody.
const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(59); // ADR-0569-EXCEPTION(CC): below the 60s ingress idle timeout, a ceiling, not a knob.

/// The lowest request timeout [`request_timeout_from_lookup`] accepts.
///
/// Exposed so a consumer's chart test can pin its schema minimum to the same
/// number rather than restating it.
pub const fn min_request_timeout() -> Duration {
    MIN_REQUEST_TIMEOUT
}

/// The highest request timeout [`request_timeout_from_lookup`] accepts.
///
/// Exposed for the same reason as [`min_request_timeout`].
pub const fn max_request_timeout() -> Duration {
    MAX_REQUEST_TIMEOUT
}

/// Why a request timeout read from the deployment was refused.
///
/// Every variant carries the variable and the chart key, because the reader is
/// an operator looking at a crash-looping pod's log.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RequestTimeoutError {
    #[error(
        "{var} is not set. It has no compiled-in default (ADR-0569, ADR-0925): it \
         is the bound on how long one request may wait for an upstream that is \
         connected and never replies. Set {var}, rendered from the chart's {chart_key}."
    )]
    Unset { var: String, chart_key: String },

    #[error(
        "{var} is {value:?}, which is not a whole number of seconds. Set the \
         chart's {chart_key} to an integer."
    )]
    NotSeconds {
        var: String,
        chart_key: String,
        value: String,
        // NOT INLINED in the message: a field that is also the `source()` is
        // printed by every chain walk, so inlining it prints it twice (the
        // class ledger 737 removed from `BalanceError`).
        #[source]
        source: ParseIntError,
    },

    #[error(
        "{var} is {seconds}, outside {min}..={max} seconds. Below {min} the request \
         bound fires before HTTP/2 keepalive can notice a vanished peer; at or \
         above 60 the answer arrives after the ingress has given up. Set the \
         chart's {chart_key} inside that range.",
        min = MIN_REQUEST_TIMEOUT.as_secs(),
        max = MAX_REQUEST_TIMEOUT.as_secs()
    )]
    OutOfRange {
        var: String,
        chart_key: String,
        seconds: u64,
    },
}

/// Read the per-request bound from `var`, refusing a value the crate's other
/// timeouts cannot hold.
///
/// `lookup` is `|name| std::env::var(name).ok()` in a binary and a fake in a
/// test. `chart_key` is the values key that renders `var`, named in every
/// refusal. The result is what [`connect_with_request_timeout`] and
/// [`connect_tls_with_request_timeout`] take.
///
/// [`connect_with_request_timeout`]: crate::connect_with_request_timeout
/// [`connect_tls_with_request_timeout`]: crate::connect_tls_with_request_timeout
pub fn request_timeout_from_lookup(
    lookup: impl Fn(&str) -> Option<String>,
    var: &str,
    chart_key: &str,
) -> Result<Duration, RequestTimeoutError> {
    let Some(value) = lookup(var).filter(|v| !v.is_empty()) else {
        return Err(RequestTimeoutError::Unset {
            var: var.to_string(),
            chart_key: chart_key.to_string(),
        });
    };
    let seconds = value
        .parse::<u64>()
        .map_err(|source| RequestTimeoutError::NotSeconds {
            var: var.to_string(),
            chart_key: chart_key.to_string(),
            value: value.clone(),
            source,
        })?;
    let timeout = Duration::from_secs(seconds);
    if !(MIN_REQUEST_TIMEOUT..=MAX_REQUEST_TIMEOUT).contains(&timeout) {
        return Err(RequestTimeoutError::OutOfRange {
            var: var.to_string(),
            chart_key: chart_key.to_string(),
            seconds,
        });
    }
    Ok(timeout)
}

#[cfg(test)]
mod tests;
