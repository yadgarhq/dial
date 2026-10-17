//! The operator-set request timeout, refused at boot when it cannot hold.
//!
//! Every case reads through a fake lookup rather than the process
//! environment: the environment is shared by every test in the binary, and a
//! case that set a variable there would race whichever other case read it.

use std::time::Duration;

use super::*;
use crate::{KEEPALIVE_INTERVAL, KEEPALIVE_TIMEOUT, REQUEST_TIMEOUT};

const VAR: &str = "TASK_REQUEST_TIMEOUT_SECONDS";
const KEY: &str = "task.requestTimeoutSeconds";

/// A lookup that answers `VAR` with `value` and nothing else.
fn read(value: Option<&str>) -> Result<Duration, RequestTimeoutError> {
    let value = value.map(str::to_string);
    request_timeout_from_lookup(
        |name| (name == VAR).then(|| value.clone()).flatten(),
        VAR,
        KEY,
    )
}

#[test]
fn the_shipped_default_is_accepted_unchanged() {
    assert_eq!(read(Some("30")), Ok(Duration::from_secs(30)));
    assert_eq!(read(Some("30")), Ok(REQUEST_TIMEOUT));
}

#[test]
fn the_bounds_themselves_are_accepted() {
    assert_eq!(read(Some("14")), Ok(Duration::from_secs(14)));
    assert_eq!(read(Some("59")), Ok(Duration::from_secs(59)));
    assert_eq!(read(Some("14")), Ok(min_request_timeout()));
    assert_eq!(read(Some("59")), Ok(max_request_timeout()));
}

/// No compiled-in fallback (ADR-0569): an unset variable is a refusal, not 30.
#[test]
fn an_unset_variable_is_refused_rather_than_defaulted() {
    let err = read(None).unwrap_err();
    assert!(matches!(err, RequestTimeoutError::Unset { .. }), "{err:?}");
    let empty = read(Some("")).unwrap_err();
    assert!(
        matches!(empty, RequestTimeoutError::Unset { .. }),
        "{empty:?}"
    );
}

#[test]
fn a_value_that_is_not_whole_seconds_is_refused() {
    for bad in ["30s", "-1", "1.5", " 30", "thirty"] {
        let err = read(Some(bad)).unwrap_err();
        assert!(
            matches!(err, RequestTimeoutError::NotSeconds { .. }),
            "{bad}: {err:?}"
        );
    }
}

/// Zero would fail every request; 13 would let the request bound fire before
/// keepalive could notice a vanished peer — the invariant the compiled
/// constant was pinned to, which an operator-set value must hold too.
#[test]
fn a_value_at_or_below_keepalive_detection_is_refused() {
    for low in ["0", "1", "13"] {
        let err = read(Some(low)).unwrap_err();
        assert!(
            matches!(err, RequestTimeoutError::OutOfRange { .. }),
            "{low}: {err:?}"
        );
    }
}

#[test]
fn a_value_at_or_above_the_ingress_idle_timeout_is_refused() {
    for high in ["60", "300", "18446744073709551615"] {
        let err = read(Some(high)).unwrap_err();
        assert!(
            matches!(err, RequestTimeoutError::OutOfRange { .. }),
            "{high}: {err:?}"
        );
    }
}

/// The refusal is read by an operator in a crash-looping pod's log, so it has
/// to name what to change: the variable AND the chart key that renders it.
#[test]
fn every_refusal_names_the_variable_and_the_chart_key() {
    for value in [None, Some("x"), Some("0"), Some("60")] {
        let message = read(value).unwrap_err().to_string();
        assert!(message.contains(VAR), "{value:?}: {message}");
        assert!(message.contains(KEY), "{value:?}: {message}");
    }
}

#[test]
fn an_out_of_range_refusal_names_the_bounds() {
    let message = read(Some("0")).unwrap_err().to_string();
    assert!(
        message.contains("14") && message.contains("59"),
        "{message}"
    );
}

/// The floor is DERIVED from keepalive, not a second number that can drift
/// from it: raising keepalive must raise the floor.
#[test]
fn the_floor_sits_just_above_keepalive_detection() {
    assert!(KEEPALIVE_INTERVAL + KEEPALIVE_TIMEOUT < min_request_timeout());
    assert_eq!(
        min_request_timeout(),
        KEEPALIVE_INTERVAL + KEEPALIVE_TIMEOUT + Duration::from_secs(1)
    );
}

#[test]
fn the_shipped_default_sits_inside_the_bounds() {
    assert!(min_request_timeout() <= REQUEST_TIMEOUT);
    assert!(REQUEST_TIMEOUT <= max_request_timeout());
}

/// The parse error is the `source()`, and is NOT also inlined in the message:
/// a chain walk (`yadgar_telemetry::diagnose::chain`) would print it twice —
/// the class ledger 737 removed from `BalanceError`.
#[test]
fn a_parse_failure_is_the_source_and_is_not_repeated_in_the_message() {
    use std::error::Error as _;
    let err = read(Some("thirty")).unwrap_err();
    let source = err
        .source()
        .expect("the parse error is the source")
        .to_string();
    assert!(!err.to_string().contains(&source), "{err}");
}
