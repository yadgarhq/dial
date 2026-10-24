//! `CONNECT_TIMEOUT` is public so a caller can order its own deadlines against
//! the dial bound instead of restating the number (yaadgaar #365).

use std::time::Duration;

#[test]
fn connect_timeout_is_public_and_two_seconds() {
    assert_eq!(yadgar_dial::CONNECT_TIMEOUT, Duration::from_secs(2));
}
