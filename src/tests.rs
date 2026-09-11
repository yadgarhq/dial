//! Unit tests for the boot dial and the re-resolution loop.
//!
//! Split out of `lib.rs` by LEDGER 719 into its own file, matching the
//! convention `gateway`/`iam` already use for a large inline `#[cfg(test)]
//! mod tests`: unchanged content, moved so the production file it tested
//! stops counting these lines against the file-length ceiling.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use tonic::transport::{ClientTlsConfig, Endpoint};

use super::*;
use crate::connect::{authority, connect_with, endpoint, Peer, Target};
use crate::resolve::{bounded_lookup, refresh};

/// The dial every case here re-resolves, with the caller's own bound rather
/// than a number a case could satisfy by accident.
fn target(tls: Option<ClientTlsConfig>) -> Target {
    Target {
        host: "task-db".to_string(),
        port: 50051,
        tls,
        request_timeout: REQUEST_TIMEOUT,
    }
}

/// Everything the balancer was handed, in order, as text.
///
/// TEXT rather than the `Change` values themselves so a case can assert the
/// ORDER of two different kinds of change against one another — which is
/// what the seed cases are about — in an assertion that prints what went
/// wrong.
fn drain(rx: &mut tokio::sync::mpsc::Receiver<Change<Peer, Endpoint>>) -> Vec<String> {
    let mut observed = Vec::new();
    while let Ok(change) = rx.try_recv() {
        observed.push(match change {
            Change::Insert(peer, _) => format!("insert {peer:?}"),
            Change::Remove(peer) => format!("remove {peer:?}"),
        });
    }
    observed
}

/// A resolver that never fails and always answers with `set`.
fn always(
    set: BTreeSet<SocketAddr>,
) -> impl Fn(String, u16) -> std::future::Ready<Result<BTreeSet<SocketAddr>, BalanceError>> {
    move |_host, _port| std::future::ready(Ok(set.clone()))
}

/// A resolver that never answers with an address, the way an upstream whose
/// Service does not exist yet does not.
fn never() -> impl Fn(String, u16) -> std::future::Ready<Result<BTreeSet<SocketAddr>, BalanceError>>
{
    |host, _port| {
        std::future::ready(Err(BalanceError::DnsTimedOut {
            host,
            after: RESOLVE_TIMEOUT,
        }))
    }
}

/// One metric, flattened to the three things an alert actually reads.
type Emitted = (String, Vec<(String, String)>, f64);

/// Drive `body` to completion with a recorder installed for the WHOLE run,
/// and return every metric it emitted.
///
/// **A RUNTIME BUILT BY HAND RATHER THAN `#[tokio::test]`, AND THAT IS
/// FORCED RATHER THAN A PREFERENCE.** `metrics::with_local_recorder`
/// installs a THREAD-LOCAL and takes a SYNC closure, so a recorder
/// installed inside an `async` test body would cover only the statements
/// between two awaits — and every emission here happens after an await.
/// Wrapping `block_on` instead puts every poll of the future inside the
/// closure. The clock is paused for the same reason every other case here
/// pauses it: `refresh` sleeps `RERESOLVE` between ticks.
///
/// **A NON-GAUGE PANICS HERE**, which is where the "it is a gauge" half of
/// each assertion below lives. A counter would satisfy every value
/// comparison in these cases and mean something entirely different to a
/// dashboard.
fn recorded<Fut>(body: impl FnOnce() -> Fut) -> Vec<Emitted>
where
    Fut: std::future::Future<Output = ()>,
{
    let recorder = DebuggingRecorder::new();
    let snapshotter: Snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .expect("a current-thread runtime")
            .block_on(body());
    });
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .map(|(composite, _unit, _description, value)| {
            let key = composite.key();
            (
                key.name().to_string(),
                key.labels()
                    .map(|l| (l.key().to_string(), l.value().to_string()))
                    .collect(),
                match value {
                    DebugValue::Gauge(v) => v.into_inner(),
                    other => panic!("expected a gauge, got {other:?}"),
                },
            )
        })
        .collect()
}

/// The ONE series these cases expect, asserted whole.
///
/// **THE LENGTH ASSERTION IS NOT PEDANTRY.** A `metrics-util` resolved
/// against another `metrics` major links a SECOND facade: everything
/// compiles, nothing is captured, and an assertion phrased as "no series is
/// above zero" would pass against the empty snapshot — which is exactly the
/// mutant that has to die. Every case here asserts PRESENCE and VALUE.
fn only_series(emitted: &[Emitted], host: &str) -> f64 {
    assert_eq!(
        emitted.len(),
        1,
        "exactly one series is expected — an empty snapshot means a duplicate `metrics` \
         crate, and more than one means an unintended emission: {emitted:?}"
    );
    let (name, labels, value) = &emitted[0];
    assert_eq!(
        name, UPSTREAM_NEVER_RESOLVED,
        "the name is what a dashboard queries and an alert names"
    );
    assert_eq!(
        labels,
        &vec![(UPSTREAM_LABEL.to_string(), host.to_string())],
        "the upstream and NOTHING else: a resolver error string is unbounded and D67 \
         refuses it as a label"
    );
    *value
}

/// THE SPELLING, PINNED AGAINST A LITERAL RATHER THAN AGAINST ITSELF.
///
/// **THIS CASE EXISTS BECAUSE THE OBVIOUS FORM OF IT DOES NOT WORK, AND
/// THAT WAS MEASURED RATHER THAN REASONED.** Every case below asserts
/// `name == UPSTREAM_NEVER_RESOLVED`, which reads like a check on the
/// spelling and is not one: renaming the constant renames BOTH sides, so
/// the mutant that renames the metric to `yadgar_dial_upstream_unresolved`
/// passed all fourteen of them. A rename is the one change to a metric that
/// cannot fail loudly — it blanks a panel and silences an alert while every
/// consumer of this crate goes on compiling — so the assertion that catches
/// it has to name the string a dashboard actually queries.
///
/// `yadgar-lifecycle`'s `WATCHED_FILES_UNREADABLE` carries the same "a test
/// asserts its spelling" claim and the same self-referential assertion, so
/// the same mutant survives there.
#[test]
fn the_names_a_dashboard_queries_are_pinned_to_their_spelling() {
    assert_eq!(
        UPSTREAM_NEVER_RESOLVED,
        "yadgar_dial_upstream_never_resolved"
    );
    assert_eq!(UPSTREAM_LABEL, "upstream");
}

/// THE BOOT DIAL PUBLISHES THE ABSENCE IT CREATES, and it must, because the
/// window this metric describes opens at boot and the first tick is
/// `RERESOLVE` away.
///
/// `.invalid` is reserved by RFC 6761 and guaranteed never to resolve, so
/// this needs no rig. A host with no resolver at all reaches the same
/// branch by a different error, which makes the case robust on a sandboxed
/// runner rather than dependent on one.
#[test]
fn the_boot_dial_publishes_the_absence_it_creates() {
    let host = "an-upstream-that-is-not-there-4b71.invalid";
    let emitted = recorded(|| async move {
        let _channel = connect_with(host, 50051, None, REQUEST_TIMEOUT)
            .await
            .expect("an unresolvable upstream is not a boot failure");
    });

    assert_eq!(
        only_series(&emitted, host),
        1.0,
        "the pod is Running with zero restarts and cannot serve; this gauge is the only \
         thing that says so"
    );
}

/// AND A HEALTHY BOOT PUBLISHES THE ZERO.
///
/// **This is the half that is easy to skip and cannot be.** A gauge written
/// only when something is wrong does not exist on a healthy pod, and `> 0`
/// matches nothing on a series that does not exist — so "healthy" would be
/// indistinguishable from "this crate was never linked" and from "the
/// process died before its first tick".
///
/// An ADDRESS LITERAL rather than a name: tokio resolves it by parsing,
/// with no resolver involved, so this case cannot fail on a runner with no
/// DNS.
#[test]
fn a_boot_dial_that_resolves_publishes_the_zero() {
    let host = "127.0.0.1";
    let emitted = recorded(|| async move {
        let _channel = connect_with(host, 50051, None, REQUEST_TIMEOUT)
            .await
            .expect("an address literal resolves to itself");
    });

    assert_eq!(only_series(&emitted, host), 0.0);
}

/// AN UPSTREAM THAT HAS NEVER RESOLVED KEEPS SAYING SO, on every tick.
///
/// This is the standing condition an alert fires on. `still_absent` already
/// logs it at ERROR, and that line reaches `kubectl logs` and nowhere else:
/// no log shipper runs in this estate.
#[test]
fn an_upstream_that_never_resolves_is_reported_on_every_tick() {
    let emitted = recorded(|| async {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let _ = tokio::time::timeout(
            RERESOLVE * 2 + Duration::from_secs(1),
            refresh(target(None), BTreeSet::new(), true, tx, never()),
        )
        .await;
    });

    assert_eq!(only_series(&emitted, "task-db"), 1.0);
}

/// A BLIP ON AN UPSTREAM THAT HAS RESOLVED IS NOT THE SAME CONDITION, and
/// the gauge has to draw the line `still_absent` already draws between WARN
/// and ERROR.
///
/// **Without this case the obvious wrong implementation passes**: set the
/// gauge to 1 whenever a tick produces no addresses. That reports every
/// transient DNS answer during a rolling update as an upstream that never
/// came up, and an alert nobody can trust is worse than no alert.
#[test]
fn a_blip_on_an_upstream_that_has_resolved_is_not_an_absence() {
    let addr: SocketAddr = "10.0.0.1:50051".parse().unwrap();
    let emitted = recorded(move || async move {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let _ = tokio::time::timeout(
            RERESOLVE * 2 + Duration::from_secs(1),
            // The balancer HAS been given an address; DNS is now failing.
            refresh(target(None), BTreeSet::from([addr]), false, tx, never()),
        )
        .await;
    });

    assert_eq!(
        only_series(&emitted, "task-db"),
        0.0,
        "the endpoints are kept and requests are still served — this is a warning, not the \
         condition this gauge names"
    );
}

/// THE GAUGE CLEARS ON THE TICK THAT FIRST RESOLVES, not on the one after
/// it.
///
/// **This is the case that makes the second emission load-bearing.** A tick
/// reads `current` on entry, so an implementation that writes the gauge only
/// at the top of the tick reports the absence for one more `RERESOLVE` after
/// the upstream came up. Delete the write that follows the insertions and
/// this case sees 1.0.
#[test]
fn the_gauge_clears_on_the_tick_that_first_resolves() {
    let addr: SocketAddr = "10.0.0.1:50051".parse().unwrap();
    let emitted = recorded(move || async move {
        // ALIVE across the tick: dropping it ends the loop before the tick
        // that matters.
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let _ = tokio::time::timeout(
            RERESOLVE + Duration::from_secs(1),
            refresh(
                target(None),
                BTreeSet::new(),
                true,
                tx,
                always(BTreeSet::from([addr])),
            ),
        )
        .await;
    });

    assert_eq!(only_series(&emitted, "task-db"), 0.0);
}

/// A DIAL NOBODY HOLDS ANY MORE IS NOT AN ABSENCE, and this is the leak the
/// second half of the predicate exists for.
///
/// A gauge left standing at 1 when the loop ends alerts for the life of the
/// pod about an upstream the process has stopped dialling — a page with
/// nothing behind it, which is how an alert gets muted and then ignored.
/// The condition is "this process is dialling `upstream` AND has never had
/// an address for it", and the first conjunct stops holding here.
#[test]
fn a_dial_nobody_holds_any_more_is_no_longer_an_absence() {
    let emitted = recorded(|| async {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        // The channel `connect` would have returned, and the caller is done
        // with it.
        drop(rx);
        let outcome = tokio::time::timeout(
            Duration::from_secs(60),
            // Never resolved, and the seed is in the balancer: the state
            // this gauge reports as 1 right up to the moment the loop ends.
            refresh(target(None), BTreeSet::new(), true, tx, never()),
        )
        .await;
        assert!(
            outcome.is_ok(),
            "the loop must end when the channel is dropped"
        );
    });

    assert_eq!(only_series(&emitted, "task-db"), 0.0);
}

/// THE LEAK. A stable endpoint set, and a receiver nobody holds any more.
///
/// **This fails against the loop that learned about a dropped channel only
/// from a failed `tx.send`.** A stable set produces no changes, so nothing is
/// ever sent, so the failure never happens: measured, that loop was still
/// re-resolving after twelve seconds — more than two ticks — against a
/// channel nobody holds, and would have gone on for the life of the process.
///
/// The DNS-error and empty-resolution branches need no case of their own.
/// The check that ends the loop sits ABOVE all three, before a resolution is
/// even attempted, so one branch proves it for all of them.
///
/// On a paused clock the runtime jumps to the next deadline, so a loop that
/// exits does so at its first tick and this case costs no wall-clock time.
/// The sixty-second ceiling is the failure mode being asserted against: "it
/// never ended", not "it was slow".
#[tokio::test(start_paused = true)]
async fn stable_endpoint_set_exits_on_channel_drop() {
    let addr: SocketAddr = "10.0.0.1:50051".parse().unwrap();
    let stable = BTreeSet::from([addr]);

    let (tx, rx) = tokio::sync::mpsc::channel(8);
    // The channel `connect` would have returned, and the caller is done with
    // it. `current` is seeded with what resolves, so every tick is a stable
    // one and no send is ever attempted.
    drop(rx);

    let outcome = tokio::time::timeout(
        Duration::from_secs(60),
        refresh(target(None), stable.clone(), false, tx, always(stable)),
    )
    .await;

    assert!(
        outcome.is_ok(),
        "the loop must end when the channel is dropped, including on a tick that sends nothing"
    );
}

/// An endpoint that FAILED TO BUILD must not be recorded as one the balancer
/// was given.
///
/// The defect is invisible on the tick where it happens — nothing is sent
/// either way — and surfaces on the NEXT one. A `current` advanced to the
/// resolved set holds an address the balancer never received, so when that
/// address goes away the loop sends a `Remove` for it. This case watches for
/// exactly that removal, and for anything else reaching a balancer that was
/// given nothing.
///
/// Every build fails here, by way of a domain name `ServerName` refuses —
/// the same lever `a_host_that_is_not_a_valid_server_name_is_refused` pulls.
/// That makes the failure total and independent of which address is being
/// built.
#[tokio::test(start_paused = true)]
async fn an_endpoint_that_fails_to_build_is_not_recorded_as_given() {
    let first: SocketAddr = "10.0.0.1:50051".parse().unwrap();
    let second: SocketAddr = "10.0.0.2:50051".parse().unwrap();

    // The receiver stays ALIVE across both ticks. Dropping it would end the
    // loop at the top of tick two, before the tick that matters.
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);

    let tick = Arc::new(AtomicUsize::new(0));
    let resolver = move |_host: String, _port: u16| {
        let n = tick.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Ok(BTreeSet::from([if n == 0 { first } else { second }])))
    };

    // Nothing can be built with this: every `endpoint` call fails before any
    // send.
    let unbuildable = ClientTlsConfig::new().domain_name("not a server name");

    // Two ticks, then the loop is abandoned. The timeout expiring is the
    // expected outcome — the channel is alive, so the loop is meant to keep
    // running — and the assertion is on what reached the receiver.
    let _ = tokio::time::timeout(
        RERESOLVE * 2 + Duration::from_secs(1),
        refresh(
            target(Some(unbuildable)),
            BTreeSet::new(),
            false,
            tx,
            resolver,
        ),
    )
    .await;

    let observed = drain(&mut rx);
    assert!(
        observed.is_empty(),
        "no endpoint could be built, so the balancer was given nothing — and a removal here \
         takes away an address it never had: {observed:?}"
    );
}

/// THE SEED IS WITHDRAWN, and only once a resolved address has actually been
/// given to the balancer.
///
/// Leaving it in is not harmless: the name resolves to ONE pod, so a
/// balancer holding both it and every pod address sends a share of the
/// traffic down an unbalanced path for the life of the process — D23's
/// failure, reintroduced by the thing that fixed the boot.
///
/// THE ORDER IS THE OTHER HALF. The insertion goes first, so there is no
/// moment at which the balancer holds nothing and `poll_ready` is
/// `Pending`. Reverse the two statements and this case says so.
#[tokio::test(start_paused = true)]
async fn the_seed_is_withdrawn_after_a_resolved_address_is_given() {
    let addr: SocketAddr = "10.0.0.1:50051".parse().unwrap();
    let resolved = BTreeSet::from([addr]);

    // ALIVE across the tick: dropping it ends the loop before the tick that
    // matters.
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);

    let _ = tokio::time::timeout(
        RERESOLVE + Duration::from_secs(1),
        refresh(
            target(None),
            // Nothing was given at boot, and the seed is in the balancer.
            BTreeSet::new(),
            true,
            tx,
            always(resolved),
        ),
    )
    .await;

    assert_eq!(
        drain(&mut rx),
        vec![
            "insert Address(10.0.0.1:50051)".to_string(),
            "remove Unresolved".to_string(),
        ],
        "the resolved address must be in before the name goes out, and the name must go"
    );
}

/// AND IT SURVIVES A TICK THAT COULD BUILD NOTHING.
///
/// **This is the case that separates "what was given" from "what was
/// resolved" for the seed**, exactly as
/// `an_endpoint_that_fails_to_build_is_not_recorded_as_given` does for
/// `current`. DNS answers here, so a withdrawal gated on `resolved` fires —
/// and every `endpoint` build fails, so nothing replaces the seed. The
/// balancer would be left holding NOTHING, which is the empty-balancer hang
/// the seed exists to prevent.
///
/// Change the gate to `!resolved.is_empty()` and this fails.
#[tokio::test(start_paused = true)]
async fn the_seed_survives_a_tick_that_could_build_nothing() {
    let addr: SocketAddr = "10.0.0.1:50051".parse().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);

    // Nothing can be built with this: every `endpoint` call fails before any
    // send. The same lever `a_host_that_is_not_a_valid_server_name_is_refused`
    // pulls.
    let unbuildable = ClientTlsConfig::new().domain_name("not a server name");

    let _ = tokio::time::timeout(
        RERESOLVE * 2 + Duration::from_secs(1),
        refresh(
            target(Some(unbuildable)),
            BTreeSet::new(),
            true,
            tx,
            always(BTreeSet::from([addr])),
        ),
    )
    .await;

    assert!(
        drain(&mut rx).is_empty(),
        "no endpoint could be built, so the name is still the only thing that can serve a \
         request — withdrawing it leaves the balancer empty, and an empty balancer never \
         becomes ready"
    );
}

/// A resolver that stops answering has to become an error, and one that says
/// what happened rather than borrowing NXDOMAIN's name.
///
/// The outer ceiling is what makes the failure legible: without the bound
/// inside `bounded_lookup` there is nothing to end the wait, and this case
/// would otherwise hang instead of failing.
#[tokio::test(start_paused = true)]
async fn a_lookup_that_never_answers_is_bounded_and_named() {
    let outcome = tokio::time::timeout(
        RESOLVE_TIMEOUT * 12,
        bounded_lookup(
            "task-db:50051".to_string(),
            std::future::pending::<std::io::Result<std::vec::IntoIter<SocketAddr>>>(),
        ),
    )
    .await
    .expect("the lookup must be bounded from inside, not by this case's own ceiling");

    assert!(
        matches!(outcome, Err(BalanceError::DnsTimedOut { .. })),
        "a resolver that stopped answering must be reported as itself: {outcome:?}"
    );
}

/// A REGRESSION GUARD on tonic's rule, not the proof that TLS works — the
/// proof is `tests/tls.rs`, which does real handshakes. It is here because
/// the failure it catches is silent: tonic's connector switches on the URI
/// SCHEME, so an `http://` endpoint carrying a TLS configuration connects in
/// cleartext and reports nothing. Nothing about the resulting channel says
/// it happened.
#[test]
fn the_scheme_follows_the_tls_configuration() {
    let addr: SocketAddr = "10.0.0.1:50051".parse().unwrap();

    let cleartext = endpoint(&addr.to_string(), None, REQUEST_TIMEOUT).unwrap();
    assert_eq!(cleartext.uri().scheme_str(), Some("http"));

    let secured = endpoint(
        &addr.to_string(),
        Some(&ClientTlsConfig::new().domain_name("task-db")),
        REQUEST_TIMEOUT,
    )
    .expect("a TLS endpoint with a valid domain builds");
    assert_eq!(secured.uri().scheme_str(), Some("https"));
}

/// AN IPv6 LITERAL IS A VALID HOST AND NOT A VALID AUTHORITY.
///
/// This never mattered while every endpoint was built from a resolved
/// `SocketAddr`, because `SocketAddr`'s `Display` brackets a v6 address.
/// The seed is built from the host instead, so dropping the bracketing here
/// turns `connect("::1", …)` — which worked — into `InvalidHost`, and turns
/// it BEFORE the resolution that would have succeeded.
#[test]
fn an_ipv6_literal_host_is_bracketed_and_a_name_is_not() {
    assert_eq!(authority("::1", 50051), "[::1]:50051");
    assert_eq!(authority("task-db", 50051), "task-db:50051");
    assert_eq!(authority("10.0.0.1", 50051), "10.0.0.1:50051");

    // And what the bracketing buys: unbracketed, this is `InvalidHost`.
    let built = endpoint(&authority("::1", 50051), None, REQUEST_TIMEOUT)
        .expect("an IPv6 literal must still be dialable");
    assert_eq!(
        built.uri().authority().map(|a| a.as_str()),
        Some("[::1]:50051")
    );
}

/// A host that is not a name TLS can verify has to be refused. `ServerName`
/// rejects it, and the only alternatives are to dial it unverified or to
/// dial it in cleartext.
#[test]
fn a_host_that_is_not_a_valid_server_name_is_refused() {
    let addr: SocketAddr = "10.0.0.1:50051".parse().unwrap();
    let tls = ClientTlsConfig::new().domain_name("not a server name");
    assert!(matches!(
        endpoint(&addr.to_string(), Some(&tls), REQUEST_TIMEOUT),
        Err(BalanceError::Tls { .. })
    ));
}

/// The `Error::source()` walk a caller performs, inlined.
///
/// This is `yadgar-telemetry`'s `diagnose::chain` byte for byte. It is
/// COPIED rather than depended on because the property under test is a
/// property of THIS crate's messages, and taking a dependency on the
/// telemetry crate to assert it would make `dial` — which every other
/// module dials through — depend on the crate that renders its errors.
fn flattened(error: &dyn std::error::Error) -> String {
    let mut rendered = error.to_string();
    let mut source = error.source();
    while let Some(current) = source {
        rendered.push_str(": ");
        rendered.push_str(&current.to_string());
        source = current.source();
    }
    rendered
}

/// LEDGER 737. A variant that marks a field `#[source]` must not also
/// interpolate that field into its own `#[error]` string.
///
/// A caller that walks the chain appends every layer itself, so a message
/// that already carries the layer prints the inner cause TWICE. The cause
/// is asserted to appear exactly ONCE, and the `#[source]` link is asserted
/// to still be there — dropping the interpolation must not be done by
/// dropping the attribute, which would delete the information instead of
/// moving it.
///
/// The inner cause is a SENTINEL rather than a real `io::Error` message so
/// the count does not depend on how a platform words `ENOENT`.
#[test]
fn a_variant_that_marks_a_source_does_not_also_interpolate_it() {
    const SENTINEL: &str = "sentinel-inner-cause";
    let io = || std::io::Error::new(std::io::ErrorKind::NotFound, SENTINEL);
    let path = || PathBuf::from("/nonexistent/pem");

    let cases: Vec<(&str, BalanceError)> = vec![
        (
            "Dns",
            BalanceError::Dns {
                host: "task-db".to_string(),
                source: io(),
            },
        ),
        (
            "CaUnreadable",
            BalanceError::CaUnreadable {
                path: path(),
                source: io(),
            },
        ),
        (
            "CaUnparsable",
            BalanceError::CaUnparsable {
                path: path(),
                // `Base64Decode` is the one `pem::Error` variant that carries
                // caller-supplied text, so it is the only one that can hold
                // the sentinel.
                source: rustls_pki_types::pem::Error::Base64Decode(SENTINEL.to_string()),
            },
        ),
        (
            "ClientCertificateUnreadable",
            BalanceError::ClientCertificateUnreadable {
                path: path(),
                source: io(),
            },
        ),
        (
            "ClientKeyUnreadable",
            BalanceError::ClientKeyUnreadable {
                path: path(),
                source: io(),
            },
        ),
    ];

    for (variant, error) in cases {
        assert!(
            std::error::Error::source(&error).is_some(),
            "{variant} must keep its `#[source]` link — the cause moves to \
             the chain, it does not go away"
        );
        let flat = flattened(&error);
        assert_eq!(
            flat.matches(SENTINEL).count(),
            1,
            "{variant} prints its cause {} time(s) in a walked chain, not \
             once: {flat}",
            flat.matches(SENTINEL).count()
        );
    }
}

/// LEDGER 737, stated as the whole operator-facing line rather than as a
/// count, so the diff shows a human what a log actually reads.
#[test]
fn the_walked_message_for_an_unreadable_bundle_reads_end_to_end() {
    let error = BalanceError::CaUnreadable {
        path: PathBuf::from("/nonexistent/ca.pem"),
        source: std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No such file or directory (os error 2)",
        ),
    };
    assert_eq!(
        flattened(&error),
        "TLS was requested, so a CA certificate bundle that cannot be read \
         is an error rather than a reason to connect in cleartext. The \
         bundle at /nonexistent/ca.pem could not be read: No such file or \
         directory (os error 2)"
    );
}

/// LEDGER 737 for the one variant that cannot be built by hand.
///
/// `tonic::transport::Error` is opaque, so `Tls` is reached through the real
/// path that produces it. It needs no sentinel: the type renders as
/// `transport error` and carries the real cause as its OWN source, so the
/// duplication is visible as that phrase appearing twice. This is the
/// measured example ledger 737 was filed on.
#[test]
fn the_tls_variant_does_not_repeat_the_transport_layer() {
    let addr: SocketAddr = "10.0.0.1:50051".parse().unwrap();
    let tls = ClientTlsConfig::new().domain_name("not a server name");
    let error = match endpoint(&addr.to_string(), Some(&tls), REQUEST_TIMEOUT) {
        Err(error) => error,
        Ok(_) => panic!("a host that is not a valid server name must be refused"),
    };
    let flat = flattened(&error);
    assert_eq!(
        flat.matches("transport error").count(),
        1,
        "the transport layer must appear once, not twice: {flat}"
    );
    assert_eq!(
        flat,
        "TLS could not be configured: transport error: invalid dns name"
    );
}
