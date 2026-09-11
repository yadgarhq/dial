//! The re-resolution loop: keep polling DNS, diff what came back against what
//! the balancer already holds, and apply the difference.
//!
//! Split out of `lib.rs` by LEDGER 719. The one behavioural change made in
//! the split: [`re_resolve`]'s per-tick application of a resolved diff was
//! extracted into [`apply_changes`] so the function stays under the
//! function-length ceiling the split also adopts. The extracted code is
//! unchanged — same sends, same log lines, same order — and `apply_changes`
//! returning `false` (send failed, channel dropped) is exactly the case that
//! used to `return` straight out of `re_resolve`'s `for` loop.

use std::collections::BTreeSet;
use std::future::Future;
use std::net::SocketAddr;

use tokio::sync::mpsc::Sender;
use tonic::transport::channel::Change;
use tonic::transport::{ClientTlsConfig, Endpoint};

use crate::connect::{endpoint, Peer, Target};
use crate::error::BalanceError;
use crate::{diff, report_never_resolved, RERESOLVE, RESOLVE_TIMEOUT};

/// The loop. Separate from `connect` so a failed resolution never takes down a
/// channel that is still serving: DNS blipping is not a reason to stop using
/// endpoints that currently work.
///
/// **`resolver` IS A PARAMETER BECAUSE THIS FUNCTION HAD NO SEAM, and that is
/// why two defects lived in twenty lines of it.** The loop called `resolve`
/// directly and slept `RERESOLVE` — five seconds — between ticks, while the
/// integration suites finish in under three. A probe placed after the sleep took
/// zero hits across all fourteen of them: no branch of this function was ever
/// executed by a test, and a doc comment on `connect` claiming the opposite of
/// what this code did went unchallenged through review.
///
/// A GENERIC rather than a function pointer: an `async fn`'s future type cannot
/// be named, so a `fn` pointer would force a boxed future and an allocation on
/// every tick for a seam only tests use. The parameter never reaches the public
/// API, because `refresh` is private and `connect_with` supplies it.
///
/// **`current` is what the balancer HAS BEEN GIVEN, not what DNS last said**, and
/// the distinction is the second defect. An endpoint whose `Endpoint` fails to
/// build is skipped; recording it as present anyway means `diff` never offers it
/// again, so one transient failure to build an address removes that pod from the
/// balancer permanently. "Given" here means handed to the discovery channel — the
/// balancer applies it from there — so this tracks the sends that succeeded,
/// never the resolution that prompted them.
///
/// **`seeded` IS A ONE-WAY LATCH, and there is an invariant behind that.** It
/// says the balancer is holding [`Peer::Unresolved`] — the name — because boot
/// resolved nothing. The seed has to go once real addresses are in, or traffic
/// keeps being split between the balanced pods and whichever single pod the
/// name happens to resolve to. It never has to come BACK, because the
/// empty-resolution guard below forbids `current` from returning to empty once
/// it is non-empty: an empty answer removes nothing. So the seed is needed at
/// most once, at boot, and this is a latch rather than per-tick bookkeeping.
pub(crate) async fn refresh<R, F>(
    target: Target,
    current: BTreeSet<SocketAddr>,
    seeded: bool,
    tx: Sender<Change<Peer, Endpoint>>,
    resolver: R,
) where
    R: Fn(String, u16) -> F,
    F: Future<Output = Result<BTreeSet<SocketAddr>, BalanceError>>,
{
    let host = target.host.clone();
    re_resolve(target, current, seeded, tx, resolver).await;

    // THE ONE EXIT, AND IT IS A WRAPPER FOR THAT REASON. `re_resolve` returns
    // from five places, and a gauge left standing at 1 by the one that got
    // missed alerts for the life of the pod about an upstream this process
    // stopped dialling. The condition `UPSTREAM_NEVER_RESOLVED` names has two
    // conjuncts, and the first of them — that a live dial exists — is false
    // from here on however the loop ended.
    report_never_resolved(&host, false);
}

/// The loop itself. See [`refresh`] for why it is wrapped rather than being the
/// whole of it.
async fn re_resolve<R, F>(
    target: Target,
    mut current: BTreeSet<SocketAddr>,
    mut seeded: bool,
    tx: Sender<Change<Peer, Endpoint>>,
    resolver: R,
) where
    R: Fn(String, u16) -> F,
    F: Future<Output = Result<BTreeSet<SocketAddr>, BalanceError>>,
{
    let Target {
        host,
        port,
        tls,
        request_timeout,
    } = target;

    loop {
        tokio::time::sleep(RERESOLVE).await;

        // THE EXIT, and it is a poll rather than a failed send deliberately.
        // The two commonest ticks — a stable endpoint set, and an empty
        // resolution that must be ignored — send NOTHING, so a loop that
        // learned about a dropped channel only from `tx.send` returning an
        // error would go on resolving for the life of the process. Asking here
        // also spares a dead channel's host one DNS lookup per tick.
        if tx.is_closed() {
            tracing::debug!(host, "channel dropped; ending re-resolution");
            return;
        }

        // ONE WRITE COVERING EVERY TICK THAT CHANGES NOTHING, and there are
        // three of them: a resolver error, an empty answer, and an unchanged
        // set. Each `continue`s, so a write placed at the bottom of the loop
        // would miss all three — and the first two are precisely the ticks a
        // never-resolved upstream produces for ever.
        //
        // `current.is_empty()` IS the predicate rather than a proxy for it: the
        // empty-resolution guard below forbids `current` from returning to
        // empty once it is non-empty, so an empty `current` means no address
        // has EVER been given. It is the same value `still_absent` splits its
        // ERROR from its WARN on, read at the same point, which is what keeps
        // the log line and the gauge from ever disagreeing.
        report_never_resolved(&host, current.is_empty());

        let resolved = match resolver(host.clone(), port).await {
            Ok(r) => r,
            Err(e) => {
                still_absent(&host, current.is_empty(), format_args!("{e}"));
                continue;
            }
        };

        // An EMPTY result is not a reason to remove everything. A headless
        // Service briefly returns nothing during some rollouts, and acting on it
        // would take the client to zero endpoints and fail every request — a
        // self-inflicted outage from a transient DNS answer.
        if resolved.is_empty() {
            still_absent(&host, current.is_empty(), format_args!("no addresses"));
            continue;
        }

        if resolved == current {
            continue;
        }

        let changes = diff(&current, &resolved);
        if !apply_changes(
            &host,
            tls.as_ref(),
            request_timeout,
            &tx,
            &mut current,
            changes,
        )
        .await
        {
            tracing::debug!(host, "channel dropped; ending re-resolution");
            return;
        }

        // THE SEED GOES ONLY ONCE A RESOLVED ADDRESS HAS BEEN GIVEN, and
        // "given" is `current` — the same distinction the rest of this loop
        // draws, for the same reason.
        //
        // GATING THIS ON `!resolved.is_empty()` COMPILES, READS IDENTICALLY AND
        // IS WRONG. A tick where DNS answers and every `endpoint` above fails
        // to build sends nothing, so withdrawing the seed on the strength of
        // the ANSWER would leave the balancer holding no endpoint at all — the
        // empty-balancer hang this seed exists to prevent, reintroduced by the
        // code that retires it.
        //
        // AFTER the insertions rather than before, so there is no tick on which
        // the balancer holds nothing.
        if seeded && !current.is_empty() {
            if tx.send(Change::Remove(Peer::Unresolved)).await.is_err() {
                tracing::debug!(host, "channel dropped; ending re-resolution");
                return;
            }
            seeded = false;
            tracing::info!(
                host,
                count = current.len(),
                "the upstream resolved; the name is withdrawn and traffic is balanced across \
                 replicas"
            );
        }

        // AND AGAIN, BECAUSE THIS IS THE ONLY PATH THAT CHANGED `current`.
        // The write at the top of the tick read the set as it was on ENTRY, so
        // without this one the tick that finally resolved an upstream would go
        // on reporting the absence for another `RERESOLVE`. Every other path
        // out of this tick left `current` alone and needs no second write.
        report_never_resolved(&host, current.is_empty());
    }
}

/// Apply one tick's [`diff`] to the balancer, advancing `current` as sends
/// succeed and logging exactly as [`re_resolve`] did inline before this was
/// split out of it.
///
/// Returns `false` the moment a send finds the channel dropped, which is the
/// caller's signal to stop re-resolving rather than continue the tick.
/// Otherwise returns `true` once every change has been applied — including a
/// change skipped because its `Endpoint` failed to build, which is neither a
/// dropped channel nor recorded into `current` (see the comment at that call).
async fn apply_changes(
    host: &str,
    tls: Option<&ClientTlsConfig>,
    request_timeout: std::time::Duration,
    tx: &Sender<Change<Peer, Endpoint>>,
    current: &mut BTreeSet<SocketAddr>,
    changes: Vec<Change<SocketAddr, ()>>,
) -> bool {
    for change in changes {
        match change {
            Change::Insert(addr, ()) => {
                // Defensive: the configuration was already accepted once in
                // `connect_tls`, and nothing here depends on the address, so
                // this cannot fail for one pod and succeed for another. It
                // is written out anyway because the wrong recovery — adding
                // the endpoint in cleartext — is the exact downgrade this
                // module exists to prevent, and it must not be reachable
                // even by accident.
                let built = match endpoint(&addr.to_string(), tls, request_timeout) {
                    Ok(built) => built,
                    Err(e) => {
                        tracing::error!(
                            host, %addr, error = %e,
                            "could not build a TLS endpoint; the address is skipped rather than dialled in cleartext"
                        );
                        // AND NOT RECORDED. `current` advances only where a
                        // send succeeded, so this address is still missing
                        // from it next tick and `diff` offers it again.
                        continue;
                    }
                };
                // The receiver is gone, so the channel was dropped: stop
                // rather than spin against a dead sender. The check at the
                // top of the tick does not replace this one — the receiver
                // can be dropped part-way through a batch of changes.
                if tx
                    .send(Change::Insert(Peer::Address(addr), built))
                    .await
                    .is_err()
                {
                    return false;
                }
                current.insert(addr);
                tracing::info!(host, %addr, "endpoint added");
            }
            Change::Remove(addr) => {
                if tx.send(Change::Remove(Peer::Address(addr))).await.is_err() {
                    return false;
                }
                current.remove(&addr);
                tracing::info!(host, %addr, "endpoint removed");
            }
        }
    }
    true
}

/// Report a tick that produced no addresses, at the level the SITUATION
/// deserves rather than at one level for both.
///
/// **The two cases are different operator situations and used to share a
/// message.** An upstream that has endpoints and blipped is a warning and
/// nothing more: the current set is kept, and requests keep being served. An
/// upstream that has NEVER produced an address is a service that started
/// happily and cannot serve anything — the failure mode the boot exit used to
/// make obvious, and the one this crate now has to state for itself, on every
/// tick, because nothing else will.
pub(crate) fn still_absent(host: &str, nothing_given_yet: bool, why: std::fmt::Arguments<'_>) {
    if nothing_given_yet {
        tracing::error!(
            host,
            reason = %why,
            interval_secs = RERESOLVE.as_secs(),
            "the upstream has never resolved; NO endpoint has ever been available and every \
             request to it is failing. This is a missing or unready Service, not a slow one."
        );
    } else {
        tracing::warn!(
            host,
            reason = %why,
            "re-resolution produced nothing; keeping the current endpoints"
        );
    }
}

pub(crate) async fn resolve(host: &str, port: u16) -> Result<BTreeSet<SocketAddr>, BalanceError> {
    let target = format!("{host}:{port}");
    bounded_lookup(target.clone(), tokio::net::lookup_host(target)).await
}

/// The bound, separated from `tokio::net::lookup_host` so a lookup that never
/// answers can be handed to it directly.
///
/// What changed is not that a timeout exists — it is that a resolver which
/// STOPPED ANSWERING becomes a named error, distinct from a name that does not
/// exist. Those are different operator situations: NXDOMAIN answers, and answers
/// promptly. See [`RESOLVE_TIMEOUT`] for what the bound does and does not free.
pub(crate) async fn bounded_lookup<I, F>(
    target: String,
    lookup: F,
) -> Result<BTreeSet<SocketAddr>, BalanceError>
where
    I: Iterator<Item = SocketAddr>,
    F: Future<Output = std::io::Result<I>>,
{
    match tokio::time::timeout(RESOLVE_TIMEOUT, lookup).await {
        Err(_) => Err(BalanceError::DnsTimedOut {
            host: target,
            after: RESOLVE_TIMEOUT,
        }),
        Ok(Err(source)) => Err(BalanceError::Dns {
            host: target,
            source,
        }),
        Ok(Ok(addrs)) => Ok(addrs.collect()),
    }
}
