//! The re-resolution loop: keep polling DNS, diff what came back against what
//! the balancer already holds, and apply the difference.
//!
//! Split out of `lib.rs` by LEDGER 719. LEDGER 1401 then changed how a tick's
//! diff reaches the balancer: [`give`] queues it whole or not at all, and
//! never waits for room — see there for the idle-channel failure that waiting
//! caused.

use std::collections::BTreeSet;
use std::future::Future;
use std::net::SocketAddr;

use tokio::sync::mpsc::error::TrySendError;
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
        match give(
            &host,
            tls.as_ref(),
            request_timeout,
            &tx,
            &mut current,
            changes,
            seeded,
        ) {
            Given::Dropped => {
                tracing::debug!(host, "channel dropped; ending re-resolution");
                return;
            }
            // NOTHING WAS QUEUED AND `current` IS UNCHANGED, so the next tick
            // diffs from the same place against a fresher answer. Not a
            // `return` and not a wait: see `give`.
            Given::Deferred => continue,
            Given::All { withdrew_seed } => {
                if withdrew_seed {
                    seeded = false;
                    tracing::info!(
                        host,
                        count = current.len(),
                        "the upstream resolved; the name is withdrawn and traffic is balanced \
                         across replicas"
                    );
                }
            }
        }

        // AND AGAIN, BECAUSE THIS IS THE ONLY PATH THAT CHANGED `current`.
        // The write at the top of the tick read the set as it was on ENTRY, so
        // without this one the tick that finally resolved an upstream would go
        // on reporting the absence for another `RERESOLVE`. Every other path
        // out of this tick left `current` alone and needs no second write.
        report_never_resolved(&host, current.is_empty());
    }
}

/// What [`give`] did with one tick's diff.
enum Given {
    /// Every change was queued, and `current` now says so.
    All { withdrew_seed: bool },
    /// The channel had no room for the whole diff, so NONE of it was queued.
    Deferred,
    /// The receiver is gone: the channel was dropped.
    Dropped,
}

/// Queue one tick's [`diff`] for the balancer — ALL OF IT OR NONE OF IT, and
/// never by waiting.
///
/// **LEDGER 1401: THIS USED TO `send().await`, AND ON AN IDLE CHANNEL THAT
/// WAITS FOR EVER.** tonic's balancer reads the discovery channel only from
/// `Balance::poll_ready` (`tower-0.5.3/src/balance/p2c/service.rs:208-211`),
/// and the `Buffer` worker in front of it calls `poll_ready` only when it holds
/// a request (`tower-0.5.3/src/buffer/worker.rs:147-170`). On a channel nobody
/// calls, nothing consumes what this loop queues. Once the channel filled, the
/// loop parked mid-diff and stopped resolving; the first request hours later
/// drained a queue that ended part-way through an old rolling update, on pods
/// that no longer existed (kind-yadgar, 2026-10-09: gateway → iam and
/// gateway → task, `tcp connect error`).
///
/// So the whole tick is reserved up front with `try_reserve_many`, and a diff
/// that does not fit is [`Given::Deferred`]: nothing is queued, `current` is
/// left alone, and the loop goes on resolving. Whatever the queue holds then
/// still ends on a set this loop really resolved, and the next tick with room
/// queues the diff from there to the newest answer in one piece. The
/// capacity that makes this rare is `connect::BALANCE_BUFFER`.
///
/// `seeded` is whether the balancer still holds the name. Its withdrawal is
/// part of the same reservation, AFTER the insertions, so there is no point in
/// the queue at which the balancer would hold nothing.
fn give(
    host: &str,
    tls: Option<&ClientTlsConfig>,
    request_timeout: std::time::Duration,
    tx: &Sender<Change<Peer, Endpoint>>,
    current: &mut BTreeSet<SocketAddr>,
    changes: Vec<Change<SocketAddr, ()>>,
    seeded: bool,
) -> Given {
    let outgoing = build(host, tls, request_timeout, changes);

    // THE SEED GOES ONLY ONCE A RESOLVED ADDRESS HAS BEEN GIVEN, and "given"
    // is what `current` will hold after this tick — the same distinction the
    // rest of the loop draws, for the same reason.
    //
    // GATING THIS ON `!resolved.is_empty()` COMPILES, READS IDENTICALLY AND IS
    // WRONG. A tick where DNS answers and every `endpoint` fails to build
    // queues nothing, so withdrawing the seed on the strength of the ANSWER
    // would leave the balancer holding no endpoint at all — the empty-balancer
    // hang this seed exists to prevent, reintroduced by the code that retires
    // it.
    let mut after = current.clone();
    for change in &outgoing {
        match change {
            Change::Insert(addr, _) => after.insert(*addr),
            Change::Remove(addr) => after.remove(addr),
        };
    }
    let withdraw_seed = seeded && !after.is_empty();

    let needed = outgoing.len() + usize::from(withdraw_seed);
    if needed == 0 {
        return Given::All {
            withdrew_seed: false,
        };
    }
    let mut permits = match tx.try_reserve_many(needed) {
        Ok(permits) => permits,
        Err(TrySendError::Closed(())) => return Given::Dropped,
        Err(TrySendError::Full(())) => {
            tracing::warn!(
                host,
                needed,
                room = tx.capacity(),
                "the balancer has not consumed its endpoint changes (no request since they were \
                 queued); this tick's are held back whole and offered again on the next"
            );
            return Given::Deferred;
        }
    };

    for change in outgoing {
        // `try_reserve_many` handed out exactly `needed` permits.
        let Some(permit) = permits.next() else { break };
        match change {
            Change::Insert(addr, built) => {
                permit.send(Change::Insert(Peer::Address(addr), built));
                current.insert(addr);
                tracing::info!(host, %addr, "endpoint added");
            }
            Change::Remove(addr) => {
                permit.send(Change::Remove(Peer::Address(addr)));
                current.remove(&addr);
                tracing::info!(host, %addr, "endpoint removed");
            }
        }
    }
    if withdraw_seed {
        if let Some(permit) = permits.next() {
            permit.send(Change::Remove(Peer::Unresolved));
        }
    }
    Given::All {
        withdrew_seed: withdraw_seed,
    }
}

/// Build the [`Endpoint`] for every insertion in one tick's [`diff`], in the
/// diff's order.
///
/// An address whose `Endpoint` fails to build is DROPPED from the result, and
/// so never recorded into `current`: it is still missing from it next tick, and
/// `diff` offers it again.
fn build(
    host: &str,
    tls: Option<&ClientTlsConfig>,
    request_timeout: std::time::Duration,
    changes: Vec<Change<SocketAddr, ()>>,
) -> Vec<Change<SocketAddr, Endpoint>> {
    changes
        .into_iter()
        .filter_map(|change| match change {
            Change::Remove(addr) => Some(Change::Remove(addr)),
            // Defensive: the configuration was already accepted once in
            // `connect_tls`, and nothing here depends on the address, so this
            // cannot fail for one pod and succeed for another. It is written
            // out anyway because the wrong recovery — adding the endpoint in
            // cleartext — is the exact downgrade this module exists to
            // prevent, and it must not be reachable even by accident.
            Change::Insert(addr, ()) => match endpoint(&addr.to_string(), tls, request_timeout) {
                Ok(built) => Some(Change::Insert(addr, built)),
                Err(e) => {
                    tracing::error!(
                        host, %addr, error = %e,
                        "could not build a TLS endpoint; the address is skipped rather than dialled in cleartext"
                    );
                    None
                }
            },
        })
        .collect()
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
