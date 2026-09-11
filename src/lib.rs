//! `yadgar-dial` — how a service reaches another service.
//!
//! Client-side load balancing over a headless Service (D23).
//!
//! **This crate exists because a second service needed the same code.** It began
//! as `task/src/balance.rs`, dialling `task-db`. When the gateway became `task`'s
//! first gRPC client it needed the identical logic — and the invariant is that
//! anything every service needs is implemented once, because duplication is not
//! mainly wasted effort, it is the mechanism by which two services quietly
//! disagree about how they find their peers.
//!
//! **The problem this solves is not obvious and is easy to declare solved.** gRPC
//! runs on HTTP/2 and holds ONE long-lived connection. A normal Kubernetes
//! Service balances at L4 — at connection time — so a client opens one connection,
//! gets one pod, and sends every request there for the life of the process. The
//! other replicas sit idle while looking healthy, and D68's autoscaler responds
//! to the resulting latency by adding more pods that also receive nothing.
//!
//! So the Service is HEADLESS: DNS returns every pod address rather than one
//! virtual IP, and the client balances across them itself.
//!
//! **Re-resolution is the part that must not be forgotten.** Resolving once at
//! startup pins the client to whichever pods existed then — new replicas get no
//! traffic, and a rolling update leaves the client talking to addresses that no
//! longer exist. That is the failure D68 calls self-amplifying, and it is a
//! property of D23 rather than of the autoscaler.
//!
//! NOTE ON THE EMPTY CASE: the refresh loop never acts on an empty resolution.
//! A headless Service briefly returns nothing during some rollouts, and removing
//! every endpoint on that basis is a self-inflicted outage from a transient DNS
//! answer. `diff` itself has no such opinion — it is pure — so the guard lives in
//! the loop.
//!
//! **WHERE THAT IS AND IS NOT TESTED, spelled out because this paragraph used to
//! name a test that does not exist.** Recovering from zero IS covered, at the
//! `diff` level, by
//! `tests/balance.rs::recovering_from_an_empty_set_inserts_everything`. The
//! loop's OWN `resolved.is_empty()` guard — that an empty answer removes nothing
//! — has no test. `mod tests` below covers the loop's exit, its bookkeeping of
//! what the balancer was given, and when it withdraws the lazy seed; not the
//! effect of that branch on the endpoint set.
//!
//! That guard is nonetheless what makes the seed a ONE-WAY latch: an endpoint
//! set that has been non-empty once can never return to empty, so the name is
//! needed at most once, at boot. See `refresh`.
//!
//! # The boot dial
//!
//! **NOTHING HERE FAILS BECAUSE AN UPSTREAM IS NOT THERE YET.** Every entry
//! point used to resolve and return the error, and three of the four internal
//! hops in this estate dial at boot — so `gateway` exited with `could not
//! resolve task:50052` and crash-looped six times on a rebuilt cluster, before
//! `task`'s Service existed. It self-healed. That is the argument FOR fixing it
//! rather than against: the cold start costs exponential backoff, and a restart
//! count spent on an ordering accident is a restart count that no longer shows
//! a real crash.
//!
//! **THE WINDOW IS THE DESIGN, not the omission.** A balanced channel with no
//! endpoints is not one that connects later: `Balance::poll_ready` is
//! `Poll::Pending` while its ready set is empty, and no bound in this crate
//! sits above that — [`default_request_timeout`] lives INSIDE a connection and
//! never sees a request that has not been given one. So "return a channel and
//! let the loop fill it" would trade a crash loop for a process that starts
//! happily and hangs every caller, which is worse and much harder to see.
//!
//! What is returned instead always holds at least one endpoint. Until an
//! address resolves that endpoint is the NAME — `Peer::Unresolved` — which is
//! precisely what `gateway`'s `connect_iam` does with `Endpoint::connect_lazy`,
//! the one internal hop that never crash-looped. A request in the window is
//! dialled at the name and comes back with the transport's own error in
//! milliseconds; the next request retries. The refresh loop then inserts the
//! resolved addresses and withdraws the name, in that order, so the balancer is
//! never empty.
//!
//! **WHAT STILL FAILS LOUDLY, because fail-fast was the property traded away.**
//! A CONFIGURATION mistake is still an error before a channel exists: an
//! unreadable or rootless CA bundle, a client certificate that is not there, a
//! host that does not form a URI authority. No resolution would ever fix any of
//! those. And an upstream that is genuinely, permanently absent is reported by
//! the refresh loop at ERROR on every tick, naming the host and saying that no
//! endpoint has EVER been available — see `still_absent`. A service that starts
//! and cannot serve is the failure mode this estate keeps finding, so it is
//! stated rather than left to be inferred from a silence.
//!
//! **AND STATED AS A METRIC, BECAUSE THE LOG LINE ABOVE REACHES NOBODY.** That
//! ERROR was offered as the replacement for the crash loop and cannot be one:
//! the `observability` namespace runs a Prometheus server and NO log shipper,
//! so the line reaches `kubectl logs` and nowhere else — which is to say it
//! reaches an operator who has already guessed the answer. Meanwhile the pod
//! reads `1/1 Running`, zero restarts, Argo Healthy. So the same condition is
//! also published as [`UPSTREAM_NEVER_RESOLVED`], a gauge keyed by upstream,
//! and READ THAT ITEM'S DOCS BEFORE ALERTING ON IT: the predicate is narrower
//! than the name.
//!
//! **A METRIC IS A CAPABILITY AND NOT YET A SIGNAL, and pretending otherwise
//! would repeat the mistake this paragraph is correcting.** Nothing alerts on
//! it today. Verified 2026-09-04 in `yadgarhq/deploy`: no `PrometheusRule`
//! exists anywhere, no Prometheus Operator is installed — no
//! `monitoring.coreos.com` CRD, no `ServiceMonitor` — so that resource is not
//! even reconcilable, and `infra/prometheus.yaml` sets `alertmanager.enabled:
//! false`, so there is nothing to route a firing rule to. The rule this gauge
//! is SHAPED for is `max_over_time(yadgar_dial_upstream_never_resolved[5m]) >
//! 0`, `for: 2m`, grouped by `upstream`. Landing it means a rules file on the
//! Prometheus chart and an Alertmanager to receive it, both in `deploy`, and
//! both a separate change from this one.
//!
//! # TLS
//!
//! [`connect`] dials in CLEARTEXT and always has. On a single-node cluster that
//! is invisible; on a shared cluster with a flat pod network it is a bearer
//! token anyone on that network can read. [`connect_tls`] is the same dialling
//! with the transport encrypted and the peer verified, and it is OPT-IN: this
//! code ships first, and turning it on for a given caller is a separate change
//! that can be reverted on its own.
//!
//! **The part that is easy to get wrong is which name the certificate is checked
//! against.** This crate resolves a host to a set of ADDRESSES and dials those,
//! so the obvious implementation verifies the server's certificate against an IP
//! — which needs an IP SAN no issuer grants per pod, and whose usual "fix" is to
//! stop verifying. [`TlsOptions`] pins the verification domain to the HOST the
//! caller asked for, independently of the address dialled. That is what lets a
//! certificate issued for the Service name work while the balancer goes on
//! talking to pod IPs.
//!
//! **Configuration is file paths, never an issuer-specific resource** (D80). A
//! CA bundle on disk is written by cert-manager in the reference deployment and
//! by a hand-assembled Secret anywhere else, and this crate cannot tell the
//! difference — which is the point.
//!
//! **A misconfiguration is an error, never a downgrade.** An unreadable bundle,
//! an undecodable one, one that contains no certificate, and one whose sections
//! decode as PEM and yield no usable trust anchor all fail at [`connect_tls`].
//! The last of those is the one worth naming: it is the case a count of PEM
//! sections cannot see, and it produces the same rootless trust store as an empty
//! file while looking healthy. Nothing here falls back to cleartext, and nothing
//! here falls back to the platform trust store.
//!
//! **Mutual TLS is the same shape, one step further** (ADR-0516). Where the
//! bundle above says which peers this caller will trust,
//! [`TlsOptions::identity`] says who this caller IS, so a server can accept
//! only peers the deployment issued a certificate to. It is opt-in on the same
//! terms: unset by default, and a caller that never mentions it dials exactly
//! as it did before. What a server LEARNS from it is narrower than it looks —
//! see [`TlsOptions::identity`].
//!
//! # Timeouts
//!
//! Four bounds, on four different things, and the distinction is the whole reason
//! each of the last two exists.
//!
//! | bound | what it catches |
//! | --- | --- |
//! | `RESOLVE_TIMEOUT` | a resolver that stopped answering, BEFORE any connection |
//! | `connect_timeout` | a TCP connect that does not complete |
//! | HTTP/2 keepalive | a peer that VANISHED without closing its connection |
//! | [`default_request_timeout`] | a peer that is alive, connected, answering pings, and never replies |
//!
//! **The first bounds a phase the other three never reach.** Every entry point
//! still ATTEMPTS a resolution before it returns, so a wedged resolver held
//! `connect` open for ever with nothing to report — and most callers here dial
//! at boot, which makes that a process that starts and never finishes starting.
//! The attempt is no longer allowed to FAIL the dial (see "The boot dial"), but
//! it is still an await, so it still needs the bound.
//!
//! **The last was missing too, and nothing else covers it.** A `-db` blocked on its
//! engine connects fine, pings fine, and holds every caller's handler open
//! indefinitely — which is also why a `tcpSocket` readiness probe stays green
//! straight through it. [`connect`] and [`connect_tls`] apply a default;
//! [`connect_with_request_timeout`] and [`connect_tls_with_request_timeout`]
//! take the caller's own.
//!
//! # This file
//!
//! LEDGER 719 split what used to be one 1987-line `lib.rs` along the seams
//! already in it: [`tls`] (options and their preparation), [`connect`] (the
//! entry points and the boot dial), [`resolve`] (the re-resolution loop), and
//! [`error`] (the one error type all of them return). This file keeps the
//! crate's shared vocabulary — the metric, the timeouts, and [`diff`], which
//! every other module reads but none of them owns.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::time::Duration;

// tonic re-exports its OWN Change. Importing tower::discover::Change directly
// compiles and then fails to match: the two are distinct types even at the same
// tower version, and the error reads "expected Change, found a different Change".
use tonic::transport::channel::Change;

mod connect;
mod error;
mod resolve;
mod tls;

pub use connect::{
    connect, connect_tls, connect_tls_with_request_timeout, connect_with_request_timeout,
};
pub use error::BalanceError;
pub use tls::TlsOptions;

/// The gauge saying that this process is dialling an upstream it has NEVER had
/// an address for.
///
/// **THIS EXISTS BECAUSE MAKING THE BOOT DIAL LAZY REMOVED A SIGNAL AND PUT
/// NOTHING BACK.** Before v0.2.0 an absent upstream was a crash loop, which
/// Kubernetes reported for free — `CrashLoopBackOff`, a climbing restart count,
/// a Deployment at 0/2, a Degraded Argo application. After it, the same pod is
/// `1/1 Running` with zero restarts and nothing in the cluster says anything is
/// wrong. The change was right and its CLIENT-side half was paid for; this is
/// the operator's half.
///
/// # Read the predicate before alerting on it
///
/// It is `1` when BOTH of these hold, and `0` otherwise:
///
/// 1. this process still has a live dial to `upstream`, and
/// 2. no address for it has EVER been given to the balancer.
///
/// **It is therefore NOT "the upstream is unreachable now", and an alert author
/// who assumes otherwise is wrong in the quiet direction.** `refresh`'s
/// `current` is a one-way latch — an empty resolution removes nothing, so a set
/// that has been non-empty once can never return to empty — which means this
/// gauge answers "has this upstream EVER resolved since boot", and falls to `0`
/// for good at the first address. An upstream that resolves at boot and then
/// vanishes entirely reads `0` here, exactly as a healthy one does. That is the
/// right scope, because the failure being restored is the BOOT-ORDERING one the
/// lazy dial introduced. It is a narrower claim than the name alone suggests,
/// which is why the name is not the documentation.
///
/// The second conjunct is what makes the exit path honest. Once the channel is
/// dropped nothing in this process dials `upstream` any more, so the condition
/// stops holding and the gauge is set to `0` rather than left standing at `1`
/// for the life of a pod that has moved on.
///
/// # `upstream` is a label, and `lifecycle` refused the analogous one
///
/// `yadgar-lifecycle`'s `WATCHED_FILES_UNREADABLE` is a COUNT with no per-path
/// label, and its own doc says a path label "would make the cardinality of this
/// metric a property of a deployment's configuration, which D67 refuses". A
/// reviewer holding both open should see the discriminator rather than a
/// contradiction:
///
/// - The range here is the set of upstreams ONE PROCESS DIALS — one or two in
///   this estate: `gateway` reaching `iam` and `task`, `task` reaching
///   `task-db`. A watch set grows with every file a deployment adds; a dial set
///   is fixed by the call graph, and a new one is a code change.
/// - The value is a service DNS name, the same class of string as the `service`
///   label `lifecycle` already puts on that very gauge.
/// - Without it an alert cannot NAME the absent upstream, and a page saying
///   only "something did not resolve" sends the operator back to `kubectl logs`
///   — the legibility this whole change exists to restore.
///
/// There is no second label. This crate is a library dialling outward and has
/// no service identity of its own; the scrape supplies the pod and the job.
///
/// **A NAME IS AN INTERFACE TO A DASHBOARD.** Renaming it blanks a panel rather
/// than failing anything, so it is a constant and a test asserts its spelling.
pub const UPSTREAM_NEVER_RESOLVED: &str = "yadgar_dial_upstream_never_resolved";

/// Which upstream a [`UPSTREAM_NEVER_RESOLVED`] series is about. A constant for
/// the same reason the metric name is one: an alert groups by it.
pub const UPSTREAM_LABEL: &str = "upstream";

/// Write [`UPSTREAM_NEVER_RESOLVED`] for one upstream.
///
/// **EVERY PATH THAT CAN CHANGE THE ANSWER CALLS THIS, THE HEALTHY ONES
/// INCLUDED, and that is the part it is easy to leave out.** A gauge written
/// only when something is wrong does not exist on a healthy pod, and a series
/// that does not exist cannot be compared against zero: `> 0` matches nothing,
/// and "healthy" becomes indistinguishable from "this crate was never linked"
/// and from "the process died before its first tick". So the boot dial
/// publishes it both ways, before any tick has run.
fn report_never_resolved(host: &str, never_resolved: bool) {
    metrics::gauge!(UPSTREAM_NEVER_RESOLVED, UPSTREAM_LABEL => host.to_string())
        .set(if never_resolved { 1.0 } else { 0.0 });
}

/// How often the endpoint set is re-resolved.
///
/// Kubernetes headless DNS has a short TTL, and pods come and go on deploys and
/// autoscaling events. Five seconds is well inside a rolling update's window.
const RERESOLVE: Duration = Duration::from_secs(5);

/// How long one phase of establishing a connection may take.
///
/// A dead pod must not hold a request open until the caller's deadline. Named
/// rather than written twice because it bounds TWO phases once TLS is on — see
/// `endpoint`, where the reason it has to be stated twice is recorded.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// How long ONE request may take once a connection has been chosen for it.
///
/// **Nothing else here bounds this.** `CONNECT_TIMEOUT` bounds the TCP connect,
/// and HTTP/2 keepalive notices a peer that vanished. A peer that is alive,
/// connected, answering pings and simply never replying is bounded by neither,
/// and that is precisely the shape of a `-db` blocked on its engine: without
/// this, one wedged callee holds every caller's handler open for as long as it
/// stays wedged.
///
/// **THIRTY SECONDS, chosen against the deadlines already in this system rather
/// than picked.** It has to sit ABOVE every deadline a caller set deliberately,
/// or it pre-empts a number somebody sized for a real call — `gateway`'s
/// `AUTH_DEADLINE` is 10s, sized for the Argon2id `iam` pays on every login
/// attempt, and its `RESOLVE_DEADLINE` is 5s, on the hot path of every call. It
/// has to sit BELOW the point at which the answer arrives to nobody: 60s is the
/// conventional idle timeout of an ingress and of most HTTP clients. Thirty is
/// three times the longest deliberate deadline in the tree and half the point
/// where the caller has already gone. A caller that needs another number passes
/// one rather than editing this.
///
/// It is a CEILING on the pathological case, not a latency target. A healthy
/// call through `dial` is a single query away from its answer and finishes
/// three orders of magnitude inside this.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long ONE resolution may take before it is abandoned.
///
/// **IT STILL APPLIES ON THE BOOT PATH, and that is deliberate.** `connect_with`
/// no longer DEPENDS on a resolution — a failure there is a warning and a lazy
/// dial at the name — but it still ATTEMPTS one, because a `-db` that is already
/// up should produce a balancer full of pod addresses before the first request,
/// with no window at all. An awaited lookup needs a bound whether or not its
/// failure is fatal: unbounded, a wedged resolver is a process that starts and
/// then never finishes starting — a silent startup hang rather than a crash
/// loop, so no restart policy notices and nothing is logged. With the bound,
/// the worst a wedged resolver costs the boot dial is this long, after which
/// the channel comes back dialling the name.
///
/// The loop applies the same bound on every tick, through the same `resolve`.
///
/// **WHAT THIS DOES NOT FIX, said rather than left to be discovered.** A `String`
/// target is resolved on the blocking pool — `spawn_blocking(getaddrinfo)`,
/// `tokio-1.53.1/src/net/addr.rs:182,219` — and a blocking task cannot be
/// cancelled. This bound releases the CALLER; the abandoned thread stays parked
/// until the resolver answers or the process ends. The hang is fixed. The pool
/// drain is only mitigated.
///
/// Five seconds is one `RERESOLVE` tick: a wedged resolver costs the refresh loop
/// at most a doubled interval, and costs startup an error instead of a wait with
/// no end.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// What changed between two resolutions.
///
/// Extracted as a PURE function on purpose: the DNS loop around it is thin and
/// hard to test, while getting the diff wrong is easy and silent. Removing an
/// endpoint that is still live drops traffic; failing to remove a dead one sends
/// requests into a black hole; re-inserting an unchanged endpoint churns
/// connections on every tick, which looks like working code and is not.
pub fn diff(
    current: &BTreeSet<SocketAddr>,
    resolved: &BTreeSet<SocketAddr>,
) -> Vec<Change<SocketAddr, ()>> {
    let added = resolved.difference(current).map(|a| Change::Insert(*a, ()));
    let removed = current.difference(resolved).map(|a| Change::Remove(*a));
    // Removals first: a rolling update reuses IPs, so inserting before removing
    // can leave the balancer holding a stale entry under a key it just re-added.
    removed.chain(added).collect()
}

/// The interval at which endpoints are re-resolved. Exposed so a caller can log
/// it, and so "did anyone actually re-resolve?" is answerable from outside.
pub const fn reresolve_interval() -> Duration {
    RERESOLVE
}

/// The per-request bound [`connect`] and [`connect_tls`] apply.
///
/// Exposed so a caller can log the number it is actually running with, and so a
/// caller that chooses its own can say what it departed from.
pub const fn default_request_timeout() -> Duration {
    REQUEST_TIMEOUT
}

#[cfg(test)]
mod tests;
