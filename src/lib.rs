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
//! the loop and the test for the recovering-from-zero case lives here.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::sync::mpsc::Sender;
// tonic re-exports its OWN Change. Importing tower::discover::Change directly
// compiles and then fails to match: the two are distinct types even at the same
// tower version, and the error reads "expected Change, found a different Change".
use tonic::transport::channel::Change;
use tonic::transport::{Channel, Endpoint};

/// How often the endpoint set is re-resolved.
///
/// Kubernetes headless DNS has a short TTL, and pods come and go on deploys and
/// autoscaling events. Five seconds is well inside a rolling update's window.
const RERESOLVE: Duration = Duration::from_secs(5);

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

fn endpoint(addr: SocketAddr) -> Endpoint {
    Endpoint::from_shared(format!("http://{addr}"))
        .expect("a socket address always forms a valid authority")
        // A dead pod must not hold a request open until the caller's deadline.
        .connect_timeout(Duration::from_secs(2))
        // HTTP/2 keepalive notices a pod that vanished without closing its
        // connection — the common case when a node goes away.
        .http2_keep_alive_interval(Duration::from_secs(10))
        .keep_alive_timeout(Duration::from_secs(3))
}

/// Resolve `host`, build a balanced channel, and KEEP RESOLVING.
///
/// The refresh loop is the whole point. Resolving once pins the client to
/// whichever pods existed at startup: new replicas receive nothing, and a rolling
/// update leaves it talking to addresses that no longer exist. Under D68 that is
/// self-amplifying — the autoscaler adds pods that get no traffic, so the metric
/// does not move, so it adds more.
///
/// The task holds a `Sender` into the channel's discovery stream and lives as
/// long as the channel does; when the channel is dropped the send fails and the
/// loop exits, so there is no task leak.
pub async fn connect(host: &str, port: u16) -> Result<Channel, BalanceError> {
    let initial = resolve(host, port).await?;
    if initial.is_empty() {
        return Err(BalanceError::NoEndpoints {
            host: host.to_string(),
        });
    }
    tracing::info!(
        host,
        count = initial.len(),
        "balancing across task-db replicas"
    );

    let (channel, tx) = Channel::balance_channel::<SocketAddr>(initial.len().max(8));
    for addr in &initial {
        // Before any request is served: a channel with no endpoints yet would
        // fail the first calls while the loop caught up.
        let _ = tx.send(Change::Insert(*addr, endpoint(*addr))).await;
    }

    tokio::spawn(refresh(host.to_string(), port, initial, tx));
    Ok(channel)
}

/// The loop. Separate from `connect` so a failed resolution never takes down a
/// channel that is still serving: DNS blipping is not a reason to stop using
/// endpoints that currently work.
async fn refresh(
    host: String,
    port: u16,
    mut current: BTreeSet<SocketAddr>,
    tx: Sender<Change<SocketAddr, Endpoint>>,
) {
    loop {
        tokio::time::sleep(RERESOLVE).await;

        let resolved = match resolve(&host, port).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(host, error = %e, "re-resolution failed; keeping the current endpoints");
                continue;
            }
        };

        // An EMPTY result is not a reason to remove everything. A headless
        // Service briefly returns nothing during some rollouts, and acting on it
        // would take the client to zero endpoints and fail every request — a
        // self-inflicted outage from a transient DNS answer.
        if resolved.is_empty() {
            tracing::warn!(
                host,
                "re-resolution returned no addresses; keeping the current set"
            );
            continue;
        }

        if resolved == current {
            continue;
        }

        for change in diff(&current, &resolved) {
            let sent = match change {
                Change::Insert(addr, ()) => {
                    tracing::info!(%addr, "task-db endpoint added");
                    tx.send(Change::Insert(addr, endpoint(addr))).await
                }
                Change::Remove(addr) => {
                    tracing::info!(%addr, "task-db endpoint removed");
                    tx.send(Change::Remove(addr)).await
                }
            };
            // The receiver is gone, so the channel was dropped: stop rather than
            // spin forever against a dead sender.
            if sent.is_err() {
                tracing::debug!("channel dropped; ending re-resolution");
                return;
            }
        }
        current = resolved;
    }
}

async fn resolve(host: &str, port: u16) -> Result<BTreeSet<SocketAddr>, BalanceError> {
    let target = format!("{host}:{port}");
    let addrs = tokio::net::lookup_host(target.clone())
        .await
        .map_err(|source| BalanceError::Dns {
            host: target,
            source,
        })?;
    Ok(addrs.collect())
}

/// The interval at which endpoints are re-resolved. Exposed so a caller can log
/// it, and so "did anyone actually re-resolve?" is answerable from outside.
pub const fn reresolve_interval() -> Duration {
    RERESOLVE
}

#[derive(Debug, thiserror::Error)]
pub enum BalanceError {
    #[error(
        "DNS returned no addresses for {host}. For a headless Service this means \
         no ready endpoints — the -db replicas are down or failing readiness, \
         which under D69 includes failing their capability probe or migrations."
    )]
    NoEndpoints { host: String },

    #[error("could not resolve {host}: {source}")]
    Dns {
        host: String,
        #[source]
        source: std::io::Error,
    },
}
