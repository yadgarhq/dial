//! Entry points, and the boot dial: build a seeded [`Channel`] and hand its
//! discovery `Sender` to [`crate::resolve::refresh`].
//!
//! Split out of `lib.rs` by LEDGER 719; nothing here changed.

use std::collections::BTreeSet;
use std::net::{Ipv6Addr, SocketAddr};
use std::time::Duration;

use tonic::transport::channel::Change;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

use crate::error::BalanceError;
use crate::resolve::{refresh, resolve};
use crate::tls::TlsOptions;
use crate::{report_never_resolved, CONNECT_TIMEOUT, REQUEST_TIMEOUT};

/// Which peer an entry in the balancer is.
///
/// **`Unresolved` is the whole of the laziness.** A balanced channel holding no
/// endpoints is not a channel that connects later — `Balance::poll_ready`
/// returns `Poll::Pending` while its ready set is empty, and nothing in this
/// crate is above that, so a request handed to one waits for ever. So the
/// channel is never given nothing: until an address resolves it holds ONE
/// endpoint dialling the NAME, which is exactly what `gateway`'s `connect_iam`
/// does with `Endpoint::connect_lazy` and the reason that hop never crash-looped.
///
/// Every endpoint tonic puts in a balancer is a `Connection::lazy`
/// (`tonic-0.14.6/src/transport/channel/service/discover.rs:39`), and a lazy
/// connection whose connect fails reports itself READY and returns the failure
/// from the request instead (`.../service/reconnect.rs`, the `is_lazy` branch).
/// So this entry costs a fast, named error per request rather than a hang, and
/// the next request retries the connect.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum Peer {
    /// The host NAME, dialled while no resolution has answered.
    Unresolved,
    /// A pod address, from a resolution that answered.
    Address(SocketAddr),
}

/// `host` and `port` as a URI AUTHORITY, which is not the same string as
/// `host` and `port` as a resolver target.
///
/// **An IPv6 LITERAL has to be bracketed, and a name must not be.**
/// `::1:50051` is a perfectly good target — `lookup_host` splits it at its last
/// colon — and it is not a valid authority at all, so `Endpoint::from_shared`
/// refuses it. The distinction never arose while every endpoint was built from
/// a resolved `SocketAddr`, whose `Display` brackets a v6 address for free. The
/// seed is built from the HOST, so it has to do that itself, or a literal that
/// dialled perfectly well before becomes `InvalidHost`.
///
/// Nothing in this estate dials a literal today: all three consumers pass a
/// Service name out of the environment. That is a reason to get it right here
/// rather than a reason to leave it.
pub(crate) fn authority(host: &str, port: u16) -> String {
    match host.parse::<Ipv6Addr>() {
        Ok(literal) => format!("[{literal}]:{port}"),
        Err(_) => format!("{host}:{port}"),
    }
}

/// One endpoint, at `authority`.
///
/// **`authority` IS A STRING RATHER THAN A `SocketAddr` BECAUSE TWO DIFFERENT
/// THINGS ARE DIALLED HERE.** The steady state is a pod address. The other is
/// the NAME itself, dialled while no resolution has answered yet — see [`Peer`]
/// — and a name is not a `SocketAddr`. ONE builder serves both, so the scheme,
/// the timeouts and the keepalive cannot come to differ between the endpoint
/// that serves the first seconds of a process's life and the ones that serve
/// the rest of it.
///
/// That is also why the URI parse is an ERROR rather than the `expect` it used
/// to be: a socket address always forms an authority, and a host out of a
/// deployment's environment does not.
pub(crate) fn endpoint(
    authority: &str,
    tls: Option<&ClientTlsConfig>,
    request_timeout: Duration,
) -> Result<Endpoint, BalanceError> {
    // THE SCHEME IS WHAT SWITCHES TLS ON, not the presence of a configuration.
    // tonic's connector tests `uri.scheme_str() == Some("https")` and, for an
    // `http://` URI, connects in cleartext while holding a perfectly good TLS
    // configuration it never consults. So the two are decided together, here,
    // and cannot drift apart.
    let scheme = if tls.is_some() { "https" } else { "http" };
    let endpoint = Endpoint::from_shared(format!("{scheme}://{authority}"))
        .map_err(|_| BalanceError::InvalidHost {
            host: authority.to_string(),
        })?
        // A dead pod must not hold a request open until the caller's deadline.
        // tonic applies this to the TCP connect alone: it is set on the inner
        // HTTP connector, while the TLS handshake runs in the layer above it. A
        // peer that accepts the connection and then stalls the handshake would
        // otherwise be unbounded, so `TlsOptions::prepare` gives the handshake
        // the SAME bound explicitly. A stalled peer therefore costs at most two
        // of these, not one — which is the one place the TLS path differs from
        // the cleartext path, stated rather than left to be discovered.
        .connect_timeout(CONNECT_TIMEOUT)
        // HTTP/2 keepalive notices a pod that vanished without closing its
        // connection — the common case when a node goes away.
        .http2_keep_alive_interval(Duration::from_secs(10))
        .keep_alive_timeout(Duration::from_secs(3))
        // THE BOUND ON A PEER THAT IS SIMPLY SILENT, which neither of the two
        // above covers. See `REQUEST_TIMEOUT` for the reason a healthy-looking
        // connection needs one at all.
        //
        // ONE bound, BOTH paths: this call site is reached identically whether
        // or not `tls` is set, so there is nothing for the cleartext and TLS
        // paths to drift apart about. The handshake bound in
        // `TlsOptions::prepare` stays the one timeout the TLS path carries
        // alone, and it bounds a different thing — see the note above.
        .timeout(request_timeout);

    match tls {
        None => Ok(endpoint),
        Some(tls) => endpoint
            .tls_config(tls.clone())
            .map_err(|source| BalanceError::Tls { source }),
    }
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
/// long as the channel does. It ends by POLLING `Sender::is_closed` at the top of
/// every tick, and naming the mechanism matters: this paragraph used to say the
/// loop ended because "the send fails", which was false on the two commonest
/// ticks. A stable endpoint set and an empty resolution both skip the send
/// entirely, so a loop that learned of a dropped channel only from a failed send
/// never learned of it at all and re-resolved a dead channel's host for the life
/// of the process.
///
/// The bound is ONE `RERESOLVE` tick rather than instant: the task is asleep when
/// the channel is dropped, and notices when it next wakes.
///
/// **THIS DOES NOT FAIL BECAUSE `host` DOES NOT RESOLVE.** A name with no
/// Service behind it yet is an ordering accident, not a reason to take the
/// caller's process down, and the channel returned serves requests by dialling
/// the name until an address answers — see "The boot dial" on the crate. What
/// still fails here is a host that cannot form a URI authority, which no
/// resolution would fix.
///
/// Requests are bounded by [`default_request_timeout`]. A caller that needs its
/// own bound uses [`connect_with_request_timeout`].
pub async fn connect(host: &str, port: u16) -> Result<Channel, BalanceError> {
    connect_with(host, port, None, REQUEST_TIMEOUT).await
}

/// [`connect`], with the caller's own per-request bound instead of the default.
///
/// **It is a BACKSTOP, not the caller's deadline, and the two are not the same
/// thing.** A caller that sets a gRPC deadline — `tonic::Request::set_timeout`,
/// which travels as the `grpc-timeout` header — still gets that deadline when
/// it is SHORTER: tonic applies whichever of the two is smaller. What this adds
/// is the other side of that comparison, so a caller with a long deadline, or
/// with none at all, cannot leave a request open indefinitely on a peer that
/// has stopped answering. A caller that bounds the call some other way, such as
/// wrapping it in `tokio::time::timeout` — which is what `gateway` does today —
/// is not talking to this mechanism at all: the two run independently, and
/// whichever expires first ends that caller's wait.
///
/// **What it does not cover, said rather than left to be discovered.** The
/// bound is on the wait for the response to BEGIN — the future it wraps yields
/// the response head — so a peer that sends headers and then stalls its body is
/// not caught by it. Nor is a request that has not been handed to a connection
/// yet because no endpoint is ready; that is the balancer's readiness, one
/// layer up, and NOTHING in this crate bounds it. That is why the channel is
/// never handed back with an empty endpoint set — see "The boot dial" on the
/// crate — rather than something this bound could be stretched to cover.
pub async fn connect_with_request_timeout(
    host: &str,
    port: u16,
    request_timeout: Duration,
) -> Result<Channel, BalanceError> {
    connect_with(host, port, None, request_timeout).await
}

/// [`connect`], with the transport encrypted and the peer verified.
///
/// Everything about the balancing is identical — the same resolution, the same
/// refresh loop, the same timeouts. What changes is that the connection is TLS
/// and the server's certificate is checked against `host` rather than against
/// the address the balancer dialled.
///
/// **It fails rather than degrades.** A CA bundle that cannot be read, cannot be
/// decoded, contains no certificate, or yields no usable trust anchor is an error
/// returned from here, before any channel exists. There is no path through this
/// function that produces a cleartext channel.
///
/// **An absent upstream is not one of those**, on this path exactly as on
/// [`connect`]'s: a name that does not resolve yet is dialled lazily rather than
/// returned as an error, and the endpoint that serves the window carries this
/// same configuration. The seam a misconfiguration could slip through is the
/// one `endpoint` closes by deciding the scheme and the TLS configuration in a
/// single expression, for the name and for a pod address alike.
///
/// Server TLS with client-side verification is what this provides by default.
/// Presenting a CLIENT certificate — mutual TLS — is [`TlsOptions::identity`]
/// on the options passed in, and changes nothing about this signature.
pub async fn connect_tls(host: &str, port: u16, tls: &TlsOptions) -> Result<Channel, BalanceError> {
    connect_tls_with_request_timeout(host, port, tls, REQUEST_TIMEOUT).await
}

/// [`connect_tls`], with the caller's own per-request bound instead of the
/// default.
///
/// The bound is the same one [`connect_with_request_timeout`] applies, set at
/// the same place, and everything said there about a caller's own deadline
/// holds here unchanged. Encryption does not move it.
pub async fn connect_tls_with_request_timeout(
    host: &str,
    port: u16,
    tls: &TlsOptions,
    request_timeout: Duration,
) -> Result<Channel, BalanceError> {
    // BEFORE the DNS lookup, deliberately. A misconfigured bundle is the
    // operator's mistake and should be reported as itself, not shadowed by
    // whatever the resolver says about a host they were never going to reach.
    let prepared = tls.prepare(host)?;
    connect_with(host, port, Some(prepared), request_timeout).await
}

pub(crate) async fn connect_with(
    host: &str,
    port: u16,
    tls: Option<ClientTlsConfig>,
    request_timeout: Duration,
) -> Result<Channel, BalanceError> {
    // BUILT FIRST, AND UNCONDITIONALLY, for two separate reasons.
    //
    // It is what the channel is seeded with when nothing resolves, and it is
    // also the only place a host that cannot be dialled AT ALL is caught. Doing
    // it here rather than only on the empty path means an unusable name is an
    // error on every call, not on the calls where DNS happened to fail too.
    let seed = endpoint(&authority(host, port), tls.as_ref(), request_timeout)?;

    // ATTEMPTED, NO LONGER DEPENDED ON — and the distinction is the change.
    //
    // The resolution still happens here and is still bounded by
    // `RESOLVE_TIMEOUT`, because the steady state is worth keeping: a `-db` that
    // is already up produces a balancer full of pod addresses before the first
    // request, with no window at all. What went away is the `?`. A name that
    // does not resolve is an upstream that is not there YET — the Service is
    // created seconds after the Deployment that dials it — and exiting on it
    // costs a cold start of exponential backoff and spends the restart count
    // that would otherwise have shown a real crash.
    let initial = match resolve(host, port).await {
        Ok(resolved) if !resolved.is_empty() => resolved,
        Ok(_) => {
            tracing::warn!(
                host,
                port,
                tls = tls.is_some(),
                "the upstream resolved to no addresses at startup; dialling the name until it \
                 does. Under D69 this is a -db whose replicas are down or failing readiness."
            );
            BTreeSet::new()
        }
        Err(e) => {
            tracing::warn!(
                host,
                port,
                tls = tls.is_some(),
                error = %e,
                "the upstream is not resolvable at startup; dialling the name until it is. \
                 This is not a boot failure: the Service usually appears seconds later."
            );
            BTreeSet::new()
        }
    };

    // EVERY endpoint is built BEFORE the channel exists. Building them inside
    // the send loop would let a late failure return an error after earlier
    // endpoints had already been pushed into a balancer no caller will ever
    // receive. `connect_tls` promises that a configuration error is reported
    // before a channel exists, and that should hold by construction rather than
    // by the accident that nothing in `endpoint` depends on the address.
    let built = initial
        .iter()
        .map(|addr| {
            Ok((
                *addr,
                endpoint(&addr.to_string(), tls.as_ref(), request_timeout)?,
            ))
        })
        .collect::<Result<Vec<_>, BalanceError>>()?;

    let (channel, tx) = Channel::balance_channel::<Peer>(built.len().max(8));

    // `tls` is recorded because "is this connection encrypted?" must be
    // answerable from the logs of the process doing the connecting. The
    // cut-over is a separate change from this one, and an operator has to be
    // able to see which side of it a given pod is on.
    let seeded = built.is_empty();
    // BEFORE THE FIRST TICK, AND BOTH WAYS. The window this reports opens here
    // and the refresh loop's first tick is `RERESOLVE` away, so a gauge first
    // written there is silent for the five seconds that matter most — and a
    // gauge written only on the unhealthy path never exists on a healthy pod,
    // which makes `> 0` unable to tell health from an unlinked crate.
    report_never_resolved(host, seeded);
    if seeded {
        // THE CHANNEL IS NEVER GIVEN NOTHING. See `Peer` for why an empty
        // balancer is a hang rather than a wait.
        let _ = tx.send(Change::Insert(Peer::Unresolved, seed)).await;
        tracing::info!(
            host,
            tls = tls.is_some(),
            "dialling the name until an address resolves"
        );
    } else {
        tracing::info!(
            host,
            count = built.len(),
            tls = tls.is_some(),
            "balancing across replicas"
        );
        for (addr, built) in built {
            // Before any request is served: a channel with no endpoints yet
            // would fail the first calls while the loop caught up.
            let _ = tx.send(Change::Insert(Peer::Address(addr), built)).await;
        }
    }

    tokio::spawn(refresh(
        Target {
            host: host.to_string(),
            port,
            tls,
            request_timeout,
        },
        initial,
        seeded,
        tx,
        // The production resolver. `refresh` takes it as a parameter rather
        // than calling `resolve` itself — see there for why the seam exists.
        |host, port| async move { resolve(&host, port).await },
    ));
    Ok(channel)
}

/// What a dial IS, independent of which addresses it currently reaches.
///
/// A struct rather than four more arguments because the four travel together
/// everywhere and mean nothing apart: `refresh` needs all of them on every tick
/// to rebuild an endpoint, and a rebuild that used a different `tls` or a
/// different `request_timeout` from the boot dial would be the silent drift
/// this crate exists to prevent.
pub(crate) struct Target {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) tls: Option<ClientTlsConfig>,
    pub(crate) request_timeout: Duration,
}
