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

use std::collections::BTreeSet;
use std::future::Future;
use std::net::{Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use tokio::sync::mpsc::Sender;
// tonic re-exports its OWN Change. Importing tower::discover::Change directly
// compiles and then fails to match: the two are distinct types even at the same
// tower version, and the error reads "expected Change, found a different Change".
use tonic::transport::channel::Change;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

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

/// Per-service TLS: a CA bundle on disk, and the name to verify against.
///
/// **Paths and a name, deliberately — never an issuer-specific resource** (D80).
/// The reference deployment has cert-manager write these files; an operator on
/// EKS assembling a Secret by hand produces something this crate cannot tell
/// apart, and neither can be named here without making one platform a
/// requirement.
///
/// **The verification domain defaults to the host being dialled, and that is the
/// whole point.** `dial` balances across pod ADDRESSES, so a certificate is
/// verified against the Service name the caller asked for rather than against
/// whichever IP the balancer happens to have picked. [`TlsOptions::domain_name`]
/// overrides it for the case where the certificate names something else — a
/// per-namespace FQDN, say — and is not needed otherwise.
///
/// **Mutual TLS is a configuration addition, not a redesign**, and
/// [`TlsOptions::identity`] is it: two more paths, no change to
/// [`connect_tls`]'s signature. It is OFF unless set, so every caller that
/// says nothing about it dials exactly as it did before.
#[derive(Clone, Debug)]
pub struct TlsOptions {
    ca_certificate: PathBuf,
    domain_name: Option<String>,
    identity: Option<ClientIdentity>,
}

/// The certificate a caller presents to prove WHO IT IS, and its private key.
///
/// The two paths live together rather than as two `Option`s because one
/// without the other is not a configuration, it is a mistake — and a shape that
/// cannot express the mistake needs no check for it.
#[derive(Clone, Debug)]
struct ClientIdentity {
    certificate: PathBuf,
    key: PathBuf,
}

impl TlsOptions {
    /// Verify the peer against the certificate authorities in the PEM bundle at
    /// `ca_certificate`.
    ///
    /// The file is read and checked when [`connect_tls`] runs, not here.
    pub fn new(ca_certificate: impl Into<PathBuf>) -> Self {
        Self {
            ca_certificate: ca_certificate.into(),
            domain_name: None,
            identity: None,
        }
    }

    /// Verify the peer's certificate against `domain_name` instead of against
    /// the host passed to [`connect_tls`].
    pub fn domain_name(self, domain_name: impl Into<String>) -> Self {
        Self {
            domain_name: Some(domain_name.into()),
            ..self
        }
    }

    /// Present `certificate`, proved by `key`, so the peer can authenticate
    /// this caller — mutual TLS (ADR-0516).
    ///
    /// **This is the CALLER's identity, and it is a different certificate from
    /// the one the caller SERVES.** Every internal service is both, so the two
    /// are easy to confuse and the consequence of confusing them is not an
    /// error: a serving certificate is issued for `server auth`, a peer
    /// verifies a client chain for `client auth`, and a leaf that names the
    /// wrong purpose is refused at the handshake by a server that trusts its
    /// issuer perfectly well. That separation is what lets one authority issue
    /// both, and `tests/tls.rs` holds it as a property rather than a comment.
    ///
    /// **THE SEPARATION IS BETWEEN NAMED PURPOSES, AND ONLY THOSE.** webpki
    /// checks `client auth` as `required_if_present`, so a leaf carrying no
    /// extended-key-usage extension is accepted — and that is the shape
    /// cert-manager issues when `usages` is omitted. One authority is therefore
    /// safe only while it never issues a leaf without a purpose. `tests/tls.rs`
    /// pins that as an accepted gap rather than a guarantee.
    ///
    /// **Paths, never an issuer-specific resource** (D80), for the reason given
    /// on [`TlsOptions`]. Both files are read when [`connect_tls`] runs.
    ///
    /// NOTHING VERIFIES WHAT THE CERTIFICATE SAYS THE CALLER IS. A peer that
    /// checks a client certificate learns that this deployment issued it, not
    /// which service is on the other end — distinguishing callers needs a check
    /// against the name in the certificate, and no such check exists in this
    /// estate today.
    pub fn identity(self, certificate: impl Into<PathBuf>, key: impl Into<PathBuf>) -> Self {
        Self {
            identity: Some(ClientIdentity {
                certificate: certificate.into(),
                key: key.into(),
            }),
            ..self
        }
    }

    /// Read and CHECK the CA bundle, and settle the verification domain.
    ///
    /// Everything that can be wrong about the configuration is wrong here, once,
    /// before a channel exists — so a bad path is a startup error rather than an
    /// unexplained handshake failure much later, and never a quiet downgrade.
    fn prepare(&self, host: &str) -> Result<ClientTlsConfig, BalanceError> {
        let pem =
            std::fs::read(&self.ca_certificate).map_err(|source| BalanceError::CaUnreadable {
                path: self.ca_certificate.clone(),
                source,
            })?;

        // THE ASSERTION THIS FUNCTION EXISTS FOR. The PEM reader yields nothing
        // — rather than an error — for input that contains no certificate
        // section, so "parsed successfully" can mean "parsed nothing", and a
        // trust store with no roots trusts nobody. Left unchecked that surfaces
        // as a handshake failure against a hostname the operator has never seen,
        // which is among the hardest errors here to diagnose.
        let certificates = CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| BalanceError::CaUnparsable {
                path: self.ca_certificate.clone(),
                source,
            })?;
        if certificates.is_empty() {
            return Err(BalanceError::CaEmpty {
                path: self.ca_certificate.clone(),
            });
        }

        // AND THE ASSERTION A SECTION COUNT CANNOT MAKE. The check above counts
        // PEM SECTIONS. What has to be non-empty is the ROOT STORE, and the two
        // part company for a bundle whose sections decode as PEM and then fail
        // to parse as a trust anchor — a key pasted under a CERTIFICATE header,
        // a truncated DER body. tonic hands exactly these DERs to
        // `add_parsable_certificates` and DISCARDS its `(accepted, rejected)`
        // return with no check after it
        // (`tonic-0.14.6/src/transport/channel/service/tls.rs:104`), so such a
        // bundle yields precisely the rootless trust store this function exists
        // to prevent, and the section count sees a healthy `1`.
        //
        // The store is built HERE, the way tonic will build it, and then
        // dropped: tonic accepts a PEM bundle rather than a store, so what this
        // buys is the answer to "how many roots will that produce", asked before
        // a channel exists instead of never.
        let sections = certificates.len();
        let mut roots = rustls::RootCertStore::empty();
        let (accepted, _rejected) = roots.add_parsable_certificates(certificates);
        if accepted == 0 {
            return Err(BalanceError::CaNoTrustAnchor {
                path: self.ca_certificate.clone(),
                sections,
            });
        }

        let mut configured = ClientTlsConfig::new()
            // The host, NOT the address that gets dialled.
            .domain_name(self.domain_name.as_deref().unwrap_or(host))
            .ca_certificate(Certificate::from_pem(&pem))
            // See `endpoint` for why the handshake needs its own bound.
            .timeout(CONNECT_TIMEOUT);

        // READ HERE, with the bundle, for the same reason: a mount that did not
        // happen is the operator's mistake and is reported as itself, naming
        // the file, rather than as a connection the peer closed without saying
        // why.
        //
        // THERE IS NO EMPTY-FILE CHECK TO MATCH `CaEmpty`, and the asymmetry is
        // deliberate rather than an omission. An empty CA bundle parses to a
        // trust store with no roots and fails much later; an empty client chain
        // is refused where rustls builds the configuration, and reaches the
        // caller as `Tls` from `endpoint` — observed as
        // `NoCertificatesPresented` — before any channel exists. Neither dials.
        // `tests/tls.rs` asserts that VARIANT rather than merely that it fails,
        // so a future tonic that accepted an empty chain and dialled anonymously
        // would be caught rather than pass for the wrong reason.
        if let Some(identity) = &self.identity {
            let certificate = std::fs::read(&identity.certificate).map_err(|source| {
                BalanceError::ClientCertificateUnreadable {
                    path: identity.certificate.clone(),
                    source,
                }
            })?;
            let key = std::fs::read(&identity.key).map_err(|source| {
                BalanceError::ClientKeyUnreadable {
                    path: identity.key.clone(),
                    source,
                }
            })?;
            configured = configured.identity(Identity::from_pem(certificate, key));
        }

        Ok(configured)
        // NOTE the two methods NOT called here: `with_native_roots` and
        // `with_webpki_roots`. Either would add the platform's trust store
        // alongside the bundle, so a CA that failed to load would leave the
        // peer verified against public roots instead — the silent downgrade
        // this change exists to remove, reintroduced one layer up.
    }
}

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
enum Peer {
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
fn authority(host: &str, port: u16) -> String {
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
fn endpoint(
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

async fn connect_with(
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
struct Target {
    host: String,
    port: u16,
    tls: Option<ClientTlsConfig>,
    request_timeout: Duration,
}

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
async fn refresh<R, F>(
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

        for change in diff(&current, &resolved) {
            match change {
                Change::Insert(addr, ()) => {
                    // Defensive: the configuration was already accepted once in
                    // `connect_tls`, and nothing here depends on the address, so
                    // this cannot fail for one pod and succeed for another. It
                    // is written out anyway because the wrong recovery — adding
                    // the endpoint in cleartext — is the exact downgrade this
                    // module exists to prevent, and it must not be reachable
                    // even by accident.
                    let built = match endpoint(&addr.to_string(), tls.as_ref(), request_timeout) {
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
                        tracing::debug!(host, "channel dropped; ending re-resolution");
                        return;
                    }
                    current.insert(addr);
                    tracing::info!(host, %addr, "endpoint added");
                }
                Change::Remove(addr) => {
                    if tx.send(Change::Remove(Peer::Address(addr))).await.is_err() {
                        tracing::debug!(host, "channel dropped; ending re-resolution");
                        return;
                    }
                    current.remove(&addr);
                    tracing::info!(host, %addr, "endpoint removed");
                }
            }
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
    }
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
fn still_absent(host: &str, nothing_given_yet: bool, why: std::fmt::Arguments<'_>) {
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

async fn resolve(host: &str, port: u16) -> Result<BTreeSet<SocketAddr>, BalanceError> {
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
async fn bounded_lookup<I, F>(
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

#[derive(Debug, thiserror::Error)]
pub enum BalanceError {
    #[error(
        "resolving {host} did not finish within {after:?}. This is NOT a name \
         that does not exist — that answers, and answers quickly. It is a \
         resolver that stopped answering at all, and the caller is released \
         rather than left waiting with no end. The lookup itself runs on the \
         blocking pool and cannot be cancelled: that thread stays parked until \
         the resolver replies."
    )]
    DnsTimedOut { host: String, after: Duration },

    #[error(
        "{host} cannot be dialled at all: it does not form a URI authority. This \
         is NOT an upstream that is absent — no resolution will ever fix it — so \
         it is reported before a channel exists rather than deferred to a lazy \
         dial that could never succeed."
    )]
    InvalidHost { host: String },

    #[error("could not resolve {host}: {source}")]
    Dns {
        host: String,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "could not read the CA certificate bundle at {path}: {source}. TLS was \
         requested, so this is an error rather than a reason to connect in \
         cleartext."
    )]
    CaUnreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("could not decode the CA certificate bundle at {path}: {source}")]
    CaUnparsable {
        path: PathBuf,
        #[source]
        source: rustls_pki_types::pem::Error,
    },

    #[error(
        "the CA certificate bundle at {path} decoded without error but contains \
         no certificate. That is not the same as a missing file: the PEM reader \
         returns an empty list for input with no certificate section, so an \
         empty or truncated bundle would otherwise produce a trust store with \
         no roots — which trusts nobody and fails much later, at the handshake."
    )]
    CaEmpty { path: PathBuf },

    #[error(
        "the CA certificate bundle at {path} holds {sections} PEM certificate \
         section(s) and NONE of them is a usable trust anchor. That is not the \
         same as an empty bundle: the sections are present and they decode as \
         PEM, so counting them says the file is fine. tonic builds its root \
         store with `add_parsable_certificates`, which reports how many it \
         accepted and how many it threw away, and discards that report — so a \
         bundle like this one produces a trust store with no roots and no error, \
         and fails much later, at the handshake."
    )]
    CaNoTrustAnchor { path: PathBuf, sections: usize },

    #[error(
        "could not read the client certificate at {path}: {source}. A client \
         certificate was configured, so this is an error rather than a reason \
         to connect without presenting one."
    )]
    ClientCertificateUnreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "could not read the client private key at {path}: {source}. A client \
         certificate without its key proves nothing, so this is an error rather \
         than a reason to connect without presenting one."
    )]
    ClientKeyUnreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("TLS could not be configured: {source}")]
    Tls {
        #[source]
        source: tonic::transport::Error,
    },
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;

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
    ) -> impl Fn(String, u16) -> std::future::Ready<Result<BTreeSet<SocketAddr>, BalanceError>>
    {
        move |_host, _port| std::future::ready(Ok(set.clone()))
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
}
