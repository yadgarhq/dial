# dial — how a service reaches another service

Client-side gRPC balancing over a headless Kubernetes Service (D23), and nothing
else.

## Why it is its own crate

It began as `task/src/balance.rs`. When the gateway became `task`'s first gRPC
client it needed exactly the same logic, and the invariant is that anything every
service needs is implemented once — duplication is not mainly wasted effort, it
is the mechanism by which two services quietly disagree.

## What it solves

gRPC runs on HTTP/2 and holds **one** long-lived connection. An ordinary
Kubernetes Service balances at L4, at connection time, so a client opens one
connection, gets one pod, and sends every request there for the life of the
process. The other replicas sit idle while looking perfectly healthy — and D68's
autoscaler answers the resulting latency by adding more pods that also receive
nothing.

So the callee's Service is **headless**: DNS returns every pod address, and the
caller balances across them itself.

**Re-resolution is the half that gets forgotten.** Resolving once at startup pins
the client to whichever pods existed then: new replicas get no traffic, and a
rolling update leaves the client holding addresses that no longer exist.

## Using it

```rust
let channel = yadgar_dial::connect("task-db", 50051).await?;
```

The callee's Service must be headless (`clusterIP: None`). Against a Service with
a virtual IP this still works and still balances nothing — which is the failure
worth knowing about, because it looks identical from the outside.

## TLS

`connect` dials in cleartext, and always has. On the single-node development
cluster that is invisible; on a shared cluster with a flat pod network it is a
bearer token anyone on that network can read. `connect_tls` is the same dialling,
encrypted, with the peer verified:

```rust
let tls = yadgar_dial::TlsOptions::new("/etc/tls/ca.crt");
let channel = yadgar_dial::connect_tls("task-db", 50051, &tls).await?;
```

**It is opt-in, and that is deliberate.** The code ships first; turning it on for
a given caller is a separate change that can be reverted on its own.

**The certificate is verified against the host, not against the address dialled.**
This is the part that is easy to get wrong. `dial` resolves a host to a set of pod
addresses and balances across them, so the obvious implementation checks the
server's certificate against an IP — which needs an IP SAN no issuer grants per
pod, and whose usual "fix" is to stop checking. The verification domain is pinned
to the host the caller asked for instead, so a certificate issued for the Service
name works while the balancer goes on talking to pod IPs. Pass
`TlsOptions::domain_name` when the certificate names something else.

**Configuration is file paths, never an issuer-specific resource** (D80). The
reference deployment has cert-manager write the CA bundle; a Secret assembled by
hand on EKS produces a file this crate cannot tell apart. Nothing here names
cert-manager, an ingress implementation or a cloud.

**A misconfiguration fails, it does not downgrade.** An unreadable bundle, an
undecodable one, and one that decodes to no certificate at all are errors
returned from `connect_tls`. There is no path through it that yields a cleartext
channel, and the platform trust store is never added beside the bundle.

Server TLS with client-side verification is what exists today. Presenting a
**client** certificate — mutual TLS — is two more paths on `TlsOptions` and does
not change `connect_tls`.

## Timeouts

Three bounds, on three different things:

| bound                 | what it catches                                                     |
| --------------------- | ------------------------------------------------------------------- |
| connect timeout (2s)  | a TCP connect that does not complete                                |
| HTTP/2 keepalive      | a peer that **vanished** without closing its connection             |
| request timeout (30s) | a peer that is alive, connected, answering pings, and never replies |

**The third one is the one that gets left out.** The first two look like they
cover everything, and they do not: a `-db` blocked on its engine completes its
connect, answers every keepalive ping, and holds each caller's handler open for
as long as it stays blocked. That is also why a `tcpSocket` readiness probe
stays green straight through such an outage — the same defect seen from the
other end.

`connect` and `connect_tls` apply the default. A caller that needs its own
passes one:

```rust
let channel =
    yadgar_dial::connect_with_request_timeout("task-db", 50051, Duration::from_secs(5)).await?;
```

**It is a backstop, not the caller's deadline.** A caller that sets a gRPC
deadline (`Request::set_timeout`) still gets that deadline when it is shorter —
tonic applies whichever of the two is smaller. What this adds is the other side
of that comparison, so a caller with a long deadline, or with none at all,
cannot leave a request open indefinitely on a peer that stopped answering. A
caller that bounds the call some other way, such as `tokio::time::timeout`, is
not talking to this mechanism at all: the two run independently, and whichever
expires first ends that caller's wait.

**The default is 30s, chosen against the deadlines already in this system.** It
sits above every deadline a caller set on purpose — the longest is `gateway`'s
10s for a login, sized for the Argon2id `iam` pays on every attempt — so it
never pre-empts a number somebody chose for a real call. It sits below 60s, the
conventional idle timeout of an ingress and of most HTTP clients, so it fires
while somebody is still waiting for the answer.

**Both paths carry the same bound**, set at one call site from one argument, so
`connect` and `connect_tls` have nothing to drift apart about. The one timeout
the TLS path carries alone is the handshake bound in `TlsOptions`, and it bounds
a different thing: tonic's connect timeout covers the TCP connect only, while
the handshake runs in the layer above it.

What the bound does **not** cover, so it is not mistaken for more than it is: a
peer that sends response headers and then stalls its body, because the bound is
on the wait for the response to begin; and a request that has not been handed to
a connection yet because no endpoint is ready, which is the balancer's readiness
one layer up.

## Dependencies

Deliberately minimal: `tonic`, `tokio`, `tracing`, and `rustls-pki-types` to
check the CA bundle with the same parser `tonic` will use on it. A crate every
service links makes its dependency tree everyone's. TLS uses `tls-ring` rather
than `tls-aws-lc`: every service that links this crate builds for
`x86_64-unknown-linux-musl` (D63), and `aws-lc-rs` wants cmake and a C toolchain
to get there.
