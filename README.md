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

## Dependencies

Deliberately minimal: `tonic`, `tokio`, `tracing`, and `rustls-pki-types` to
check the CA bundle with the same parser `tonic` will use on it. A crate every
service links makes its dependency tree everyone's. TLS uses `tls-ring` rather
than `tls-aws-lc`: every service that links this crate builds for
`x86_64-unknown-linux-musl` (D63), and `aws-lc-rs` wants cmake and a C toolchain
to get there.
