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

## Dependencies

Deliberately minimal: `tonic`, `tokio`, `tracing`. A crate every service links
makes its dependency tree everyone's.
