//! The endpoint diff. Pure, so it is testable — which is the reason it was
//! extracted from the DNS loop at all.
//!
//! Every case here is a way to be wrong that still compiles and still looks like
//! working code in production.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use tonic::transport::channel::Change;
use yadgar_dial::diff;

fn set(addrs: &[&str]) -> BTreeSet<SocketAddr> {
    addrs.iter().map(|a| a.parse().unwrap()).collect()
}

fn classify(changes: &[Change<SocketAddr, ()>]) -> (Vec<String>, Vec<String>) {
    let mut ins = vec![];
    let mut rem = vec![];
    for c in changes {
        match c {
            Change::Insert(a, ()) => ins.push(a.to_string()),
            Change::Remove(a) => rem.push(a.to_string()),
        }
    }
    (ins, rem)
}

/// The case the whole loop exists for: the autoscaler adds a replica. Without
/// this, the new pod receives nothing and the metric never moves — so D68's HPA
/// adds another pod that also receives nothing.
#[test]
fn a_new_replica_is_inserted() {
    let changes = diff(
        &set(&["10.0.0.1:50051"]),
        &set(&["10.0.0.1:50051", "10.0.0.2:50051"]),
    );
    let (ins, rem) = classify(&changes);
    assert_eq!(ins, vec!["10.0.0.2:50051"]);
    assert!(rem.is_empty(), "an unchanged endpoint must not be touched");
}

/// A pod that went away. Leaving it in sends requests into a black hole.
#[test]
fn a_departed_replica_is_removed() {
    let changes = diff(
        &set(&["10.0.0.1:50051", "10.0.0.2:50051"]),
        &set(&["10.0.0.1:50051"]),
    );
    let (ins, rem) = classify(&changes);
    assert_eq!(rem, vec!["10.0.0.2:50051"]);
    assert!(ins.is_empty());
}

/// The steady state, and the one that matters most for churn: re-inserting an
/// unchanged endpoint on every tick tears down and rebuilds a working
/// connection every few seconds. It looks like working code.
#[test]
fn an_unchanged_set_produces_no_changes() {
    let s = set(&["10.0.0.1:50051", "10.0.0.2:50051"]);
    assert!(
        diff(&s, &s).is_empty(),
        "a stable set must produce no churn"
    );
}

/// A rolling update: every address replaced at once.
#[test]
fn a_full_replacement_removes_before_inserting() {
    let changes = diff(&set(&["10.0.0.1:50051"]), &set(&["10.0.0.9:50051"]));
    let (ins, rem) = classify(&changes);
    assert_eq!(rem, vec!["10.0.0.1:50051"]);
    assert_eq!(ins, vec!["10.0.0.9:50051"]);

    // ORDER, not decoration. Kubernetes reuses pod IPs, so an insert before the
    // matching remove can leave the balancer holding a stale entry under a key
    // it just re-added.
    assert!(
        matches!(changes.first(), Some(Change::Remove(_))),
        "removals must be applied before insertions"
    );
}

/// Scaling from zero — the -db was down and came back.
#[test]
fn recovering_from_an_empty_set_inserts_everything() {
    let changes = diff(
        &BTreeSet::new(),
        &set(&["10.0.0.1:50051", "10.0.0.2:50051"]),
    );
    let (ins, rem) = classify(&changes);
    assert_eq!(ins.len(), 2);
    assert!(rem.is_empty());
}
