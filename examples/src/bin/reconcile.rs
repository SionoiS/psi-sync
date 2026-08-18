//! In-memory LIP-182 reconciliation demo.
//!
//! Run with:
//! ```bash
//! cargo run -p examples --bin reconcile
//! ```

use reconciliation::{
    encode, RangeBounds, ReconcileRound, ReconcileSession, ReconcileStore, SyncId, SyncScope,
};
use rand::rngs::OsRng;
use rand::RngCore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Range-based set reconciliation (LIP-182) ===\n");

    let mut rng = OsRng;
    let mut alice_store = ReconcileStore::new(Default::default())?;
    let mut bob_store = ReconcileStore::new(Default::default())?;

    let mut shared = Vec::new();
    for _ in 0..20 {
        let id = random_id(&mut rng, 1_000, 2_000);
        alice_store.insert(id)?;
        bob_store.insert(id)?;
        shared.push(id);
    }
    for _ in 0..180 {
        alice_store.insert(random_id(&mut rng, 1_000, 2_000))?;
        bob_store.insert(random_id(&mut rng, 1_000, 2_000))?;
    }

    println!("Alice: {} items", alice_store.len());
    println!("Bob:   {} items", bob_store.len());
    println!("Shared (inserted): {}\n", shared.len());

    let bounds = RangeBounds::window(0, 10_000)?;
    let scope = SyncScope::any();
    let (mut alice, first) = ReconcileSession::initiate(&alice_store, bounds, scope.clone())?;
    let mut bob = ReconcileSession::respond_with_config(scope, &bob_store);

    println!("First payload: {} bytes\n", encode(&first).len());

    let mut incoming = first;
    let mut rounds = 0u32;
    let (alice_result, bob_result) = loop {
        rounds += 1;
        match bob.step(&bob_store, incoming)? {
            ReconcileRound::Continue(msg) => {
                println!(
                    "round {rounds}: Bob → Alice ({} ranges, {} bytes)",
                    msg.ranges.len(),
                    encode(&msg).len()
                );
                if msg.is_terminal() {
                    let ar = match alice.step(&alice_store, msg)? {
                        ReconcileRound::Done(r) => r,
                        ReconcileRound::Continue(_) => alice.into_result(),
                    };
                    break (ar, bob.into_result());
                }
                match alice.step(&alice_store, msg)? {
                    ReconcileRound::Continue(next) => {
                        println!(
                            "round {rounds}: Alice → Bob ({} ranges, {} bytes)",
                            next.ranges.len(),
                            encode(&next).len()
                        );
                        if next.is_terminal() {
                            let br = match bob.step(&bob_store, next)? {
                                ReconcileRound::Done(r) => r,
                                ReconcileRound::Continue(_) => bob.into_result(),
                            };
                            break (alice.into_result(), br);
                        }
                        incoming = next;
                    }
                    ReconcileRound::Done(ar) => break (ar, bob.into_result()),
                }
            }
            ReconcileRound::Done(br) => break (alice.into_result(), br),
        }
    };

    println!(
        "\nAlice to_send={} to_recv={}",
        alice_result.to_send.len(),
        alice_result.to_recv.len()
    );
    println!(
        "Bob   to_send={} to_recv={}",
        bob_result.to_send.len(),
        bob_result.to_recv.len()
    );

    assert_eq!(alice_result.to_send, bob_result.to_recv);
    assert_eq!(alice_result.to_recv, bob_result.to_send);
    println!("\nDiffs are complementary.");

    Ok(())
}

fn random_id(rng: &mut OsRng, t0: u64, t1: u64) -> SyncId {
    let mut hash = [0u8; 32];
    rng.fill_bytes(&mut hash);
    let span = t1.saturating_sub(t0).max(1);
    let timestamp = t0 + (u64::from_le_bytes(hash[0..8].try_into().unwrap()) % span);
    SyncId::new(timestamp, hash)
}
