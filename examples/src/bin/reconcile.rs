//! In-memory range-based reconciliation demo.
//!
//! Run with:
//! ```bash
//! cargo run -p examples --bin reconcile
//! ```

use rand::rngs::OsRng;
use rand::RngCore;
use sync::{
    codec, RangeBounds, Reconcile, ReconcileMessage, ReconcileResult, ReconcileStep,
    ReconcileStore, SyncId,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Range-based set reconciliation ===\n");

    let mut rng = OsRng;
    let mut alice_store = ReconcileStore::new(Default::default())?;
    let mut bob_store = ReconcileStore::new(Default::default())?;

    let mut shared = 0usize;
    for _ in 0..20 {
        let id = random_id(&mut rng, 1_000, 2_000);
        alice_store.insert(id)?;
        bob_store.insert(id)?;
        shared += 1;
    }
    for _ in 0..180 {
        alice_store.insert(random_id(&mut rng, 1_000, 2_000))?;
        bob_store.insert(random_id(&mut rng, 1_000, 2_000))?;
    }

    println!("Alice: {} items", alice_store.len());
    println!("Bob:   {} items", bob_store.len());
    println!("Shared (inserted): {shared}\n");

    let bounds = RangeBounds::window(0, 10_000)?;
    let (alice, first) = Reconcile::initiate(&alice_store, bounds)?;
    let bob = Reconcile::respond(&bob_store);

    println!("First message: {} bytes\n", codec::encode(&first).len());

    let (alice_result, bob_result) = run(alice, bob, first)?;

    println!(
        "Alice to_send={} to_recv={}",
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

fn run<'a>(
    mut alice: Reconcile<'a, sync::Running>,
    mut bob: Reconcile<'a, sync::Running>,
    mut incoming: ReconcileMessage,
) -> Result<(ReconcileResult, ReconcileResult), sync::ReconcileError> {
    let mut rounds = 0u32;
    loop {
        rounds += 1;
        match bob.step(incoming)? {
            ReconcileStep::Next { next, message } => {
                println!(
                    "round {rounds}: Bob → Alice ({} ranges, {} bytes)",
                    message.ranges.len(),
                    codec::encode(&message).len()
                );
                bob = next;
                match alice.step(message)? {
                    ReconcileStep::Next { next, message } => {
                        println!(
                            "round {rounds}: Alice → Bob ({} ranges, {} bytes)",
                            message.ranges.len(),
                            codec::encode(&message).len()
                        );
                        alice = next;
                        incoming = message;
                    }
                    ReconcileStep::Done { result, farewell } => {
                        return Ok((result, close(bob, farewell)?));
                    }
                }
            }
            ReconcileStep::Done { result, farewell } => {
                return Ok((close(alice, farewell)?, result));
            }
        }
    }
}

fn close(
    session: Reconcile<'_, sync::Running>,
    farewell: Option<ReconcileMessage>,
) -> Result<ReconcileResult, sync::ReconcileError> {
    let msg = farewell.unwrap_or_else(ReconcileMessage::empty);
    match session.step(msg)? {
        ReconcileStep::Done { result, .. } => Ok(result),
        ReconcileStep::Next { .. } => panic!("closer must finish the session"),
    }
}

fn random_id(rng: &mut OsRng, t0: u64, t1: u64) -> SyncId {
    let mut hash = [0u8; 32];
    rng.fill_bytes(&mut hash);
    let span = t1.saturating_sub(t0).max(1);
    let timestamp = t0 + (u64::from_le_bytes(hash[0..8].try_into().unwrap()) % span);
    SyncId::new(timestamp, hash)
}
