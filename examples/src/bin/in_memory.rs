//! In-memory example of PSI protocol execution.
//!
//! This example runs both parties in one process and passes messages by
//! value. A real deployment must exchange the same two messages on an
//! authenticated, confidential, order-preserving channel (for example TLS).
//!
//! Run with:
//! ```bash
//! cargo run -p examples --bin in_memory
//! ```

use psi::{hash_bytes, PsiProtocol, PsiResult};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashSet;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== PSI Protocol In-Memory Example ===\n");

    let alice_items: Vec<Vec<u8>> = vec![
        b"alice_secret_1".to_vec(),
        b"shared_secret_1".to_vec(),
        b"alice_secret_2".to_vec(),
        b"shared_secret_2".to_vec(),
    ];

    let bob_items: Vec<Vec<u8>> = vec![
        b"bob_secret_1".to_vec(),
        b"shared_secret_1".to_vec(),
        b"bob_secret_2".to_vec(),
        b"shared_secret_2".to_vec(),
    ];

    println!("Alice's items ({}):", alice_items.len());
    for (i, item) in alice_items.iter().enumerate() {
        println!("  {}: {}", i + 1, String::from_utf8_lossy(item));
    }

    println!("\nBob's items ({}):", bob_items.len());
    for (i, item) in bob_items.iter().enumerate() {
        println!("  {}: {}", i + 1, String::from_utf8_lossy(item));
    }

    println!("\n--- Phase 1: Initialize Protocol ---");

    let alice = PsiProtocol::new(&alice_items)?;
    println!("Alice initialized with {} items", alice_items.len());

    let bob = PsiProtocol::new(&bob_items)?;
    println!("Bob initialized with {} items", bob_items.len());

    println!("\n--- Phase 2: Exchange Messages ---");
    println!("Exchanging messages (in-memory simulation)...");

    let alice_message = alice.message();
    let bob_message = bob.message();

    println!("\n--- Phase 3: Compute Double-Blinded Points ---");

    let (alice_mid, alice_double) = alice.compute(bob_message)?;
    let (bob_mid, bob_double) = bob.compute(alice_message)?;

    println!("\n--- Phase 4: Exchange Double-Blinded Messages ---");
    println!("Exchanging double-blinded messages (in-memory simulation)...");

    println!("\n--- Phase 5: Finalize and Compute Intersection ---");

    let alice_result: PsiResult = alice_mid.finalize(bob_double)?;
    let bob_result: PsiResult = bob_mid.finalize(alice_double)?;

    println!("\n=== Results ===");
    println!("Alice found {} items in intersection", alice_result.len());
    println!("Bob found {} items in intersection", bob_result.len());

    let alice_set: HashSet<_> = alice_result.intersection_hashes.iter().collect();
    let bob_set: HashSet<_> = bob_result.intersection_hashes.iter().collect();
    assert_eq!(alice_set, bob_set, "Intersections do not match!");

    println!("\nIntersection items:");
    for (i, hash) in alice_result.intersection_hashes.iter().enumerate() {
        let matching_item = alice_items
            .iter()
            .find(|item| hash_bytes(item) == *hash)
            .expect("intersection hash must come from a local item");

        println!(
            "  {}: {} (hash: {:02x?}...)",
            i + 1,
            String::from_utf8_lossy(matching_item),
            &hash[..8]
        );
    }

    println!("\nProtocol completed successfully.");
    println!("Both parties computed the same intersection.");
    println!("Non-intersecting items were not revealed.");

    println!("\n\n=== Large Random Sets Example ===\n");

    let mut rng = OsRng;
    let mut alice_large = Vec::new();
    let mut bob_large = Vec::new();

    println!("Generating random datasets...");

    for _ in 0..100 {
        let mut alice_bytes = [0u8; 32];
        rng.fill_bytes(&mut alice_bytes);
        alice_large.push(alice_bytes.to_vec());

        let mut bob_bytes = [0u8; 32];
        rng.fill_bytes(&mut bob_bytes);
        bob_large.push(bob_bytes.to_vec());
    }

    for _ in 0..10 {
        let mut common = [0u8; 32];
        rng.fill_bytes(&mut common);
        alice_large.push(common.to_vec());
        bob_large.push(common.to_vec());
    }

    println!(
        "Alice: {} items, Bob: {} items",
        alice_large.len(),
        bob_large.len()
    );

    let alice_proto = PsiProtocol::new(&alice_large)?;
    let bob_proto = PsiProtocol::new(&bob_large)?;

    let alice_msg = alice_proto.message();
    let bob_msg = bob_proto.message();

    let (alice_int, alice_double) = alice_proto.compute(bob_msg)?;
    let (bob_int, bob_double) = bob_proto.compute(alice_msg)?;

    let alice_res = alice_int.finalize(bob_double)?;
    let bob_res = bob_int.finalize(alice_double)?;

    println!("\nIntersection size: {} (expected: 10)", alice_res.len());
    let alice_set: HashSet<_> = alice_res.intersection_hashes.iter().collect();
    let bob_set: HashSet<_> = bob_res.intersection_hashes.iter().collect();
    assert_eq!(alice_set, bob_set);
    assert_eq!(alice_res.len(), 10);

    println!("Verification: PASSED");

    Ok(())
}
