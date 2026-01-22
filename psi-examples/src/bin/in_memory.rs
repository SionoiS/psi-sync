//! In-memory example of PSI protocol execution.
//!
//! This example demonstrates the PSI protocol running within a single process,
//! simulating the message exchange between Alice and Bob without network I/O.
//!
//! Run with:
//! ```bash
//! cargo run --bin in_memory
//! ```

use psi_protocol::{PsiProtocol, PsiResult};
use rand::RngCore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== PSI Protocol In-Memory Example ===\n");

    // Define Alice's private set
    let alice_items: Vec<Vec<u8>> = vec![
        b"alice_secret_1".to_vec(),
        b"shared_secret_1".to_vec(),
        b"alice_secret_2".to_vec(),
        b"shared_secret_2".to_vec(),
    ];

    // Define Bob's private set
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

    // === Phase 1: Initialize protocol and prepare blinded points ===
    println!("\n--- Phase 1: Initialize Protocol ---");

    let alice = PsiProtocol::new(&alice_items)?;
    println!("Alice initialized with {} items", alice_items.len());

    let bob = PsiProtocol::new(&bob_items)?;
    println!("Bob initialized with {} items", bob_items.len());

    // === Phase 2: Exchange messages ===
    // In a real scenario, these would be sent over the network (with TLS!)
    // For this example, we just pass them directly:
    println!("\n--- Phase 2: Exchange Messages ---");
    println!("Exchanging messages (in-memory simulation)...");

    let alice_message = alice.message();
    let bob_message = bob.message();

    // === Phase 3: Compute double-blinded points ===
    println!("\n--- Phase 3: Compute Double-Blinded Points ---");

    let (alice_intermediate, alice_double_message) = alice.compute(bob_message)?;
    let (bob_intermediate, bob_double_message) = bob.compute(alice_message)?;

    // === Phase 4: Exchange double-blinded messages ===
    println!("\n--- Phase 4: Exchange Double-Blinded Messages ---");
    println!("Exchanging double-blinded messages (in-memory simulation)...");

    // === Phase 5: Finalize and compute intersection ===
    println!("\n--- Phase 5: Finalize and Compute Intersection ---");

    let (_alice_final, alice_result): (_, PsiResult) = alice_intermediate.finalize(bob_double_message)?;
    let (_bob_final, bob_result): (_, PsiResult) = bob_intermediate.finalize(alice_double_message)?;

    // === Results ===
    println!("\n=== Results ===");
    println!(
        "Alice found {} items in intersection",
        alice_result.len()
    );
    println!("Bob found {} items in intersection", bob_result.len());

    // Verify both got the same result (convert to sets since order may differ)
    let alice_set: std::collections::HashSet<_> = alice_result.intersection_hashes.iter().collect();
    let bob_set: std::collections::HashSet<_> = bob_result.intersection_hashes.iter().collect();
    assert_eq!(alice_set, bob_set, "Intersections do not match!");

    println!("\nIntersection items:");
    for (i, hash) in alice_result.intersection_hashes.iter().enumerate() {
        // Find the original item (for demonstration only - in practice,
        // you wouldn't be able to reverse the hash)
        let matching_item = alice_items
            .iter()
            .find(|item| {
                // Re-hash to find which item this corresponds to
                use sha2::{Digest, Sha512};
                let mut hasher = Sha512::new();
                hasher.update(item);
                let result = hasher.finalize();
                let mut h = [0u8; 32];
                h.copy_from_slice(&result[..32]);
                &h == hash
            })
            .unwrap();

        println!(
            "  {}: {} (hash: {:?})",
            i + 1,
            String::from_utf8_lossy(matching_item),
            &hash[..8] // Show first 8 bytes of hash
        );
    }

    println!("\n✓ Protocol completed successfully!");
    println!("✓ Both parties computed the same intersection");
    println!("✓ No information about non-intersecting items was revealed");

    // === Additional example: Large random sets ===
    println!("\n\n=== Large Random Sets Example ===\n");

    let mut rng = rand::rngs::OsRng;
    let mut alice_large = Vec::new();
    let mut bob_large = Vec::new();

    // Generate 100 random items each, plus 10 common items
    println!("Generating random datasets...");

    for _ in 0..100 {
        let mut alice_bytes = [0u8; 32];
        rng.fill_bytes(&mut alice_bytes);
        alice_large.push(alice_bytes.to_vec());

        let mut bob_bytes = [0u8; 32];
        rng.fill_bytes(&mut bob_bytes);
        bob_large.push(bob_bytes.to_vec());
    }

    // Add 10 common items
    for _ in 0..10 {
        let mut common = [0u8; 32];
        rng.fill_bytes(&mut common);
        alice_large.push(common.to_vec());
        bob_large.push(common.to_vec());
    }

    println!("Alice: {} items, Bob: {} items", alice_large.len(), bob_large.len());

    let alice_proto = PsiProtocol::new(&alice_large)?;
    let bob_proto = PsiProtocol::new(&bob_large)?;

    let alice_msg = alice_proto.message();
    let bob_msg = bob_proto.message();

    let (alice_int, alice_double) = alice_proto.compute(bob_msg)?;
    let (bob_int, bob_double) = bob_proto.compute(alice_msg)?;

    let (_alice_fin, alice_res) = alice_int.finalize(bob_double)?;
    let (_bob_fin, bob_res) = bob_int.finalize(alice_double)?;

    println!(
        "\nIntersection size: {} (expected: 10)",
        alice_res.len()
    );
    // Compare as sets since order may differ
    let alice_set: std::collections::HashSet<_> = alice_res.intersection_hashes.iter().collect();
    let bob_set: std::collections::HashSet<_> = bob_res.intersection_hashes.iter().collect();
    println!(
        "✓ Verification: {}",
        if alice_set == bob_set {
            "PASSED"
        } else {
            "FAILED"
        }
    );

    Ok(())
}
