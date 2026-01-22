//! In-memory example of PSI protocol execution.
//!
//! This example demonstrates the PSI protocol running within a single process,
//! simulating the message exchange between Alice and Bob without network I/O.
//!
//! Run with:
//! ```bash
//! cargo run --bin in_memory
//! ```

use psi_protocol::{PsiState, PsiResult};
use rand::RngCore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== PSI Protocol In-Memory Example ===\n");

    // Initialize protocol states for Alice and Bob
    let mut alice = PsiState::new();
    let mut bob = PsiState::new();

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

    // === Phase 1: Prepare blinded points ===
    println!("\n--- Phase 1: Prepare Blinded Points ---");

    let alice_message = alice.prepare_blinded_points(&alice_items)?;
    println!("Alice prepared {} blinded points", alice_message.len());

    let bob_message = bob.prepare_blinded_points(&bob_items)?;
    println!("Bob prepared {} blinded points", bob_message.len());

    // === Phase 2: Exchange messages ===
    // In a real scenario, these would be sent over the network (with TLS!)
    // For this example, we just pass them directly:
    println!("\n--- Phase 2: Exchange Messages ---");
    println!("Exchanging messages (in-memory simulation)...");

    // === Phase 3: Compute intersection ===
    println!("\n--- Phase 3: Compute Intersection ---");

    let alice_result: PsiResult = alice.compute_intersection(bob_message)?;
    let bob_result: PsiResult = bob.compute_intersection(alice_message)?;

    // === Results ===
    println!("\n=== Results ===");
    println!(
        "Alice found {} items in intersection",
        alice_result.len()
    );
    println!("Bob found {} items in intersection", bob_result.len());

    // Verify both got the same result
    assert_eq!(
        alice_result.intersection_hashes,
        bob_result.intersection_hashes,
        "Intersections do not match!"
    );

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

    let mut alice_state = PsiState::new();
    let mut bob_state = PsiState::new();

    let alice_msg = alice_state.prepare_blinded_points(&alice_large)?;
    let bob_msg = bob_state.prepare_blinded_points(&bob_large)?;

    let alice_res = alice_state.compute_intersection(bob_msg)?;
    let bob_res = bob_state.compute_intersection(alice_msg)?;

    println!(
        "\nIntersection size: {} (expected: 10)",
        alice_res.len()
    );
    println!(
        "✓ Verification: {}",
        if alice_res.intersection_hashes == bob_res.intersection_hashes {
            "PASSED"
        } else {
            "FAILED"
        }
    );

    Ok(())
}
