//! TCP-based PSI protocol example.
//!
//! This example demonstrates how to use PSI with a TCP transport layer.
//! It shows a simple client-server protocol for exchanging blinded points.
//!
//! Run server:
//! ```bash
//! cargo run --bin tcp_sync -- server
//! ```
//!
//! Run client (in another terminal):
//! ```bash
//! cargo run --bin tcp_sync -- client
//! ```

use psi_protocol::PsiState;
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};

const ADDRESS: &str = "127.0.0.1:7878";

/// Message format for TCP exchange
#[derive(Debug)]
#[allow(dead_code)]
enum ProtocolMessage {
    BlindedPoints(Vec<Vec<u8>>),
}

/// Serialize blinded points to JSON for network transmission
fn serialize_blinded_points(message: &psi_protocol::BlindedPointsMessage) -> String {
    // Simple serialization: count followed by hex-encoded (hash, point) pairs
    let mut result = format!("{}\n", message.items.len());
    for (hash, point) in &message.items {
        result.push_str(&format!("{}\n", hex::encode(hash)));
        result.push_str(&format!("{}\n", hex::encode(point.to_bytes())));
    }
    result
}

/// Deserialize blinded points from network transmission
fn deserialize_blinded_points(
    s: &str,
) -> Result<psi_protocol::BlindedPointsMessage, Box<dyn std::error::Error>> {
    use curve25519_dalek::ristretto::CompressedRistretto;
    let mut lines = s.lines();
    let count: usize = lines.next().ok_or("Missing count")?.parse()?;
    let mut items = Vec::new();
    for _ in 0..count {
        let hash_line = lines.next().ok_or("Missing hash")?;
        let hash_bytes = hex::decode(hash_line)?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_bytes);

        let point_line = lines.next().ok_or("Missing point")?;
        let point_bytes = hex::decode(point_line)?;
        let mut point_array = [0u8; 32];
        point_array.copy_from_slice(&point_bytes);
        let point = CompressedRistretto(point_array);

        items.push((hash, point));
    }
    Ok(psi_protocol::BlindedPointsMessage::new(items))
}

/// Run the server (Bob)
fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== PSI TCP Server ===");
    println!("Listening on {}", ADDRESS);

    let listener = TcpListener::bind(ADDRESS)?;
    println!("Waiting for client connection...");

    let (mut stream, addr) = listener.accept()?;
    println!("Connected to {}", addr);

    // Define server's private set
    let bob_items: Vec<Vec<u8>> = vec![
        b"bob_secret_1".to_vec(),
        b"shared_item_1".to_vec(),
        b"bob_secret_2".to_vec(),
        b"shared_item_2".to_vec(),
        b"bob_secret_3".to_vec(),
    ];

    println!("\nServer's items ({}):", bob_items.len());
    for (i, item) in bob_items.iter().enumerate() {
        println!("  {}: {}", i + 1, String::from_utf8_lossy(item));
    }

    // === Phase 1: Prepare blinded points ===
    println!("\n--- Phase 1: Prepare Blinded Points ---");
    let mut bob_state = PsiState::new();
    let bob_message = bob_state.prepare_blinded_points(&bob_items)?;
    println!("Prepared {} blinded points", bob_message.len());

    // === Phase 2: Exchange messages ===
    println!("\n--- Phase 2: Exchange Messages ---");

    // Receive client's blinded points
    println!("Receiving client's blinded points...");
    let mut reader = BufReader::new(&stream);
    let mut buffer = String::new();
    let mut line_count = 0;
    loop {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            break;
        }
        buffer.push_str(&line);
        line_count += 1;
        if line_count > 1 && line_count % 2 == 0 {
            // Read count + all points
            break;
        }
    }
    let alice_message = deserialize_blinded_points(&buffer)?;
    println!(
        "Received {} blinded points from client",
        alice_message.len()
    );

    // Send server's blinded points
    println!("Sending server's blinded points...");
    let bob_serialized = serialize_blinded_points(&bob_message);
    stream.write_all(bob_serialized.as_bytes())?;
    println!("Sent {} blinded points", bob_message.len());

    // === Phase 3: Compute intersection ===
    println!("\n--- Phase 3: Compute Intersection ---");
    let bob_result = bob_state.compute_intersection(alice_message)?;
    println!("Server computed intersection: {} items", bob_result.len());

    // === Results ===
    println!("\n=== Results ===");
    println!("Server intersection size: {}", bob_result.len());

    // Try to decode and display the intersection items
    println!("\nIntersection items (server side):");
    for (i, hash) in bob_result.intersection_hashes.iter().enumerate() {
        // Find the original item
        let matching_item = bob_items.iter().find(|item| {
            use sha2::{Digest, Sha512};
            let mut hasher = Sha512::new();
            hasher.update(item);
            let result = hasher.finalize();
            let mut h = [0u8; 32];
            h.copy_from_slice(&result[..32]);
            &h == hash
        });

        if let Some(item) = matching_item {
            println!("  {}: {}", i + 1, String::from_utf8_lossy(item));
        } else {
            println!("  {}: [hash not found in server's set]", i + 1);
        }
    }

    println!("\n✓ Server protocol completed!");

    Ok(())
}

/// Run the client (Alice)
fn run_client() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== PSI TCP Client ===");
    println!("Connecting to {}", ADDRESS);

    let mut stream = TcpStream::connect(ADDRESS)?;
    println!("Connected to server");

    // Define client's private set
    let alice_items: Vec<Vec<u8>> = vec![
        b"alice_secret_1".to_vec(),
        b"shared_item_1".to_vec(),
        b"alice_secret_2".to_vec(),
        b"shared_item_2".to_vec(),
        b"alice_secret_3".to_vec(),
    ];

    println!("\nClient's items ({}):", alice_items.len());
    for (i, item) in alice_items.iter().enumerate() {
        println!("  {}: {}", i + 1, String::from_utf8_lossy(item));
    }

    // === Phase 1: Prepare blinded points ===
    println!("\n--- Phase 1: Prepare Blinded Points ---");
    let mut alice_state = PsiState::new();
    let alice_message = alice_state.prepare_blinded_points(&alice_items)?;
    println!("Prepared {} blinded points", alice_message.len());

    // === Phase 2: Exchange messages ===
    println!("\n--- Phase 2: Exchange Messages ---");

    // Send client's blinded points
    println!("Sending client's blinded points...");
    let alice_serialized = serialize_blinded_points(&alice_message);
    stream.write_all(alice_serialized.as_bytes())?;
    println!("Sent {} blinded points", alice_message.len());

    // Receive server's blinded points
    println!("Receiving server's blinded points...");
    let mut reader = BufReader::new(&stream);
    let mut buffer = String::new();
    let mut line_count = 0;
    loop {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            break;
        }
        buffer.push_str(&line);
        line_count += 1;
        if line_count > 1 && line_count % 2 == 0 {
            break;
        }
    }
    let bob_message = deserialize_blinded_points(&buffer)?;
    println!("Received {} blinded points from server", bob_message.len());

    // === Phase 3: Compute intersection ===
    println!("\n--- Phase 3: Compute Intersection ---");
    let alice_result = alice_state.compute_intersection(bob_message)?;
    println!("Client computed intersection: {} items", alice_result.len());

    // === Results ===
    println!("\n=== Results ===");
    println!("Client intersection size: {}", alice_result.len());

    // Try to decode and display the intersection items
    println!("\nIntersection items (client side):");
    for (i, hash) in alice_result.intersection_hashes.iter().enumerate() {
        // Find the original item
        let matching_item = alice_items.iter().find(|item| {
            use sha2::{Digest, Sha512};
            let mut hasher = Sha512::new();
            hasher.update(item);
            let result = hasher.finalize();
            let mut h = [0u8; 32];
            h.copy_from_slice(&result[..32]);
            &h == hash
        });

        if let Some(item) = matching_item {
            println!("  {}: {}", i + 1, String::from_utf8_lossy(item));
        } else {
            println!("  {}: [hash not found in client's set]", i + 1);
        }
    }

    println!("\n✓ Client protocol completed!");

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <server|client>", args[0]);
        eprintln!("\nRun server first: {} server", args[0]);
        eprintln!("Then run client: {} client", args[0]);
        std::process::exit(1);
    }

    match args[1].as_str() {
        "server" => run_server(),
        "client" => run_client(),
        _ => {
            eprintln!("Unknown mode: {}", args[1]);
            eprintln!("Usage: {} <server|client>", args[0]);
            std::process::exit(1);
        }
    }
}
