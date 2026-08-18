# psi-sync

Two-party [private set intersection](https://en.wikipedia.org/wiki/Private_set_intersection) in Rust.

Each party holds a private set of byte strings. After two message exchanges they both learn the SHA-512/256 identifiers of the items they share, and nothing else about the other set.

The protocol is ECDH-PSI on the [Ristretto](https://ristretto.group/) group (`curve25519-dalek` 4). The library is transport- and codec-agnostic: you serialize the two message types and send them on your own channel.

## Crate

| Crate | Role |
| --- | --- |
| `psi-protocol` | The library |
| `psi-examples` | In-process demo (`in_memory`) |

## Protocol

Both peers do the same thing:

1. `PsiProtocol::new(&items)` — hash items, map to the curve (DST `psi-sync/v1`), blind with a fresh scalar.
2. Exchange `BlindedPointsMessage` from `message()`.
3. `compute(peer_msg)` — double-blind the peer’s points. Returns an intermediate state and a `DoubleBlindedPointsMessage`.
4. Exchange that second message. **Order is significant**: each returned point must correspond to the received point at the same index.
5. `finalize(peer_double)` — `PsiResult` with `intersection_hashes`.

Empty sets are valid (intersection is empty). Duplicate items collapse. At most `MAX_ITEMS` (`1_048_576`) distinct items per set or incoming message.

## Usage

```rust
use psi_protocol::{hash_bytes, PsiProtocol};

let alice_items = vec![b"apple".to_vec(), b"banana".to_vec()];
let bob_items = vec![b"banana".to_vec(), b"cherry".to_vec()];

let alice = PsiProtocol::new(&alice_items)?;
let bob = PsiProtocol::new(&bob_items)?;

let alice_msg = alice.message();
let bob_msg = bob.message();
// send_to_peer(alice_msg);  // authenticated + confidential + order-preserving
// let bob_msg = recv_from_peer();

let (alice_mid, alice_double) = alice.compute(bob_msg)?;
let (bob_mid, bob_double) = bob.compute(alice_msg)?;
// exchange alice_double / bob_double the same way

let alice_result = alice_mid.finalize(bob_double)?;
let bob_result = bob_mid.finalize(alice_double)?;
assert_eq!(alice_result.len(), 1);

// Map identifiers back to local items.
let banana = hash_bytes(b"banana");
assert!(alice_result.intersection_hashes.contains(&banana));
# Ok::<(), psi_protocol::PsiError>(())
```

### Serializing messages

There is no serde feature. A compressed Ristretto point is 32 bytes:

```text
CompressedRistretto::to_bytes() -> [u8; 32]
CompressedRistretto([u8; 32])   // reconstruct; decompress is checked in compute()
```

A message is a length plus that many 32-byte encodings, in order.

## Threat model

Honest-but-curious (semi-honest) peers:

- The channel **must** be authenticated, confidential, and **order-preserving** (for example TLS). Reordering the second message can make a party attribute the intersection to the wrong local items.
- Set **sizes leak** (message lengths).
- A **malicious peer can lie** about its set and about the second message. There are no proofs of correct computation.
- Intersection comparison is not constant-time.

## Develop

```bash
cargo test --workspace
cargo test --doc -p psi-protocol
cargo clippy --workspace --all-targets -- --deny warnings
cargo fmt --all -- --check
cargo run -p psi-examples --bin in_memory
```

## License

Licensed under either of

- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT license (`LICENSE-MIT`)

at your option.
