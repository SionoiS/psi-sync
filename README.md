# psi-sync

Rust workspace with two complementary two-party set protocols:

| Crate | Role |
| --- | --- |
| `psi` | ECDH **private set intersection** on Ristretto |
| `reconciliation` | **Range-based set reconciliation** ([LIP-182 WAKU-SYNC](https://lip.logos.co/messaging/core/raw/sync.html)) |
| `examples` | In-process demos (`in_memory`, `reconcile`) |

They solve different problems. PSI hides exclusive items and returns only the intersection. Reconciliation finds the symmetric difference so two stores can converge; differing ranges **reveal identifiers**.

---

## `psi` (PSI)

Each party holds a private set of byte strings. After two message exchanges they both learn the SHA-512/256 identifiers of the items they share, and nothing else about the other set.

The protocol is ECDH-PSI on the [Ristretto](https://ristretto.group/) group (`curve25519-dalek` 4). Transport- and codec-agnostic.

### Flow

1. `PsiProtocol::new(&items)` — hash items, map to the curve (DST `psi-sync/v1`), blind with a fresh scalar.
2. Exchange `BlindedPointsMessage` from `message()`.
3. `compute(peer_msg)` — double-blind the peer’s points. Returns an intermediate state and a `DoubleBlindedPointsMessage`.
4. Exchange that second message. **Order is significant**: each returned point must correspond to the received point at the same index.
5. `finalize(peer_double)` — `PsiResult` with `intersection_hashes`.

Empty sets are valid. Duplicate items collapse. At most `MAX_ITEMS` (`1_048_576`) distinct items.

### Usage

```rust
use psi::{hash_bytes, PsiProtocol};

let alice_items = vec![b"apple".to_vec(), b"banana".to_vec()];
let bob_items = vec![b"banana".to_vec(), b"cherry".to_vec()];

let alice = PsiProtocol::new(&alice_items)?;
let bob = PsiProtocol::new(&bob_items)?;

let alice_msg = alice.message();
let bob_msg = bob.message();

let (alice_mid, alice_double) = alice.compute(bob_msg)?;
let (bob_mid, bob_double) = bob.compute(alice_msg)?;

let alice_result = alice_mid.finalize(bob_double)?;
let bob_result = bob_mid.finalize(alice_double)?;
assert_eq!(alice_result.len(), 1);

let banana = hash_bytes(b"banana");
assert!(alice_result.intersection_hashes.contains(&banana));
# Ok::<(), psi::PsiError>(())
```

A compressed Ristretto point is 32 bytes (`CompressedRistretto::to_bytes()`). There is no serde feature.

### PSI threat model

Honest-but-curious peers. The channel **must** be authenticated, confidential, and **order-preserving**. Set sizes leak. A malicious peer can lie. Intersection comparison is not constant-time.

---

## `reconciliation` (LIP-182 algorithm)

Range-based set reconciliation. Items are `SyncId { timestamp, hash }`, ordered by time then hash. The session is type-state (`Reconcile<Running>`), same idea as `PsiProtocol<S>`: `step` consumes `self`.

This crate implements **reconciliation only**, not a transfer protocol and not Waku message hashing (you supply the 32-byte hash). There is no cluster/shard scope — filter the store yourself.

### Flow

1. `Reconcile::initiate(&store, bounds)` sends one XOR **fingerprint** over the window.
2. Matching fingerprints become **Skip**. Small differing ranges become an **ItemSet**. Large ones are split (default 8-way time partition; hash-space fallback when timestamps collide).
3. Item sets are merge-walked. The first set has `reconciled = false`; the reply has `true`.
4. The side that produces an empty message returns `ReconcileStep::Done { farewell: Some(empty) }`. The peer `step`s that closer and finishes.

`codec` is optional and not used by the session. Cluster/shard bytes are written as zero and ignored on decode.

### Usage

```rust
use reconciliation::{RangeBounds, Reconcile, ReconcileStep, ReconcileStore, SyncId};

let mut alice = ReconcileStore::new(Default::default())?;
let mut bob = ReconcileStore::new(Default::default())?;
alice.insert(SyncId::new(1, [1u8; 32]))?;
bob.insert(SyncId::new(1, [1u8; 32]))?;
bob.insert(SyncId::new(2, [2u8; 32]))?;

let (a, first) = Reconcile::initiate(&alice, RangeBounds::window(0, 10)?)?;
let b = Reconcile::respond(&bob);
match b.step(first)? {
    ReconcileStep::Done { result, .. } => assert!(result.to_send.len() + result.to_recv.len() > 0),
    ReconcileStep::Next { message, .. } => {
        let _ = a.step(message)?;
    }
}
# Ok::<(), reconciliation::ReconcileError>(())
```

### Reconciliation threat model

Peers are trusted to follow the protocol. Fingerprints leak the XOR of hashes in a range. Item sets leak every `SyncId` in a differing range. A peer can Skip or invent IDs. Prefer an authenticated channel.

---

## Develop

```bash
cargo test --workspace
cargo test --doc -p psi
cargo test --doc -p reconciliation
cargo clippy --workspace --all-targets -- --deny warnings
cargo fmt --all -- --check
cargo run -p examples --bin in_memory
cargo run -p examples --bin reconcile
```

## License

Licensed under either of

- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT license (`LICENSE-MIT`)

at your option.
