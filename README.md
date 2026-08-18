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

## `reconciliation` (LIP-182)

Range-based set reconciliation. Items are [`SyncId`](https://lip.logos.co/messaging/core/raw/sync.html) `{ timestamp, hash }`, ordered by time then hash. Peers exchange `RangesData` until they agree on `to_send` / `to_recv`.

This crate implements **reconciliation only**, not the LIP transfer protocol and not Waku message hashing (you supply the 32-byte hash).

### Flow

1. `ReconcileSession::initiate(store, bounds, scope)` sends one XOR **fingerprint** over the window.
2. Matching fingerprints become **Skip**. Small differing ranges become an **ItemSet**. Large ones are split (default 8-way time partition; hash-space fallback when timestamps collide).
3. Item sets are merge-walked. The first set has `reconciled = false`; the reply has `true` so both sides learn the difference without a transfer protocol.
4. An empty range list ends the session.

`codec::encode` / `decode` implement LIP LEB128 + range deltas. The first range’s lower **timestamp** is written explicitly (Nwaku). The LIP wording that the first lower bound is `SyncID(0,0)` would drop a sliding window start; this crate does not do that. There is no libp2p length-prefix.

### Usage

```rust
use reconciliation::{
    RangeBounds, ReconcileRound, ReconcileSession, ReconcileStore, SyncId, SyncScope,
};

let mut alice = ReconcileStore::new(Default::default())?;
let mut bob = ReconcileStore::new(Default::default())?;
alice.insert(SyncId::new(1, [1u8; 32]))?;
bob.insert(SyncId::new(1, [1u8; 32]))?;
bob.insert(SyncId::new(2, [2u8; 32]))?;

let (mut a, first) =
    ReconcileSession::initiate(&alice, RangeBounds::window(0, 10)?, SyncScope::any())?;
let mut b = ReconcileSession::respond(SyncScope::any());
let mut incoming = first;
let result = loop {
    match b.step(&bob, incoming)? {
        ReconcileRound::Continue(msg) => {
            if msg.is_terminal() {
                break match a.step(&alice, msg)? {
                    ReconcileRound::Done(r) => r,
                    ReconcileRound::Continue(_) => a.into_result(),
                };
            }
            match a.step(&alice, msg)? {
                ReconcileRound::Continue(next) => incoming = next,
                ReconcileRound::Done(r) => break r,
            }
        }
        ReconcileRound::Done(r) => break r,
    }
};
assert_eq!(result.to_recv.len(), 1);
# Ok::<(), reconciliation::ReconcileError>(())
```

### Reconciliation threat model

LIP-182 treats peers as **fully trusted**. Fingerprints leak the XOR of hashes in a range. Item sets leak every `SyncId` in a differing range. A peer can Skip or invent IDs. Prefer an authenticated channel. Cluster/shard mismatch yields an empty payload.

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
