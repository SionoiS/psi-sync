# psi-sync

Rust workspace with two complementary two-party set protocols and a crate that composes them:

| Crate | Role |
| --- | --- |
| `psi` | ECDH **private set intersection** on Ristretto |
| `reconciliation` | **Range-based set reconciliation** ([LIP-182 WAKU-SYNC](https://lip.logos.co/messaging/core/raw/sync.html)) |
| `topic-sync` | PSI on **topics**, then reconciliation on the **shared** topics' messages |
| `examples` | In-process demos (`in_memory`, `reconcile`, `topic_sync`) |

They solve different problems. PSI hides exclusive items and returns only the intersection. Reconciliation finds the symmetric difference so two stores can converge; differing ranges **reveal identifiers**. `topic-sync` runs PSI first so exclusive subscriptions never enter a reconcile ItemSet.

---

## `psi` (PSI)

Each party holds a private set of byte strings. After two message exchanges they both learn the identifiers of the items they share (first 32 bytes of SHA-512, **not** SHA-512/256), and nothing else about the other set.

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

Range-based set reconciliation over any totally ordered item type (`ReconcileItem`). The session is type-state (`Reconcile<Running>`), same idea as `PsiProtocol<S>`: `step` consumes `self`. Type parameters default to `SyncId { timestamp, hash }`, the LIP-182 identifier (ordered by time then hash, XOR-of-hashes fingerprint, time/hash-space splits). Other types need only `Ord` plus a fingerprint; they split ranges using local item values as cut points.

The local set is a **monoid tree** (Meyer, Algorithm 1): each AVL node stores the XOR fingerprint and size of its subtree, so a range fingerprint is a path walk rather than a scan. `TaggedStore` nests that tree into a 2-D range tree (tag × item). Query a single topic with `RectBounds::topic` — never a hash **interval** of topics, which would include exclusive subscriptions whose hashes fall between two shared ones. `topic-sync` still keeps per-topic stores and PSI for that reason.

This crate implements **reconciliation only**, not a transfer protocol and not Waku message hashing (you supply the 32-byte hash). There is no cluster/shard scope — filter the store yourself. `codec`, `RangeBounds::window`, and `prune_before` are `SyncId`-specific. The store is frozen for the life of a `Reconcile` session: do not insert or remove while it is running.

### Flow

1. `Reconcile::initiate(&store, bounds)` sends one XOR **fingerprint** over the window.
2. Matching fingerprints become **Skip**. Small differing ranges become an **ItemSet**. Large ones are split (default 8-way time partition; hash-space fallback when timestamps collide).
3. Item sets are merge-walked. The first set lists local items (`reconciled = false`); the reply has exclusive `elements` + `needed` and `reconciled = true`.
4. The side that produces an empty message returns `ReconcileStep::Done { farewell: Some(empty) }`. The peer `step`s that closer and finishes.

`codec` is optional and not used by the session. It encodes the session item-set shape (`elements` then `needed`) and is **not** Nwaku's ItemSet layout. Cluster/shard bytes are written as zero and ignored on decode.

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

Items that also have a tag (topic) live in `TaggedStore`. Reconcile a single topic with `RectBounds::topic`; a tag **interval** over hashed topics would include exclusive subscriptions and is not how `topic-sync` queries the store.

```rust
use reconciliation::{RangeBounds, RectBounds, TaggedStore, SyncId};

let mut store = TaggedStore::new(Default::default())?;
store.insert([0x11; 32], SyncId::new(1, [1u8; 32]))?;
let bounds = RectBounds::topic([0x11; 32], RangeBounds::window(0, 10)?)?;
assert_eq!(store.count(bounds), 1);
# Ok::<(), reconciliation::ReconcileError>(())
```

### Reconciliation threat model

Peers are trusted to follow the protocol. Fingerprints leak a digest of items in a range (XOR of hashes for `SyncId`). Equal XOR fingerprints are treated as equal ranges; a collision can hide a real difference. Item sets leak every identifier in a differing range. A peer can Skip or invent IDs. Prefer an authenticated channel.

---

## `topic-sync`

Two parties each hold a map of **topics** (opaque byte strings) to per-topic `ReconcileStore`s. After one session they both know:

1. Which topics they share (PSI). Exclusive topics stay hidden.
2. For each shared topic, which `SyncId`s to send and receive (LIP-182).

Payload transfer is still the caller's job. The time window is the same for every shared topic. Shared topics reconcile in parallel; `PsiDone.opening` and later `Reconcile` batches list frames in lexicographic PSI-hash order. Transport- and codec-agnostic. Stores are frozen for the life of a `TopicSync` session: do not insert or remove while it is running.

### Flow

1. `TopicSync::initiate(&stores, bounds)` sends blinded topic points.
2. The responder `step`s that into a `PsiOffer` (own blinded points + double-blind of the initiator).
3. The initiator `step`s the offer, finalizes PSI, and sends `PsiDone` — the double-blind plus one opening fingerprint per shared topic (`opening` is empty on empty intersection).
4. Each still-active shared topic runs an inner `Reconcile` in the same outer round. A finished topic is omitted from later batches. The inner LIP-182 empty closer is forwarded once as a frame so the peer can `step` it.
5. `SyncResult.topics` lists per-topic `to_send` / `to_recv`. Stores are not mutated.

Empty topic intersection is a successful no-op: no reconcile frames, no message IDs exchanged.

### Usage

```rust
use topic_sync::{RangeBounds, ReconcileStore, SyncId, TopicStores, TopicSync};

let mut alice = TopicStores::new();
let mut bob = TopicStores::new();
alice.insert(b"chat".to_vec(), ReconcileStore::new(Default::default())?)?;
bob.insert(b"chat".to_vec(), ReconcileStore::new(Default::default())?)?;
alice.get_mut(b"chat").unwrap().insert(SyncId::new(1, [1u8; 32]))?;

let bounds = RangeBounds::window(0, 10)?;
let (alice_sess, first) = TopicSync::initiate(&alice, bounds)?;
let bob_sess = TopicSync::respond(&bob, bounds)?;
let _ = (alice_sess, first, bob_sess);
# Ok::<(), topic_sync::TopicSyncError>(())
```

### Topic-sync threat model

Union of the two sub-protocols. Honest-but-curious peers; authenticated, confidential, **order-preserving** channel. Topic-set sizes leak. Shared topic **hashes** appear on reconcile frames; raw exclusive topic bytes do not. Message IDs in a differing range leak. XOR fingerprints can collide and hide a difference. A peer can lie about its topic set or Skip/invent IDs.

---

## Develop

```bash
cargo test --workspace
cargo test --doc -p psi
cargo test --doc -p reconciliation
cargo test --doc -p topic-sync
cargo clippy --workspace --all-targets -- --deny warnings
cargo fmt --all -- --check
cargo run -p examples --bin in_memory
cargo run -p examples --bin reconcile
cargo run -p examples --bin topic_sync
```

## License

Licensed under either of

- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT license (`LICENSE-MIT`)

at your option.
