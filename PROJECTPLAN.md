# Production-Ready PSI Implementation Plan

## Overview
Transform the prototype ECDH-PSI implementation into a production-ready, transport-agnostic Rust library organized as a workspace.

## Requirements Summary
- **Input**: Byte arrays (Vec<u8>)
- **Output**: Intersection of private sets
- **Transport**: Agnostic (user handles message exchange)
- **Serialization**: Agnostic (well-formed structs, user chooses format)
- **Peer Model**: Symmetric peer-to-peer

## Workspace Structure

```
psi-sync/
├── Cargo.toml                          # Workspace root
├── src/lib.rs                          # [DELETE - moving to crate]
│
├── psi-protocol/                       # Core PSI protocol crate
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                      # Public API exports
│       ├── protocol.rs                 # PsiState implementation
│       ├── crypto.rs                   # Hashing & crypto operations
│       ├── messages.rs                 # Message type definitions
│       ├── state.rs                    # Protocol state management
│       └── error.rs                    # Error types
│
└── psi-examples/                       # Example usage (optional)
    ├── Cargo.toml
    └── src/
        └── bin/
            ├── in_memory.rs            # Example: in-memory protocol
            └── tcp_sync.rs             # Example: TCP transport
```

## Core Data Structures

### 1. Message Types (`psi-protocol/src/messages.rs`)
```rust
/// Message containing blinded points sent to peer
pub struct BlindedPointsMessage {
    /// Blinded points (compressed Ristretto points)
    pub blinded_points: Vec<CompressedRistretto>,
}

/// Final result of PSI protocol
pub struct PsiResult {
    /// Hashes of elements in the intersection
    pub intersection_hashes: Vec<[u8; 32]>,
    /// Double-blinded points mapped to intersection hashes
    pub double_blinded_map: HashMap<[u8; 32], CompressedRistretto>,
}
```

### 2. Protocol State (`psi-protocol/src/state.rs`)
```rust
/// State for one side of the PSI protocol
pub struct PsiState {
    secret: Scalar,
    hash_to_blinded: HashMap<[u8; 32], CompressedRistretto>,
    hash_to_double_blinded: HashMap<[u8; 32], CompressedRistretto>,
}
```

### 3. Error Types (`psi-protocol/src/error.rs`)
```rust
pub enum PsiError {
    EmptyInput,
    InvalidBlindedPoints(String),
    CryptoError(String),
}
```

## Protocol Flow (Symmetric)

Both peers follow identical steps:

**Phase 1: Prepare (Local)**
```rust
let mut state = PsiState::new();
let items = vec![b"apple".to_vec(), b"banana".to_vec()];
let message = state.prepare_blinded_points(&items)?;
```

Internal steps:
1. Generate random secret scalar
2. Hash input items: Vec<u8> → [u8; 32] using SHA-512
3. Convert hashes to RistrettoPoints via hash-to-curve
4. Blind points: secret * point
5. Compress to CompressedRistretto
6. Store mappings in state

**Phase 2: Exchange (User-Handled)**
```rust
// User serializes and sends via their preferred transport
// send_to_peer(message);
// let peer_message = receive_from_peer();
```

**Phase 3: Compute (Local)**
```rust
let result = state.compute_intersection(peer_message)?;
```

Internal steps:
1. Decompress peer's blinded points
2. Double-blind: own_secret * peer_point
3. Find matching double-blinded points
4. Build intersection result
5. Return intersection hashes and mapping

## Public API

**psi-protocol/src/lib.rs**
```rust
pub use protocol::{PsiState, PsiResult};
pub use messages::{BlindedPointsMessage};
pub use error::{PsiError, Result};

impl PsiState {
    pub fn new() -> Self;
    pub fn prepare_blinded_points(&mut self, items: &[Vec<u8>]) -> Result<BlindedPointsMessage>;
    pub fn compute_intersection(&mut self, peer_blinded: BlindedPointsMessage) -> Result<PsiResult>;
}
```

## Implementation Steps

### Step 1: Create Workspace Structure
- Transform `Cargo.toml` into workspace root
- Create `psi-protocol/Cargo.toml`
- Create directory structure
- Move existing code to new structure

### Step 2: Implement Message Types
- Create `messages.rs` with `BlindedPointsMessage` and `PsiResult`
- Note: Use `CompressedRistretto` directly (no serde yet)
- Add unit tests for message types

### Step 3: Implement Cryptographic Operations
- Create `crypto.rs` with hashing logic
- Extract from current `ecdh_psi` function
- Hash function: Vec<u8> → SHA-512 → first 32 bytes
- Hash-to-curve: Use existing `RistrettoPoint::hash_from_bytes::<Sha512>`

### Step 4: Implement Protocol State
- Create `state.rs` with `PsiState` struct
- Implement `new()` - generate secret, initialize empty maps
- Add helper methods for internal state management

### Step 5: Implement Core Protocol Logic
- Create `protocol.rs` with `PsiState` methods:
  - `prepare_blinded_points()`: Hash inputs, blind points, create message
  - `compute_intersection()`: Double-blind peer points, find matches
- Extract/refactor from current `ecdh_psi` function

### Step 6: Implement Error Handling
- Create `error.rs` with `PsiError` enum
- Add error variants: EmptyInput, InvalidBlindedPoints, CryptoError
- Update protocol methods to return `Result<T>`

### Step 7: Create Public API
- Create `lib.rs` with re-exports
- Export: PsiState, PsiResult, BlindedPointsMessage, PsiError, Result
- Add module-level documentation

### Step 8: Add Tests
- Migrate existing test to new API
- Add unit tests for each module
- Add integration test for full protocol
- Test edge cases: empty input, single element, large sets

### Step 9: Create Examples
- In-memory example (migrate current test)
- TCP example showing transport layer pattern

### Step 10: Update Documentation
- Update CLAUDE.md with new structure
- Update README with usage examples
- Document API changes

## Dependencies

**psi-protocol/Cargo.toml:**
```toml
[package]
name = "psi-protocol"
version = "0.2.0"
edition = "2021"

[dependencies]
curve25519-dalek = { version = "4", features = ["rand_core", "digest"] }
sha2 = "0.10"
rand = "0.8"
thiserror = "1.0"  # For error handling

[dev-dependencies]
# For examples only (not in core protocol)
serde = { version = "1.0", features = ["derive"], optional = true }
serde_json = { version = "1.0", optional = true }
```

## Migration from Prototype

**Files to Modify:**
- `/home/sionois/Github/psi-sync/Cargo.toml` - Convert to workspace
- `/home/sionois/Github/psi-sync/src/lib.rs` - Extract logic to new structure

**Files to Create:**
- `/home/sionois/Github/psi-sync/psi-protocol/Cargo.toml`
- `/home/sionois/Github/psi-sync/psi-protocol/src/lib.rs`
- `/home/sionois/Github/psi-sync/psi-protocol/src/protocol.rs`
- `/home/sionois/Github/psi-sync/psi-protocol/src/messages.rs`
- `/home/sionois/Github/psi-sync/psi-protocol/src/state.rs`
- `/home/sionois/Github/psi-sync/psi-protocol/src/crypto.rs`
- `/home/sionois/Github/psi-sync/psi-protocol/src/error.rs`

## Verification

After implementation, verify:

1. **Build**: `cargo build --workspace` succeeds
2. **Tests**: `cargo test --workspace` passes all tests
3. **API Usage**:
   ```rust
   // Can run full protocol
   let mut alice = PsiState::new();
   let bob_msg = /* ... */;
   let result = alice.prepare_blinded_points(&items)?.compute_intersection(bob_msg)?;
   ```
4. **Backward Compatibility**: Existing test logic works with new API
5. **Documentation**: `cargo doc --open` generates docs

## Key Design Decisions

1. **No serde in core**: Message structs are plain Rust structs; user adds serialization
2. **Input: Vec<u8>**: Accept byte arrays, handle hashing internally
3. **Symmetric API**: Both peers use same methods (`prepare_blinded_points`, `compute_intersection`)
4. **Stateful protocol**: `PsiState` holds secret and mappings between phases
5. **Hash function**: SHA-512 truncated to 32 bytes (consistent with prototype)
6. **Compressed points**: Use `CompressedRistretto` for message efficiency

## Future Enhancements (Out of Scope)

- Add serde as optional feature for convenience
- Batch processing for large datasets
- Parallel point operations with Rayon
- Multi-party PSI extensions
