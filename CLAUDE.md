# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust library implementing **Private Set Intersection (PSI)** using Elliptic Curve Diffie-Hellman (ECDH) on the Ristretto group (curve25519-dalek). The protocol allows two parties (Alice and Bob) to compute the intersection of their private sets without revealing any additional information about non-intersecting elements.

## Build and Test Commands

```bash
# Build the project
cargo build

# Build with optimizations
cargo build --release

# Run tests
cargo test

# Run a specific test
cargo test psi_works

# Run tests with output
cargo test -- --nocapture

# Check code without building
cargo check
```

## Architecture

### Core Algorithm (`src/lib.rs`)

The library contains a single function `ecdh_psi` that implements the ECDH-PSI protocol:

**Input**: Two vectors of 32-byte hashes representing Alice's and Bob's private sets

**Process**:
1. Both parties generate random secret scalars
2. Hashes are mapped to RistrettoPoints using SHA-512 hash-to-curve
3. Each party blinds their points by multiplying with their secret scalar
4. Blinded points are exchanged between parties (in production, this should use TLS)
5. Each party double-blinds received points by multiplying again with their secret
6. Intersection is found by comparing double-blinded points (identical double-blinded values indicate matching elements)
7. Returns: (Alice's intersection, Bob's intersection, mapping from intersection hashes to double-blinded points)

**Output**: Two intersection vectors (one per party) and a HashMap mapping intersection hashes to their double-blinded point representations

**Key Properties**:
- Both parties receive the same intersection (verified via assertion)
- The double-blinded point mapping is consistent across both parties
- No information about non-intersecting elements is revealed (only blinded values are exchanged)

### Cryptographic Dependencies

- **curve25519-dalek v4**: Provides Ristretto group operations and scalar arithmetic
- **sha2**: SHA-512 for hash-to-curve operations
- **rand v0.8**: Cryptographically secure random number generation via OsRng

### Security Considerations

The protocol ensures that:
- Only elements in the intersection are revealed to both parties
- Blinded points exchanged in Step 4 leak no information about the underlying elements
- In production deployments, the exchange of blinded points MUST be secured with TLS to prevent man-in-the-middle attacks

### Testing

The test suite (`psi_works`) validates the protocol by:
- Creating two sets with 90 unique elements each and 10 common elements
- Verifying both parties compute the same intersection
- Ensuring the mapping size matches the intersection size
- Using `OsRng` for cryptographically secure test data

## Development Notes

- The project uses Rust 2024 edition
- All hash arrays are fixed-size `[u8; 32]` bytes
- The Ristretto group provides a prime-order group with convenient APIs for ECDH-based protocols
- The algorithm is designed for equal-sized inputs but handles any sizes
