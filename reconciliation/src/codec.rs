//! LIP-182 payload encoding (LEB128 + range deltas).
//!
//! Logical bounds stay explicit. On the wire the first range’s lower hash is
//! implicit zero (Nwaku / LIP). A sliding window should therefore use
//! [`RangeBounds::window`]. The LIP’s “first lower bound is `SyncID(0,0)`”
//! wording would drop the window start; this codec encodes the first
//! `a.timestamp` explicitly, matching Nwaku.

use crate::bounds::RangeBounds;
use crate::error::{ReconcileError, Result};
use crate::id::{SyncId, EMPTY_HASH};
use crate::range::{ItemSet, Range, RangeContent, RangeType, RangesData, SyncScope};

/// Encode a payload. An empty range list is a single `0` byte (Nim interop).
pub fn encode(payload: &RangesData) -> Vec<u8> {
    if payload.ranges.is_empty() {
        return vec![0];
    }

    let mut out = Vec::new();
    write_uleb128(&mut out, payload.scope.cluster);
    write_uleb128(&mut out, payload.scope.shards.len() as u64);
    for shard in &payload.scope.shards {
        write_uleb128(&mut out, *shard);
    }

    let first_a = payload.ranges[0].bounds.a;
    write_uleb128(&mut out, first_a.timestamp);

    let mut last_time = first_a.timestamp;

    for range in &payload.ranges {
        let b = range.bounds.b;
        let time_diff = b.timestamp.wrapping_sub(last_time);
        write_uleb128(&mut out, time_diff);
        if time_diff == 0 {
            // Full hash: LIP prefix-delta is lossy for hash-space cuts.
            out.push(32);
            out.extend_from_slice(&b.hash);
        }
        last_time = b.timestamp;

        out.push(range.kind as u8);
        match &range.content {
            RangeContent::None => {}
            RangeContent::Fingerprint(fp) => out.extend_from_slice(fp),
            RangeContent::Items(set) => write_item_set(&mut out, set),
        }
    }

    out
}

/// Decode a payload. A lone `0` is an empty payload with default scope.
pub fn decode(bytes: &[u8]) -> Result<RangesData> {
    if bytes.is_empty() {
        return Err(ReconcileError::CodecError("empty buffer".into()));
    }
    if bytes == [0] {
        return Ok(RangesData::empty(SyncScope::any()));
    }

    let mut idx = 0;
    let cluster = read_uleb128(bytes, &mut idx)?;
    let nshards = read_uleb128(bytes, &mut idx)?;
    let mut shards = Vec::with_capacity(nshards as usize);
    for _ in 0..nshards {
        shards.push(read_uleb128(bytes, &mut idx)?);
    }
    let scope = SyncScope { cluster, shards };

    if idx >= bytes.len() {
        return Ok(RangesData::empty(scope));
    }

    let first_time = read_uleb128(bytes, &mut idx)?;
    let mut last_time = first_time;
    let mut last_hash = EMPTY_HASH;
    let mut prev = SyncId {
        timestamp: first_time,
        hash: EMPTY_HASH,
    };
    let mut ranges = Vec::new();

    while idx < bytes.len() {
        let time_diff = read_uleb128(bytes, &mut idx)?;
        let this_time = last_time.wrapping_add(time_diff);
        let hash = if time_diff == 0 {
            let h = read_hash_delta(bytes, &mut idx, &last_hash)?;
            last_hash = h;
            h
        } else {
            last_hash = EMPTY_HASH;
            EMPTY_HASH
        };
        last_time = this_time;
        let upper = SyncId {
            timestamp: this_time,
            hash,
        };
        let bounds = RangeBounds::new(prev, upper)?;
        prev = upper;

        if idx >= bytes.len() {
            return Err(ReconcileError::CodecError("truncated range type".into()));
        }
        let kind = RangeType::from_u8(bytes[idx])?;
        idx += 1;

        let content = match kind {
            RangeType::Skip => RangeContent::None,
            RangeType::Fingerprint => {
                if idx + 32 > bytes.len() {
                    return Err(ReconcileError::CodecError("truncated fingerprint".into()));
                }
                let mut fp = [0u8; 32];
                fp.copy_from_slice(&bytes[idx..idx + 32]);
                idx += 32;
                RangeContent::Fingerprint(fp)
            }
            RangeType::ItemSet => RangeContent::Items(read_item_set(bytes, &mut idx)?),
        };

        let range = Range {
            bounds,
            kind,
            content,
        };
        range.validate()?;
        ranges.push(range);
    }

    Ok(RangesData { scope, ranges })
}

fn write_item_set(out: &mut Vec<u8>, set: &ItemSet) {
    write_uleb128(out, set.elements.len() as u64);
    let mut last_time = 0u64;
    for (i, id) in set.elements.iter().enumerate() {
        if i == 0 {
            write_uleb128(out, id.timestamp);
        } else {
            write_uleb128(out, id.timestamp.wrapping_sub(last_time));
        }
        out.extend_from_slice(&id.hash);
        last_time = id.timestamp;
    }
    out.push(u8::from(set.reconciled));
}

fn read_item_set(bytes: &[u8], idx: &mut usize) -> Result<ItemSet> {
    let n = read_uleb128(bytes, idx)? as usize;
    let mut elements = Vec::with_capacity(n);
    let mut last_time = 0u64;
    for i in 0..n {
        let time = if i == 0 {
            read_uleb128(bytes, idx)?
        } else {
            last_time.wrapping_add(read_uleb128(bytes, idx)?)
        };
        if *idx + 32 > bytes.len() {
            return Err(ReconcileError::CodecError("truncated item hash".into()));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[*idx..*idx + 32]);
        *idx += 32;
        elements.push(SyncId {
            timestamp: time,
            hash,
        });
        last_time = time;
    }
    if *idx >= bytes.len() {
        return Err(ReconcileError::CodecError(
            "truncated reconciled flag".into(),
        ));
    }
    let flag = bytes[*idx];
    *idx += 1;
    let reconciled = match flag {
        0 => false,
        1 => true,
        _ => {
            return Err(ReconcileError::CodecError(format!(
                "invalid reconciled byte {flag}"
            )))
        }
    };
    Ok(ItemSet {
        elements,
        reconciled,
    })
}

#[cfg(test)]
fn write_hash_delta(out: &mut Vec<u8>, prev: &[u8; 32], next: &[u8; 32]) {
    let mut n = 32usize;
    for i in 0..32 {
        if prev[i] != next[i] {
            n = i + 1;
            break;
        }
    }
    out.push(n as u8);
    out.extend_from_slice(&next[..n]);
}

fn read_hash_delta(bytes: &[u8], idx: &mut usize, prev: &[u8; 32]) -> Result<[u8; 32]> {
    if *idx >= bytes.len() {
        return Err(ReconcileError::CodecError("truncated hash delta".into()));
    }
    let n = bytes[*idx] as usize;
    *idx += 1;
    if n > 32 || *idx + n > bytes.len() {
        return Err(ReconcileError::CodecError("invalid hash delta".into()));
    }
    let mut hash = *prev;
    hash[..n].copy_from_slice(&bytes[*idx..*idx + n]);
    *idx += n;
    Ok(hash)
}

fn write_uleb128(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn read_uleb128(bytes: &[u8], idx: &mut usize) -> Result<u64> {
    let mut result = 0u64;
    let mut shift = 0;
    loop {
        if *idx >= bytes.len() {
            return Err(ReconcileError::CodecError("truncated varint".into()));
        }
        let byte = bytes[*idx];
        *idx += 1;
        let digit = (byte & 0x7f) as u64;
        if shift >= 64 || (digit << shift) >> shift != digit {
            return Err(ReconcileError::CodecError("varint overflow".into()));
        }
        result |= digit << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::SyncId;

    fn sid(t: u64, h0: u8) -> SyncId {
        let mut hash = [0u8; 32];
        hash[0] = h0;
        SyncId::new(t, hash)
    }

    #[test]
    fn empty_is_single_zero() {
        let p = RangesData::empty(SyncScope::any());
        assert_eq!(encode(&p), vec![0]);
        assert_eq!(decode(&[0]).unwrap(), p);
    }

    #[test]
    fn round_trip_fingerprint() {
        let bounds = RangeBounds::window(1000, 2000).unwrap();
        let payload = RangesData {
            scope: SyncScope {
                cluster: 1,
                shards: vec![2, 3],
            },
            ranges: vec![Range::fingerprint(bounds, [0xab; 32])],
        };
        let bytes = encode(&payload);
        assert_eq!(decode(&bytes).unwrap(), payload);
    }

    #[test]
    fn round_trip_item_set() {
        let bounds = RangeBounds::window(10, 50).unwrap();
        let set = ItemSet {
            elements: vec![sid(11, 1), sid(12, 2)],
            reconciled: true,
        };
        let payload = RangesData {
            scope: SyncScope::any(),
            ranges: vec![Range::item_set(bounds, set)],
        };
        assert_eq!(decode(&encode(&payload)).unwrap(), payload);
    }

    #[test]
    fn round_trip_skip_then_fingerprint() {
        let payload = RangesData {
            scope: SyncScope::any(),
            ranges: vec![
                Range::skip(RangeBounds::window(0, 10).unwrap()),
                Range::fingerprint(RangeBounds::window(10, 20).unwrap(), [7u8; 32]),
            ],
        };
        assert_eq!(decode(&encode(&payload)).unwrap(), payload);
    }

    #[test]
    fn hash_delta_matches_lip_table() {
        // prev 0x351c…, next 0x3560… → length 2, bytes 0x35 0x60
        let mut prev = [0u8; 32];
        prev[0] = 0x35;
        prev[1] = 0x1c;
        prev[2] = 0x5e;
        prev[3] = 0x86;
        let mut next = [0u8; 32];
        next[0] = 0x35;
        next[1] = 0x60;
        next[2] = 0xd9;
        next[3] = 0xc4;
        let mut buf = Vec::new();
        write_hash_delta(&mut buf, &prev, &next);
        assert_eq!(buf[0], 2);
        assert_eq!(&buf[1..], &[0x35, 0x60]);
        let mut idx = 0;
        let got = read_hash_delta(&buf, &mut idx, &prev).unwrap();
        assert_eq!(got[0], 0x35);
        assert_eq!(got[1], 0x60);
        assert_eq!(got[2], 0x5e);
        assert_eq!(got[3], 0x86);
    }
}
