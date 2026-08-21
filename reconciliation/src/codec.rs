//! Optional LIP-182 bytes for a [`ReconcileMessage`].
//!
//! The session API never uses this module. Cluster/shard fields are written as
//! zeros and ignored on decode. An empty message encodes as a single `0` byte.

use crate::bounds::RangeBounds;
use crate::id::{SyncId, EMPTY_HASH};
use crate::range::{ItemSet, Range, ReconcileMessage};

/// Wire-format error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("codec error: {0}")]
pub struct Error(pub String);

pub type Result<T> = std::result::Result<T, Error>;

/// Encode a message. Empty `ranges` is a single `0` byte.
pub fn encode(message: &ReconcileMessage<SyncId>) -> Vec<u8> {
    if message.ranges.is_empty() {
        return vec![0];
    }

    let mut out = Vec::new();
    write_uleb128(&mut out, 0); // cluster
    write_uleb128(&mut out, 0); // shard count

    let first_a = message.ranges[0].bounds().a;
    write_uleb128(&mut out, first_a.timestamp);

    let mut last_time = first_a.timestamp;

    for range in &message.ranges {
        let b = range.bounds().b;
        let time_diff = b.timestamp.wrapping_sub(last_time);
        write_uleb128(&mut out, time_diff);
        if time_diff == 0 {
            out.push(32);
            out.extend_from_slice(&b.hash);
        }
        last_time = b.timestamp;

        match range {
            Range::Skip { .. } => out.push(0),
            Range::Fingerprint { fingerprint, .. } => {
                out.push(1);
                out.extend_from_slice(fingerprint);
            }
            Range::Items { set, .. } => {
                out.push(2);
                write_item_set(&mut out, set);
            }
        }
    }

    out
}

/// Decode a message. A lone `0` is empty. Cluster/shards in the header are discarded.
pub fn decode(bytes: &[u8]) -> Result<ReconcileMessage<SyncId>> {
    if bytes.is_empty() {
        return Err(Error("empty buffer".into()));
    }
    if bytes == [0] {
        return Ok(ReconcileMessage::empty());
    }

    let mut idx = 0;
    let _cluster = read_uleb128(bytes, &mut idx)?;
    let nshards = read_uleb128(bytes, &mut idx)?;
    for _ in 0..nshards {
        let _ = read_uleb128(bytes, &mut idx)?;
    }

    if idx >= bytes.len() {
        return Ok(ReconcileMessage::empty());
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
        let bounds = RangeBounds::new(prev, upper).map_err(|_| Error("invalid bounds".into()))?;
        prev = upper;

        if idx >= bytes.len() {
            return Err(Error("truncated range type".into()));
        }
        let kind = bytes[idx];
        idx += 1;

        let range = match kind {
            0 => Range::skip(bounds),
            1 => {
                if idx + 32 > bytes.len() {
                    return Err(Error("truncated fingerprint".into()));
                }
                let mut fp = [0u8; 32];
                fp.copy_from_slice(&bytes[idx..idx + 32]);
                idx += 32;
                Range::fingerprint(bounds, fp)
            }
            2 => Range::item_set(bounds, read_item_set(bytes, &mut idx)?),
            other => return Err(Error(format!("invalid range type {other}"))),
        };
        ranges.push(range);
    }

    Ok(ReconcileMessage { ranges })
}

fn write_item_set(out: &mut Vec<u8>, set: &ItemSet<SyncId>) {
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

fn read_item_set(bytes: &[u8], idx: &mut usize) -> Result<ItemSet<SyncId>> {
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
            return Err(Error("truncated item hash".into()));
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
        return Err(Error("truncated reconciled flag".into()));
    }
    let flag = bytes[*idx];
    *idx += 1;
    let reconciled = match flag {
        0 => false,
        1 => true,
        _ => return Err(Error(format!("invalid reconciled byte {flag}"))),
    };
    Ok(ItemSet {
        elements,
        reconciled,
    })
}

#[cfg(test)]
fn write_hash_delta(out: &mut Vec<u8>, prev: &[u8; 32], next: &[u8; 32]) {
    let mut n = 32usize;
    for (i, (p, nbyte)) in prev.iter().zip(next.iter()).enumerate() {
        if p != nbyte {
            n = i + 1;
            break;
        }
    }
    out.push(n as u8);
    out.extend_from_slice(&next[..n]);
}

fn read_hash_delta(bytes: &[u8], idx: &mut usize, prev: &[u8; 32]) -> Result<[u8; 32]> {
    if *idx >= bytes.len() {
        return Err(Error("truncated hash delta".into()));
    }
    let n = bytes[*idx] as usize;
    *idx += 1;
    if n > 32 || *idx + n > bytes.len() {
        return Err(Error("invalid hash delta".into()));
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
            return Err(Error("truncated varint".into()));
        }
        let byte = bytes[*idx];
        *idx += 1;
        let digit = (byte & 0x7f) as u64;
        if shift >= 64 || (digit << shift) >> shift != digit {
            return Err(Error("varint overflow".into()));
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
        let p = ReconcileMessage::empty();
        assert_eq!(encode(&p), vec![0]);
        assert_eq!(decode(&[0]).unwrap(), p);
    }

    #[test]
    fn round_trip_fingerprint() {
        let bounds = RangeBounds::window(1000, 2000).unwrap();
        let payload = ReconcileMessage {
            ranges: vec![Range::fingerprint(bounds, [0xab; 32])],
        };
        assert_eq!(decode(&encode(&payload)).unwrap(), payload);
    }

    #[test]
    fn round_trip_item_set() {
        let bounds = RangeBounds::window(10, 50).unwrap();
        let set = ItemSet {
            elements: vec![sid(11, 1), sid(12, 2)],
            reconciled: true,
        };
        let payload = ReconcileMessage {
            ranges: vec![Range::item_set(bounds, set)],
        };
        assert_eq!(decode(&encode(&payload)).unwrap(), payload);
    }

    #[test]
    fn round_trip_skip_then_fingerprint() {
        let payload = ReconcileMessage {
            ranges: vec![
                Range::skip(RangeBounds::window(0, 10).unwrap()),
                Range::fingerprint(RangeBounds::window(10, 20).unwrap(), [7u8; 32]),
            ],
        };
        assert_eq!(decode(&encode(&payload)).unwrap(), payload);
    }

    #[test]
    fn hash_delta_matches_lip_table() {
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
