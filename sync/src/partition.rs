//! Range partitioning: item-index (any [`Ord`]) and time/hash-space domain splits.

use crate::bounds::RangeBounds;
use crate::id::SyncId;

/// Split `[bounds.a, bounds.b)` using `local` item values as cut points.
///
/// The incoming first/last bounds are preserved. Interior cuts are item
/// values, so this needs only a total order. Returns an empty vec when
/// fewer than two parts can be formed (caller should send an item set).
pub fn partition_by_items<T: Clone + Ord>(
    bounds: RangeBounds<T>,
    local: &[T],
    count: usize,
) -> Vec<RangeBounds<T>> {
    partition_by_nth(bounds, local.len(), count, |k| local.get(k).cloned())
}

/// Same cut indices as [`partition_by_items`], via the k-th local item.
///
/// `n` is the number of items in the range. `nth(k)` is the k-th (0-based).
pub fn partition_by_nth<T, F>(
    bounds: RangeBounds<T>,
    n: usize,
    count: usize,
    mut nth: F,
) -> Vec<RangeBounds<T>>
where
    T: Clone + Ord,
    F: FnMut(usize) -> Option<T>,
{
    if count < 2 || n < 2 {
        return Vec::new();
    }

    let mut cuts = Vec::with_capacity(count + 1);
    cuts.push(0);
    for i in 1..count {
        let idx = n * i / count;
        if idx > *cuts.last().unwrap() && idx < n {
            cuts.push(idx);
        }
    }
    cuts.push(n);
    if cuts.len() < 3 {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(cuts.len() - 1);
    for w in cuts.windows(2) {
        let start = w[0];
        let end = w[1];
        let a = if start == 0 {
            bounds.a.clone()
        } else {
            match nth(start) {
                Some(v) => v,
                None => return Vec::new(),
            }
        };
        let b = if end == n {
            bounds.b.clone()
        } else {
            match nth(end) {
                Some(v) => v,
                None => return Vec::new(),
            }
        };
        if a < b {
            out.push(RangeBounds { a, b });
        }
    }
    out
}

/// Split `bounds` into subranges.
///
/// - If the time span is at least `count`, N-way time split (remainder on the
///   first slices), matching Nim `equalPartitioning`.
/// - If `2 <= Δt < count`, time-split into `Δt` 1-unit slices.
/// - If `Δt == 1`, two slices at the 1-unit cut.
/// - If timestamps are equal, N-way split of the hash interval.
pub fn partition_range(bounds: RangeBounds<SyncId>, count: usize) -> Vec<RangeBounds<SyncId>> {
    debug_assert!(count >= 2);
    let dt = bounds.b.timestamp.saturating_sub(bounds.a.timestamp);
    if dt >= count as u64 {
        return partition_time(bounds, count);
    }
    if dt >= 2 {
        return partition_time(bounds, dt as usize);
    }
    if dt == 1 {
        return partition_one_tick(bounds);
    }
    partition_hash(bounds, count)
}

/// [`partition_range`], optionally isolating a recency window of `hot_tail`
/// time units as a cold prefix plus an equal-time split of the tail.
///
/// Recency applies whenever `dt > w`, relative to this range's `b`. A later
/// split of the cold prefix therefore peels another `w` from the end.
pub fn partition_range_with_hot(
    bounds: RangeBounds<SyncId>,
    count: usize,
    hot_tail: Option<u64>,
) -> Vec<RangeBounds<SyncId>> {
    if let Some(w) = hot_tail {
        let dt = bounds.b.timestamp.saturating_sub(bounds.a.timestamp);
        if dt > w {
            return partition_recency(bounds, count, w);
        }
    }
    partition_range(bounds, count)
}

fn partition_recency(
    bounds: RangeBounds<SyncId>,
    count: usize,
    w: u64,
) -> Vec<RangeBounds<SyncId>> {
    let hot_lo = SyncId::min_at(bounds.b.timestamp.saturating_sub(w));
    let mut out = Vec::new();
    if bounds.a < hot_lo {
        out.push(RangeBounds {
            a: bounds.a,
            b: hot_lo,
        });
    }
    if hot_lo < bounds.b {
        out.extend(partition_range(
            RangeBounds {
                a: hot_lo,
                b: bounds.b,
            },
            count,
        ));
    }
    out
}

/// N-way split of `[a.timestamp, b.timestamp)`. First/last hashes preserved.
pub fn partition_time(bounds: RangeBounds<SyncId>, count: usize) -> Vec<RangeBounds<SyncId>> {
    let total = bounds.b.timestamp.saturating_sub(bounds.a.timestamp);
    if count < 2 || total < count as u64 {
        return Vec::new();
    }
    let n = count as u64;
    let parts = total / n;
    let mut rem = total % n;
    let mut out = Vec::with_capacity(count);
    let mut lb_time = bounds.a.timestamp;
    for i in 0..count {
        let mut ub_time = lb_time + parts;
        if rem > 0 {
            ub_time += 1;
            rem -= 1;
        }
        let lo = if i == 0 {
            bounds.a
        } else {
            SyncId::min_at(lb_time)
        };
        let hi = if i + 1 == count {
            bounds.b
        } else {
            SyncId::min_at(ub_time)
        };
        if lo < hi {
            out.push(RangeBounds { a: lo, b: hi });
        }
        lb_time = ub_time;
    }
    out
}

fn partition_one_tick(bounds: RangeBounds<SyncId>) -> Vec<RangeBounds<SyncId>> {
    let mid = SyncId::min_at(bounds.a.timestamp.saturating_add(1));
    let mut out = Vec::new();
    if bounds.a < mid {
        out.push(RangeBounds {
            a: bounds.a,
            b: mid,
        });
    }
    if mid < bounds.b {
        out.push(RangeBounds {
            a: mid,
            b: bounds.b,
        });
    }
    if out.is_empty() {
        out.push(bounds);
    }
    out
}

/// Split `[a.hash, b.hash)` as big-endian integers. Timestamps stay equal.
pub fn partition_hash(bounds: RangeBounds<SyncId>, count: usize) -> Vec<RangeBounds<SyncId>> {
    if count < 2 || bounds.a.timestamp != bounds.b.timestamp || bounds.a.hash >= bounds.b.hash {
        return Vec::new();
    }
    let start = U256::from_be_bytes(bounds.a.hash);
    let end = U256::from_be_bytes(bounds.b.hash);
    let span = end.saturating_sub(start);
    if span.is_zero() {
        return Vec::new();
    }

    let n = count as u64;
    // If the span is smaller than n, emit as many unit steps as we can.
    let steps = if span.lt_u64(n) {
        span.to_u64_saturating().max(1) as usize
    } else {
        count
    };
    if steps < 2 {
        return vec![bounds];
    }

    let parts = span.div_u64(steps as u64);
    let mut rem = span.mod_u64(steps as u64);
    let mut out = Vec::with_capacity(steps);
    let mut cursor = start;
    for i in 0..steps {
        let mut step = parts;
        if rem > 0 {
            step = step.add_u64(1);
            rem -= 1;
        }
        let next = cursor.saturating_add(step);
        let lo_hash = if i == 0 {
            bounds.a.hash
        } else {
            cursor.to_be_bytes()
        };
        let hi_hash = if i + 1 == steps {
            bounds.b.hash
        } else {
            next.to_be_bytes()
        };
        let lo = SyncId {
            timestamp: bounds.a.timestamp,
            hash: lo_hash,
        };
        let hi = SyncId {
            timestamp: bounds.b.timestamp,
            hash: hi_hash,
        };
        if lo < hi {
            out.push(RangeBounds { a: lo, b: hi });
        }
        cursor = next;
    }
    out
}

/// Minimal big-endian 256-bit unsigned int for hash-space splits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct U256([u8; 32]);

impl U256 {
    fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn to_be_bytes(self) -> [u8; 32] {
        self.0
    }

    fn is_zero(self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    fn saturating_sub(self, other: Self) -> Self {
        let mut out = [0u8; 32];
        let mut borrow = 0u16;
        for i in (0..32).rev() {
            let d = self.0[i] as u16;
            let s = other.0[i] as u16 + borrow;
            if d >= s {
                out[i] = (d - s) as u8;
                borrow = 0;
            } else {
                out[i] = (d + 256 - s) as u8;
                borrow = 1;
            }
        }
        if borrow != 0 {
            Self([0; 32])
        } else {
            Self(out)
        }
    }

    fn saturating_add(self, other: Self) -> Self {
        let mut out = [0u8; 32];
        let mut carry = 0u16;
        for i in (0..32).rev() {
            let s = self.0[i] as u16 + other.0[i] as u16 + carry;
            out[i] = (s & 0xff) as u8;
            carry = s >> 8;
        }
        Self(out)
    }

    fn add_u64(self, n: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&n.to_be_bytes());
        self.saturating_add(Self(bytes))
    }

    fn lt_u64(self, n: u64) -> bool {
        self.0[..24].iter().all(|&b| b == 0) && {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&self.0[24..]);
            u64::from_be_bytes(buf) < n
        }
    }

    fn to_u64_saturating(self) -> u64 {
        if self.0[..24].iter().any(|&b| b != 0) {
            u64::MAX
        } else {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&self.0[24..]);
            u64::from_be_bytes(buf)
        }
    }

    fn div_u64(self, d: u64) -> Self {
        if d == 0 {
            return Self([0; 32]);
        }
        let mut rem = 0u128;
        let mut out = [0u8; 32];
        for (src, dest) in self.0.iter().zip(out.iter_mut()) {
            rem = (rem << 8) | u128::from(*src);
            *dest = (rem / u128::from(d)) as u8;
            rem %= u128::from(d);
        }
        Self(out)
    }

    fn mod_u64(self, d: u64) -> u64 {
        if d == 0 {
            return 0;
        }
        let mut rem = 0u128;
        for &b in &self.0 {
            rem = (rem << 8) | b as u128;
            rem %= d as u128;
        }
        rem as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::SyncId;

    #[test]
    fn time_partition_tiles_and_remainder_on_first() {
        let bounds = RangeBounds::window(100, 110).unwrap();
        let parts = partition_time(bounds, 8);
        assert_eq!(parts.len(), 8);
        assert_eq!(parts[0].a, bounds.a);
        assert_eq!(parts[7].b, bounds.b);
        for w in parts.windows(2) {
            assert_eq!(w[0].b, w[1].a);
        }
        // 10 units / 8 = 1 rem 2 → first two slices are length 2.
        let d0 = parts[0].b.timestamp - parts[0].a.timestamp;
        let d1 = parts[1].b.timestamp - parts[1].a.timestamp;
        assert_eq!(d0, 2);
        assert_eq!(d1, 2);
        let total: u64 = parts
            .iter()
            .map(|p| p.b.timestamp.saturating_sub(p.a.timestamp))
            .sum();
        assert_eq!(total, 10);
    }

    #[test]
    fn hash_partition_used_when_same_timestamp() {
        let a = SyncId::min_at(5);
        let mut hb = [0u8; 32];
        hb[0] = 0x80;
        let b = SyncId {
            timestamp: 5,
            hash: hb,
        };
        let bounds = RangeBounds::new(a, b).unwrap();
        let parts = partition_range(bounds, 8);
        assert_eq!(parts.len(), 8);
        assert_eq!(parts[0].a, a);
        assert_eq!(parts[7].b, b);
        for w in parts.windows(2) {
            assert_eq!(w[0].b, w[1].a);
            assert_eq!(w[0].a.timestamp, 5);
        }
    }

    #[test]
    fn hash_partition_not_used_when_time_span_large() {
        let bounds = RangeBounds::window(0, 100).unwrap();
        let parts = partition_range(bounds, 8);
        assert_eq!(parts.len(), 8);
        assert!(parts.iter().any(|p| p.a.timestamp != p.b.timestamp));
    }

    #[test]
    fn item_partition_tiles_and_uses_values_as_cuts() {
        let bounds = RangeBounds::new(0u64, 100).unwrap();
        let local = [10u64, 20, 30, 40, 50, 60, 70, 80];
        let parts = partition_by_items(bounds, &local, 4);
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0].a, 0);
        assert_eq!(parts[3].b, 100);
        for w in parts.windows(2) {
            assert_eq!(w[0].b, w[1].a);
        }
        // 8 items / 4 = 2 per part; interior cuts are local[2], [4], [6].
        assert_eq!(parts[0].b, 30);
        assert_eq!(parts[1].b, 50);
        assert_eq!(parts[2].b, 70);
    }

    #[test]
    fn item_partition_too_small_is_empty() {
        let bounds = RangeBounds::new(0u64, 10).unwrap();
        assert!(partition_by_items(bounds, &[], 4).is_empty());
        assert!(partition_by_items(bounds, &[1], 4).is_empty());
    }

    #[test]
    fn partition_by_nth_matches_slice() {
        let bounds = RangeBounds::new(0u64, 100).unwrap();
        let local = [10u64, 20, 30, 40, 50, 60, 70, 80];
        let from_slice = partition_by_items(bounds, &local, 4);
        let from_nth = partition_by_nth(bounds, local.len(), 4, |k| local.get(k).copied());
        assert_eq!(from_slice, from_nth);
    }

    #[test]
    fn hot_tail_cold_prefix_plus_equal_time_hot() {
        let bounds = RangeBounds::window(0, 1000).unwrap();
        let parts = partition_range_with_hot(bounds, 8, Some(100));
        assert_eq!(parts.len(), 9);
        assert_eq!(parts[0].a, bounds.a);
        assert_eq!(parts[0].b, SyncId::min_at(900));
        assert_eq!(parts[8].b, bounds.b);
        for w in parts.windows(2) {
            assert_eq!(w[0].b, w[1].a);
        }
        let hot = RangeBounds::window(900, 1000).unwrap();
        assert_eq!(&parts[1..], partition_range(hot, 8).as_slice());
    }

    #[test]
    fn hot_tail_none_matches_partition_range() {
        let bounds = RangeBounds::window(0, 1000).unwrap();
        assert_eq!(
            partition_range_with_hot(bounds, 8, None),
            partition_range(bounds, 8)
        );
        let tight = RangeBounds::window(0, 100).unwrap();
        assert_eq!(
            partition_range_with_hot(tight, 8, Some(100)),
            partition_range(tight, 8)
        );
        let a = SyncId::min_at(5);
        let mut hb = [0u8; 32];
        hb[0] = 0x80;
        let b = SyncId {
            timestamp: 5,
            hash: hb,
        };
        let hash_bounds = RangeBounds::new(a, b).unwrap();
        assert_eq!(
            partition_range_with_hot(hash_bounds, 8, Some(100)),
            partition_range(hash_bounds, 8)
        );
        let one_tick = RangeBounds::window(5, 6).unwrap();
        assert_eq!(
            partition_range_with_hot(one_tick, 8, Some(100)),
            partition_range(one_tick, 8)
        );
    }

    #[test]
    fn hot_tail_peels_again_on_cold_prefix() {
        let bounds = RangeBounds::window(0, 1000).unwrap();
        let first = partition_range_with_hot(bounds, 8, Some(100));
        let cold = first[0];
        assert_eq!(cold, RangeBounds::window(0, 900).unwrap());
        let again = partition_range_with_hot(cold, 8, Some(100));
        assert_eq!(again.len(), 9);
        assert_eq!(again[0], RangeBounds::window(0, 800).unwrap());
        let hot = RangeBounds::window(800, 900).unwrap();
        assert_eq!(&again[1..], partition_range(hot, 8).as_slice());
        let mut cur = bounds;
        let mut peels = 0;
        while cur.b.timestamp.saturating_sub(cur.a.timestamp) > 100 {
            let parts = partition_range_with_hot(cur, 8, Some(100));
            cur = parts[0];
            peels += 1;
        }
        assert_eq!(peels, 9);
        assert_eq!(cur, RangeBounds::window(0, 100).unwrap());
    }
}
