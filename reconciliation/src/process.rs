//! Per-payload processing (LIP-182 reconciliation heuristic).

use crate::bounds::RangeBounds;
use crate::id::SyncId;
use crate::partition::partition_range;
use crate::range::{merge_skips, ItemSet, Range, RangeContent, RangeType, RangesData, SyncScope};
use crate::store::ReconcileStore;

/// Result of processing one incoming payload.
pub(crate) struct ProcessOutput {
    pub reply: RangesData,
    pub to_send: Vec<SyncId>,
    pub to_recv: Vec<SyncId>,
}

/// Process `incoming` against `store` using `local_scope` on the reply.
pub(crate) fn process_payload(
    store: &ReconcileStore,
    local_scope: &SyncScope,
    incoming: &RangesData,
) -> ProcessOutput {
    if !local_scope.compatible(&incoming.scope) {
        return ProcessOutput {
            reply: RangesData::empty(local_scope.clone()),
            to_send: Vec::new(),
            to_recv: Vec::new(),
        };
    }

    let mut reply_ranges = Vec::new();
    let mut to_send = Vec::new();
    let mut to_recv = Vec::new();
    let threshold = store.config().threshold;
    let partitions = store.config().partitions;

    for range in &incoming.ranges {
        match range.kind {
            RangeType::Skip => {
                reply_ranges.push(Range::skip(range.bounds));
            }
            RangeType::Fingerprint => {
                let fp = match range.content {
                    RangeContent::Fingerprint(fp) => fp,
                    _ => continue,
                };
                process_fingerprint(
                    store,
                    range.bounds,
                    fp,
                    threshold,
                    partitions,
                    &mut reply_ranges,
                );
            }
            RangeType::ItemSet => {
                let set = match &range.content {
                    RangeContent::Items(set) => set,
                    _ => continue,
                };
                process_item_set(
                    store,
                    range.bounds,
                    set,
                    &mut to_send,
                    &mut to_recv,
                    &mut reply_ranges,
                );
            }
        }
    }

    let reply_ranges = merge_skips(reply_ranges);
    let all_skip =
        !reply_ranges.is_empty() && reply_ranges.iter().all(|r| r.kind == RangeType::Skip);
    let reply = if reply_ranges.is_empty() || all_skip {
        RangesData::empty(local_scope.clone())
    } else {
        RangesData {
            scope: local_scope.clone(),
            ranges: reply_ranges,
        }
    };

    ProcessOutput {
        reply,
        to_send,
        to_recv,
    }
}

fn process_fingerprint(
    store: &ReconcileStore,
    bounds: RangeBounds,
    theirs: [u8; 32],
    threshold: usize,
    partitions: usize,
    out: &mut Vec<Range>,
) {
    let ours = store.fingerprint(bounds);
    if ours == theirs {
        out.push(Range::skip(bounds));
        return;
    }

    let local = store.slice(bounds);
    if local.len() <= threshold {
        out.push(Range::item_set(
            bounds,
            ItemSet {
                elements: local.to_vec(),
                reconciled: false,
            },
        ));
        return;
    }

    let parts = partition_range(bounds, partitions);
    if parts.is_empty() {
        out.push(Range::item_set(
            bounds,
            ItemSet {
                elements: local.to_vec(),
                reconciled: false,
            },
        ));
        return;
    }

    for part in parts {
        let slice = store.slice(part);
        if slice.len() <= threshold {
            out.push(Range::item_set(
                part,
                ItemSet {
                    elements: slice.to_vec(),
                    reconciled: false,
                },
            ));
        } else {
            out.push(Range::fingerprint(part, store.fingerprint(part)));
        }
    }
}

fn process_item_set(
    store: &ReconcileStore,
    bounds: RangeBounds,
    theirs: &ItemSet,
    to_send: &mut Vec<SyncId>,
    to_recv: &mut Vec<SyncId>,
    out: &mut Vec<Range>,
) {
    let ours = store.slice(bounds);
    let mut i = 0;
    let mut j = 0;
    while i < theirs.elements.len() && j < ours.len() {
        match theirs.elements[i].cmp(&ours[j]) {
            std::cmp::Ordering::Less => {
                to_recv.push(theirs.elements[i]);
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                to_send.push(ours[j]);
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                i += 1;
                j += 1;
            }
        }
    }
    while i < theirs.elements.len() {
        to_recv.push(theirs.elements[i]);
        i += 1;
    }
    while j < ours.len() {
        to_send.push(ours[j]);
        j += 1;
    }

    if !theirs.reconciled {
        out.push(Range::item_set(
            bounds,
            ItemSet {
                elements: ours.to_vec(),
                reconciled: true,
            },
        ));
    } else {
        out.push(Range::skip(bounds));
    }
}
