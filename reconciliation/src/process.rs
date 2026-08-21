//! Per-message processing (LIP-182 reconciliation heuristic).

use crate::bounds::RangeBounds;
use crate::item::ReconcileItem;
use crate::range::{merge_skips, ItemSet, Range, ReconcileMessage};
use crate::store::ReconcileStore;

/// Result of processing one incoming message.
pub(crate) struct ProcessOutput<T: ReconcileItem> {
    pub reply: ReconcileMessage<T>,
    pub to_send: Vec<T>,
    pub to_recv: Vec<T>,
}

/// Process `incoming` against `store`.
pub(crate) fn process_payload<T: ReconcileItem>(
    store: &ReconcileStore<T>,
    incoming: &ReconcileMessage<T>,
) -> ProcessOutput<T> {
    let mut reply_ranges = Vec::new();
    let mut to_send = Vec::new();
    let mut to_recv = Vec::new();
    let threshold = store.config().threshold;
    let partitions = store.config().partitions;

    for range in &incoming.ranges {
        match range {
            Range::Skip { bounds } => {
                reply_ranges.push(Range::skip(bounds.clone()));
            }
            Range::Fingerprint {
                bounds,
                fingerprint,
            } => {
                process_fingerprint(
                    store,
                    bounds.clone(),
                    fingerprint.clone(),
                    threshold,
                    partitions,
                    &mut reply_ranges,
                );
            }
            Range::Items { bounds, set } => {
                process_item_set(
                    store,
                    bounds.clone(),
                    set,
                    &mut to_send,
                    &mut to_recv,
                    &mut reply_ranges,
                );
            }
        }
    }

    let reply_ranges = merge_skips(reply_ranges);
    let all_skip = !reply_ranges.is_empty() && reply_ranges.iter().all(Range::is_skip);
    let reply = if reply_ranges.is_empty() || all_skip {
        ReconcileMessage::empty()
    } else {
        ReconcileMessage {
            ranges: reply_ranges,
        }
    };

    ProcessOutput {
        reply,
        to_send,
        to_recv,
    }
}

fn process_fingerprint<T: ReconcileItem>(
    store: &ReconcileStore<T>,
    bounds: RangeBounds<T>,
    theirs: T::Fingerprint,
    threshold: usize,
    partitions: usize,
    out: &mut Vec<Range<T>>,
) {
    let ours = store.fingerprint(bounds.clone());
    if ours == theirs {
        out.push(Range::skip(bounds));
        return;
    }

    let local = store.slice(bounds.clone());
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

    let parts = T::partition(bounds.clone(), local, partitions);
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
        let slice = store.slice(part.clone());
        if slice.len() <= threshold {
            out.push(Range::item_set(
                part,
                ItemSet {
                    elements: slice.to_vec(),
                    reconciled: false,
                },
            ));
        } else {
            out.push(Range::fingerprint(part.clone(), store.fingerprint(part)));
        }
    }
}

fn process_item_set<T: ReconcileItem>(
    store: &ReconcileStore<T>,
    bounds: RangeBounds<T>,
    theirs: &ItemSet<T>,
    to_send: &mut Vec<T>,
    to_recv: &mut Vec<T>,
    out: &mut Vec<Range<T>>,
) {
    let ours = store.slice(bounds.clone());
    let mut i = 0;
    let mut j = 0;
    while i < theirs.elements.len() && j < ours.len() {
        match theirs.elements[i].cmp(&ours[j]) {
            std::cmp::Ordering::Less => {
                to_recv.push(theirs.elements[i].clone());
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                to_send.push(ours[j].clone());
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                i += 1;
                j += 1;
            }
        }
    }
    while i < theirs.elements.len() {
        to_recv.push(theirs.elements[i].clone());
        i += 1;
    }
    while j < ours.len() {
        to_send.push(ours[j].clone());
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
