//! Per-message processing (LIP-182 reconciliation heuristic).

use crate::error::{ReconcileError, Result};
use crate::item::ReconcileItem;
use crate::range::{merge_skips, ItemSet, Range, ReconcileMessage};
use crate::source::{ReconcileSource, SessionBounds};

/// Result of processing one incoming message.
pub(crate) struct ProcessOutput<T: ReconcileItem, B: crate::source::SessionBounds> {
    pub reply: ReconcileMessage<T, B>,
    pub to_send: Vec<T>,
    pub to_recv: Vec<T>,
}

/// Process `incoming` against `store`.
pub(crate) fn process_payload<Src: ReconcileSource>(
    store: &Src,
    incoming: &ReconcileMessage<Src::Item, Src::Bounds>,
) -> Result<ProcessOutput<Src::Item, Src::Bounds>> {
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
                )?;
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

    Ok(ProcessOutput {
        reply,
        to_send,
        to_recv,
    })
}

fn process_fingerprint<Src: ReconcileSource>(
    store: &Src,
    bounds: Src::Bounds,
    theirs: <Src::Item as ReconcileItem>::Fingerprint,
    threshold: usize,
    partitions: usize,
    out: &mut Vec<Range<Src::Item, Src::Bounds>>,
) {
    let ours = store.fingerprint(bounds.clone());
    if ours == theirs {
        out.push(Range::skip(bounds));
        return;
    }

    if store.count(bounds.clone()) <= threshold {
        out.push(Range::item_set(
            bounds.clone(),
            ItemSet {
                elements: store.items(bounds),
                reconciled: false,
            },
        ));
        return;
    }

    let parts = store.partition(bounds.clone(), partitions);
    if parts.len() < 2 {
        out.push(Range::item_set(
            bounds.clone(),
            ItemSet {
                elements: store.items(bounds),
                reconciled: false,
            },
        ));
        return;
    }

    for part in parts {
        if store.count(part.clone()) <= threshold {
            out.push(Range::item_set(
                part.clone(),
                ItemSet {
                    elements: store.items(part),
                    reconciled: false,
                },
            ));
        } else {
            out.push(Range::fingerprint(part.clone(), store.fingerprint(part)));
        }
    }
}

fn process_item_set<Src: ReconcileSource>(
    store: &Src,
    bounds: Src::Bounds,
    theirs: &ItemSet<Src::Item>,
    to_send: &mut Vec<Src::Item>,
    to_recv: &mut Vec<Src::Item>,
    out: &mut Vec<Range<Src::Item, Src::Bounds>>,
) -> Result<()> {
    let max = store.config().max_items;
    if theirs.elements.len() > max {
        return Err(ReconcileError::ItemSetTooLarge {
            size: theirs.elements.len(),
            max,
        });
    }
    if theirs.elements.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ReconcileError::UnsortedItemSet);
    }
    if theirs.elements.iter().any(|item| !bounds.contains(item)) {
        return Err(ReconcileError::ItemOutOfBounds);
    }

    let ours = store.items(bounds.clone());
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
                elements: ours,
                reconciled: true,
            },
        ));
    } else {
        out.push(Range::skip(bounds));
    }
    Ok(())
}
