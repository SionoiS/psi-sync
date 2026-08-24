//! Per-message processing (range-based reconciliation heuristic).

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

    let fp_bounds: Vec<Src::Bounds> = incoming
        .ranges
        .iter()
        .filter_map(|range| match range {
            Range::Fingerprint { bounds, .. } => Some(bounds.clone()),
            _ => None,
        })
        .collect();
    let ours = store.fingerprint_counts(&fp_bounds);
    let mut fp_i = 0;

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
                    ours[fp_i].0.clone(),
                    ours[fp_i].1,
                    &mut reply_ranges,
                );
                fp_i += 1;
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
    ours: <Src::Item as ReconcileItem>::Fingerprint,
    ours_count: usize,
    out: &mut Vec<Range<Src::Item, Src::Bounds>>,
) {
    if ours == theirs {
        out.push(Range::skip(bounds));
        return;
    }

    let threshold = store.config().threshold;
    if ours_count <= threshold {
        out.push(Range::item_set(
            bounds.clone(),
            ItemSet {
                elements: store.items(bounds),
                needed: Vec::new(),
                reconciled: false,
            },
        ));
        return;
    }

    let parts = store.partition(bounds.clone(), store.config().partitions);
    if parts.len() < 2 {
        out.push(Range::item_set(
            bounds.clone(),
            ItemSet {
                elements: store.items(bounds),
                needed: Vec::new(),
                reconciled: false,
            },
        ));
        return;
    }

    let part_stats = store.fingerprint_counts(&parts);
    for (part, (fp, count)) in parts.into_iter().zip(part_stats) {
        if count <= threshold {
            out.push(Range::item_set(
                part.clone(),
                ItemSet {
                    elements: store.items(part),
                    needed: Vec::new(),
                    reconciled: false,
                },
            ));
        } else {
            out.push(Range::fingerprint(part, fp));
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
    validate_item_list(&theirs.elements, &bounds, max)?;
    validate_item_list(&theirs.needed, &bounds, max)?;

    if theirs.reconciled {
        to_recv.extend(theirs.elements.iter().cloned());
        to_send.extend(theirs.needed.iter().cloned());
        out.push(Range::skip(bounds));
        return Ok(());
    }

    let ours = store.items(bounds.clone());
    let mut exclusive_local = Vec::new();
    let mut exclusive_remote = Vec::new();
    let mut i = 0;
    let mut j = 0;
    while i < theirs.elements.len() && j < ours.len() {
        match theirs.elements[i].cmp(&ours[j]) {
            std::cmp::Ordering::Less => {
                exclusive_remote.push(theirs.elements[i].clone());
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                exclusive_local.push(ours[j].clone());
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                i += 1;
                j += 1;
            }
        }
    }
    while i < theirs.elements.len() {
        exclusive_remote.push(theirs.elements[i].clone());
        i += 1;
    }
    while j < ours.len() {
        exclusive_local.push(ours[j].clone());
        j += 1;
    }

    to_send.extend(exclusive_local.iter().cloned());
    to_recv.extend(exclusive_remote.iter().cloned());

    if exclusive_local.is_empty() && exclusive_remote.is_empty() {
        out.push(Range::skip(bounds));
    } else {
        out.push(Range::item_set(
            bounds,
            ItemSet {
                elements: exclusive_local,
                needed: exclusive_remote,
                reconciled: true,
            },
        ));
    }
    Ok(())
}

fn validate_item_list<T: ReconcileItem, B: SessionBounds<Item = T>>(
    items: &[T],
    bounds: &B,
    max: usize,
) -> Result<()> {
    if items.len() > max {
        return Err(ReconcileError::ItemSetTooLarge {
            size: items.len(),
            max,
        });
    }
    if items.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ReconcileError::UnsortedItemSet);
    }
    if items.iter().any(|item| !bounds.contains(item)) {
        return Err(ReconcileError::ItemOutOfBounds);
    }
    Ok(())
}
