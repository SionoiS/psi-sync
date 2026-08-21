//! Composed session: PSI on topics, then multiplexed inner reconciles.

use crate::error::{Result, TopicSyncError};
use crate::message::{ReconcileFrame, SyncMessage};
use crate::result::SyncResult;
use crate::state::{Phase, Reconciling};
use crate::stores::TopicStores;
use psi::PsiProtocol;
use reconciliation::{RangeBounds, Reconcile, ReconcileError, ReconcileStep, ReconcileStore};
use std::collections::HashMap;

/// Outcome of [`TopicSync::step`].
#[derive(Debug)]
pub enum SyncStep<'a> {
    /// Send `message` and continue with `next`.
    Next {
        /// Session after processing `incoming`.
        next: TopicSync<'a>,
        /// Outbound frame.
        message: SyncMessage,
    },
    /// Session over. Send `farewell` if this side produced the closer.
    Done {
        /// Per-topic diffs.
        result: SyncResult,
        /// Message the peer still needs, if any.
        farewell: Option<SyncMessage>,
    },
}

/// One side of a topic-sync exchange.
///
/// Construct with [`TopicSync::initiate`] or [`TopicSync::respond`]. `step`
/// consumes `self`, like [`Reconcile::step`](reconciliation::Reconcile::step).
///
/// The public type is not generic over PSI vs reconciling: the outer protocol
/// has a variable number of rounds, so a wrong-phase message is
/// [`TopicSyncError::UnexpectedMessage`] rather than a compile error.
pub struct TopicSync<'a> {
    stores: &'a TopicStores,
    bounds: RangeBounds,
    phase: Phase<'a>,
}

impl std::fmt::Debug for TopicSync<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TopicSync").finish_non_exhaustive()
    }
}

impl<'a> TopicSync<'a> {
    /// Start as initiator: send blinded topic points.
    ///
    /// `bounds` is the time window used for every shared topic.
    pub fn initiate(stores: &'a TopicStores, bounds: RangeBounds) -> Result<(Self, SyncMessage)> {
        check_bounds(bounds)?;
        let psi = PsiProtocol::new(&stores.psi_items())?;
        let message = SyncMessage::PsiBlinded(psi.message());
        Ok((
            Self {
                stores,
                bounds,
                phase: Phase::InitiatorPsi(psi),
            },
            message,
        ))
    }

    /// Start as responder. The first [`step`](Self::step) consumes the
    /// initiator's [`SyncMessage::PsiBlinded`].
    pub fn respond(stores: &'a TopicStores, bounds: RangeBounds) -> Result<Self> {
        check_bounds(bounds)?;
        let psi = PsiProtocol::new(&stores.psi_items())?;
        Ok(Self {
            stores,
            bounds,
            phase: Phase::ResponderPsi(psi),
        })
    }

    /// Process one incoming message. Consumes `self`.
    pub fn step(self, incoming: SyncMessage) -> Result<SyncStep<'a>> {
        let TopicSync {
            stores,
            bounds,
            phase,
        } = self;
        match phase {
            Phase::InitiatorPsi(psi) => match incoming {
                SyncMessage::PsiOffer {
                    blinded,
                    double_blinded,
                } => initiator_on_offer(stores, bounds, psi, blinded, double_blinded),
                _ => Err(TopicSyncError::UnexpectedMessage),
            },
            Phase::ResponderPsi(psi) => match incoming {
                SyncMessage::PsiBlinded(blinded) => {
                    responder_on_blinded(stores, bounds, psi, blinded)
                }
                _ => Err(TopicSyncError::UnexpectedMessage),
            },
            Phase::ResponderPsiMid(psi) => match incoming {
                SyncMessage::PsiDone {
                    double_blinded,
                    opening,
                } => responder_on_psi_done(stores, bounds, psi, double_blinded, opening),
                _ => Err(TopicSyncError::UnexpectedMessage),
            },
            Phase::Reconciling(rec) => match incoming {
                SyncMessage::Reconcile(frames) => on_reconcile(stores, bounds, rec, frames),
                _ => Err(TopicSyncError::UnexpectedMessage),
            },
        }
    }
}

fn check_bounds(bounds: RangeBounds) -> Result<()> {
    if bounds.a >= bounds.b {
        return Err(ReconcileError::InvalidBounds.into());
    }
    Ok(())
}

fn sorted_hashes(mut hashes: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    hashes.sort_unstable();
    hashes
}

fn require_local(stores: &TopicStores, hashes: &[[u8; 32]]) -> Result<()> {
    for hash in hashes {
        if stores.get_by_hash(hash).is_none() {
            return Err(TopicSyncError::UnknownTopic(*hash));
        }
    }
    Ok(())
}

fn store_for<'a>(stores: &'a TopicStores, hash: &[u8; 32]) -> Result<&'a ReconcileStore> {
    stores
        .get_by_hash(hash)
        .ok_or(TopicSyncError::UnknownTopic(*hash))
}

fn expect_hash(expected: [u8; 32], actual: [u8; 32]) -> Result<()> {
    if expected != actual {
        return Err(TopicSyncError::TopicMismatch { expected, actual });
    }
    Ok(())
}

fn expect_opening(hashes: &[[u8; 32]], opening: &[ReconcileFrame]) -> Result<()> {
    if hashes.len() != opening.len() {
        return Err(TopicSyncError::UnexpectedMessage);
    }
    for (expected, frame) in hashes.iter().zip(opening) {
        expect_hash(*expected, frame.topic_hash)?;
    }
    Ok(())
}

fn session<'a>(stores: &'a TopicStores, bounds: RangeBounds, phase: Phase<'a>) -> TopicSync<'a> {
    TopicSync {
        stores,
        bounds,
        phase,
    }
}

fn initiator_on_offer<'a>(
    stores: &'a TopicStores,
    bounds: RangeBounds,
    psi: PsiProtocol<psi::PreparedState>,
    blinded: psi::BlindedPointsMessage,
    double_blinded: psi::DoubleBlindedPointsMessage,
) -> Result<SyncStep<'a>> {
    let (mid, my_double) = psi.compute(blinded)?;
    let psi_result = mid.finalize(double_blinded)?;
    let hashes = sorted_hashes(psi_result.intersection_hashes);
    require_local(stores, &hashes)?;

    if hashes.is_empty() {
        return Ok(SyncStep::Done {
            result: SyncResult::default(),
            farewell: Some(SyncMessage::PsiDone {
                double_blinded: my_double,
                opening: Vec::new(),
            }),
        });
    }

    let mut inner = HashMap::with_capacity(hashes.len());
    let mut opening = Vec::with_capacity(hashes.len());
    for hash in &hashes {
        let (sess, body) = Reconcile::initiate(store_for(stores, hash)?, bounds)?;
        inner.insert(*hash, sess);
        opening.push(ReconcileFrame::new(*hash, body));
    }
    let rec = Reconciling {
        hashes,
        inner,
        diffs: Vec::new(),
    };
    Ok(SyncStep::Next {
        next: session(stores, bounds, Phase::Reconciling(rec)),
        message: SyncMessage::PsiDone {
            double_blinded: my_double,
            opening,
        },
    })
}

fn responder_on_blinded<'a>(
    stores: &'a TopicStores,
    bounds: RangeBounds,
    psi: PsiProtocol<psi::PreparedState>,
    blinded: psi::BlindedPointsMessage,
) -> Result<SyncStep<'a>> {
    let my_blinded = psi.message();
    let (mid, my_double) = psi.compute(blinded)?;
    Ok(SyncStep::Next {
        next: session(stores, bounds, Phase::ResponderPsiMid(mid)),
        message: SyncMessage::PsiOffer {
            blinded: my_blinded,
            double_blinded: my_double,
        },
    })
}

fn responder_on_psi_done<'a>(
    stores: &'a TopicStores,
    bounds: RangeBounds,
    psi: PsiProtocol<psi::DoubleBlindedState>,
    double_blinded: psi::DoubleBlindedPointsMessage,
    opening: Vec<ReconcileFrame>,
) -> Result<SyncStep<'a>> {
    let psi_result = psi.finalize(double_blinded)?;
    let hashes = sorted_hashes(psi_result.intersection_hashes);
    require_local(stores, &hashes)?;
    expect_opening(&hashes, &opening)?;

    if hashes.is_empty() {
        return Ok(SyncStep::Done {
            result: SyncResult::default(),
            farewell: None,
        });
    }

    let mut inner = HashMap::with_capacity(hashes.len());
    for hash in &hashes {
        inner.insert(*hash, Reconcile::respond(store_for(stores, hash)?));
    }
    let rec = Reconciling {
        hashes,
        inner,
        diffs: Vec::new(),
    };
    on_reconcile(stores, bounds, rec, opening)
}

fn on_reconcile<'a>(
    stores: &'a TopicStores,
    bounds: RangeBounds,
    mut rec: Reconciling<'a>,
    frames: Vec<ReconcileFrame>,
) -> Result<SyncStep<'a>> {
    if frames.is_empty() || frames.len() != rec.inner.len() {
        return Err(TopicSyncError::UnexpectedMessage);
    }

    let mut incoming = HashMap::with_capacity(frames.len());
    for frame in frames {
        if incoming.insert(frame.topic_hash, frame.body).is_some() {
            return Err(TopicSyncError::UnexpectedMessage);
        }
        if !rec.inner.contains_key(&frame.topic_hash) {
            return Err(TopicSyncError::TopicMismatch {
                expected: rec.inner.keys().copied().min().unwrap_or(frame.topic_hash),
                actual: frame.topic_hash,
            });
        }
    }

    let mut hashes: Vec<_> = incoming.keys().copied().collect();
    hashes.sort_unstable();
    let mut outbound = Vec::new();
    for hash in hashes {
        let body = incoming.remove(&hash).expect("just inserted");
        let inner = rec.inner.remove(&hash).expect("checked");
        match inner.step(body)? {
            ReconcileStep::Next { next, message } => {
                rec.inner.insert(hash, next);
                outbound.push(ReconcileFrame::new(hash, message));
            }
            ReconcileStep::Done { result, farewell } => {
                rec.record(hash, result);
                if let Some(body) = farewell {
                    outbound.push(ReconcileFrame::new(hash, body));
                }
            }
        }
    }

    emit(stores, bounds, rec, outbound)
}

fn emit<'a>(
    stores: &'a TopicStores,
    bounds: RangeBounds,
    mut rec: Reconciling<'a>,
    outbound: Vec<ReconcileFrame>,
) -> Result<SyncStep<'a>> {
    if rec.inner.is_empty() {
        rec.diffs.sort_by_key(|d| d.topic_hash);
        if rec.diffs.len() != rec.hashes.len() {
            return Err(TopicSyncError::UnexpectedMessage);
        }
        Ok(SyncStep::Done {
            result: SyncResult { topics: rec.diffs },
            farewell: if outbound.is_empty() {
                None
            } else {
                Some(SyncMessage::Reconcile(outbound))
            },
        })
    } else if outbound.is_empty() {
        Err(TopicSyncError::UnexpectedMessage)
    } else {
        Ok(SyncStep::Next {
            next: session(stores, bounds, Phase::Reconciling(rec)),
            message: SyncMessage::Reconcile(outbound),
        })
    }
}

/// Drive two sessions to completion over an in-memory channel.
#[cfg(test)]
pub(crate) fn run_pair(
    alice: &TopicStores,
    bob: &TopicStores,
    bounds: RangeBounds,
) -> Result<(SyncResult, SyncResult)> {
    let (alice_sess, first) = TopicSync::initiate(alice, bounds)?;
    let bob_sess = TopicSync::respond(bob, bounds)?;
    drive(alice_sess, bob_sess, first)
}

/// Like [`run_pair`], but records every on-wire message including the first.
#[cfg(test)]
pub(crate) fn run_pair_traced(
    alice: &TopicStores,
    bob: &TopicStores,
    bounds: RangeBounds,
) -> Result<(SyncResult, SyncResult, Vec<SyncMessage>)> {
    let (alice_sess, first) = TopicSync::initiate(alice, bounds)?;
    let bob_sess = TopicSync::respond(bob, bounds)?;
    let mut wire = vec![first.clone()];
    let (ar, br) = drive_traced(alice_sess, bob_sess, first, &mut wire)?;
    Ok((ar, br, wire))
}

#[cfg(test)]
fn drive<'a>(
    alice: TopicSync<'a>,
    bob: TopicSync<'a>,
    first: SyncMessage,
) -> Result<(SyncResult, SyncResult)> {
    let mut wire = Vec::new();
    drive_traced(alice, bob, first, &mut wire)
}

#[cfg(test)]
fn drive_traced<'a>(
    mut alice: TopicSync<'a>,
    mut bob: TopicSync<'a>,
    mut incoming: SyncMessage,
    wire: &mut Vec<SyncMessage>,
) -> Result<(SyncResult, SyncResult)> {
    loop {
        match bob.step(incoming)? {
            SyncStep::Next { next, message } => {
                wire.push(message.clone());
                bob = next;
                match alice.step(message)? {
                    SyncStep::Next { next, message } => {
                        wire.push(message.clone());
                        alice = next;
                        incoming = message;
                    }
                    SyncStep::Done { result, farewell } => {
                        let br = finish_peer(bob, farewell, wire)?;
                        return Ok((result, br));
                    }
                }
            }
            SyncStep::Done { result, farewell } => {
                let ar = finish_peer(alice, farewell, wire)?;
                return Ok((ar, result));
            }
        }
    }
}

#[cfg(test)]
fn finish_peer(
    session: TopicSync<'_>,
    farewell: Option<SyncMessage>,
    wire: &mut Vec<SyncMessage>,
) -> Result<SyncResult> {
    match farewell {
        None => Err(TopicSyncError::UnexpectedMessage),
        Some(msg) => {
            wire.push(msg.clone());
            match session.step(msg)? {
                SyncStep::Done {
                    result,
                    farewell: None,
                } => Ok(result),
                SyncStep::Done {
                    farewell: Some(_), ..
                }
                | SyncStep::Next { .. } => Err(TopicSyncError::UnexpectedMessage),
            }
        }
    }
}
