//! Composed session: PSI on topics, then one reconcile per shared topic.

use crate::error::{Result, TopicSyncError};
use crate::message::{ReconcileFrame, SyncMessage};
use crate::result::SyncResult;
use crate::state::{Phase, Reconciling, Role};
use crate::stores::TopicStores;
use psi::PsiProtocol;
use reconciliation::{
    RangeBounds, Reconcile, ReconcileError, ReconcileMessage, ReconcileStep, ReconcileStore,
};

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
                    first_reconcile,
                } => responder_on_psi_done(stores, bounds, psi, double_blinded, first_reconcile),
                _ => Err(TopicSyncError::UnexpectedMessage),
            },
            Phase::Reconciling(rec) => match incoming {
                SyncMessage::Reconcile(frame) => on_reconcile(stores, bounds, rec, frame),
                SyncMessage::TopicComplete { topic_hash, next } => {
                    on_topic_complete(stores, bounds, rec, topic_hash, next)
                }
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
                first_reconcile: None,
            }),
        });
    }

    let first_hash = hashes[0];
    let (inner, first_body) = Reconcile::initiate(store_for(stores, &first_hash)?, bounds)?;
    let rec = Reconciling {
        role: Role::Initiator,
        hashes,
        completed: 0,
        inner: Some(inner),
        diffs: Vec::new(),
    };
    Ok(SyncStep::Next {
        next: session(stores, bounds, Phase::Reconciling(rec)),
        message: SyncMessage::PsiDone {
            double_blinded: my_double,
            first_reconcile: Some(ReconcileFrame::new(first_hash, first_body)),
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
    first_reconcile: Option<ReconcileFrame>,
) -> Result<SyncStep<'a>> {
    let psi_result = psi.finalize(double_blinded)?;
    let hashes = sorted_hashes(psi_result.intersection_hashes);
    require_local(stores, &hashes)?;

    match (hashes.is_empty(), first_reconcile) {
        (true, None) => Ok(SyncStep::Done {
            result: SyncResult::default(),
            farewell: None,
        }),
        (false, Some(frame)) => {
            let rec = Reconciling {
                role: Role::Responder,
                hashes,
                completed: 0,
                inner: None,
                diffs: Vec::new(),
            };
            start_responder_topic(stores, bounds, rec, frame)
        }
        _ => Err(TopicSyncError::UnexpectedMessage),
    }
}

fn start_responder_topic<'a>(
    stores: &'a TopicStores,
    bounds: RangeBounds,
    mut rec: Reconciling<'a>,
    frame: ReconcileFrame,
) -> Result<SyncStep<'a>> {
    let expected = rec
        .current_hash()
        .ok_or(TopicSyncError::UnexpectedMessage)?;
    expect_hash(expected, frame.topic_hash)?;
    let inner = Reconcile::respond(store_for(stores, &frame.topic_hash)?);
    match inner.step(frame.body)? {
        ReconcileStep::Next { next, message } => {
            rec.inner = Some(next);
            Ok(SyncStep::Next {
                next: session(stores, bounds, Phase::Reconciling(rec)),
                message: SyncMessage::Reconcile(ReconcileFrame::new(frame.topic_hash, message)),
            })
        }
        ReconcileStep::Done { result, farewell } => {
            rec.record(result);
            match farewell {
                Some(body) => Ok(SyncStep::Next {
                    next: session(stores, bounds, Phase::Reconciling(rec)),
                    message: SyncMessage::Reconcile(ReconcileFrame::new(frame.topic_hash, body)),
                }),
                None => Err(TopicSyncError::UnexpectedMessage),
            }
        }
    }
}

fn on_reconcile<'a>(
    stores: &'a TopicStores,
    bounds: RangeBounds,
    mut rec: Reconciling<'a>,
    frame: ReconcileFrame,
) -> Result<SyncStep<'a>> {
    let expected = rec
        .current_hash()
        .ok_or(TopicSyncError::UnexpectedMessage)?;
    expect_hash(expected, frame.topic_hash)?;
    let inner = rec.inner.take().ok_or(TopicSyncError::UnexpectedMessage)?;
    match inner.step(frame.body)? {
        ReconcileStep::Next { next, message } => {
            rec.inner = Some(next);
            Ok(SyncStep::Next {
                next: session(stores, bounds, Phase::Reconciling(rec)),
                message: SyncMessage::Reconcile(ReconcileFrame::new(frame.topic_hash, message)),
            })
        }
        ReconcileStep::Done { result, farewell } => {
            let finished = frame.topic_hash;
            rec.record(result);
            match rec.role {
                Role::Initiator => initiator_after_topic_done(stores, bounds, rec, finished),
                Role::Responder => match farewell {
                    Some(body) => Ok(SyncStep::Next {
                        next: session(stores, bounds, Phase::Reconciling(rec)),
                        message: SyncMessage::Reconcile(ReconcileFrame::new(finished, body)),
                    }),
                    None => Err(TopicSyncError::UnexpectedMessage),
                },
            }
        }
    }
}

fn initiator_after_topic_done<'a>(
    stores: &'a TopicStores,
    bounds: RangeBounds,
    mut rec: Reconciling<'a>,
    finished_hash: [u8; 32],
) -> Result<SyncStep<'a>> {
    if rec.completed < rec.hashes.len() {
        let next_hash = rec.hashes[rec.completed];
        let (inner, first) = Reconcile::initiate(store_for(stores, &next_hash)?, bounds)?;
        rec.inner = Some(inner);
        Ok(SyncStep::Next {
            next: session(stores, bounds, Phase::Reconciling(rec)),
            message: SyncMessage::TopicComplete {
                topic_hash: finished_hash,
                next: Some(ReconcileFrame::new(next_hash, first)),
            },
        })
    } else {
        Ok(SyncStep::Done {
            result: SyncResult { topics: rec.diffs },
            farewell: Some(SyncMessage::TopicComplete {
                topic_hash: finished_hash,
                next: None,
            }),
        })
    }
}

fn on_topic_complete<'a>(
    stores: &'a TopicStores,
    bounds: RangeBounds,
    mut rec: Reconciling<'a>,
    topic_hash: [u8; 32],
    next: Option<ReconcileFrame>,
) -> Result<SyncStep<'a>> {
    if rec.role != Role::Responder {
        return Err(TopicSyncError::UnexpectedMessage);
    }

    if let Some(inner) = rec.inner.take() {
        let expected = rec
            .current_hash()
            .ok_or(TopicSyncError::UnexpectedMessage)?;
        expect_hash(expected, topic_hash)?;
        match inner.step(ReconcileMessage::empty())? {
            ReconcileStep::Done { result, .. } => rec.record(result),
            ReconcileStep::Next { .. } => return Err(TopicSyncError::UnexpectedMessage),
        }
    } else {
        if rec.completed == 0 {
            return Err(TopicSyncError::UnexpectedMessage);
        }
        expect_hash(rec.hashes[rec.completed - 1], topic_hash)?;
    }

    match next {
        Some(frame) => start_responder_topic(stores, bounds, rec, frame),
        None => {
            if rec.completed != rec.hashes.len() {
                return Err(TopicSyncError::UnexpectedMessage);
            }
            Ok(SyncStep::Done {
                result: SyncResult { topics: rec.diffs },
                farewell: None,
            })
        }
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
