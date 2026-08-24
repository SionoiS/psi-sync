//! In-memory topic-sync demo: PSI on topics, then multiplexed per-topic reconciliation.
//!
//! Run with:
//! ```bash
//! cargo run -p examples --bin topic_sync
//! ```

use psi_sync::{
    RangeBounds, ReconcileStore, SyncId, SyncMessage, SyncResult, SyncStep, TopicStores, TopicSync,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Topic-sync (PSI then reconcile) ===\n");

    let alice_topics = TopicStores::new();
    let bob_topics = TopicStores::new();

    fill(
        &alice_topics,
        b"shared-chat",
        &[(1_000, 0x01), (1_100, 0x02), (1_200, 0x0a)],
    )?;
    fill(
        &bob_topics,
        b"shared-chat",
        &[(1_000, 0x01), (1_100, 0x02), (1_300, 0x0b)],
    )?;

    fill(
        &alice_topics,
        b"shared-alerts",
        &[(2_000, 0x21), (2_100, 0x22)],
    )?;
    fill(
        &bob_topics,
        b"shared-alerts",
        &[(2_000, 0x21), (2_100, 0x22)],
    )?;

    fill(&alice_topics, b"alice-private", &[(3_000, 0x31)])?;
    fill(&bob_topics, b"bob-private", &[(4_000, 0x41)])?;

    println!("Alice topics: {}", alice_topics.len());
    println!("Bob topics:   {}\n", bob_topics.len());

    let bounds = RangeBounds::window(0, 10_000)?;
    let (alice, first) = TopicSync::initiate(&alice_topics, bounds)?;
    let bob = TopicSync::respond(&bob_topics, bounds)?;

    let (alice_result, bob_result) = run(alice, bob, first)?;

    println!("Shared topics: {}\n", alice_result.len());
    for diff in &alice_result.topics {
        let name = alice_topics
            .topic_bytes(&diff.topic_hash)
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_else(|| hex32(&diff.topic_hash));
        println!(
            "  {name}: alice to_send={} to_recv={}",
            diff.to_send.len(),
            diff.to_recv.len()
        );
    }

    assert_eq!(alice_result.len(), bob_result.len());
    for (a, b) in alice_result.topics.iter().zip(&bob_result.topics) {
        assert_eq!(a.topic_hash, b.topic_hash);
        assert_eq!(a.to_send, b.to_recv);
        assert_eq!(a.to_recv, b.to_send);
    }
    println!("\nDiffs are complementary. Exclusive topics were not reconciled.");

    Ok(())
}

fn fill(
    map: &TopicStores,
    topic: &[u8],
    ids: &[(u64, u8)],
) -> Result<(), psi_sync::TopicSyncError> {
    let store = ReconcileStore::new(Default::default())?;
    for &(t, h0) in ids {
        let mut hash = [0u8; 32];
        hash[0] = h0;
        store.insert(SyncId::new(t, hash))?;
    }
    map.insert(topic.to_vec(), store)
}

fn run(
    mut alice: TopicSync,
    mut bob: TopicSync,
    mut incoming: SyncMessage,
) -> Result<(SyncResult, SyncResult), psi_sync::TopicSyncError> {
    loop {
        match bob.step(incoming)? {
            SyncStep::Next { next, message } => {
                bob = next;
                match alice.step(message)? {
                    SyncStep::Next { next, message } => {
                        alice = next;
                        incoming = message;
                    }
                    SyncStep::Done { result, farewell } => {
                        return Ok((result, close(bob, farewell)?));
                    }
                }
            }
            SyncStep::Done { result, farewell } => {
                return Ok((close(alice, farewell)?, result));
            }
        }
    }
}

fn close(
    session: TopicSync,
    farewell: Option<SyncMessage>,
) -> Result<SyncResult, psi_sync::TopicSyncError> {
    let msg = farewell.ok_or(psi_sync::TopicSyncError::UnexpectedMessage)?;
    match session.step(msg)? {
        SyncStep::Done { result, .. } => Ok(result),
        SyncStep::Next { .. } => Err(psi_sync::TopicSyncError::UnexpectedMessage),
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
