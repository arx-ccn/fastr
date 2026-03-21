use std::sync::Arc;

use tokio::sync::{mpsc, RwLock};
use tracing::warn;

use crate::db::store::unix_now;
use crate::nostr::{event_expiry, filter_matches, Filter};
use crate::pack::Event;

/// A live event sent to a connection's write task, paired with the subscription id.
pub struct LiveEvent {
    pub sub_id: String,
    pub event: Arc<Event>,
}

struct Subscription {
    sub_id: String,
    filters: Vec<Filter>,
    sender: mpsc::Sender<LiveEvent>,
}

/// Fan-out hub: distributes freshly ingested events to all matching live subscriptions.
pub struct Fanout {
    subs: RwLock<Vec<Subscription>>,
}

impl Fanout {
    pub fn new() -> Arc<Self> {
        Arc::new(Fanout {
            subs: RwLock::new(Vec::new()),
        })
    }

    /// Register or replace a subscription. A REQ with a duplicate sub_id on the same
    /// sender replaces the previous one per NIP-01.
    pub async fn subscribe(&self, sub_id: String, filters: Vec<Filter>, sender: mpsc::Sender<LiveEvent>) {
        let mut subs = self.subs.write().await;
        // Replace existing entry with the same sub_id + sender identity.
        if let Some(pos) = subs
            .iter()
            .position(|s| s.sub_id == sub_id && s.sender.same_channel(&sender))
        {
            subs[pos] = Subscription {
                sub_id,
                filters,
                sender,
            };
        } else {
            subs.push(Subscription {
                sub_id,
                filters,
                sender,
            });
        }
    }

    /// Remove a single subscription by sub_id + sender identity.
    pub async fn unsubscribe(&self, sub_id: &str, sender: &mpsc::Sender<LiveEvent>) {
        let mut subs = self.subs.write().await;
        subs.retain(|s| !(s.sub_id == sub_id && s.sender.same_channel(sender)));
    }

    /// Remove all subscriptions belonging to a connection (connection closed).
    pub async fn unsubscribe_all(&self, sender: &mpsc::Sender<LiveEvent>) {
        let mut subs = self.subs.write().await;
        subs.retain(|s| !s.sender.same_channel(sender));
        subs.shrink_to_fit();
    }

    /// Broadcast a freshly ingested event to all matching subscriptions.
    /// Slow clients (full channel) are skipped; closed channels are pruned.
    pub async fn broadcast(&self, ev: Arc<Event>) {
        // NIP-40: drop expired live events before delivery.
        if let Some(exp) = event_expiry(&ev) {
            if exp <= unix_now() {
                return;
            }
        }

        let subs = self.subs.read().await;
        let mut needs_prune = false;

        for sub in subs.iter() {
            if !filter_matches(&sub.filters, &ev) {
                continue;
            }
            let live = LiveEvent {
                sub_id: sub.sub_id.clone(),
                event: Arc::clone(&ev),
            };
            match sub.sender.try_send(live) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!(sub_id = %sub.sub_id, "fanout: channel full, dropping event for slow client");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    needs_prune = true;
                }
            }
        }

        // Upgrade to write lock only when pruning is needed.
        // Use retain with is_closed() instead of saved indices - safe against
        // concurrent subscribe/unsubscribe between lock release and reacquire.
        if needs_prune {
            drop(subs);
            let mut subs = self.subs.write().await;
            subs.retain(|s| !s.sender.is_closed());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr::Filter;
    use crate::pack::{Event, EventId, Pubkey, Sig};
    use std::collections::HashMap;

    fn make_event(kind: u16) -> Arc<Event> {
        Arc::new(Event {
            id: EventId([1u8; 32]),
            pubkey: Pubkey([2u8; 32]),
            sig: Sig([3u8; 64]),
            created_at: 1_000_000,
            kind,
            tags: vec![],
            content: "test".to_owned(),
        })
    }

    fn kind_filter(kind: u16) -> Filter {
        Filter {
            ids: vec![],
            authors: vec![],
            kinds: vec![kind],
            since: None,
            until: None,
            limit: None,
            tags: HashMap::new(),
        }
    }

    fn any_filter() -> Filter {
        Filter {
            ids: vec![],
            authors: vec![],
            kinds: vec![],
            since: None,
            until: None,
            limit: None,
            tags: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_broadcast_two_subscribers_receive() {
        let fanout = Fanout::new();
        let (tx1, mut rx1) = mpsc::channel::<LiveEvent>(8);
        let (tx2, mut rx2) = mpsc::channel::<LiveEvent>(8);

        fanout.subscribe("s1".to_owned(), vec![any_filter()], tx1).await;
        fanout.subscribe("s2".to_owned(), vec![any_filter()], tx2).await;

        let ev = make_event(1);
        fanout.broadcast(Arc::clone(&ev)).await;

        assert!(rx1.try_recv().is_ok(), "sub1 should receive");
        assert!(rx2.try_recv().is_ok(), "sub2 should receive");
    }

    #[tokio::test]
    async fn test_broadcast_after_unsubscribe_receives_nothing() {
        let fanout = Fanout::new();
        let (tx, mut rx) = mpsc::channel::<LiveEvent>(8);

        fanout.subscribe("s1".to_owned(), vec![any_filter()], tx.clone()).await;
        fanout.unsubscribe("s1", &tx).await;

        fanout.broadcast(make_event(1)).await;
        assert!(rx.try_recv().is_err(), "unsubscribed channel must be empty");
    }

    #[tokio::test]
    async fn test_unsubscribe_all_removes_all_for_sender() {
        let fanout = Fanout::new();
        let (tx, mut rx) = mpsc::channel::<LiveEvent>(8);

        fanout.subscribe("s1".to_owned(), vec![any_filter()], tx.clone()).await;
        fanout.subscribe("s2".to_owned(), vec![any_filter()], tx.clone()).await;
        fanout.unsubscribe_all(&tx).await;

        fanout.broadcast(make_event(1)).await;
        assert!(rx.try_recv().is_err(), "all subs removed, must be empty");
    }

    #[tokio::test]
    async fn test_full_channel_does_not_block_broadcast() {
        let fanout = Fanout::new();
        // Capacity 0 is not allowed by tokio; use capacity 1 and pre-fill it.
        let (tx1, mut rx1) = mpsc::channel::<LiveEvent>(1);
        let (tx2, mut rx2) = mpsc::channel::<LiveEvent>(8);

        fanout.subscribe("s1".to_owned(), vec![any_filter()], tx1).await;
        fanout.subscribe("s2".to_owned(), vec![any_filter()], tx2).await;

        // Fill tx1's channel first so the next send via try_send returns Full.
        fanout.broadcast(make_event(1)).await;
        // Channel for s1 is now full (capacity 1). A second broadcast should skip s1,
        // still deliver to s2, and not block.
        fanout.broadcast(make_event(1)).await;

        // s2 gets both events; s1 only gets the first (second was dropped).
        let _ = rx1.try_recv();
        assert!(rx1.try_recv().is_err(), "s1 missed second event (full channel)");
        let _ = rx2.try_recv();
        let _ = rx2.try_recv();
    }

    #[tokio::test]
    async fn test_filter_mismatch_not_delivered() {
        let fanout = Fanout::new();
        let (tx, mut rx) = mpsc::channel::<LiveEvent>(8);

        fanout.subscribe("s1".to_owned(), vec![kind_filter(2)], tx).await;

        // Broadcast a kind=1 event; filter requires kind=2 -> no delivery.
        fanout.broadcast(make_event(1)).await;
        assert!(rx.try_recv().is_err(), "kind mismatch must not deliver");
    }
}
