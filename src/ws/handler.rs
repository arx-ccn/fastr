use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use negentropy::{Id as NegId, Negentropy, NegentropyStorageVector};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMsg;
use tracing::{debug, warn};

use crate::config::Config;
use crate::db::Store;
use crate::error::Error;
use crate::nostr::{classify_kind, has_protected_tag, parse_client_msg, validate_event, ClientMsg, Filter, KindClass, ServerMsg};
use crate::pack::{self, Event, EventId};
use crate::ws::auth::{verify_auth_event, AuthState};
use crate::ws::fanout::{Fanout, LiveEvent};

/// Unified subscription entry: either a live fanout subscription or a negentropy session.
enum Sub {
    Live,
    Neg(Box<Negentropy<'static, NegentropyStorageVector>>),
}

/// Send an `OK` server message for a specific event to the outbound channel.
///
/// The message encodes the event `id`, whether it was `accepted`, and an explanatory `reason`,
/// then serializes to JSON and sends it as `Out::Text` on `out_tx`. Send errors are ignored.
///
/// # Examples
///
/// ```no_run
/// use tokio::sync::mpsc;
/// // create a small channel for outbound messages
/// let (tx, mut rx) = mpsc::channel(2);
/// let id = EventId::default();
/// // fire-and-forget the send
/// tokio::spawn(async move {
///     send_ok(&id, true, "accepted", &tx).await;
/// });
/// // the receiver should get an Out::Text frame (send failures are ignored by send_ok)
/// let received = futures::executor::block_on(async { rx.recv().await });
/// assert!(received.is_some());
/// ```
async fn send_ok(id: &EventId, accepted: bool, reason: &str, out_tx: &mpsc::Sender<Out>) {
    let msg = ServerMsg::Ok { id, accepted, reason }.to_json();
    let _ = out_tx.send(Out::Text(msg)).await;
}

// Outbound message: either a pre-serialised JSON string or a live fanout event.
enum Out {
    Text(String),
    Batch(Vec<String>),
    Live(LiveEvent),
}

/// Convert a single Out message to JSON. Returns None for Batch (handled separately).
#[inline]
fn msg_to_json(msg: Out) -> Option<String> {
    match msg {
        Out::Text(s) => Some(s),
        Out::Batch(_) => None, // handled inline in write loop
        Out::Live(le) => Some(
            ServerMsg::Event {
                sub_id: &le.sub_id,
                event: &le.event,
            }
            .to_json(),
        ),
    }
}

/// Handle an incoming WebSocket connection for a single relay client session.
///
/// This function runs the full lifecycle for a connected client: it upgrades the
/// provided stream to a WebSocket, spawns background tasks for writing outbound
/// frames and forwarding live events, sends the NIP-42 AUTH challenge, processes
/// incoming client messages (EVENT, REQ, CLOSE, COUNT, NIP-42 AUTH, NIP-77 NEG-*),
/// manages per-connection subscriptions (live and Negentropy sessions), applies
/// NIP-17 gift-wrap delivery rules for live events, and performs cleanup when
/// the connection closes.
///
/// On normal termination (client closes the socket or read loop ends) it returns
/// `Ok(())`. Errors returned indicate failures during WebSocket upgrade or other
/// internal I/O/upgrade errors.
///
/// # Examples
///
/// ```no_run
/// use std::sync::Arc;
/// use tokio::net::TcpListener;
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let listener = TcpListener::bind("127.0.0.1:9000").await?;
/// let store = Arc::new(crate::db::store::Store::open(std::path::Path::new("/tmp/store"))?);
/// let config = Arc::new(crate::config::Config::default());
/// let fanout = crate::ws::fanout::Fanout::new();
///
/// let (stream, peer) = listener.accept().await?;
/// // Spawn the connection handler; it runs until the client disconnects.
/// tokio::spawn(async move {
///     let _ = crate::ws::handler::handle_connection(stream, peer, store, config, fanout).await;
/// });
/// # Ok(()) }
/// ```
pub async fn handle_connection<S>(
    stream: S,
    peer: SocketAddr,
    store: Arc<Store>,
    config: Arc<Config>,
    fanout: Arc<Fanout>,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ws = tokio_tungstenite::accept_async(stream)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let (mut sink, mut ws_stream) = ws.split();

    // Unified outbound channel: direct responses and live events flow here.
    let (out_tx, mut out_rx) = mpsc::channel::<Out>(512);

    // Typed live-event sender wired to the fanout.
    let (live_tx, mut live_rx) = mpsc::channel::<LiveEvent>(256);

    // NIP-17: share authenticated pubkey with the forward task for gift-wrap filtering.
    let auth_pk_shared = std::sync::Arc::new(std::sync::RwLock::new(None::<crate::pack::Pubkey>));
    let auth_pk_fwd = auth_pk_shared.clone();

    // Forward task: bridge live events into the unified outbound channel.
    // NIP-17: filter kind-1059 events that don't match the authenticated pubkey's p-tag.
    let fwd_out = out_tx.clone();
    let forward_task = tokio::spawn(async move {
        while let Some(le) = live_rx.recv().await {
            // NIP-17: kind-1059 (gift-wrapped DM) only delivered to the p-tag recipient.
            if le.event.kind == crate::nostr::KIND_GIFT_WRAP {
                let auth_pk = auth_pk_fwd.read().ok().and_then(|g| g.clone());
                let allowed = auth_pk.map_or(false, |pk| {
                    crate::nostr::event_has_p_tag(&le.event, &pk.0)
                });
                if !allowed {
                    continue;
                }
            }
            if fwd_out.send(Out::Live(le)).await.is_err() {
                break;
            }
        }
    });

    // Write task: drain the unified channel and send JSON frames to the client.
    //
    // Uses feed()+flush() batching: buffer all messages currently in the channel
    // with feed() (no syscall per frame), then flush() once when the channel is
    // momentarily empty. This collapses N writes into one TCP segment burst,
    // cutting REQ->EOSE latency by ~100x for queries returning many events.
    let write_task = tokio::spawn(async move {
        loop {
            // Block until at least one message is ready.
            let msg = match out_rx.recv().await {
                Some(m) => m,
                None => break,
            };
            // Handle batch: feed all frames in a tight loop, no channel round-trips.
            match msg {
                Out::Batch(frames) => {
                    for json in frames {
                        if sink.feed(WsMsg::Text(json.into())).await.is_err() {
                            return;
                        }
                    }
                }
                other => {
                    if let Some(json) = msg_to_json(other) {
                        if sink.feed(WsMsg::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                }
            }
            // Drain all additional messages that are already queued without
            // yielding to the scheduler - feed() each one (no flush yet).
            loop {
                match out_rx.try_recv() {
                    Ok(Out::Batch(frames)) => {
                        for json in frames {
                            if sink.feed(WsMsg::Text(json.into())).await.is_err() {
                                return;
                            }
                        }
                    }
                    Ok(other) => {
                        if let Some(json) = msg_to_json(other) {
                            if sink.feed(WsMsg::Text(json.into())).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(_) => break, // channel empty - fall through to flush
                }
            }
            // One flush per burst - one syscall for N frames.
            if sink.flush().await.is_err() {
                break;
            }
        }
    });

    debug!(peer = %peer, "connection established");

    // NIP-42: send AUTH challenge immediately on connect.
    let mut auth = AuthState::new();
    let auth_challenge_msg = format!(r#"["AUTH","{}"]"#, auth.challenge);
    let _ = out_tx.send(Out::Text(auth_challenge_msg)).await;

    let mut subs: HashMap<String, Sub> = HashMap::new();

    // Read loop.
    while let Some(result) = ws_stream.next().await {
        let msg = match result {
            Ok(m) => m,
            Err(e) => {
                warn!(peer = %peer, "ws read error: {e}");
                break;
            }
        };

        match msg {
            WsMsg::Text(raw) => {
                let raw = raw.as_str();

                if raw.len() > config.max_message_bytes {
                    let notice = ServerMsg::Notice {
                        message: "message too large",
                    }
                    .to_json();
                    let _ = out_tx.send(Out::Text(notice)).await;
                    continue;
                }

                match parse_client_msg(raw) {
                    Err(reason) => {
                        let notice = ServerMsg::Notice { message: &reason }.to_json();
                        let _ = out_tx.send(Out::Text(notice)).await;
                    }
                    Ok(ClientMsg::Event(ev)) => {
                        handle_event(*ev, &store, &fanout, &out_tx, &auth).await;
                    }
                    Ok(ClientMsg::Req { sub_id, filters }) => {
                        handle_req(
                            sub_id, filters, &store, &config, &fanout, &live_tx, &out_tx, &mut subs, &auth,
                        )
                        .await;
                    }
                    Ok(ClientMsg::Close { sub_id }) | Ok(ClientMsg::NegClose { sub_id }) => {
                        remove_sub(&sub_id, &mut subs, &fanout, &live_tx).await;
                    }
                    Ok(ClientMsg::Count { sub_id, filters }) => {
                        handle_count(&sub_id, &filters, &store, &out_tx).await;
                    }
                    Ok(ClientMsg::NegOpen { sub_id, filter, msg }) => {
                        // If replacing a Live subscription, unsubscribe from fanout first.
                        remove_sub(&sub_id, &mut subs, &fanout, &live_tx).await;
                        handle_neg_open(
                            sub_id, filter, msg, &store, &config, &auth, &out_tx, &mut subs,
                        ).await;
                    }
                    Ok(ClientMsg::NegMsg { sub_id, msg }) => {
                        handle_neg_msg(sub_id, msg, &out_tx, &mut subs).await;
                    }
                    Ok(ClientMsg::Auth(ev)) => {
                        let id = ev.id.clone();
                        match verify_auth_event(&ev, &auth.challenge, &config.relay_url) {
                            Ok(pubkey) => {
                                auth.authenticated = Some(pubkey.clone());
                                // NIP-17: update shared auth pubkey for the forward task.
                                if let Ok(mut g) = auth_pk_shared.write() {
                                    *g = Some(pubkey);
                                }
                                let ok = ServerMsg::Ok {
                                    id: &id,
                                    accepted: true,
                                    reason: "",
                                }
                                .to_json();
                                let _ = out_tx.send(Out::Text(ok)).await;
                            }
                            Err(reason) => {
                                let ok = ServerMsg::Ok {
                                    id: &id,
                                    accepted: false,
                                    reason: &reason,
                                }
                                .to_json();
                                let _ = out_tx.send(Out::Text(ok)).await;
                            }
                        }
                    }
                }
            }
            WsMsg::Binary(_) => {}
            WsMsg::Ping(_) => {} // tungstenite auto-replies with Pong
            WsMsg::Pong(_) => {}
            WsMsg::Close(_) => break,
            WsMsg::Frame(_) => {}
        }
    }

    // Remove all live subscriptions for this connection.
    fanout.unsubscribe_all(&live_tx).await;
    forward_task.abort();
    write_task.abort();

    debug!(peer = %peer, "connection closed");
    Ok(())
}

async fn handle_event(
    ev: Event,
    store: &Arc<Store>,
    fanout: &Arc<Fanout>,
    out_tx: &mpsc::Sender<Out>,
    auth: &AuthState,
) {
    let id = ev.id.clone();

    if let Err(reason) = validate_event(&ev) {
        send_ok(&id, false, &reason, out_tx).await;
        return;
    }

    // NIP-62: reject events from vanished pubkeys
    if store.is_vanished(&ev.pubkey.0) {
        send_ok(&id, false, "blocked: pubkey vanished", out_tx).await;
        return;
    }

    // NIP-70: reject protected events unless AUTH'd as the event author
    if has_protected_tag(&ev.tags) {
        if auth.authenticated.as_ref() != Some(&ev.pubkey) {
            send_ok(&id, false, "auth-required: protected event", out_tx).await;
            return;
        }
    }

    // Kind classification - ephemeral events skip storage
    let kind_class = classify_kind(ev.kind, &ev.tags);
    if matches!(kind_class, KindClass::Ephemeral) {
        let ev = Arc::new(ev);
        fanout.broadcast(Arc::clone(&ev)).await;
        send_ok(&id, true, "", out_tx).await;
        return;
    }

    // NIP-62: handle vanish requests
    if matches!(&kind_class, KindClass::Vanish) {
        match store.append(&ev) {
            Ok(()) => {
                if let Err(e) = store.vanish(&ev) {
                    warn!("vanish error: {e}");
                }
                let ev = Arc::new(ev);
                fanout.broadcast(Arc::clone(&ev)).await;
                send_ok(&id, true, "", out_tx).await;
            }
            Err(Error::Duplicate) => {
                send_ok(&id, false, "duplicate: already have this event", out_tx).await;
            }
            Err(e) => {
                warn!("store append error: {e}");
                send_ok(&id, false, "error: internal store error", out_tx).await;
            }
        }
        return;
    }

    match store.append(&ev) {
        Ok(()) => {
            let ev = Arc::new(ev);
            if !store.is_tombstoned(&ev.id.0) {
                fanout.broadcast(Arc::clone(&ev)).await;
            }
            send_ok(&id, true, "", out_tx).await;
        }
        Err(Error::Duplicate) => {
            send_ok(&id, false, "duplicate: already have this event", out_tx).await;
        }
        Err(Error::Rejected(reason)) => {
            send_ok(&id, false, reason, out_tx).await;
        }
        Err(e) => {
            warn!("store append error: {e}");
            send_ok(&id, false, "error: internal store error", out_tx).await;
        }
    }
}

/// Sends stored events matching `filters` to the client (as a single batched outbound message),
/// then subscribes the connection for live delivery under `sub_id`.
///
/// This enforces per-connection and per-request limits, clamps each filter's `limit` to the
/// configured maximum, and applies the connection's authenticated pubkey (if any) when querying
/// so kind-1059 ("gift-wrap") visibility follows NIP-17 rules. If subscription limits or filter
/// count are exceeded, a `NOTICE` is sent and the request is rejected. After sending stored
/// matches plus a single `EOSE` message in one outbound batch, the function registers
/// `sub_id -> Sub::Live` (replacing any existing entry) and subscribes the fanout for live events.
///
/// # Parameters
///
/// - `sub_id`: subscription identifier provided by the client.
/// - `filters`: list of filters from the client's `REQ`; each filter's `limit` will be clamped.
/// - `store`, `config`, `fanout`, `live_tx`, `out_tx`, `subs`, `auth`: shared services and per-connection
///   state used to query stored events, enforce limits, publish outbound frames, manage subscriptions,
///   and apply authenticated-pubkey filtering.
///
/// # Examples
///
/// ```no_run
/// # use std::sync::Arc;
/// # use tokio::sync::mpsc;
/// # async fn example() {
/// // placeholder values for illustration only
/// let sub_id = "s1".to_string();
/// let filters = vec![]; // build appropriate Filter values
/// let store = Arc::new(/* Store */ todo!());
/// let config = Arc::new(/* Config */ todo!());
/// let fanout = Arc::new(/* Fanout */ todo!());
/// let (live_tx, _live_rx) = mpsc::channel(16);
/// let (out_tx, _out_rx) = mpsc::channel(16);
/// let mut subs = std::collections::HashMap::new();
/// let auth = /* AuthState */ todo!();
///
/// // call the handler (runs asynchronously)
/// super::handle_req(
///     sub_id,
///     filters,
///     &store,
///     &config,
///     &fanout,
///     &live_tx,
///     &out_tx,
///     &mut subs,
///     &auth,
/// ).await;
/// # }
/// ```
async fn handle_req(
    sub_id: String,
    mut filters: Vec<Filter>,
    store: &Arc<Store>,
    config: &Arc<Config>,
    fanout: &Arc<Fanout>,
    live_tx: &mpsc::Sender<LiveEvent>,
    out_tx: &mpsc::Sender<Out>,
    subs: &mut HashMap<String, Sub>,
    auth: &AuthState,
) {
    if subs.len() >= config.max_subscriptions_per_conn && !subs.contains_key(&sub_id) {
        let msg = ServerMsg::Notice {
            message: "too many subscriptions",
        }
        .to_json();
        let _ = out_tx.send(Out::Text(msg)).await;
        return;
    }
    if filters.len() > config.max_filters_per_req {
        let msg = ServerMsg::Notice {
            message: "too many filters",
        }
        .to_json();
        let _ = out_tx.send(Out::Text(msg)).await;
        return;
    }

    // Clamp filter limits.
    for f in &mut filters {
        if f.limit.map(|l| l > config.max_limit).unwrap_or(false) {
            f.limit = Some(config.max_limit);
        }
    }

    // Send stored events for each filter.
    // Transcode BASED -> JSON directly, bypassing Event struct entirely.
    // Collect all events into a batch, then send once through the channel.
    // This cuts channel operations from N to 1, eliminating per-event async overhead.
    let mut batch: Vec<String> = Vec::with_capacity(128);
    let mut json_buf = String::with_capacity(1024);
    // NIP-17: pass authenticated pubkey so kind-1059 events are filtered.
    let auth_pk = auth.authenticated.as_ref().map(|pk| &pk.0);
    for filter in &filters {
        let sid = sub_id.clone();
        let res = store.query_authed(filter, auth_pk, |dp_bytes| {
            json_buf.clear();
            pack::transcode_to_event_json(dp_bytes, &sid, &mut json_buf)?;
            batch.push(std::mem::take(&mut json_buf));
            Ok(())
        });
        if let Err(e) = res {
            warn!("store query error during REQ: {e}");
        }
    }

    // Append EOSE to the batch so it arrives in the same channel message.
    let eose = ServerMsg::Eose { sub_id: &sub_id }.to_json();
    batch.push(eose);

    // One channel send for all stored events + EOSE.
    let _ = out_tx.send(Out::Batch(batch)).await;

    // If replacing a Neg session, just overwrite; if replacing a Live, fanout.subscribe handles it.
    subs.insert(sub_id.clone(), Sub::Live);
    fanout.subscribe(sub_id, filters, live_tx.clone()).await;
}

/// Sends a NIP-45 `COUNT` response containing the sum of counts for the provided filters.
///
/// The function computes the total by summing `store.count(filter)` for each filter, formats
/// a JSON `["COUNT", <sub_id>, {"count": <total>}]` message (with `sub_id` JSON-escaped),
/// and sends it as `Out::Text` to `out_tx`. Send errors are ignored.
///
/// # Examples
///
/// ```
/// use serde_json;
///
/// // example inputs
/// let sub_id = "s1";
/// let total = 42u64;
/// let escaped_id = serde_json::to_string(sub_id).unwrap();
/// let msg = format!(r#"["COUNT",{},{{"count":{}}}]"#, escaped_id, total);
/// assert_eq!(msg, r#"["COUNT","s1",{"count":42}]"#);
/// ```
async fn handle_count(
    sub_id: &str,
    filters: &[Filter],
    store: &Arc<Store>,
    out_tx: &mpsc::Sender<Out>,
) {
    let total: u64 = filters.iter().map(|f| store.count(f)).sum();
    let escaped_id = serde_json::to_string(sub_id).unwrap_or_else(|_| "\"\"".to_owned());
    let msg = format!(r#"["COUNT",{},{{"count":{}}}]"#, escaped_id, total);
    let _ = out_tx.send(Out::Text(msg)).await;
}

/// Remove a subscription by id from the connection's subscription map.
///
/// If the removed subscription was a live fanout subscription, unsubscribes it from `fanout` using `live_tx`.
///
/// # Examples
///
/// ```no_run
/// use std::sync::Arc;
/// use std::collections::HashMap;
/// use tokio::sync::mpsc;
///
/// // assume `Sub`, `Fanout`, and `LiveEvent` are available in scope
/// # async fn example(
/// #     fanout: Arc<Fanout>,
/// #     live_tx: mpsc::Sender<LiveEvent>,
/// # ) {
/// let mut subs: HashMap<String, Sub> = HashMap::new();
/// subs.insert("sub1".to_string(), Sub::Live);
///
/// // remove the subscription; if it was Live, `fanout.unsubscribe` will be awaited
/// remove_sub("sub1", &mut subs, &fanout, &live_tx).await;
/// # }
/// ```
async fn remove_sub(
    sub_id: &str,
    subs: &mut HashMap<String, Sub>,
    fanout: &Arc<Fanout>,
    live_tx: &mpsc::Sender<LiveEvent>,
) {
    if let Some(Sub::Live) = subs.remove(sub_id) {
        fanout.unsubscribe(sub_id, live_tx).await;
    }
}

/// Creates a server-side Negentropy session for `sub_id` from stored server state, runs the first
/// reconciliation round with the client's initial message, and stores the session on success.
///
/// If the connection has reached the maximum subscriptions limit, an error `NOTICE` is sent and the
/// function returns. On storage/seal/negentropy construction or reconcile errors, a `NEG-ERR` is
/// sent. On successful reconcile, a `NEG-MSG` reply is sent and the session is inserted into
/// `subs` as `Sub::Neg` for subsequent rounds driven by `NEG-MSG` from the client.
///
/// # Examples
///
/// ```no_run
/// # use std::sync::Arc;
/// # use tokio::sync::mpsc;
/// # use std::collections::HashMap;
/// # async fn example() {
/// // placeholders for required values:
/// // let sub_id = "s1".to_string();
/// // let filter = Filter::default();
/// // let msg = vec![/* client initial negentropy message bytes */];
/// // handle_neg_open(sub_id, filter, msg, &store, &config, &auth, &out_tx, &mut subs).await;
/// # }
/// ```
async fn handle_neg_open(
    sub_id: String,
    filter: Filter,
    msg: Vec<u8>,
    store: &Arc<Store>,
    config: &Arc<Config>,
    auth: &AuthState,
    out_tx: &mpsc::Sender<Out>,
    subs: &mut HashMap<String, Sub>,
) {
    // Check subscription limit (caller already removed any existing sub with this id).
    if subs.len() >= config.max_subscriptions_per_conn {
        let notice = ServerMsg::Notice { message: "too many subscriptions" }.to_json();
        let _ = out_tx.send(Out::Text(notice)).await;
        return;
    }

    // Build the negentropy storage.
    let auth_pk = auth.authenticated.as_ref().map(|pk| &pk.0);
    let mut storage = NegentropyStorageVector::new();
    let mut insert_error: Option<String> = None;

    if let Err(e) = store.iter_negentropy(&filter, auth_pk, |ts, id| {
        if insert_error.is_none() {
            if let Err(e) = storage.insert(ts as u64, NegId::from_byte_array(id)) {
                insert_error = Some(e.to_string());
            }
        }
    }) {
        let err = ServerMsg::NegErr { sub_id: &sub_id, reason: &e.to_string() }.to_json();
        let _ = out_tx.send(Out::Text(err)).await;
        return;
    }

    if let Some(err_msg) = insert_error {
        let err = ServerMsg::NegErr { sub_id: &sub_id, reason: &err_msg }.to_json();
        let _ = out_tx.send(Out::Text(err)).await;
        return;
    }

    if let Err(e) = storage.seal() {
        let err = ServerMsg::NegErr { sub_id: &sub_id, reason: &e.to_string() }.to_json();
        let _ = out_tx.send(Out::Text(err)).await;
        return;
    }

    let mut neg = match Negentropy::owned(storage, config.max_message_bytes as u64) {
        Ok(n) => n,
        Err(e) => {
            let err = ServerMsg::NegErr { sub_id: &sub_id, reason: &e.to_string() }.to_json();
            let _ = out_tx.send(Out::Text(err)).await;
            return;
        }
    };

    // Reconcile.
    match neg.reconcile(&msg) {
        Err(e) => {
            let err = ServerMsg::NegErr { sub_id: &sub_id, reason: &e.to_string() }.to_json();
            let _ = out_tx.send(Out::Text(err)).await;
        }
        Ok(reply) => {
            let resp = ServerMsg::NegMsg { sub_id: &sub_id, msg: &reply }.to_json();
            let _ = out_tx.send(Out::Text(resp)).await;
            // Always store the session — the client drives NEG-CLOSE when done.
            // The server-side reconcile reply is never empty (always contains at
            // least the protocol-version byte), so there is no first-round
            // "already done" signal on the server side.
            subs.insert(sub_id, Sub::Neg(Box::new(neg)));
        }
    }
}

/// Processes an incoming Negentropy (`NEG-MSG`) payload for a named subscription session.
///
/// Looks up a Negentropy session by `sub_id` in `subs`. If no session exists, sends a
/// `ServerMsg::NegErr { "session not found" }` and returns. Otherwise, attempts to reconcile
/// the session with `msg`. On reconcile error, sends `ServerMsg::NegErr { reason }` and
/// removes the session from `subs`. On success, sends `ServerMsg::NegMsg { msg: <reply> }`
/// and leaves the session active until explicitly closed by the client.
///
/// # Parameters
///
/// - `sub_id`: subscription identifier associated with the Negentropy session.
/// - `msg`: incoming Negentropy message bytes from the client.
/// - `out_tx`: outbound channel used to send serialized `ServerMsg` frames to the write task.
/// - `subs`: mutable map of active subscriptions; a failing reconcile will remove the entry.
///
/// # Examples
///
/// ```ignore
/// // Example (illustrative): receive a NEG-MSG for an existing negentropy session.
/// // `out_tx` and `subs` would be created/managed by the connection handler.
/// let sub_id = "neg-123".to_string();
/// let incoming = vec![ /* negentropy payload bytes */ ];
/// // handle_neg_msg(sub_id, incoming, &out_tx, &mut subs).await;
/// ```
async fn handle_neg_msg(
    sub_id: String,
    msg: Vec<u8>,
    out_tx: &mpsc::Sender<Out>,
    subs: &mut HashMap<String, Sub>,
) {
    let neg = match subs.get_mut(&sub_id) {
        Some(Sub::Neg(n)) => n,
        _ => {
            let err = ServerMsg::NegErr { sub_id: &sub_id, reason: "session not found" }.to_json();
            let _ = out_tx.send(Out::Text(err)).await;
            return;
        }
    };

    match neg.reconcile(&msg) {
        Err(e) => {
            let err = ServerMsg::NegErr { sub_id: &sub_id, reason: &e.to_string() }.to_json();
            let _ = out_tx.send(Out::Text(err)).await;
            subs.remove(&sub_id);
        }
        Ok(reply) => {
            let resp = ServerMsg::NegMsg { sub_id: &sub_id, msg: &reply }.to_json();
            let _ = out_tx.send(Out::Text(resp)).await;
            // Session stays alive until client sends NEG-CLOSE.
        }
    }
}

// Integration tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::Tag;
    use crate::test_util::make_event;
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::Message as TMsg;

    fn event_json(ev: &Event) -> String {
        use crate::nostr::hex_encode_bytes as hex;
        let id_hex = hex(&ev.id.0);
        let pk_hex = hex(&ev.pubkey.0);
        let sig_hex = hex(&ev.sig.0);
        let tags: Vec<Vec<String>> = ev.tags.iter().map(|t| t.fields.clone()).collect();
        format!(
            r#"{{"id":"{id_hex}","pubkey":"{pk_hex}","created_at":{},"kind":{},"tags":{},"content":{},"sig":"{sig_hex}"}}"#,
            ev.created_at,
            ev.kind,
            serde_json::to_string(&tags).unwrap(),
            serde_json::to_string(&ev.content).unwrap(),
        )
    }

    fn event_msg(ev: &Event) -> String {
        format!("[\"EVENT\",{}]", event_json(ev))
    }

    type WsClient = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    async fn connect(port: u16) -> WsClient {
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}"))
            .await
            .unwrap();
        ws
    }

    async fn recv_text(ws: &mut WsClient) -> String {
        loop {
            match ws.next().await.unwrap().unwrap() {
                TMsg::Text(s) => {
                    // Skip AUTH challenges transparently so existing tests don't need updating.
                    if s.as_str().starts_with(r#"["AUTH""#) {
                        continue;
                    }
                    return s.to_string();
                }
                TMsg::Ping(_) | TMsg::Pong(_) => continue,
                other => panic!("unexpected: {other:?}"),
            }
        }
    }

    /// Receive the first text frame verbatim, including AUTH challenges.
    async fn recv_text_raw(ws: &mut WsClient) -> String {
        loop {
            match ws.next().await.unwrap().unwrap() {
                TMsg::Text(s) => return s.to_string(),
                TMsg::Ping(_) | TMsg::Pong(_) => continue,
                other => panic!("unexpected: {other:?}"),
            }
        }
    }

    async fn spawn_server() -> (u16, Arc<Store>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let dir = tempfile::tempdir().unwrap();
        // Keep tempdir alive for the life of the server by moving it into the task.
        let store_path = dir.keep();
        let store = Arc::new(Store::open(&store_path).unwrap());
        let config = Arc::new(Config {
            relay_url: format!("ws://127.0.0.1:{port}"),
            ..Config::default()
        });
        let fanout = Fanout::new();

        let srv_store = Arc::clone(&store);
        let srv_config = Arc::clone(&config);
        let srv_fanout = Arc::clone(&fanout);

        tokio::spawn(async move {
            loop {
                if let Ok((stream, peer)) = listener.accept().await {
                    let s = Arc::clone(&srv_store);
                    let c = Arc::clone(&srv_config);
                    let f = Arc::clone(&srv_fanout);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, peer, s, c, f).await {
                            warn!("test server conn error: {e}");
                        }
                    });
                }
            }
        });

        (port, store)
    }

    #[tokio::test]
    async fn test_valid_event_accepted() {
        let (port, _) = spawn_server().await;
        let mut ws = connect(port).await;
        let ev = make_event(1, 1, 1_700_000_000, vec![]);
        ws.send(TMsg::Text(event_msg(&ev).into())).await.unwrap();
        let resp = recv_text(&mut ws).await;
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v[0], "OK");
        assert_eq!(v[2], true, "event must be accepted: {resp}");
    }

    #[tokio::test]
    async fn test_invalid_event_rejected() {
        let (port, _) = spawn_server().await;
        let mut ws = connect(port).await;
        let mut ev = make_event(1, 1, 1_700_000_000, vec![]);
        ev.sig.0[0] ^= 0xFF; // corrupt sig - id is still correct
        ws.send(TMsg::Text(event_msg(&ev).into())).await.unwrap();
        let resp = recv_text(&mut ws).await;
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v[0], "OK");
        assert_eq!(v[2], false, "bad sig must be rejected: {resp}");
    }

    #[tokio::test]
    async fn test_req_stored_events_and_eose() {
        let (port, store) = spawn_server().await;
        for i in 1u8..=3 {
            store
                .append(&make_event(i, 1, i as i64 * 1000, vec![]))
                .unwrap();
        }

        let mut ws = connect(port).await;
        ws.send(TMsg::Text(r#"["REQ","s1",{"kinds":[1]}]"#.into()))
            .await
            .unwrap();

        let mut events = 0;
        let mut got_eose = false;
        for _ in 0..20 {
            let resp = recv_text(&mut ws).await;
            let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
            match v[0].as_str().unwrap() {
                "EVENT" => {
                    assert_eq!(v[1], "s1");
                    events += 1;
                }
                "EOSE" => {
                    assert_eq!(v[1], "s1");
                    got_eose = true;
                    break;
                }
                _ => {}
            }
        }
        assert_eq!(events, 3, "3 stored events expected");
        assert!(got_eose, "EOSE expected");
    }

    #[tokio::test]
    async fn test_req_empty_store_eose() {
        let (port, _) = spawn_server().await;
        let mut ws = connect(port).await;
        ws.send(TMsg::Text(r#"["REQ","s1",{}]"#.into()))
            .await
            .unwrap();
        let resp = recv_text(&mut ws).await;
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v[0], "EOSE");
        assert_eq!(v[1], "s1");
    }

    #[tokio::test]
    async fn test_live_delivery_two_clients() {
        let (port, _) = spawn_server().await;
        let mut subscriber = connect(port).await;
        let mut publisher = connect(port).await;

        subscriber
            .send(TMsg::Text(r#"["REQ","live",{"kinds":[1]}]"#.into()))
            .await
            .unwrap();
        // Wait for EOSE.
        loop {
            let r = recv_text(&mut subscriber).await;
            if r.contains("EOSE") {
                break;
            }
        }

        let ev = make_event(2, 1, 1_700_000_001, vec![]);
        publisher.send(TMsg::Text(event_msg(&ev).into())).await.unwrap();
        let ok = recv_text(&mut publisher).await;
        assert!(ok.contains("true"), "publish must succeed: {ok}");

        let live = recv_text(&mut subscriber).await;
        let v: serde_json::Value = serde_json::from_str(&live).unwrap();
        assert_eq!(v[0], "EVENT", "subscriber must get live event: {live}");
        assert_eq!(v[1], "live");
    }

    #[tokio::test]
    async fn test_close_stops_delivery() {
        let (port, _) = spawn_server().await;
        let mut subscriber = connect(port).await;
        let mut publisher = connect(port).await;

        subscriber
            .send(TMsg::Text(r#"["REQ","live",{"kinds":[1]}]"#.into()))
            .await
            .unwrap();
        loop {
            let r = recv_text(&mut subscriber).await;
            if r.contains("EOSE") {
                break;
            }
        }

        subscriber
            .send(TMsg::Text(r#"["CLOSE","live"]"#.into()))
            .await
            .unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;

        let ev = make_event(2, 1, 1_700_000_002, vec![]);
        publisher.send(TMsg::Text(event_msg(&ev).into())).await.unwrap();
        let _ = recv_text(&mut publisher).await;

        let r = tokio::time::timeout(
            tokio::time::Duration::from_millis(80),
            recv_text(&mut subscriber),
        )
        .await;
        assert!(r.is_err(), "no live event expected after CLOSE");
    }

    #[tokio::test]
    async fn test_oversized_message_notice_connection_stays_open() {
        let (port, _) = spawn_server().await;
        let mut ws = connect(port).await;
        let big = "x".repeat(200 * 1024);
        let msg = format!(r#"["REQ","s",{{"ids":["{big}"]}}]"#);
        ws.send(TMsg::Text(msg.into())).await.unwrap();
        let resp = recv_text(&mut ws).await;
        assert!(resp.contains("NOTICE"), "expected NOTICE: {resp}");
        // Connection must remain alive.
        ws.send(TMsg::Text(r#"["REQ","alive",{}]"#.into()))
            .await
            .unwrap();
        let eose = recv_text(&mut ws).await;
        assert!(
            eose.contains("EOSE"),
            "connection must still be alive: {eose}"
        );
    }

    #[tokio::test]
    async fn test_or_filter_semantics() {
        let (port, store) = spawn_server().await;
        store.append(&make_event(1, 1, 1000, vec![])).unwrap();
        store.append(&make_event(2, 2, 2000, vec![])).unwrap();

        let mut ws = connect(port).await;
        ws.send(TMsg::Text(
            r#"["REQ","s1",{"kinds":[1]},{"kinds":[2]}]"#.into(),
        ))
        .await
        .unwrap();

        let mut events = 0;
        for _ in 0..20 {
            let resp = recv_text(&mut ws).await;
            let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
            match v[0].as_str().unwrap() {
                "EVENT" => events += 1,
                "EOSE" => break,
                _ => {}
            }
        }
        // OR semantics: each filter runs independently, so both events should be returned.
        assert_eq!(events, 2, "OR filter: 2 events expected");
    }

    #[tokio::test]
    async fn test_duplicate_sub_id_replaced() {
        let (port, store) = spawn_server().await;
        // Store one kind-1 and one kind-2.
        store.append(&make_event(1, 1, 1000, vec![])).unwrap();
        store.append(&make_event(2, 2, 2000, vec![])).unwrap();

        let mut ws = connect(port).await;
        // First REQ: only kind-1.
        ws.send(TMsg::Text(r#"["REQ","s1",{"kinds":[1]}]"#.into()))
            .await
            .unwrap();
        let mut ev1 = 0;
        loop {
            let r = recv_text(&mut ws).await;
            let v: serde_json::Value = serde_json::from_str(&r).unwrap();
            match v[0].as_str().unwrap() {
                "EVENT" => ev1 += 1,
                "EOSE" => break,
                _ => {}
            }
        }
        assert_eq!(ev1, 1, "first REQ: one kind-1 event");

        // Second REQ with same sub_id: only kind-2 (replaces first).
        ws.send(TMsg::Text(r#"["REQ","s1",{"kinds":[2]}]"#.into()))
            .await
            .unwrap();
        let mut ev2 = 0;
        loop {
            let r = recv_text(&mut ws).await;
            let v: serde_json::Value = serde_json::from_str(&r).unwrap();
            match v[0].as_str().unwrap() {
                "EVENT" => ev2 += 1,
                "EOSE" => break,
                _ => {}
            }
        }
        assert_eq!(ev2, 1, "second REQ: one kind-2 event");
    }

    // NIP-42 handler tests

    fn make_auth_event_for_conn(
        sk_scalar: u8,
        challenge: &str,
        relay_url: &str,
        created_at_offset: i64,
    ) -> Event {
        use crate::nostr::canonical_json;
        use crate::pack::{EventId, Sig, Tag};
        use secp256k1::{Keypair, Secp256k1, SecretKey};
        use sha2::{Digest, Sha256};
        use std::time::{SystemTime, UNIX_EPOCH};

        let secp = Secp256k1::new();
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = sk_scalar;
        let sk = SecretKey::from_byte_array(sk_bytes).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mut ev = Event {
            id: EventId([0u8; 32]),
            pubkey: crate::pack::Pubkey(xonly.serialize()),
            sig: Sig([0u8; 64]),
            created_at: now + created_at_offset,
            kind: 22242,
            tags: vec![
                Tag {
                    fields: vec!["challenge".to_owned(), challenge.to_owned()],
                },
                Tag {
                    fields: vec!["relay".to_owned(), relay_url.to_owned()],
                },
            ],
            content: String::new(),
        };
        let hash = Sha256::digest(canonical_json(&ev).as_bytes());
        ev.id.0.copy_from_slice(&hash);
        let sig = secp.sign_schnorr_no_aux_rand(hash.as_slice(), &kp);
        ev.sig.0.copy_from_slice(&sig.to_byte_array());
        ev
    }

    #[tokio::test]
    async fn test_nip42_auth_challenge_sent_on_connect() {
        let (port, _) = spawn_server().await;
        let mut ws = connect(port).await;
        let first = recv_text_raw(&mut ws).await;
        let v: serde_json::Value = serde_json::from_str(&first).unwrap();
        assert_eq!(v[0], "AUTH", "first message must be AUTH: {first}");
        assert!(v[1].is_string(), "AUTH challenge must be a string");
        let challenge = v[1].as_str().unwrap();
        assert_eq!(challenge.len(), 32, "challenge must be 32 chars");
    }

    #[tokio::test]
    async fn test_nip42_valid_auth_accepted() {
        let (port, _) = spawn_server().await;
        let mut ws = connect(port).await;

        let first = recv_text_raw(&mut ws).await;
        let v: serde_json::Value = serde_json::from_str(&first).unwrap();
        let challenge = v[1].as_str().unwrap().to_owned();

        let relay_url = format!("ws://127.0.0.1:{port}");
        let ev = make_auth_event_for_conn(1, &challenge, &relay_url, 0);
        let auth_msg = format!(r#"["AUTH",{}]"#, event_json(&ev));
        ws.send(TMsg::Text(auth_msg.into())).await.unwrap();

        let resp = recv_text(&mut ws).await;
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v[0], "OK", "AUTH response must be OK: {resp}");
        assert_eq!(v[2], true, "valid auth must be accepted: {resp}");
    }

    #[tokio::test]
    async fn test_nip42_wrong_challenge_rejected() {
        let (port, _) = spawn_server().await;
        let mut ws = connect(port).await;
        // Consume the AUTH challenge but use a different one for the event.
        let _ = recv_text_raw(&mut ws).await;

        let relay_url = format!("ws://127.0.0.1:{port}");
        let ev = make_auth_event_for_conn(1, "wrongchallenge1234567890123456", &relay_url, 0);
        let auth_msg = format!(r#"["AUTH",{}]"#, event_json(&ev));
        ws.send(TMsg::Text(auth_msg.into())).await.unwrap();

        let resp = recv_text(&mut ws).await;
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v[0], "OK");
        assert_eq!(v[2], false, "wrong challenge must be rejected: {resp}");
    }

    #[tokio::test]
    async fn test_nip42_kind22242_not_stored() {
        let (port, store) = spawn_server().await;
        let mut ws = connect(port).await;

        let first = recv_text_raw(&mut ws).await;
        let v: serde_json::Value = serde_json::from_str(&first).unwrap();
        let challenge = v[1].as_str().unwrap().to_owned();

        let relay_url = format!("ws://127.0.0.1:{port}");
        let ev = make_auth_event_for_conn(1, &challenge, &relay_url, 0);
        let auth_msg = format!(r#"["AUTH",{}]"#, event_json(&ev));
        ws.send(TMsg::Text(auth_msg.into())).await.unwrap();
        let _ = recv_text(&mut ws).await; // consume OK

        // A REQ for all events should return 0 stored events (AUTH event not stored).
        ws.send(TMsg::Text(r#"["REQ","s1",{}]"#.into()))
            .await
            .unwrap();
        let mut event_count = 0;
        loop {
            let r = recv_text(&mut ws).await;
            let v: serde_json::Value = serde_json::from_str(&r).unwrap();
            match v[0].as_str().unwrap() {
                "EVENT" => event_count += 1,
                "EOSE" => break,
                _ => {}
            }
        }
        assert_eq!(event_count, 0, "kind-22242 must not be stored");
        assert_eq!(store.event_count(), 0, "store must be empty");
    }

    #[tokio::test]
    async fn test_ephemeral_event_not_stored() {
        let (port, _store) = spawn_server().await;
        let mut ws = connect(port).await;
        // recv_text() already skips AUTH challenges transparently

        // Send ephemeral event (kind 20001)
        let ev = make_event(1, 20001, 0, vec![]);
        let msg = event_msg(&ev);
        ws.send(msg.into()).await.unwrap();

        // Should get OK true
        let resp = recv_text(&mut ws).await;
        assert!(resp.contains("true"), "ephemeral event should be accepted: {resp}");

        // Query for it - should NOT be stored
        let req = format!(r#"["REQ","sub1",{{"kinds":[20001]}}]"#);
        ws.send(req.into()).await.unwrap();
        let resp = recv_text(&mut ws).await;
        // Should get EOSE immediately with no events
        assert!(resp.contains("EOSE"), "ephemeral should not be in store: {resp}");
    }

    #[tokio::test]
    async fn test_ephemeral_event_broadcast_to_subscribers() {
        let (port, _store) = spawn_server().await;
        let mut ws1 = connect(port).await;
        let mut ws2 = connect(port).await;

        // ws2 subscribes to ephemeral kind
        let req = r#"["REQ","sub1",{"kinds":[20001]}]"#;
        ws2.send(req.into()).await.unwrap();
        let eose = recv_text(&mut ws2).await;
        assert!(eose.contains("EOSE"));

        // ws1 sends ephemeral event
        let ev = make_event(1, 20001, 0, vec![]);
        ws1.send(event_msg(&ev).into()).await.unwrap();
        let _ = recv_text(&mut ws1).await; // OK

        // ws2 should receive it via live subscription
        let live = recv_text(&mut ws2).await;
        assert!(live.contains("EVENT"), "ephemeral should be broadcast: {live}");
    }

    #[tokio::test]
    async fn test_protected_event_rejected_without_auth() {
        let (port, _store) = spawn_server().await;
        let mut ws = connect(port).await;
        // recv_text() already skips AUTH challenges transparently

        // Send event with protected tag ["-"] - without AUTH
        let ev = make_event(1, 1, 0, vec![Tag { fields: vec!["-".into()] }]);
        let msg = event_msg(&ev);
        ws.send(msg.into()).await.unwrap();

        let resp = recv_text(&mut ws).await;
        assert!(resp.contains("false"), "protected event should be rejected: {resp}");
        assert!(resp.contains("auth-required"), "should mention auth-required: {resp}");
    }

    #[tokio::test]
    async fn test_vanish_blocks_future_events() {
        let (port, _store) = spawn_server().await;
        let mut ws = connect(port).await;

        // Store a regular event from author 1
        let ev1 = make_event(1, 1, 0, vec![]);
        ws.send(event_msg(&ev1).into()).await.unwrap();
        let resp = recv_text(&mut ws).await;
        assert!(resp.contains("true"));

        // Send vanish (kind 62) from author 1
        let vanish = make_event(1, 62, 0, vec![]);
        ws.send(event_msg(&vanish).into()).await.unwrap();
        let resp = recv_text(&mut ws).await;
        assert!(resp.contains("true"), "vanish should be accepted: {resp}");

        // Try to send another event from author 1 - should be blocked
        let ev2 = make_event(1, 1, 0, vec![Tag { fields: vec!["x".into()] }]);
        ws.send(event_msg(&ev2).into()).await.unwrap();
        let resp = recv_text(&mut ws).await;
        assert!(resp.contains("false"), "post-vanish event should be rejected: {resp}");
        assert!(resp.contains("vanished"), "should mention vanished: {resp}");
    }

    #[tokio::test]
    async fn test_nip42_unauthenticated_req_works() {
        let (port, store) = spawn_server().await;
        store
            .append(&make_event(1, 1, 1_700_000_000, vec![]))
            .unwrap();

        let mut ws = connect(port).await;
        ws.send(TMsg::Text(r#"["REQ","s1",{"kinds":[1]}]"#.into()))
            .await
            .unwrap();

        let mut count = 0;
        loop {
            let r = recv_text(&mut ws).await;
            let v: serde_json::Value = serde_json::from_str(&r).unwrap();
            match v[0].as_str().unwrap() {
                "EVENT" => count += 1,
                "EOSE" => break,
                _ => {}
            }
        }
        assert_eq!(count, 1, "unauthenticated REQ must still work");
    }

    // NIP-45 COUNT handler tests

    #[tokio::test]
    async fn test_count_response() {
        let (port, _store) = spawn_server().await;
        let mut ws = connect(port).await;

        // Store some events
        let ev1 = make_event(1, 1, 0, vec![]);
        ws.send(event_msg(&ev1).into()).await.unwrap();
        let _ = recv_text(&mut ws).await; // OK

        let ev2 = make_event(1, 1, 0, vec![Tag { fields: vec!["x".into()] }]);
        ws.send(event_msg(&ev2).into()).await.unwrap();
        let _ = recv_text(&mut ws).await; // OK

        // Send COUNT
        let count_msg = r#"["COUNT","c1",{"kinds":[1]}]"#;
        ws.send(count_msg.into()).await.unwrap();
        let resp = recv_text(&mut ws).await;
        assert!(resp.contains("COUNT"), "should be COUNT response: {resp}");
        assert!(resp.contains(r#""count":2"#), "should count 2 events: {resp}");
    }

    // NIP-17 private DM tests

    /// Helper: authenticate a WebSocket client and return the pubkey bytes.
    async fn authenticate(ws: &mut WsClient, port: u16, sk_scalar: u8) -> [u8; 32] {
        // recv_text_raw gets the raw first frame (the AUTH challenge).
        // recv_text would skip it.
        let first = recv_text_raw(ws).await;
        let v: serde_json::Value = serde_json::from_str(&first).unwrap();
        let challenge = v[1].as_str().unwrap().to_owned();

        let relay_url = format!("ws://127.0.0.1:{port}");
        let ev = make_auth_event_for_conn(sk_scalar, &challenge, &relay_url, 0);
        let pubkey = ev.pubkey.0;
        let auth_msg = format!(r#"["AUTH",{}]"#, event_json(&ev));
        ws.send(TMsg::Text(auth_msg.into())).await.unwrap();

        let resp = recv_text(ws).await;
        assert!(resp.contains("true"), "auth must succeed: {resp}");
        pubkey
    }

    #[tokio::test]
    async fn test_nip17_gift_wrap_hidden_from_unauthenticated() {
        let (port, store) = spawn_server().await;

        // Compute recipient pubkey (sk_scalar=2)
        let secp = secp256k1::Secp256k1::new();
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 2;
        let sk = secp256k1::SecretKey::from_byte_array(sk_bytes).unwrap();
        let kp = secp256k1::Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();
        let recipient_hex = crate::nostr::hex_encode_bytes(&xonly.serialize());

        // Store a kind-1059 gift-wrapped event with p-tag pointing to recipient.
        let ev = make_event(1, 1059, 1_700_000_000, vec![
            Tag { fields: vec!["p".into(), recipient_hex] },
        ]);
        store.append(&ev).unwrap();

        // Unauthenticated client queries for kind 1059 - should get nothing.
        let mut ws = connect(port).await;
        ws.send(TMsg::Text(r#"["REQ","s1",{"kinds":[1059]}]"#.into()))
            .await.unwrap();
        let resp = recv_text(&mut ws).await;
        assert!(resp.contains("EOSE"), "unauthenticated should get only EOSE: {resp}");
    }

    #[tokio::test]
    async fn test_nip17_gift_wrap_visible_to_recipient() {
        let (port, store) = spawn_server().await;

        // Recipient is sk_scalar=1
        let secp = secp256k1::Secp256k1::new();
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 1;
        let sk = secp256k1::SecretKey::from_byte_array(sk_bytes).unwrap();
        let kp = secp256k1::Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();
        let recipient_hex = crate::nostr::hex_encode_bytes(&xonly.serialize());

        // Store a kind-1059 event with p-tag pointing to recipient (sk=1).
        let ev = make_event(3, 1059, 1_700_000_000, vec![
            Tag { fields: vec!["p".into(), recipient_hex] },
        ]);
        store.append(&ev).unwrap();

        // Connect and authenticate as the recipient (sk=1).
        let mut ws = connect(port).await;
        let _pk = authenticate(&mut ws, port, 1).await;

        // Query for kind 1059 - should get the event.
        ws.send(TMsg::Text(r#"["REQ","s1",{"kinds":[1059]}]"#.into()))
            .await.unwrap();
        let mut event_count = 0;
        loop {
            let r = recv_text(&mut ws).await;
            let v: serde_json::Value = serde_json::from_str(&r).unwrap();
            match v[0].as_str().unwrap() {
                "EVENT" => event_count += 1,
                "EOSE" => break,
                _ => {}
            }
        }
        assert_eq!(event_count, 1, "recipient should see their gift-wrapped DM");
    }

    #[tokio::test]
    async fn test_nip17_gift_wrap_hidden_from_non_recipient() {
        let (port, store) = spawn_server().await;

        // Recipient is sk_scalar=2
        let secp = secp256k1::Secp256k1::new();
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = 2;
        let sk = secp256k1::SecretKey::from_byte_array(sk_bytes).unwrap();
        let kp = secp256k1::Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();
        let recipient_hex = crate::nostr::hex_encode_bytes(&xonly.serialize());

        // Store a kind-1059 event addressed to sk=2.
        let ev = make_event(3, 1059, 1_700_000_000, vec![
            Tag { fields: vec!["p".into(), recipient_hex] },
        ]);
        store.append(&ev).unwrap();

        // Connect and authenticate as a DIFFERENT user (sk=1).
        let mut ws = connect(port).await;
        let _pk = authenticate(&mut ws, port, 1).await;

        // Query for kind 1059 - should NOT see events addressed to someone else.
        ws.send(TMsg::Text(r#"["REQ","s1",{"kinds":[1059]}]"#.into()))
            .await.unwrap();
        let resp = recv_text(&mut ws).await;
        assert!(resp.contains("EOSE"), "non-recipient should get only EOSE: {resp}");
    }

    // NIP-77 Negentropy tests

    use negentropy::{Id as NegId, Negentropy as Neg, NegentropyStorageVector, Storage as NegStorage};

    /// Builds a sealed Negentropy storage from the given (timestamp, id) items and returns it
    /// together with the client's initial Negentropy message encoded as hex.
    ///
    /// The `items` slice should contain pairs of (timestamp, 32-byte event id). The returned
    /// `NegentropyStorageVector` is sealed and ready for use by a `Negentropy` session. The
    /// hex string is the client's initial `NEG-MSG` payload (ready to send to the peer).
    ///
    /// # Examples
    ///
    /// ```
    /// let items = vec![(1u64, [0u8; 32]), (2u64, [1u8; 32])];
    /// let (storage, hex_msg) = crate::ws::handler::neg_initiate(&items);
    /// // storage is sealed and non-empty; hex_msg is a non-empty hex string
    /// assert!(!hex_msg.is_empty());
    /// assert!(storage.len() >= 2);
    /// ```
    fn neg_initiate(items: &[(u64, [u8; 32])]) -> (NegentropyStorageVector, String) {
        let mut storage = NegentropyStorageVector::new();
        for (ts, id) in items {
            storage.insert(*ts, NegId::from_byte_array(*id)).unwrap();
        }
        storage.seal().unwrap();
        let mut client = Neg::new(NegStorage::Borrowed(&storage), 0).unwrap();
        let init_msg = client.initiate().unwrap();
        let hex_msg = crate::nostr::hex_encode_bytes(&init_msg);
        (storage, hex_msg)
    }

    /// Perform a client-side Negentropy reconciliation loop over a WebSocket.
    ///
    /// The function drives a local `Neg` instance by exchanging `NEG-MSG` frames with the remote
    /// peer until reconciliation completes, then returns the final `(have_ids, need_ids)` vectors
    /// produced by the local side.
    ///
    /// # Examples
    ///
    /// ```
    /// // This example demonstrates the call shape; test helpers for creating `WsClient`,
    /// // `NegentropyStorageVector` and `initial_reply` are provided by the test harness.
    /// # async fn run_example(ws: &mut crate::tests::WsClient, storage: &crate::negentropy::NegentropyStorageVector, sub_id: &str, initial_reply: Vec<u8>) {
    /// let (have, need) = crate::ws::handler::neg_reconcile(ws, sub_id, storage, initial_reply).await;
    /// // `have` contains IDs the client claims to have; `need` contains IDs the client requests.
    /// # }
    /// ```
    async fn neg_reconcile(
        ws: &mut WsClient,
        sub_id: &str,
        storage: &NegentropyStorageVector,
        initial_reply: Vec<u8>,
    ) -> (Vec<NegId>, Vec<NegId>) {
        let mut client = Neg::new(NegStorage::Borrowed(storage), 0).unwrap();
        let _init = client.initiate().unwrap();
        let mut have_ids = Vec::new();
        let mut need_ids = Vec::new();
        let mut current_reply = initial_reply;
        loop {
            match client.reconcile_with_ids(&current_reply, &mut have_ids, &mut need_ids).unwrap() {
                None => break,
                Some(next_msg) => {
                    let hex = crate::nostr::hex_encode_bytes(&next_msg);
                    let msg = format!(r#"["NEG-MSG","{}","{hex}"]"#, sub_id);
                    ws.send(TMsg::Text(msg.into())).await.unwrap();
                    let resp = recv_text(ws).await;
                    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
                    assert_eq!(v[0], "NEG-MSG", "expected NEG-MSG, got: {resp}");
                    let hex_reply = v[2].as_str().unwrap();
                    current_reply = vec![0u8; hex_reply.len() / 2];
                    crate::pack::hex::decode(hex_reply.as_bytes(), &mut current_reply).unwrap();
                }
            }
        }
        (have_ids, need_ids)
    }

    /// Performs a NEG-OPEN handshake over the provided WebSocket client and returns the decoded reply bytes.
    ///
    /// Sends a `NEG-OPEN` message using `sub_id`, `filter_json`, and `hex_msg`, then waits for a `NEG-MSG` response
    /// with the same `sub_id` and decodes its hex payload to raw bytes.
    ///
    /// # Parameters
    ///
    /// - `ws`: the WebSocket test client to use for sending and receiving messages.
    /// - `sub_id`: subscription identifier used in the `NEG-OPEN` and expected in the `NEG-MSG` reply.
    /// - `filter_json`: a JSON string representing the filter argument included in the `NEG-OPEN` frame.
    /// - `hex_msg`: the initial hex-encoded message payload sent with `NEG-OPEN`.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the bytes decoded from the hex payload of the received `NEG-MSG`.
    ///
    /// # Examples
    ///
    /// ```
    /// # async fn _example(ws: &mut crate::tests::WsClient) {
    /// let sub_id = "s1";
    /// let filter_json = r#"{"kind":[1]}"#;
    /// let hex_msg = "deadbeef";
    /// let reply_bytes = crate::ws::handler::neg_open(ws, sub_id, filter_json, hex_msg).await;
    /// assert!(!reply_bytes.is_empty());
    /// # }
    /// ```
    async fn neg_open(ws: &mut WsClient, sub_id: &str, filter_json: &str, hex_msg: &str) -> Vec<u8> {
        let msg = format!(r#"["NEG-OPEN","{}",{},"{hex_msg}"]"#, sub_id, filter_json);
        ws.send(TMsg::Text(msg.into())).await.unwrap();
        let resp = recv_text(ws).await;
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v[0], "NEG-MSG", "expected NEG-MSG, got: {resp}");
        assert_eq!(v[1], sub_id);
        let hex = v[2].as_str().unwrap();
        let mut bytes = vec![0u8; hex.len() / 2];
        crate::pack::hex::decode(hex.as_bytes(), &mut bytes).unwrap();
        bytes
    }

    /// Verifies that a Negentropy session produces no differences when client and server stores contain the same items.
    ///
    /// This integration test seeds the server store with three events, constructs a client-side Negentropy
    /// storage containing the identical (timestamp, id) tuples, initiates a `NEG-OPEN` and completes the
    /// first reconciliation round, and asserts that both the `have` and `need` result sets are empty.
    ///
    /// # Examples
    ///
    /// ```
    /// // Integration-style example (conceptual):
    /// // - spawn server with pre-seeded store
    /// // - create client negentropy storage with same items
    /// // - perform NEG-OPEN and reconcile
    /// // - assert both have and need sets are empty
    /// ```
    #[tokio::test]
    async fn test_neg_identical_stores() {
        let (port, store) = spawn_server().await;
        // Store 3 events on server.
        let ev1 = make_event(1, 1, 1000, vec![]);
        let ev2 = make_event(2, 1, 2000, vec![]);
        let ev3 = make_event(3, 1, 3000, vec![]);
        store.append(&ev1).unwrap();
        store.append(&ev2).unwrap();
        store.append(&ev3).unwrap();

        // Client has the same 3 events.
        let client_items: Vec<(u64, [u8; 32])> = vec![
            (1000, ev1.id.0),
            (2000, ev2.id.0),
            (3000, ev3.id.0),
        ];
        let (client_storage, hex_msg) = neg_initiate(&client_items);

        let mut ws = connect(port).await;
        let reply = neg_open(&mut ws, "neg1", "{}", &hex_msg).await;
        let (have_ids, need_ids) = neg_reconcile(&mut ws, "neg1", &client_storage, reply).await;

        // Identical stores: no have_ids, no need_ids.
        assert!(have_ids.is_empty(), "have_ids should be empty for identical sets");
        assert!(need_ids.is_empty(), "need_ids should be empty for identical sets");
    }

    #[tokio::test]
    async fn test_neg_partial_overlap() {
        let (port, store) = spawn_server().await;
        // Server has events [1, 2, 3, 4].
        let ev1 = make_event(1, 1, 1000, vec![]);
        let ev2 = make_event(2, 1, 2000, vec![]);
        let ev3 = make_event(3, 1, 3000, vec![]);
        let ev4 = make_event(4, 1, 4000, vec![]);
        store.append(&ev1).unwrap();
        store.append(&ev2).unwrap();
        store.append(&ev3).unwrap();
        store.append(&ev4).unwrap();

        // Client has [2, 4].
        let client_items: Vec<(u64, [u8; 32])> = vec![
            (2000, ev2.id.0),
            (4000, ev4.id.0),
        ];
        let (client_storage, hex_msg) = neg_initiate(&client_items);

        let mut ws = connect(port).await;
        let reply = neg_open(&mut ws, "neg1", r#"{"kinds":[1]}"#, &hex_msg).await;
        let (_have_ids, need_ids) = neg_reconcile(&mut ws, "neg1", &client_storage, reply).await;

        // Client needs events [1, 3] from server.
        let need_set: std::collections::HashSet<[u8; 32]> = need_ids.iter().map(|id| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(id.as_bytes());
            arr
        }).collect();
        assert!(need_set.contains(&ev1.id.0), "client should need event 1");
        assert!(need_set.contains(&ev3.id.0), "client should need event 3");
        assert!(!need_set.contains(&ev2.id.0), "client should NOT need event 2");
        assert!(!need_set.contains(&ev4.id.0), "client should NOT need event 4");
    }

    #[tokio::test]
    async fn test_neg_close_removes_session() {
        let (port, store) = spawn_server().await;
        store.append(&make_event(1, 1, 1000, vec![])).unwrap();

        let client_items: Vec<(u64, [u8; 32])> = vec![];
        let (_, hex_msg) = neg_initiate(&client_items);

        let mut ws = connect(port).await;
        let _ = neg_open(&mut ws, "neg1", "{}", &hex_msg).await;

        // Send NEG-CLOSE.
        ws.send(TMsg::Text(r#"["NEG-CLOSE","neg1"]"#.into())).await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

        // Now send NEG-MSG — should get NEG-ERR because session is gone.
        ws.send(TMsg::Text(r#"["NEG-MSG","neg1","00"]"#.into())).await.unwrap();
        let resp = recv_text(&mut ws).await;
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v[0], "NEG-ERR", "expected NEG-ERR after CLOSE: {resp}");
    }

    /// Verifies that sending a regular `CLOSE` (NIP-01) also removes an active Negentropy session.
    ///
    /// After a `NEG-OPEN` creates a negentropy session, a subsequent `CLOSE` for the same
    /// subscription id must remove that session so that any following `NEG-MSG` for the id
    /// receives `NEG-ERR`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// // 1. Start test server and seed store.
    /// // 2. Negotiate a negentropy session with sub id "neg1" via NEG-OPEN.
    /// // 3. Send a regular CLOSE for "neg1".
    /// // 4. Sending NEG-MSG for "neg1" now yields NEG-ERR.
    /// ```
    #[tokio::test]
    async fn test_close_also_removes_neg_session() {
        let (port, store) = spawn_server().await;
        store.append(&make_event(1, 1, 1000, vec![])).unwrap();

        let client_items: Vec<(u64, [u8; 32])> = vec![];
        let (_, hex_msg) = neg_initiate(&client_items);

        let mut ws = connect(port).await;
        let _ = neg_open(&mut ws, "neg1", "{}", &hex_msg).await;

        // Send regular CLOSE (NIP-01) — should also remove neg session.
        ws.send(TMsg::Text(r#"["CLOSE","neg1"]"#.into())).await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

        // NEG-MSG should now get NEG-ERR.
        ws.send(TMsg::Text(r#"["NEG-MSG","neg1","00"]"#.into())).await.unwrap();
        let resp = recv_text(&mut ws).await;
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v[0], "NEG-ERR", "expected NEG-ERR after CLOSE: {resp}");
    }

    #[tokio::test]
    async fn test_neg_duplicate_sub_id_replaces_session() {
        let (port, store) = spawn_server().await;
        store.append(&make_event(1, 1, 1000, vec![])).unwrap();

        let client_items: Vec<(u64, [u8; 32])> = vec![];
        let (_, hex_msg) = neg_initiate(&client_items);

        let mut ws = connect(port).await;
        // Open first session.
        let _ = neg_open(&mut ws, "s1", "{}", &hex_msg).await;

        // Open second session with same sub_id — replaces first.
        let (_, hex_msg2) = neg_initiate(&client_items);
        let _ = neg_open(&mut ws, "s1", "{}", &hex_msg2).await;

        // The connection should still be alive and working.
        ws.send(TMsg::Text(r#"["NEG-CLOSE","s1"]"#.into())).await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

        // Verify session is gone.
        ws.send(TMsg::Text(r#"["NEG-MSG","s1","00"]"#.into())).await.unwrap();
        let resp = recv_text(&mut ws).await;
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v[0], "NEG-ERR");
    }

    #[tokio::test]
    async fn test_neg_empty_server() {
        // Server has nothing, client has 3 events.
        let (port, _store) = spawn_server().await;

        let ev1 = make_event(1, 1, 1000, vec![]);
        let ev2 = make_event(2, 1, 2000, vec![]);
        let ev3 = make_event(3, 1, 3000, vec![]);
        let client_items: Vec<(u64, [u8; 32])> = vec![
            (1000, ev1.id.0),
            (2000, ev2.id.0),
            (3000, ev3.id.0),
        ];
        let (client_storage, hex_msg) = neg_initiate(&client_items);

        let mut ws = connect(port).await;
        let reply = neg_open(&mut ws, "neg1", "{}", &hex_msg).await;
        let (have_ids, need_ids) = neg_reconcile(&mut ws, "neg1", &client_storage, reply).await;

        // Client has all 3, server has none. Client "has" these IDs (server doesn't).
        assert_eq!(have_ids.len(), 3, "client should have 3 ids server doesn't");
        assert!(need_ids.is_empty(), "client should need nothing");
    }

    /// Verifies that a Negentropy `NEG-OPEN` with an `#e` tag filter produces a reconciliation set
    /// that includes only events matching that tag.
    ///
    /// This test seeds the server store with two events (one containing the specified `#e` tag and
    /// one without), initiates a negentropy session from a client that has neither event, opens the
    /// session with the tag-filtered request, and asserts that the client's "need" set contains only
    /// the tagged event.
    ///
    /// # Examples
    ///
    /// ```
    /// // Conceptual example: open a negentropy session that filters by `#e` tag and expect only
    /// // tagged events to be required by the client.
    /// // (See test_neg_tag_filter_produces_correct_set for the full integration test.)
    /// ```
    #[tokio::test]
    async fn test_neg_tag_filter_produces_correct_set() {
        let (port, store) = spawn_server().await;
        let hex64 = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

        // Store events: one with the tag, one without.
        let ev_tagged = make_event(1, 1, 1000, vec![Tag {
            fields: vec!["e".into(), hex64.into()],
        }]);
        let ev_untagged = make_event(2, 1, 2000, vec![]);
        store.append(&ev_tagged).unwrap();
        store.append(&ev_untagged).unwrap();

        // Client has neither event.
        let client_items: Vec<(u64, [u8; 32])> = vec![];
        let (client_storage, hex_msg) = neg_initiate(&client_items);

        let mut ws = connect(port).await;
        let filter = format!("{{\"#e\":[\"{}\"]}}", hex64);
        let reply = neg_open(&mut ws, "neg1", &filter, &hex_msg).await;
        let (_have_ids, need_ids) = neg_reconcile(&mut ws, "neg1", &client_storage, reply).await;

        // Client should need only the tagged event, not the untagged one.
        let need_set: std::collections::HashSet<[u8; 32]> = need_ids.iter().map(|id| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(id.as_bytes());
            arr
        }).collect();
        assert_eq!(need_set.len(), 1, "should need exactly 1 event");
        assert!(need_set.contains(&ev_tagged.id.0), "should need the tagged event");
        assert!(!need_set.contains(&ev_untagged.id.0), "should not need the untagged event");
    }

    /// Ensures the connection's per-connection subscription limit applies to Negentropy sessions.
    ///
    /// Spawns a test server with `max_subscriptions_per_conn = 2`, opens two `NEG-OPEN` sessions that consume the available slots, then attempts a third `NEG-OPEN` and asserts the server responds with a `NOTICE` mentioning the limit.
    ///
    /// # Examples
    ///
    /// ```
    /// // Start server with limit 2, open "s1" and "s2" successfully, then expect "s3" to be rejected with a NOTICE.
    /// ```
    #[tokio::test]
    async fn test_neg_sub_id_limit_applies_to_neg_sessions() {
        // Spin a server with a low subscription cap.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&dir.keep()).unwrap());
        let config = Arc::new(Config {
            relay_url: format!("ws://127.0.0.1:{port}"),
            max_subscriptions_per_conn: 2,
            ..Config::default()
        });
        let fanout = Fanout::new();
        let srv_store = Arc::clone(&store);
        let srv_config = Arc::clone(&config);
        let srv_fanout = Arc::clone(&fanout);
        tokio::spawn(async move {
            loop {
                if let Ok((stream, peer)) = listener.accept().await {
                    let s = Arc::clone(&srv_store);
                    let c = Arc::clone(&srv_config);
                    let f = Arc::clone(&srv_fanout);
                    tokio::spawn(async move {
                        let _ = handle_connection(stream, peer, s, c, f).await;
                    });
                }
            }
        });

        // Store one event so the server set is non-empty, ensuring the first-round
        // reply is non-empty and a session slot is actually consumed per NEG-OPEN.
        store.append(&make_event(1, 1, 1000, vec![])).unwrap();

        // Client has nothing — first-round reply will be non-empty, session is stored.
        let (_, hex_msg) = neg_initiate(&[]);

        let mut ws = connect(port).await;

        // Open slot 1.
        neg_open(&mut ws, "s1", "{}", &hex_msg).await;
        // Open slot 2.
        let (_, hex_msg2) = neg_initiate(&[]);
        neg_open(&mut ws, "s2", "{}", &hex_msg2).await;

        // Attempt to open a third session — should be rejected with NOTICE.
        let (_, hex_msg3) = neg_initiate(&[]);
        let raw = format!(r#"["NEG-OPEN","s3",{{}},"{hex_msg3}"]"#);
        ws.send(TMsg::Text(raw.into())).await.unwrap();
        let resp = recv_text(&mut ws).await;
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v[0], "NOTICE", "expected NOTICE when limit is reached: {resp}");
        assert!(
            v[1].as_str().unwrap_or("").contains("too many"),
            "NOTICE should mention subscription limit: {resp}",
        );
    }


}