use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use socketioxide::extract::{AckSender, Data, SocketRef};
use socketioxide::SocketIo;
use tokio::sync::RwLock;
use tracing::{error, info};

use crate::{
    middleware::verify_token,
    models::{AppState, PendingCall},
    args,
    db::DbArg,
};

// Maps socket_id -> uid (for knowing which uid a socket belongs to on disconnect)

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct JoinCallData {
    #[serde(rename = "callId")]
    pub call_id: String,
    #[serde(rename = "sessionId")]
    pub session_id: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ResumeCallData {
    #[serde(rename = "callId")]
    pub call_id: String,
    #[serde(rename = "sessionId")]
    pub session_id: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct IncomingCallData {
    pub to_uid: String,
    pub caller: Value,
    #[serde(rename = "callId")]
    pub call_id: String,
    #[serde(rename = "isVideo")]
    pub is_video: bool,
}

#[derive(Deserialize, Clone, Debug)]
pub struct PeerTargetData {
    pub to_uid: String,
    #[serde(rename = "callId")]
    pub call_id: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct MarkSeenData {
    pub message_id: i64,
    pub to_uid: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct ReactionData {
    pub message_id: i64,
    pub reaction: String,
    pub to_uid: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct SendMessageData {
    pub to_uid: String,
    pub text: String,
}

pub async fn on_connect(socket: SocketRef, state: AppState, io: Arc<SocketIo>) {
    let sid = socket.id.to_string();
    info!("[SOCKET] connect id={}", sid);

    // socket_uid_map: sid -> uid (shared across all connections via AppState extension)
    // We'll store it in a DashMap in AppState extended or use the existing user_sockets inversely.
    // Simple approach: use a separate Arc<DashMap<sid, uid>> stored in AppState
    // For now, we track it via a local Arc per connection and clean up on disconnect.
    let state_rc = Arc::new(state);
    let io_rc    = io;
    // uid cell for this socket connection
    let uid_cell: Arc<tokio::sync::RwLock<Option<String>>> = Arc::new(tokio::sync::RwLock::new(None));

    // ── register_user ────────────────────────────────────────────────────────
    {
        let s       = socket.clone();
        let state2  = state_rc.clone();
        let io2     = io_rc.clone();
        let uid2    = uid_cell.clone();
        socket.on("register_user", move |token: Data<String>| {
            let s2     = s.clone();
            let state3 = state2.clone();
            let io3    = io2.clone();
            let uid3   = uid2.clone();
            let sid2   = s2.id.to_string();
            async move {
                match verify_token(&token.0) {
                    Ok(claims) => {
                        let uid = claims.uid.clone();
                        *uid3.write().await = Some(uid.clone());

                        let is_new = !state3.user_sockets.contains_key(&uid);
                        state3.user_sockets
                            .entry(uid.clone())
                            .or_insert_with(HashSet::new)
                            .insert(sid2.clone());

                        if is_new {
                            let state4 = state3.clone();
                            let uid2 = uid.clone();
                            tokio::spawn(async move {
                                let _ = state4.db.query(
                                    "UPDATE users SET last_active = datetime('now') WHERE uid = ?",
                                    args![uid2],
                                ).await;
                            });
                            let _ = io3.emit("user_status", json!({
                                "uid": uid,
                                "is_online": true,
                                "last_active": chrono::Utc::now().to_rfc3339()
                            }));
                        }

                        deliver_pending_call(&uid.clone(), &state3, &io3).await;
                        info!("[SOCKET] Registered user {} on socket {}", uid, sid2);
                    }
                    Err(_) => error!("[SOCKET] register_user: Invalid token"),
                }
            }
        });
    }

    // ── send_message ──────────────────────────────────────────────────────────
    {
        let s      = socket.clone();
        let state2 = state_rc.clone();
        let io2    = io_rc.clone();
        let uid2   = uid_cell.clone();
        socket.on("send_message", move |data: Data<SendMessageData>, ack: AckSender| {
            let _s2     = s.clone();
            let state3 = state2.clone();
            let io3    = io2.clone();
            let uid3   = uid2.clone();
            async move {
                let from_uid = match uid3.read().await.clone() {
                    Some(u) => u,
                    None => { let _ = ack.send(json!({ "success": false, "error": "Not authenticated" })); return; }
                };
                if data.to_uid.is_empty() || data.text.is_empty() { return; }

                let encrypted = state3.db.encrypt_message(&data.text);
                match state3.db.query(
                    "INSERT INTO messages (from_uid, to_uid, encrypted_text) VALUES (?, ?, ?) RETURNING id, created_at",
                    args![from_uid.clone(), data.to_uid.clone(), encrypted],
                ).await {
                    Ok(result) if !result.rows.is_empty() => {
                        let id: i64 = result.rows[0].0.get(0).map(|c| c.as_i64()).unwrap_or(result.last_insert_rowid);
                        let created_at = result.rows[0].0.get(1).map(|c| c.as_string()).unwrap_or_default();
                        let msg = json!({
                            "id": id, "from_uid": from_uid, "to_uid": data.to_uid,
                            "text": data.text, "created_at": created_at, "reactions": null
                        });
                        if let Some(sids) = state3.user_sockets.get(&data.to_uid) {
                            for recv_sid in sids.value() {
                                let _ = io3.to(recv_sid.clone()).emit("new_message", msg.clone());
                            }
                        }
                        let _ = ack.send(json!({ "success": true, "message": msg }));
                    }
                    Ok(_) => { let _ = ack.send(json!({ "success": false, "error": "Insert returned no rows" })); }
                    Err(e) => { let _ = ack.send(json!({ "success": false, "error": e.to_string() })); }
                }
            }
        });
    }

    // ── mark_seen ─────────────────────────────────────────────────────────────
    {
        let _s      = socket.clone();
        let state2 = state_rc.clone();
        let io2    = io_rc.clone();
        let uid2   = uid_cell.clone();
        socket.on("mark_seen", move |data: Data<MarkSeenData>| {
            let state3 = state2.clone();
            let io3    = io2.clone();
            let uid3   = uid2.clone();
            async move {
                let my_uid = match uid3.read().await.clone() { Some(u) => u, None => return };
                let mid = data.message_id;
                let uid_clone = my_uid.clone();
                let state4 = state3.clone();
                tokio::spawn(async move {
                    let _ = state4.db.query(
                        "UPDATE messages SET read_at = datetime('now') WHERE id = ? AND to_uid = ?",
                        args![mid, uid_clone],
                    ).await;
                });
                if let Some(sids) = state3.user_sockets.get(&data.to_uid) {
                    for sid_val in sids.value() {
                        let _ = io3.to(sid_val.clone()).emit("message_seen", json!({
                            "message_id": data.message_id,
                            "by_uid": my_uid
                        }));
                    }
                }
            }
        });
    }

    // ── add_reaction ──────────────────────────────────────────────────────────
    {
        let _s      = socket.clone();
        let state2 = state_rc.clone();
        let io2    = io_rc.clone();
        let uid2   = uid_cell.clone();
        socket.on("add_reaction", move |data: Data<ReactionData>| {
            let state3 = state2.clone();
            let io3    = io2.clone();
            let uid3   = uid2.clone();
            async move {
                let my_uid = match uid3.read().await.clone() { Some(u) => u, None => return };
                match state3.db.query(
                    "SELECT reactions FROM messages WHERE id = ?",
                    args![data.message_id],
                ).await {
                    Ok(result) if !result.rows.is_empty() => {
                        let reactions_str = result.rows[0].0.get(0).and_then(|c| c.as_opt_string());
                        let mut reactions: HashMap<String, String> = reactions_str
                            .and_then(|s| serde_json::from_str(&s).ok())
                            .unwrap_or_default();

                        if reactions.get(&my_uid).map(|r| r == &data.reaction).unwrap_or(false) {
                            reactions.remove(&my_uid);
                        } else {
                            reactions.insert(my_uid.clone(), data.reaction.clone());
                        }

                        let new_str = if reactions.is_empty() { None }
                            else { Some(serde_json::to_string(&reactions).unwrap()) };

                        let _ = state3.db.query(
                            "UPDATE messages SET reactions = ? WHERE id = ?",
                            vec![DbArg::from(new_str), DbArg::Int(data.message_id)],
                        ).await;

                        let payload = json!({ "message_id": data.message_id, "reactions": reactions });
                        for target in [&data.to_uid, &my_uid] {
                            if let Some(sids) = state3.user_sockets.get(target) {
                                for sid_val in sids.value() {
                                    let _ = io3.to(sid_val.clone()).emit("message_reaction", payload.clone());
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        });
    }

    // ── incoming_call ─────────────────────────────────────────────────────────
    {
        let _s      = socket.clone();
        let state2 = state_rc.clone();
        let io2    = io_rc.clone();
        let uid2   = uid_cell.clone();
        socket.on("incoming_call", move |data: Data<IncomingCallData>, ack: AckSender| {
            let state3 = state2.clone();
            let io3    = io2.clone();
            let uid3   = uid2.clone();
            async move {
                let from_uid = match uid3.read().await.clone() {
                    Some(u) => u,
                    None => { let _ = ack.send(json!({ "ok": false })); return; }
                };
                let payload = json!({
                    "from_uid": from_uid,
                    "caller": data.caller,
                    "callId": data.call_id,
                    "isVideo": data.is_video
                });
                let delivered = if let Some(sids) = state3.user_sockets.get(&data.to_uid) {
                    for sid_val in sids.value() {
                        let _ = io3.to(sid_val.clone()).emit("incoming_call", payload.clone());
                    }
                    state3.pending_calls.remove(&data.to_uid);
                    true
                } else {
                    state3.pending_calls.insert(data.to_uid.clone(), PendingCall {
                        data: payload,
                        expires_at: Instant::now() + Duration::from_secs(30),
                    });
                    info!("[CALL] Receiver {} offline — queued for 30s", data.to_uid);
                    false
                };
                let _ = ack.send(json!({ "ok": delivered }));
            }
        });
    }

    // Relay events to uid — one handler per event
    for event in ["call_reject", "call_busy", "call_ringing", "call_accepted", "call_no_answer"] {
        let _s      = socket.clone();
        let state2 = state_rc.clone();
        let io2    = io_rc.clone();
        let uid2   = uid_cell.clone();
        let ev     = event;
        socket.on(event, move |data: Data<PeerTargetData>| {
            let state3 = state2.clone();
            let io3    = io2.clone();
            let uid3   = uid2.clone();
            let ev2    = ev;
            async move {
                let from_uid = match uid3.read().await.clone() { Some(u) => u, None => return };
                let payload  = json!({ "by_uid": from_uid, "callId": data.call_id });
                if let Some(sids) = state3.user_sockets.get(&data.to_uid) {
                    for sid_val in sids.value() {
                        let _ = io3.to(sid_val.clone()).emit(ev2, payload.clone());
                        // call_no_answer → also emit call_missed to callee so their UI reacts
                        if ev2 == "call_no_answer" {
                            let _ = io3.to(sid_val.clone()).emit("call_missed", json!({}));
                        }
                    }
                }
            }
        });
    }

    // ── join_call ─────────────────────────────────────────────────────────────
    {
        let s      = socket.clone();
        let state2 = state_rc.clone();
        let io2    = io_rc.clone();
        socket.on("join_call", move |data: Data<JoinCallData>| {
            let s2     = s.clone();
            let state3 = state2.clone();
            let io3    = io2.clone();
            async move {
                let call_id = data.call_id.clone();
                if call_id.len() > 128 {
                    let _ = s2.emit("error", json!({ "message": "Invalid call ID" }));
                    return;
                }
                // Track room membership via DashMap: call_id -> count
                let room_count = {
                    let entry = state3.room_counts.entry(call_id.clone()).or_insert(0);
                    *entry.value()
                };
                if room_count >= 2 {
                    let _ = s2.emit("error", json!({ "message": "Room is full" }));
                    return;
                }
                state3.room_counts.entry(call_id.clone()).and_modify(|c| *c += 1).or_insert(1);
                let _ = s2.join(call_id.clone());
                let is_polite = room_count == 1;
                let _ = s2.emit("peer_role", json!({ "polite": is_polite }));
                if is_polite {
                    let _ = io3.to(call_id.clone()).emit("peer_connected", json!({}));
                }
                info!("[ROOM] join callId={} polite={}", call_id, is_polite);
            }
        });
    }

    // ── resume_call ────────────────────────────────────────────────────────────
    {
        let s  = socket.clone();
        let io2 = io_rc.clone();
        socket.on("resume_call", move |data: Data<ResumeCallData>, ack: AckSender| {
            let s2  = s.clone();
            let io3 = io2.clone();
            async move {
                let call_id = data.call_id.clone();
                let _ = s2.join(call_id.clone());
                let _ = io3.to(call_id.clone()).emit("peer_connected", json!({}));
                let _ = ack.send(json!({ "status": "resume_ok" }));
                info!("[ROOM] resumed callId={}", call_id);
            }
        });
    }

    // ── WebRTC signal relay to room ────────────────────────────────────────────
    for event in ["offer", "answer", "ice_candidate", "peer_action"] {
        let s  = socket.clone();
        let ev = event;
        socket.on(event, move |data: Data<Value>| {
            let s2 = s.clone();
            let ev2 = ev;
            async move {
                if let Some(cid) = data.get("callId").and_then(|v| v.as_str()) {
                    let _ = s2.to(cid.to_string()).emit(ev2, data.0.clone());
                }
            }
        });
    }

    // ── call_end ──────────────────────────────────────────────────────────────
    {
        let s      = socket.clone();
        let state2 = state_rc.clone();
        socket.on("call_end", move |data: Data<Value>| {
            let s2     = s.clone();
            let state3 = state2.clone();
            async move {
                if let Some(cid) = data.get("callId").and_then(|v| v.as_str()) {
                    let _ = s2.to(cid.to_string()).emit("call_end", json!({}));
                    // Decrement / remove room count
                    state3.room_counts.remove(cid);
                }
            }
        });
    }

    // ── disconnect ────────────────────────────────────────────────────────────
    {
        let s      = socket.clone();
        let state2 = state_rc.clone();
        let io2    = io_rc.clone();
        let uid2   = uid_cell.clone();
        socket.on_disconnect(move |_reason: socketioxide::socket::DisconnectReason| {
            let s2     = s.clone();
            let state3 = state2.clone();
            let io3    = io2.clone();
            let uid3   = uid2.clone();
            let sid2   = s2.id.to_string();
            async move {
                if let Some(uid) = uid3.read().await.clone() {
                    let mut went_offline = false;
                    if let Some(mut entry) = state3.user_sockets.get_mut(&uid) {
                        entry.remove(&sid2);
                        if entry.is_empty() { went_offline = true; }
                    }
                    if went_offline {
                        state3.user_sockets.remove(&uid);
                        let state4 = state3.clone();
                        let uid2 = uid.clone();
                        tokio::spawn(async move {
                            let _ = state4.db.query(
                                "UPDATE users SET last_active = datetime('now') WHERE uid = ?",
                                args![uid2],
                            ).await;
                        });
                        let _ = io3.emit("user_status", json!({
                            "uid": uid,
                            "is_online": false,
                            "last_active": chrono::Utc::now().to_rfc3339()
                        }));
                    }
                }
                // Notify call room peers of disconnect
                if let Ok(rooms) = s2.rooms() {
                    for room in rooms {
                        let _ = s2.to(room).emit("peer_disconnected", json!({}));
                    }
                }
            }
        });
    }
}

async fn deliver_pending_call(uid: &str, state: &AppState, io: &Arc<SocketIo>) {
    if let Some((_, pending)) = state.pending_calls.remove(uid) {
        if pending.expires_at > Instant::now() {
            if let Some(sids) = state.user_sockets.get(uid) {
                for sid_val in sids.value() {
                    let _ = io.to(sid_val.clone()).emit("incoming_call", pending.data.clone());
                }
                info!("[CALL] Delivered pending call to {}", uid);
            }
        }
    }
}
