use std::sync::Arc;
use dashmap::DashMap;
use once_cell::sync::OnceCell;
use socketioxide::SocketIo;

use crate::db::Database;

/// Per-user socket tracking: uid -> Set<socket_id>
pub type UserSockets = Arc<DashMap<String, std::collections::HashSet<String>>>;

/// OTP store entry
#[derive(Clone, Debug)]
pub struct OtpEntry {
    pub otp: String,
    pub entry_type: OtpType,
    pub expires_at: std::time::Instant,
    /// Only set for registration OTPs
    pub registration_data: Option<RegistrationData>,
}

#[derive(Clone, Debug)]
pub enum OtpType {
    Register,
    Reset,
}

#[derive(Clone, Debug)]
pub struct RegistrationData {
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub password_hash: String,
}

/// Pending call queue: to_uid -> PendingCall
#[derive(Clone, Debug)]
pub struct PendingCall {
    pub data: serde_json::Value,
    pub expires_at: std::time::Instant,
}

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub otp_store: Arc<DashMap<String, OtpEntry>>,
    pub user_sockets: UserSockets,
    pub pending_calls: Arc<DashMap<String, PendingCall>>,
    pub room_counts: Arc<DashMap<String, usize>>,
    pub io: Arc<OnceCell<Arc<SocketIo>>>,
}

impl AppState {
    pub fn new(db: Arc<Database>) -> Self {
        let state = Self {
            db,
            otp_store: Arc::new(DashMap::new()),
            user_sockets: Arc::new(DashMap::new()),
            pending_calls: Arc::new(DashMap::new()),
            room_counts: Arc::new(DashMap::new()),
            io: Arc::new(OnceCell::new()),
        };

        // Background OTP cleanup every 60 seconds
        let otp_store = state.otp_store.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let now = std::time::Instant::now();
                otp_store.retain(|_, v| v.expires_at > now);
            }
        });

        // Background pending call cleanup every 5 seconds
        let pending_calls = state.pending_calls.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                let now = std::time::Instant::now();
                pending_calls.retain(|_, v| v.expires_at > now);
            }
        });

        state
    }

    pub fn set_io(&self, io: Arc<SocketIo>) {
        let _ = self.io.set(io);
    }

    pub fn io(&self) -> Option<&Arc<SocketIo>> {
        self.io.get()
    }
}
