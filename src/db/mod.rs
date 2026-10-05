use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{info, warn};

/// Turso HTTP Hrana v2 client — pure Rust, no C compiler
pub struct Database {
    client: reqwest::Client,
    url: String,
    token: String,
    pub chat_key: [u8; 32],
    pub jwt_secret: String,
}

#[derive(Serialize, Clone)]
struct HranaStmt {
    sql: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    args: Vec<HranaArg>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    named_args: bool,
}

#[derive(Serialize, Clone)]
#[serde(untagged)]
enum HranaArg {
    Text { r#type: &'static str, value: String },
    Integer { r#type: &'static str, value: i64 },
    Null { r#type: &'static str },
}

impl HranaArg {
    fn text(s: impl Into<String>) -> Self {
        HranaArg::Text { r#type: "text", value: s.into() }
    }
    fn int(v: i64) -> Self {
        HranaArg::Integer { r#type: "integer", value: v }
    }
    fn null() -> Self {
        HranaArg::Null { r#type: "null" }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct Row(pub Vec<CellValue>);

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum CellValue {
    Null,
    Text(String),
    Integer(i64),
    Float(f64),
    Blob,
}

impl CellValue {
    pub fn as_str(&self) -> Option<&str> {
        match self { CellValue::Text(s) => Some(s.as_str()), _ => None }
    }
    pub fn as_string(&self) -> String {
        match self {
            CellValue::Text(s)    => s.clone(),
            CellValue::Integer(v) => v.to_string(),
            CellValue::Float(v)   => v.to_string(),
            _                     => String::new(),
        }
    }
    pub fn as_i64(&self) -> i64 {
        match self {
            CellValue::Integer(v) => *v,
            CellValue::Float(v)   => *v as i64,
            CellValue::Text(s)    => s.parse().unwrap_or(0),
            _                     => 0,
        }
    }
    pub fn as_opt_string(&self) -> Option<String> {
        match self { CellValue::Text(s) => Some(s.clone()), _ => None }
    }
}

pub struct QueryResult {
    pub rows: Vec<Row>,
    pub last_insert_rowid: i64,
}

impl Database {
    pub async fn new() -> Result<Self> {
        let url   = std::env::var("TURSO_DB_URL")
            .unwrap_or_else(|_| "https://not-configured.turso.io".to_string());
        let token = std::env::var("TURSO_AUTH_TOKEN")
            .unwrap_or_else(|_| "not-configured".to_string());

        use sha2::{Sha256, Digest};
        let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| {
            format!("chet_secret_change_in_prod_{}", hex::encode(rand::random::<[u8; 8]>()))
        });
        let mut hasher = Sha256::new();
        hasher.update(jwt_secret.as_bytes());
        let chat_key: [u8; 32] = hasher.finalize().into();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()?;

        info!("[DB] Turso HTTP client initialized url={}", &url[..url.len().min(40)]);

        Ok(Self { client, url, token, chat_key, jwt_secret })
    }

    fn pipeline_url(&self) -> String {
        // Strip trailing slash
        let base = self.url.trim_end_matches('/');
        // Turso Hrana v2 pipeline
        format!("{}/v2/pipeline", base)
    }

    /// Execute a single SQL statement with positional args
    pub async fn query(&self, sql: &str, args: Vec<DbArg>) -> Result<QueryResult> {
        let stmt = HranaStmt {
            sql: sql.to_string(),
            args: args.into_iter().map(|a| a.into_hrana()).collect(),
            named_args: false,
        };
        let body = json!({
            "requests": [
                { "type": "execute", "stmt": stmt },
                { "type": "close" }
            ]
        });

        let resp = self.client
            .post(&self.pipeline_url())
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Turso HTTP {} : {}", status, text));
        }

        let data: Value = resp.json().await?;
        parse_result(&data, 0)
    }

    /// Run multiple SQL statements (schema migrations / batch DDL)
    pub async fn batch(&self, statements: &[(&str, Vec<DbArg>)]) -> Result<()> {
        let requests: Vec<Value> = statements.iter().map(|(sql, args)| {
            json!({
                "type": "execute",
                "stmt": {
                    "sql": sql,
                    "args": args.iter().map(|a| a.to_json()).collect::<Vec<_>>()
                }
            })
        }).chain(std::iter::once(json!({ "type": "close" })))
        .collect();

        let body = json!({ "requests": requests });

        let resp = self.client
            .post(&self.pipeline_url())
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Turso batch HTTP {} : {}", status, text));
        }
        Ok(())
    }

    pub async fn migrate(&self) -> Result<()> {
        let ddl_statements = vec![
            ("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, uid TEXT UNIQUE NOT NULL, username TEXT UNIQUE NOT NULL, first_name TEXT NOT NULL, last_name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now')), last_active TEXT DEFAULT NULL, profile_photo TEXT DEFAULT NULL, is_verified INTEGER DEFAULT 0, bio TEXT, tagline TEXT, location TEXT, cover_photo TEXT)", vec![]),
            ("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, from_uid TEXT NOT NULL, to_uid TEXT NOT NULL, encrypted_text TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now')), read_at TEXT DEFAULT NULL, reactions TEXT DEFAULT NULL)", vec![]),
            ("CREATE TABLE IF NOT EXISTS verified_uids (uid TEXT PRIMARY KEY, added_at TEXT DEFAULT (datetime('now')))", vec![]),
            ("CREATE TABLE IF NOT EXISTS email_domain_rules (domain TEXT PRIMARY KEY, rule_type TEXT NOT NULL DEFAULT 'allow', added_at TEXT DEFAULT (datetime('now')))", vec![]),
            ("INSERT OR IGNORE INTO email_domain_rules (domain, rule_type) VALUES ('gmail.com', 'allow')", vec![]),
        ];

        self.batch(&ddl_statements).await?;

        // Safe column migrations
        let col_migrations = [
            ("ALTER TABLE users ADD COLUMN last_active TEXT",          vec![]),
            ("ALTER TABLE users ADD COLUMN profile_photo TEXT",        vec![]),
            ("ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 0", vec![]),
            ("ALTER TABLE users ADD COLUMN bio TEXT",                  vec![]),
            ("ALTER TABLE users ADD COLUMN tagline TEXT",              vec![]),
            ("ALTER TABLE users ADD COLUMN location TEXT",             vec![]),
            ("ALTER TABLE users ADD COLUMN cover_photo TEXT",          vec![]),
            ("ALTER TABLE messages ADD COLUMN read_at TEXT",           vec![]),
            ("ALTER TABLE messages ADD COLUMN reactions TEXT",         vec![]),
        ];

        for (sql, args) in &col_migrations {
            match self.query(sql, args.clone()).await {
                Ok(_) => info!("[DB] Migration: {}", &sql[..40.min(sql.len())]),
                Err(e) => {
                    let msg = e.to_string();
                    if !msg.contains("duplicate") && !msg.contains("already exists") {
                        warn!("[DB] Migration ignored: {}", msg);
                    }
                }
            }
        }

        info!("[DB] Tables ready");
        Ok(())
    }

    pub fn encrypt_message(&self, text: &str) -> String {
        use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
        let key    = Key::<Aes256Gcm>::from_slice(&self.chat_key);
        let cipher = Aes256Gcm::new(key);
        let iv: [u8; 12] = rand::random();
        let nonce  = Nonce::from_slice(&iv);
        let ciphertext = cipher.encrypt(nonce, text.as_bytes()).expect("encrypt");
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);
        format!("{}:{}:{}", hex::encode(iv), hex::encode(tag), hex::encode(ct))
    }

    pub fn decrypt_message(&self, s: &str) -> String {
        use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        if parts.len() != 3 { return "[Message decryption failed]".into(); }
        let Ok(iv)  = hex::decode(parts[0]) else { return "[Message decryption failed]".into(); };
        let Ok(tag) = hex::decode(parts[1]) else { return "[Message decryption failed]".into(); };
        let Ok(ct)  = hex::decode(parts[2]) else { return "[Message decryption failed]".into(); };
        let mut combined = ct;
        combined.extend_from_slice(&tag);
        let key    = Key::<Aes256Gcm>::from_slice(&self.chat_key);
        let cipher = Aes256Gcm::new(key);
        let nonce  = Nonce::from_slice(&iv);
        match cipher.decrypt(nonce, combined.as_ref()) {
            Ok(plain) => String::from_utf8(plain).unwrap_or_else(|_| "[Invalid UTF-8]".into()),
            Err(_)    => "[Message decryption failed]".into(),
        }
    }
}

// ─── DbArg — ergonomic arg builder ───────────────────────────────────────────
#[derive(Clone, Debug)]
pub enum DbArg {
    Text(String),
    Int(i64),
    Null,
}

impl DbArg {
    fn into_hrana(self) -> HranaArg {
        match self {
            DbArg::Text(s) => HranaArg::text(s),
            DbArg::Int(v)  => HranaArg::int(v),
            DbArg::Null    => HranaArg::null(),
        }
    }
    fn to_json(&self) -> Value {
        match self {
            DbArg::Text(s) => json!({ "type": "text", "value": s }),
            DbArg::Int(v)  => json!({ "type": "integer", "value": v.to_string() }),
            DbArg::Null    => json!({ "type": "null" }),
        }
    }
}

impl From<String>  for DbArg { fn from(s: String)  -> Self { DbArg::Text(s) } }
impl From<&str>    for DbArg { fn from(s: &str)    -> Self { DbArg::Text(s.to_string()) } }
impl From<i64>     for DbArg { fn from(v: i64)     -> Self { DbArg::Int(v) } }
impl From<i32>     for DbArg { fn from(v: i32)     -> Self { DbArg::Int(v as i64) } }
impl From<u64>     for DbArg { fn from(v: u64)     -> Self { DbArg::Int(v as i64) } }
impl From<Option<String>> for DbArg {
    fn from(v: Option<String>) -> Self {
        match v { Some(s) => DbArg::Text(s), None => DbArg::Null }
    }
}
impl From<Option<&str>> for DbArg {
    fn from(v: Option<&str>) -> Self {
        match v { Some(s) => DbArg::Text(s.to_string()), None => DbArg::Null }
    }
}

// ─── Macro for building arg lists cleanly ────────────────────────────────────
#[macro_export]
macro_rules! args {
    ($($x:expr),* $(,)?) => {
        vec![$( crate::db::DbArg::from($x) ),*]
    };
}

// ─── Response parser ─────────────────────────────────────────────────────────
fn parse_result(data: &Value, idx: usize) -> Result<QueryResult> {
    let result = &data["results"][idx];
    if result["type"] == "error" {
        return Err(anyhow!("Turso error: {}", result["error"]["message"]));
    }
    let response = &result["response"];
    let _cols = response["result"]["cols"]
        .as_array()
        .map(|a| a.iter().map(|c| c["name"].as_str().unwrap_or("").to_string()).collect::<Vec<_>>())
        .unwrap_or_default();
    let raw_rows = response["result"]["rows"].as_array().cloned().unwrap_or_default();
    let last_insert_rowid = response["result"]["last_insert_rowid"]
        .as_str().and_then(|s| s.parse().ok())
        .or_else(|| response["result"]["last_insert_rowid"].as_i64())
        .unwrap_or(0);

    let rows = raw_rows.into_iter().map(|row| {
        let cells = row.as_array().cloned().unwrap_or_default().into_iter().map(|cell| {
            match cell["type"].as_str() {
                Some("text")    => CellValue::Text(cell["value"].as_str().unwrap_or("").to_string()),
                Some("integer") => CellValue::Integer(
                    cell["value"].as_str().and_then(|s| s.parse().ok())
                        .or_else(|| cell["value"].as_i64()).unwrap_or(0)
                ),
                Some("float") => CellValue::Float(cell["value"].as_f64().unwrap_or(0.0)),
                _ => CellValue::Null,
            }
        }).collect();
        Row(cells)
    }).collect();

    Ok(QueryResult { rows, last_insert_rowid })
}
