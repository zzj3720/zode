use std::{collections::BTreeMap, ops::Deref, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::domain::{
    AsyncCallbackBinding, DomainError, EventDraft, EventRecord, GlobalPosition, SessionOwner,
    SessionSelection, SessionState, SessionStatus, StreamVersion,
};

pub const SNAPSHOT_ENCODING_JSON: &str = "json";
pub const MAX_OWNED_SESSION_SCAN_LIMIT: usize = 256;
pub const MAX_SESSION_LIST_LIMIT: usize = 200;

const SESSION_LIST_CURSOR_SCHEMA: &str = "zode.session-list-cursor.v1";
const SESSION_LIST_CURSOR_ROUTE: &str = "/v1/sessions";
const SESSION_LIST_CURSOR_SORT_VERSION: u32 = 1;
const MAX_SESSION_LIST_CURSOR_BYTES: usize = 4 * 1024;
pub(crate) const INTEGRITY_DIGEST_BYTES: usize = 32;
pub(crate) type IntegrityDigest = [u8; INTEGRITY_DIGEST_BYTES];

#[derive(Clone, Debug, PartialEq)]
pub struct AppendResult {
    pub stream_id: String,
    pub command_id: String,
    pub events: Vec<EventRecord>,
    pub stream_version: StreamVersion,
    pub replayed: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SessionAppendResult {
    pub append: AppendResult,
    pub state: VerifiedSessionState,
}

/// One immutable session projection bound to the integrity anchor that proved
/// it.  The fields are private so callers cannot pair a valid proof with a
/// modified projection; a new value can only come from a successful storage
/// read or append.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedSessionState {
    pub(crate) state: Arc<SessionState>,
    pub(crate) prefix_digest: Vec<u8>,
    pub(crate) state_digest_version: i64,
    pub(crate) state_digest: Vec<u8>,
    pub(crate) digest_components: StateDigestComponents,
}

impl VerifiedSessionState {
    pub fn into_state(self) -> SessionState {
        Arc::try_unwrap(self.state).unwrap_or_else(|state| (*state).clone())
    }
}

impl Deref for VerifiedSessionState {
    type Target = SessionState;

    fn deref(&self) -> &Self::Target {
        self.state.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SessionCreateCommand {
    pub(crate) command_id: String,
    pub(crate) request_hash: [u8; INTEGRITY_DIGEST_BYTES],
}

impl SessionCreateCommand {
    pub fn new<T: Serialize>(
        owner: &SessionOwner,
        idempotency_key: &str,
        semantic_request: &T,
    ) -> Result<Self, StoreError> {
        owner.validate()?;
        require_text("idempotency_key", idempotency_key)?;
        let mut command_hasher = Sha256::new();
        command_hasher.update(b"zode:session-create-command:v1");
        hash_field(&mut command_hasher, owner.authority_id.as_bytes());
        hash_field(&mut command_hasher, owner.subject.as_bytes());
        hash_field(&mut command_hasher, idempotency_key.as_bytes());

        let request = canonical_json_bytes(semantic_request)?;
        let mut request_hasher = Sha256::new();
        request_hasher.update(b"zode:session-create-request:v1");
        hash_field(&mut request_hasher, &request);
        Ok(Self {
            command_id: format!("session-create:v1:{:x}", command_hasher.finalize()),
            request_hash: request_hasher.finalize().into(),
        })
    }

    pub fn command_id(&self) -> &str {
        &self.command_id
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SessionCreate {
    pub owner: SessionOwner,
    pub command: SessionCreateCommand,
    pub created_at_ms: i64,
    pub selection: SessionSelection,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SessionCreateResult {
    pub append: AppendResult,
    pub state: SessionState,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExternalCallbackLookup {
    pub owner: SessionOwner,
    pub session_id: String,
    pub binding: AsyncCallbackBinding,
    pub state: SessionState,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SessionListItem {
    pub session_id: String,
    pub version: StreamVersion,
    pub status: SessionStatus,
    pub created_at_ms: i64,
    pub creation_global_position: GlobalPosition,
    pub selection: SessionSelection,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionListCursor {
    owner: SessionOwner,
    creation_global_position: GlobalPosition,
    session_id: String,
}

impl SessionListCursor {
    pub fn new(
        owner: &SessionOwner,
        creation_global_position: GlobalPosition,
        session_id: impl Into<String>,
    ) -> Result<Self, StoreError> {
        owner.validate()?;
        if creation_global_position == 0 {
            return Err(StoreError::InvalidSessionListCursor);
        }
        let session_id = session_id.into();
        require_text("session_id", &session_id)?;
        Ok(Self {
            owner: owner.clone(),
            creation_global_position,
            session_id,
        })
    }

    pub fn owner(&self) -> &SessionOwner {
        &self.owner
    }

    pub fn creation_global_position(&self) -> GlobalPosition {
        self.creation_global_position
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn encode(&self) -> Result<String, StoreError> {
        let wire = SessionListCursorWire {
            schema: SESSION_LIST_CURSOR_SCHEMA.to_owned(),
            route: SESSION_LIST_CURSOR_ROUTE.to_owned(),
            sort_version: SESSION_LIST_CURSOR_SORT_VERSION,
            owner: self.owner.clone(),
            creation_global_position: self.creation_global_position,
            session_id: self.session_id.clone(),
        };
        let bytes = canonical_json_bytes(&wire)?;
        if bytes.len() > MAX_SESSION_LIST_CURSOR_BYTES {
            return Err(StoreError::InvalidSessionListCursor);
        }
        Ok(format!("zsc1.{}", hex_encode(&bytes)))
    }

    pub fn decode(encoded: &str) -> Result<Self, StoreError> {
        let encoded = encoded
            .strip_prefix("zsc1.")
            .ok_or(StoreError::InvalidSessionListCursor)?;
        let bytes = hex_decode(encoded).ok_or(StoreError::InvalidSessionListCursor)?;
        if bytes.is_empty() || bytes.len() > MAX_SESSION_LIST_CURSOR_BYTES {
            return Err(StoreError::InvalidSessionListCursor);
        }
        let wire: SessionListCursorWire =
            serde_json::from_slice(&bytes).map_err(|_| StoreError::InvalidSessionListCursor)?;
        if wire.schema != SESSION_LIST_CURSOR_SCHEMA
            || wire.route != SESSION_LIST_CURSOR_ROUTE
            || wire.sort_version != SESSION_LIST_CURSOR_SORT_VERSION
        {
            return Err(StoreError::InvalidSessionListCursor);
        }
        Self::new(&wire.owner, wire.creation_global_position, wire.session_id)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionListCursorWire {
    schema: String,
    route: String,
    sort_version: u32,
    owner: SessionOwner,
    creation_global_position: GlobalPosition,
    session_id: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SessionListPage {
    pub items: Vec<SessionListItem>,
    pub next_cursor: Option<SessionListCursor>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedSessionRef {
    pub owner: SessionOwner,
    pub session_id: String,
    pub creation_global_position: GlobalPosition,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SnapshotRecord {
    pub snapshot_id: Option<i64>,
    pub stream_id: String,
    pub stream_version: StreamVersion,
    pub state_schema_version: u32,
    pub reducer_schema_version: u32,
    pub encoding: String,
    pub checksum: String,
    pub payload: Vec<u8>,
}

impl SnapshotRecord {
    pub fn from_state(
        stream_id: impl Into<String>,
        state: &SessionState,
        state_schema_version: u32,
        reducer_schema_version: u32,
    ) -> Result<Self, serde_json::Error> {
        let payload = serde_json::to_vec(state)?;
        Ok(Self {
            snapshot_id: None,
            stream_id: stream_id.into(),
            stream_version: state.stream_version,
            state_schema_version,
            reducer_schema_version,
            encoding: SNAPSHOT_ENCODING_JSON.into(),
            checksum: checksum(&payload),
            payload,
        })
    }

    pub fn checksum_matches(&self) -> bool {
        self.checksum == checksum(&self.payload)
    }
}

pub trait StorePort: Send + Sync {
    fn create_session(&self, create: &SessionCreate) -> Result<SessionCreateResult, StoreError>;

    fn lookup_session_create(
        &self,
        owner: &SessionOwner,
        command: &SessionCreateCommand,
    ) -> Result<Option<SessionCreateResult>, StoreError>;

    fn append_owned(
        &self,
        owner: &SessionOwner,
        stream_id: &str,
        current: &SessionState,
        command_id: &str,
        events: &[EventDraft],
    ) -> Result<SessionAppendResult, StoreError>;

    fn append_verified_owned(
        &self,
        owner: &SessionOwner,
        stream_id: &str,
        current: VerifiedSessionState,
        command_id: &str,
        events: &[EventDraft],
    ) -> Result<SessionAppendResult, StoreError>;

    fn rehydrate_owned(
        &self,
        owner: &SessionOwner,
        stream_id: &str,
    ) -> Result<SessionState, RehydrateError>;

    fn rehydrate_verified_owned(
        &self,
        owner: &SessionOwner,
        stream_id: &str,
    ) -> Result<VerifiedSessionState, RehydrateError>;

    fn read_stream_owned(
        &self,
        owner: &SessionOwner,
        stream_id: &str,
        after_version: StreamVersion,
    ) -> Result<Vec<EventRecord>, StoreError>;

    fn read_session_events(
        &self,
        owner: &SessionOwner,
        stream_id: &str,
        after_position: GlobalPosition,
        limit: usize,
    ) -> Result<Vec<EventRecord>, StoreError>;

    fn read_owned_events(
        &self,
        owner: &SessionOwner,
        after_position: GlobalPosition,
        limit: usize,
    ) -> Result<Vec<EventRecord>, StoreError>;

    fn latest_global_position(&self) -> Result<GlobalPosition, StoreError>;

    fn scan_owned_session_refs(
        &self,
        after_creation_position: GlobalPosition,
        limit: usize,
    ) -> Result<Vec<OwnedSessionRef>, StoreError>;

    fn list_sessions(
        &self,
        owner: &SessionOwner,
        limit: usize,
    ) -> Result<Vec<SessionListItem>, StoreError>;

    fn list_sessions_page(
        &self,
        owner: &SessionOwner,
        cursor: Option<&SessionListCursor>,
        limit: usize,
    ) -> Result<SessionListPage, StoreError>;

    fn write_snapshot(&self, snapshot: &SnapshotRecord) -> Result<(), StoreError>;

    fn write_state_snapshot(&self, state: &SessionState) -> Result<(), StoreError>;

    /// Resolve an opaque callback ID from the verified append-only stream.
    ///
    /// The callback bearer is never accepted here; callers compare a keyed
    /// fingerprint against the returned non-secret binding before appending a
    /// terminal callback event.  Implementations may cache this lookup as a
    /// rebuildable projection, but the event stream remains authoritative.
    fn lookup_external_callback(
        &self,
        callback_id: &str,
    ) -> Result<Option<ExternalCallbackLookup>, StoreError>;
}

pub use StorePort as EventStore;

#[derive(Debug, Error)]
pub enum StorePortError {
    #[error("storage backend error")]
    Backend,
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid {field}: must not be empty")]
    EmptyField { field: &'static str },
    #[error("event batch must not be empty")]
    EmptyEventBatch,
    #[error("value for {field} is outside SQLite's signed integer range")]
    IntegerRange { field: &'static str },
    #[error(
        "optimistic concurrency conflict on stream {stream_id}: expected version {expected}, actual {actual}"
    )]
    OptimisticConcurrency {
        stream_id: String,
        expected: StreamVersion,
        actual: StreamVersion,
    },
    #[error("command {command_id} was reused with a different event batch")]
    CommandIdempotencyConflict { command_id: String },
    #[error("event {event_id} already exists in stream {stream_id}")]
    EventIdempotencyConflict { stream_id: String, event_id: String },
    #[error("event id {event_id} is duplicated in one append batch")]
    DuplicateEventIdInBatch { event_id: String },
    #[error("stored event has unsupported schema version {0}")]
    UnsupportedEventSchema(u32),
    #[error("stored event type {stored} does not match decoded type {decoded}")]
    EventTypeMismatch { stored: String, decoded: String },
    #[error("stored event fingerprint is invalid for {stream_id} at version {version}")]
    InvalidEventFingerprint {
        stream_id: String,
        version: StreamVersion,
    },
    #[error("corrupt stored integer for {field}: {value}")]
    CorruptInteger { field: &'static str, value: i64 },
    #[error("snapshot checksum is invalid")]
    InvalidSnapshotChecksum,
    #[error("snapshot encoding {0} is not supported")]
    UnsupportedSnapshotEncoding(String),
    #[error("snapshot version {snapshot} is newer than stream version {stream}")]
    SnapshotAheadOfStream {
        snapshot: StreamVersion,
        stream: StreamVersion,
    },
    #[error("cannot write a snapshot for missing stream {0}")]
    SnapshotStreamMissing(String),
    #[error("event stream projection error: {0}")]
    Domain(#[from] DomainError),
    #[error("storage schema version {0} is not supported")]
    UnsupportedStorageSchema(i64),
    #[error("storage schema is missing required authority metadata: {0}")]
    IncompatibleStorageSchema(&'static str),
    #[error(
        "stored command fingerprint is inconsistent for stream {stream_id}, command {command_id}"
    )]
    InconsistentCommandFingerprint {
        stream_id: String,
        command_id: String,
    },
    #[error("stream integrity metadata is invalid for {stream_id} at version {version}")]
    InvalidIntegrityAnchor {
        stream_id: String,
        version: StreamVersion,
    },
    #[error("snapshot state does not match the append-time integrity anchor")]
    SnapshotStateMismatch,
    #[error("rehydration integrity check failed for {stream_id} at version {version}")]
    RehydrationIntegrity {
        stream_id: String,
        version: StreamVersion,
    },
    #[error("event store mutex was poisoned")]
    Poisoned,
    #[error("session was not found")]
    SessionNotFound,
    #[error("session list limit must be between 1 and {MAX_SESSION_LIST_LIMIT}")]
    InvalidSessionListLimit,
    #[error("session list cursor is malformed or bound to another owner")]
    InvalidSessionListCursor,
    #[error("owned session scan limit must be between 1 and {MAX_OWNED_SESSION_SCAN_LIMIT}")]
    InvalidOwnedSessionScanLimit,
    #[error("session create receipt is inconsistent with its creation event")]
    InvalidSessionCreateReceipt,
    #[error("external callback {0} is mapped by multiple session streams")]
    ExternalCallbackConflict(String),
}

pub use StorePortError as StoreError;

#[derive(Debug, Error)]
pub enum RehydrateError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Domain(#[from] DomainError),
    #[error("rehydrated state stopped at version {actual}, stream is at version {expected}")]
    IncompleteReplay {
        actual: StreamVersion,
        expected: StreamVersion,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StateDigestComponents {
    pub(crate) transcript: IntegrityDigest,
    pub(crate) async_tools: Arc<BTreeMap<String, IntegrityDigest>>,
    pub(crate) async_tools_root: IntegrityDigest,
}

pub(crate) fn require_text(field: &'static str, value: &str) -> Result<(), StoreError> {
    if value.is_empty() {
        Err(StoreError::EmptyField { field })
    } else {
        Ok(())
    }
}

pub(crate) fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

pub(crate) fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, StoreError> {
    let value = serde_json::to_value(value)?;
    let mut bytes = Vec::new();
    write_canonical_json(&value, &mut bytes)?;
    Ok(bytes)
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<(), StoreError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => output.extend_from_slice(&serde_json::to_vec(value)?),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
            output.push(b'{');
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(&serde_json::to_vec(key)?);
                output.push(b':');
                write_canonical_json(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn hex_decode(encoded: &str) -> Option<Vec<u8>> {
    if encoded.is_empty()
        || !encoded.len().is_multiple_of(2)
        || encoded.len() / 2 > MAX_SESSION_LIST_CURSOR_BYTES
    {
        return None;
    }
    let mut decoded = Vec::with_capacity(encoded.len() / 2);
    let bytes = encoded.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        decoded.push((high << 4) | low);
    }
    Some(decoded)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn checksum(payload: &[u8]) -> String {
    checksum_from_digest(&Sha256::digest(payload))
}

pub(crate) fn checksum_from_digest(digest: &[u8]) -> String {
    format!("sha256:{}", hex_encode(digest))
}
