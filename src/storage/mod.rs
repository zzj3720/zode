use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Mutex, MutexGuard},
};

use rusqlite::{
    params, types::Value as SqlValue, Connection, OptionalExtension, Transaction,
    TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use ulid::Ulid;

use crate::domain::{
    AsyncCallbackBinding, DomainError, EventDraft, EventRecord, GlobalPosition, SessionEvent,
    SessionOwner, SessionSelection, SessionState, SessionStatus, StreamVersion,
    EVENT_SCHEMA_VERSION, REDUCER_SCHEMA_VERSION, SESSION_CREATED_SCHEMA_VERSION,
    STATE_SCHEMA_VERSION,
};

pub const SNAPSHOT_ENCODING_JSON: &str = "json";

const STORAGE_SCHEMA_VERSION: i64 = 1;
const PROJECTION_SCHEMA_VERSION: i64 = 1;
const COMMAND_FINGERPRINT_VERSION: i64 = 1;
const EVENT_FINGERPRINT_VERSION: i64 = 1;
const EVENT_PREFIX_DIGEST_VERSION: i64 = 1;
const STATE_DIGEST_VERSION: i64 = 1;
const SESSION_CREATE_COMMAND_VERSION: i64 = 1;
const INTEGRITY_DIGEST_BYTES: usize = 32;
const SESSION_LIST_CURSOR_SCHEMA: &str = "zode.session-list-cursor.v1";
const SESSION_LIST_CURSOR_ROUTE: &str = "/v1/sessions";
const SESSION_LIST_CURSOR_SORT_VERSION: u32 = 1;
const MAX_SESSION_LIST_CURSOR_BYTES: usize = 4 * 1024;
pub const MAX_OWNED_SESSION_SCAN_LIMIT: usize = 256;
pub const MAX_SESSION_LIST_LIMIT: usize = 200;

#[derive(Clone, Debug, PartialEq)]
pub struct AppendResult {
    pub stream_id: String,
    pub command_id: String,
    pub events: Vec<EventRecord>,
    pub stream_version: StreamVersion,
    pub replayed: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SessionCreateCommand {
    command_id: String,
    request_hash: [u8; INTEGRITY_DIGEST_BYTES],
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

pub trait EventStore: Send + Sync {
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
        expected_version: StreamVersion,
        command_id: &str,
        events: &[EventDraft],
    ) -> Result<AppendResult, StoreError>;

    fn rehydrate_owned(
        &self,
        owner: &SessionOwner,
        stream_id: &str,
    ) -> Result<SessionState, RehydrateError>;

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

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
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

pub struct SqliteEventStore {
    connection: Mutex<Connection>,
}

impl std::fmt::Debug for SqliteEventStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteEventStore")
            .finish_non_exhaustive()
    }
}

impl SqliteEventStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let connection = Connection::open(path)?;
        Self::from_connection(connection)
    }

    fn from_connection(mut connection: Connection) -> Result<Self, StoreError> {
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA recursive_triggers = OFF;",
        )?;
        prepare_database(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, StoreError> {
        self.connection.lock().map_err(|_| StoreError::Poisoned)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SchemaRole {
    Authority,
    Projection,
    RequiredIndex,
}

#[derive(Clone, Copy)]
struct SchemaDefinition {
    name: &'static str,
    role: SchemaRole,
    sql: &'static str,
}

impl SchemaDefinition {
    const fn table(name: &'static str, role: SchemaRole, sql: &'static str) -> Self {
        Self { name, role, sql }
    }

    const fn index(name: &'static str, sql: &'static str) -> Self {
        Self {
            name,
            role: SchemaRole::RequiredIndex,
            sql,
        }
    }

    const fn object_type(self) -> &'static str {
        match self.role {
            SchemaRole::RequiredIndex => "index",
            _ => "table",
        }
    }
}

const STORAGE_SCHEMA: [SchemaDefinition; 12] = [
    SchemaDefinition::table(
        "events",
        SchemaRole::Authority,
        "CREATE TABLE events (
            global_position INTEGER PRIMARY KEY AUTOINCREMENT,
            stream_id TEXT NOT NULL,
            stream_version INTEGER NOT NULL CHECK (stream_version > 0),
            event_id TEXT NOT NULL,
            command_id TEXT NOT NULL,
            command_fingerprint_version INTEGER NOT NULL,
            command_fingerprint BLOB NOT NULL,
            event_schema_version INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            payload BLOB NOT NULL,
            event_fingerprint_version INTEGER NOT NULL,
            event_fingerprint BLOB NOT NULL,
            UNIQUE (stream_id, stream_version),
            UNIQUE (stream_id, event_id)
        );",
    ),
    SchemaDefinition::table(
        "integrity_anchors",
        SchemaRole::Authority,
        "CREATE TABLE integrity_anchors (
            stream_id TEXT NOT NULL,
            stream_version INTEGER NOT NULL CHECK (stream_version > 0),
            event_prefix_digest_version INTEGER NOT NULL,
            event_prefix_digest BLOB NOT NULL,
            state_schema_version INTEGER NOT NULL,
            reducer_schema_version INTEGER NOT NULL,
            state_digest_version INTEGER NOT NULL,
            state_digest BLOB NOT NULL,
            PRIMARY KEY (stream_id, stream_version)
        );",
    ),
    SchemaDefinition::table(
        "snapshots",
        SchemaRole::Authority,
        "CREATE TABLE snapshots (
            snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
            stream_id TEXT NOT NULL,
            stream_version INTEGER NOT NULL CHECK (stream_version >= 0),
            state_schema_version INTEGER NOT NULL CHECK (state_schema_version >= 0),
            reducer_schema_version INTEGER NOT NULL CHECK (reducer_schema_version >= 0),
            encoding TEXT NOT NULL,
            checksum TEXT NOT NULL,
            payload BLOB NOT NULL,
            event_prefix_digest_version INTEGER NOT NULL,
            event_prefix_digest BLOB NOT NULL,
            state_digest_version INTEGER NOT NULL,
            state_digest BLOB NOT NULL
        );",
    ),
    SchemaDefinition::table(
        "event_streams",
        SchemaRole::Projection,
        "CREATE TABLE event_streams (
            stream_id TEXT PRIMARY KEY NOT NULL,
            current_version INTEGER NOT NULL CHECK (current_version >= 0)
        );",
    ),
    SchemaDefinition::table(
        "commands",
        SchemaRole::Projection,
        "CREATE TABLE commands (
            stream_id TEXT NOT NULL,
            command_id TEXT NOT NULL,
            fingerprint_version INTEGER NOT NULL,
            request_hash BLOB NOT NULL,
            first_version INTEGER NOT NULL CHECK (first_version >= 0),
            last_version INTEGER NOT NULL CHECK (last_version >= 0),
            event_count INTEGER NOT NULL CHECK (event_count >= 0),
            PRIMARY KEY (stream_id, command_id)
        );",
    ),
    SchemaDefinition::table(
        "session_create_receipts",
        SchemaRole::Projection,
        "CREATE TABLE session_create_receipts (
            authority_id TEXT NOT NULL,
            subject TEXT NOT NULL,
            command_id TEXT NOT NULL,
            fingerprint_version INTEGER NOT NULL,
            request_hash BLOB NOT NULL,
            stream_id TEXT NOT NULL,
            stream_version INTEGER NOT NULL CHECK (stream_version = 1),
            creation_global_position INTEGER NOT NULL CHECK (creation_global_position > 0),
            PRIMARY KEY (authority_id, subject, command_id),
            UNIQUE (stream_id),
            UNIQUE (creation_global_position)
        );",
    ),
    SchemaDefinition::table(
        "session_index",
        SchemaRole::Projection,
        "CREATE TABLE session_index (
            stream_id TEXT PRIMARY KEY NOT NULL,
            authority_id TEXT NOT NULL,
            subject TEXT NOT NULL,
            creation_global_position INTEGER NOT NULL CHECK (creation_global_position > 0),
            created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
            status TEXT NOT NULL CHECK (status IN ('idle', 'active')),
            UNIQUE (creation_global_position)
        );",
    ),
    SchemaDefinition::table(
        "storage_metadata",
        SchemaRole::Authority,
        "CREATE TABLE storage_metadata (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            storage_schema_version INTEGER NOT NULL,
            projection_schema_version INTEGER NOT NULL,
            projections_dirty INTEGER NOT NULL CHECK (projections_dirty IN (0, 1))
        );",
    ),
    SchemaDefinition::index(
        "events_by_stream_version",
        "CREATE INDEX events_by_stream_version
            ON events (stream_id, stream_version);",
    ),
    SchemaDefinition::index(
        "events_by_command",
        "CREATE INDEX events_by_command
            ON events (stream_id, command_id, stream_version);",
    ),
    SchemaDefinition::index(
        "snapshots_by_stream_version",
        "CREATE INDEX snapshots_by_stream_version
            ON snapshots (
                stream_id,
                state_schema_version,
                reducer_schema_version,
                stream_version DESC,
                snapshot_id DESC
            );",
    ),
    SchemaDefinition::index(
        "session_index_by_owner_creation",
        "CREATE INDEX session_index_by_owner_creation
            ON session_index (
                authority_id,
                subject,
                creation_global_position DESC,
                stream_id DESC
            );",
    ),
];

const MARK_PROJECTIONS_DIRTY: &str = "
    UPDATE storage_metadata SET projections_dirty = 1
    WHERE singleton = 1 AND projections_dirty = 0;";
const INVALIDATE_UPDATED_EVENT: &str = "
    DELETE FROM integrity_anchors
    WHERE (stream_id = OLD.stream_id AND stream_version >= OLD.stream_version)
       OR (stream_id = NEW.stream_id AND stream_version >= NEW.stream_version);";
const INVALIDATE_DELETED_EVENT: &str = "
    DELETE FROM integrity_anchors
    WHERE stream_id = OLD.stream_id AND stream_version >= OLD.stream_version;";

#[derive(Clone, Copy)]
struct TriggerDefinition {
    name: &'static str,
    table_name: &'static str,
    event: &'static str,
    body: &'static str,
}

impl TriggerDefinition {
    const fn new(
        name: &'static str,
        table_name: &'static str,
        event: &'static str,
        body: &'static str,
    ) -> Self {
        Self {
            name,
            table_name,
            event,
            body,
        }
    }

    fn sql(self) -> String {
        format!(
            "CREATE TRIGGER {} {} ON {} BEGIN {} END;",
            self.name, self.event, self.table_name, self.body
        )
    }
}

const STORAGE_TRIGGERS: [TriggerDefinition; 15] = [
    TriggerDefinition::new(
        "events_insert_dirty",
        "events",
        "AFTER INSERT",
        MARK_PROJECTIONS_DIRTY,
    ),
    TriggerDefinition::new(
        "event_streams_insert_dirty",
        "event_streams",
        "AFTER INSERT",
        MARK_PROJECTIONS_DIRTY,
    ),
    TriggerDefinition::new(
        "event_streams_update_dirty",
        "event_streams",
        "AFTER UPDATE",
        MARK_PROJECTIONS_DIRTY,
    ),
    TriggerDefinition::new(
        "event_streams_delete_dirty",
        "event_streams",
        "AFTER DELETE",
        MARK_PROJECTIONS_DIRTY,
    ),
    TriggerDefinition::new(
        "commands_insert_dirty",
        "commands",
        "AFTER INSERT",
        MARK_PROJECTIONS_DIRTY,
    ),
    TriggerDefinition::new(
        "commands_update_dirty",
        "commands",
        "AFTER UPDATE",
        MARK_PROJECTIONS_DIRTY,
    ),
    TriggerDefinition::new(
        "commands_delete_dirty",
        "commands",
        "AFTER DELETE",
        MARK_PROJECTIONS_DIRTY,
    ),
    TriggerDefinition::new(
        "session_create_receipts_insert_dirty",
        "session_create_receipts",
        "AFTER INSERT",
        MARK_PROJECTIONS_DIRTY,
    ),
    TriggerDefinition::new(
        "session_create_receipts_update_dirty",
        "session_create_receipts",
        "AFTER UPDATE",
        MARK_PROJECTIONS_DIRTY,
    ),
    TriggerDefinition::new(
        "session_create_receipts_delete_dirty",
        "session_create_receipts",
        "AFTER DELETE",
        MARK_PROJECTIONS_DIRTY,
    ),
    TriggerDefinition::new(
        "session_index_insert_dirty",
        "session_index",
        "AFTER INSERT",
        MARK_PROJECTIONS_DIRTY,
    ),
    TriggerDefinition::new(
        "session_index_update_dirty",
        "session_index",
        "AFTER UPDATE",
        MARK_PROJECTIONS_DIRTY,
    ),
    TriggerDefinition::new(
        "session_index_delete_dirty",
        "session_index",
        "AFTER DELETE",
        MARK_PROJECTIONS_DIRTY,
    ),
    TriggerDefinition::new(
        "events_update_invalidates_integrity",
        "events",
        "AFTER UPDATE",
        INVALIDATE_UPDATED_EVENT,
    ),
    TriggerDefinition::new(
        "events_delete_invalidates_integrity",
        "events",
        "AFTER DELETE",
        INVALIDATE_DELETED_EVENT,
    ),
];

#[derive(Debug)]
struct CatalogObject {
    object_type: String,
    name: String,
    table_name: String,
    sql: Option<String>,
}

#[derive(Clone, Copy, Debug)]
struct StorageMetadata {
    storage_version: i64,
    projection_version: i64,
    projections_dirty: bool,
}

#[derive(Clone, Copy, Debug, Default)]
struct RepairPlan {
    projections: bool,
    indexes: bool,
}

#[derive(Clone, Copy, Debug)]
enum DatabaseState {
    Empty,
    Current(RepairPlan),
}

fn prepare_database(connection: &mut Connection) -> Result<(), StoreError> {
    let state = inspect_database_read_only(connection)?;
    let journal_is_wal = journal_mode(connection)?.eq_ignore_ascii_case("wal");
    if matches!(state, DatabaseState::Current(plan) if !plan.projections && !plan.indexes)
        && journal_is_wal
    {
        return Ok(());
    }

    ensure_wal(connection)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    match inspect_database(&transaction)? {
        DatabaseState::Empty => initialize_database(&transaction)?,
        DatabaseState::Current(plan) => repair_database(&transaction, plan)?,
    }
    transaction.commit()?;
    Ok(())
}

fn inspect_database_read_only(connection: &mut Connection) -> Result<DatabaseState, StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let state = inspect_database(&transaction)?;
    transaction.commit()?;
    Ok(state)
}

fn inspect_database(connection: &Connection) -> Result<DatabaseState, StoreError> {
    let catalog = read_catalog(connection)?;
    if catalog.is_empty() {
        return Ok(DatabaseState::Empty);
    }

    let metadata_definition = STORAGE_SCHEMA
        .iter()
        .find(|definition| definition.name == "storage_metadata")
        .ok_or(StoreError::IncompatibleStorageSchema(
            "storage_metadata definition",
        ))?;
    if !definition_is_current(&catalog, metadata_definition)? {
        return Err(StoreError::IncompatibleStorageSchema(
            "storage_metadata table",
        ));
    }
    let metadata = read_storage_metadata(connection)?;
    if metadata.storage_version != STORAGE_SCHEMA_VERSION {
        return Err(StoreError::UnsupportedStorageSchema(
            metadata.storage_version,
        ));
    }
    if metadata.projection_version > PROJECTION_SCHEMA_VERSION || metadata.projection_version < 0 {
        return Err(StoreError::IncompatibleStorageSchema(
            "projection schema version",
        ));
    }

    let mut plan = RepairPlan {
        projections: metadata.projections_dirty
            || metadata.projection_version != PROJECTION_SCHEMA_VERSION,
        indexes: false,
    };
    for definition in &STORAGE_SCHEMA {
        let is_current = definition_is_current(&catalog, definition)?;
        match definition.role {
            SchemaRole::Authority => {
                if !is_current {
                    return Err(StoreError::IncompatibleStorageSchema(
                        "current authority schema",
                    ));
                }
            }
            SchemaRole::Projection => {
                if !is_current {
                    plan.projections = true;
                }
            }
            SchemaRole::RequiredIndex => {
                if !is_current {
                    plan.indexes = true;
                }
            }
        }
    }
    validate_explicit_indexes(connection, &catalog)?;
    validate_storage_triggers(&catalog, plan.projections)?;
    Ok(DatabaseState::Current(plan))
}

fn read_catalog(connection: &Connection) -> Result<Vec<CatalogObject>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_master
         WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(CatalogObject {
            object_type: row.get(0)?,
            name: row.get(1)?,
            table_name: row.get(2)?,
            sql: row.get(3)?,
        })
    })?;
    rows.collect::<rusqlite::Result<_>>()
        .map_err(StoreError::from)
}

fn definition_is_current(
    catalog: &[CatalogObject],
    definition: &SchemaDefinition,
) -> Result<bool, StoreError> {
    let mut named = catalog
        .iter()
        .filter(|object| object.name == definition.name);
    let Some(object) = named.next() else {
        return Ok(false);
    };
    if named.next().is_some() || object.object_type != definition.object_type() {
        return Err(StoreError::IncompatibleStorageSchema(
            "storage catalog object kind",
        ));
    }
    Ok(object
        .sql
        .as_ref()
        .is_some_and(|sql| normalize_schema_sql(sql) == normalize_schema_sql(definition.sql)))
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.trim()
        .strip_suffix(';')
        .unwrap_or(sql.trim())
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn read_storage_metadata(connection: &Connection) -> Result<StorageMetadata, StoreError> {
    let mut statement = connection.prepare(
        "SELECT singleton, storage_schema_version, projection_schema_version,
                projections_dirty
         FROM storage_metadata ORDER BY singleton LIMIT 2",
    )?;
    let mut rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?;
    let (singleton, storage_version, projection_version, projections_dirty) = rows
        .next()
        .transpose()?
        .ok_or(StoreError::IncompatibleStorageSchema(
            "storage_metadata singleton row",
        ))?;
    if rows.next().transpose()?.is_some() {
        return Err(StoreError::IncompatibleStorageSchema(
            "storage_metadata singleton row",
        ));
    }
    if singleton != 1 || !matches!(projections_dirty, 0 | 1) {
        return Err(StoreError::IncompatibleStorageSchema(
            "storage_metadata singleton row",
        ));
    }
    Ok(StorageMetadata {
        storage_version,
        projection_version,
        projections_dirty: projections_dirty != 0,
    })
}

fn require_clean_storage_metadata(connection: &Connection) -> Result<(), StoreError> {
    let metadata = read_storage_metadata(connection)?;
    if metadata.storage_version == STORAGE_SCHEMA_VERSION
        && metadata.projection_version == PROJECTION_SCHEMA_VERSION
        && !metadata.projections_dirty
    {
        Ok(())
    } else if metadata.storage_version != STORAGE_SCHEMA_VERSION {
        Err(StoreError::UnsupportedStorageSchema(
            metadata.storage_version,
        ))
    } else {
        Err(StoreError::IncompatibleStorageSchema(
            "clean current storage metadata",
        ))
    }
}

#[derive(Debug)]
struct VerifiedStreamHead {
    version: StreamVersion,
    anchor: IntegrityAnchor,
}

fn verified_stream_head(
    connection: &Connection,
    stream_id: &str,
) -> Result<Option<VerifiedStreamHead>, StoreError> {
    let (projected, persisted) = connection.query_row(
        "SELECT
            (SELECT current_version FROM event_streams WHERE stream_id = ?1),
            (SELECT MAX(stream_version) FROM events WHERE stream_id = ?1)",
        params![stream_id],
        |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?)),
    )?;
    let projected = projected
        .map(|version| from_sqlite_integer("current_version", version))
        .transpose()?;
    let persisted = persisted
        .map(|version| from_sqlite_integer("maximum stream_version", version))
        .transpose()?;
    match (projected, persisted) {
        (None, None) | (Some(0), None) => Ok(None),
        (Some(projected), Some(persisted)) if projected == persisted && projected > 0 => {
            Ok(Some(VerifiedStreamHead {
                version: projected,
                anchor: require_integrity_anchor(connection, stream_id, projected)?,
            }))
        }
        (projected, persisted) => Err(StoreError::RehydrationIntegrity {
            stream_id: stream_id.into(),
            version: persisted.or(projected).unwrap_or(0),
        }),
    }
}

fn journal_mode(connection: &Connection) -> Result<String, StoreError> {
    connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(StoreError::from)
}

fn ensure_wal(connection: &Connection) -> Result<(), StoreError> {
    let mode: String = connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(StoreError::IncompatibleStorageSchema("journal mode"));
    }
    Ok(())
}

fn is_owned_table(name: &str) -> bool {
    table_role(name).is_some()
}

fn table_role(name: &str) -> Option<SchemaRole> {
    STORAGE_SCHEMA
        .iter()
        .find(|definition| definition.object_type() == "table" && definition.name == name)
        .map(|definition| definition.role)
}

fn validate_explicit_indexes(
    connection: &Connection,
    catalog: &[CatalogObject],
) -> Result<(), StoreError> {
    for object in catalog.iter().filter(|object| {
        object.object_type == "index" && object.sql.is_some() && is_owned_table(&object.table_name)
    }) {
        if STORAGE_SCHEMA.iter().any(|definition| {
            definition.role == SchemaRole::RequiredIndex && definition.name == object.name
        }) {
            continue;
        }
        if !explicit_index_is_harmless(connection, object)? {
            return Err(StoreError::IncompatibleStorageSchema(
                "unsupported explicit storage index",
            ));
        }
    }
    Ok(())
}

fn explicit_index_is_harmless(
    connection: &Connection,
    object: &CatalogObject,
) -> Result<bool, StoreError> {
    connection
        .query_row(
            "SELECT EXISTS (
             SELECT 1 FROM pragma_index_list(?1)
             WHERE name = ?2 AND origin = 'c' AND \"unique\" = 0 AND partial = 0
               AND NOT EXISTS (
                   SELECT 1 FROM pragma_index_xinfo(?2)
                   WHERE \"key\" = 1
                     AND (cid < 0 OR coll IS NULL
                          OR lower(coll) NOT IN ('binary', 'nocase', 'rtrim'))
               )
         )",
            params![&object.table_name, &object.name],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

fn validate_storage_triggers(
    catalog: &[CatalogObject],
    projection_repair_allowed: bool,
) -> Result<(), StoreError> {
    let triggers = catalog
        .iter()
        .filter(|object| object.object_type == "trigger")
        .filter(|object| {
            is_owned_table(&object.table_name)
                || STORAGE_TRIGGERS
                    .iter()
                    .any(|trigger| trigger.name == object.name)
        })
        .collect::<Vec<_>>();
    let missing_projection_triggers = STORAGE_TRIGGERS
        .iter()
        .filter(|expected| {
            projection_repair_allowed
                && table_role(expected.table_name) == Some(SchemaRole::Projection)
                && projection_table_needs_repair(catalog, expected.table_name)
                && !triggers.iter().any(|actual| actual.name == expected.name)
        })
        .count();
    if triggers.len() + missing_projection_triggers != STORAGE_TRIGGERS.len() {
        return Err(StoreError::IncompatibleStorageSchema(
            "storage trigger closed set",
        ));
    }
    for expected in STORAGE_TRIGGERS {
        let Some(actual) = triggers.iter().find(|object| object.name == expected.name) else {
            let missing_projection_table = projection_repair_allowed
                && table_role(expected.table_name) == Some(SchemaRole::Projection)
                && projection_table_needs_repair(catalog, expected.table_name);
            if missing_projection_table {
                continue;
            }
            return Err(StoreError::IncompatibleStorageSchema(
                "storage trigger closed set",
            ));
        };
        if actual.table_name != expected.table_name
            || actual.sql.as_ref().is_none_or(|sql| {
                normalize_schema_sql(sql) != normalize_schema_sql(&expected.sql())
            })
        {
            return Err(StoreError::IncompatibleStorageSchema(
                "storage trigger definition",
            ));
        }
    }
    Ok(())
}

fn projection_table_needs_repair(catalog: &[CatalogObject], table_name: &str) -> bool {
    let Some(definition) = STORAGE_SCHEMA.iter().find(|definition| {
        definition.role == SchemaRole::Projection && definition.name == table_name
    }) else {
        return false;
    };
    definition_is_current(catalog, definition).is_ok_and(|current| !current)
}

fn initialize_database(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    for definition in STORAGE_SCHEMA {
        transaction.execute_batch(definition.sql)?;
    }
    transaction.execute(
        "INSERT INTO storage_metadata
            (singleton, storage_schema_version, projection_schema_version, projections_dirty)
         VALUES (1, ?1, ?2, 0)",
        params![STORAGE_SCHEMA_VERSION, PROJECTION_SCHEMA_VERSION],
    )?;
    install_storage_triggers(transaction)
}

fn repair_database(transaction: &Transaction<'_>, plan: RepairPlan) -> Result<(), StoreError> {
    if plan.projections {
        let changed = transaction.execute(
            "UPDATE storage_metadata SET projections_dirty = 1 WHERE singleton = 1",
            [],
        )?;
        if changed != 1 {
            return Err(StoreError::IncompatibleStorageSchema(
                "storage metadata row",
            ));
        }
        drop_storage_triggers(transaction)?;
        for definition in STORAGE_SCHEMA
            .iter()
            .filter(|definition| definition.role == SchemaRole::Projection)
        {
            transaction.execute_batch(&format!("DROP TABLE IF EXISTS {};", definition.name))?;
            transaction.execute_batch(definition.sql)?;
        }
        rebuild_projections_in_transaction(transaction)?;
        install_storage_triggers(transaction)?;
    }
    if plan.projections || plan.indexes {
        rebuild_required_indexes(transaction)?;
    }
    if plan.projections {
        mark_projections_clean(transaction)?;
    }
    Ok(())
}

fn rebuild_required_indexes(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    for definition in STORAGE_SCHEMA
        .iter()
        .filter(|definition| definition.role == SchemaRole::RequiredIndex)
    {
        transaction.execute_batch(&format!("DROP INDEX IF EXISTS {};", definition.name))?;
        transaction.execute_batch(definition.sql)?;
    }
    Ok(())
}

fn install_storage_triggers(connection: &Connection) -> Result<(), StoreError> {
    for trigger in STORAGE_TRIGGERS {
        connection.execute_batch(&trigger.sql())?;
    }
    Ok(())
}

fn drop_storage_triggers(connection: &Connection) -> Result<(), StoreError> {
    for trigger in STORAGE_TRIGGERS {
        connection.execute_batch(&format!("DROP TRIGGER IF EXISTS {};", trigger.name))?;
    }
    Ok(())
}

#[derive(Debug)]
struct AppendedState {
    append: AppendResult,
    state: SessionState,
}

#[derive(Clone, Copy)]
struct AppendCommand<'a> {
    id: &'a str,
    fingerprint_version: i64,
    request_hash: &'a [u8],
}

fn validate_event_batch(events: &[EventDraft]) -> Result<(), StoreError> {
    if events.is_empty() {
        return Err(StoreError::EmptyEventBatch);
    }
    let mut event_ids = std::collections::BTreeSet::new();
    for draft in events {
        require_text("event_id", &draft.event_id)?;
        if !event_ids.insert(draft.event_id.clone()) {
            return Err(StoreError::DuplicateEventIdInBatch {
                event_id: draft.event_id.clone(),
            });
        }
        draft.event.validate()?;
    }
    Ok(())
}

fn append_in_transaction(
    transaction: &Transaction<'_>,
    stream_id: &str,
    expected_version: StreamVersion,
    command: AppendCommand<'_>,
    mut preverified: Option<RehydratedState>,
    events: &[EventDraft],
) -> Result<AppendedState, StoreError> {
    let AppendCommand {
        id: command_id,
        fingerprint_version,
        request_hash,
    } = command;
    if fingerprint_version != COMMAND_FINGERPRINT_VERSION
        || request_hash.len() != INTEGRITY_DIGEST_BYTES
    {
        return Err(StoreError::CommandIdempotencyConflict {
            command_id: command_id.into(),
        });
    }
    require_clean_storage_metadata(transaction)?;

    if let Some((stored_version, stored_hash, last_version)) = transaction
        .query_row(
            "SELECT fingerprint_version, request_hash, last_version
             FROM commands WHERE stream_id = ?1 AND command_id = ?2",
            params![stream_id, command_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?
    {
        if stored_version != fingerprint_version || !digest_matches(&stored_hash, request_hash) {
            return Err(StoreError::CommandIdempotencyConflict {
                command_id: command_id.into(),
            });
        }
        let head = verified_stream_head(transaction, stream_id)?.map_or(0, |head| head.version);
        let last_version = from_sqlite_integer("last_version", last_version)?;
        if last_version > head {
            return Err(StoreError::RehydrationIntegrity {
                stream_id: stream_id.into(),
                version: last_version,
            });
        }
        let existing_events = read_events_by_command(transaction, stream_id, command_id, head)?;
        let state = match preverified.take() {
            Some(restored) => restored.state,
            None => {
                rehydrate_from_view(transaction, stream_id)
                    .map_err(|error| rehydrate_error_into_store_error(error, stream_id))?
                    .state
            }
        };
        if state.stream_version != head {
            return Err(StoreError::RehydrationIntegrity {
                stream_id: stream_id.into(),
                version: head,
            });
        }
        return Ok(AppendedState {
            append: AppendResult {
                stream_id: stream_id.into(),
                command_id: command_id.into(),
                events: existing_events,
                stream_version: last_version,
                replayed: true,
            },
            state,
        });
    }

    let actual_version =
        verified_stream_head(transaction, stream_id)?.map_or(0, |head| head.version);
    if actual_version != expected_version {
        return Err(StoreError::OptimisticConcurrency {
            stream_id: stream_id.into(),
            expected: expected_version,
            actual: actual_version,
        });
    }

    let mut rehydrated = match preverified {
        Some(restored) => restored,
        None => rehydrate_from_view(transaction, stream_id)
            .map_err(|error| rehydrate_error_into_store_error(error, stream_id))?,
    };
    if rehydrated.state.stream_version != expected_version {
        return Err(StoreError::RehydrationIntegrity {
            stream_id: stream_id.into(),
            version: expected_version,
        });
    }

    for draft in events {
        if transaction
            .query_row(
                "SELECT 1 FROM events WHERE stream_id = ?1 AND event_id = ?2",
                params![stream_id, &draft.event_id],
                |_row| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Err(StoreError::EventIdempotencyConflict {
                stream_id: stream_id.into(),
                event_id: draft.event_id.clone(),
            });
        }
    }

    // Reducer no-ops (stale timers, duplicate terminal completions, and
    // already-materialized deliveries) retain their command receipt but do
    // not become a second durable semantic event. Compute this projection
    // before any authority insert so an invalid batch still appends nothing.
    let mut effective_drafts = Vec::with_capacity(events.len());
    let mut candidate_state = rehydrated.state.clone();
    for draft in events {
        let next = candidate_state.apply_event(&draft.event)?;
        if next != candidate_state {
            effective_drafts.push(draft.clone());
        }
        candidate_state = next;
    }

    if effective_drafts.is_empty() {
        // Keep a durable, non-semantic idempotency fact so projection repair
        // can reconstruct this command even though the requested transition
        // was stale/no-op. The key is a digest of the command identity, never
        // the caller's raw idempotency value.
        let command_digest = hex_encode(&digest_bytes(command_id.as_bytes()));
        effective_drafts.push(EventDraft::new(
            format!("command-noop:v1:{command_digest}"),
            SessionEvent::DedupeRecorded {
                key: format!("command:{command_digest}"),
            },
        ));
    }

    let mut stored_events = Vec::with_capacity(effective_drafts.len());
    for (index, draft) in effective_drafts.iter().enumerate() {
        let offset = u64::try_from(index + 1).map_err(|_| StoreError::IntegerRange {
            field: "event batch index",
        })?;
        let stream_version =
            expected_version
                .checked_add(offset)
                .ok_or(StoreError::IntegerRange {
                    field: "stream_version",
                })?;
        let payload = serde_json::to_vec(&draft.event)?;
        let fingerprint = event_fingerprint(
            stream_id,
            stream_version,
            &draft.event_id,
            command_id,
            EVENT_SCHEMA_VERSION,
            draft.event.kind(),
            &payload,
        );
        transaction.execute(
            "INSERT INTO events
                (stream_id, stream_version, event_id, command_id,
                 command_fingerprint_version, command_fingerprint,
                 event_schema_version, event_type, payload,
                 event_fingerprint_version, event_fingerprint)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                stream_id,
                to_sqlite_integer("stream_version", stream_version)?,
                &draft.event_id,
                command_id,
                fingerprint_version,
                request_hash,
                i64::from(EVENT_SCHEMA_VERSION),
                draft.event.kind(),
                payload,
                EVENT_FINGERPRINT_VERSION,
                &fingerprint,
            ],
        )?;
        let record = EventRecord {
            stream_id: stream_id.into(),
            stream_version,
            global_position: from_sqlite_integer(
                "global_position",
                transaction.last_insert_rowid(),
            )?,
            event_id: draft.event_id.clone(),
            command_id: command_id.into(),
            event_schema_version: EVENT_SCHEMA_VERSION,
            event: draft.event.clone(),
        };
        rehydrated.prefix_digest = extend_prefix_digest(&rehydrated.prefix_digest, &fingerprint);
        rehydrated.state = rehydrated.state.apply_record(&record)?;
        stored_events.push(record);
    }

    let stream_version = expected_version
        .checked_add(u64::try_from(effective_drafts.len()).map_err(|_| {
            StoreError::IntegerRange {
                field: "event batch length",
            }
        })?)
        .ok_or(StoreError::IntegerRange {
            field: "stream_version",
        })?;
    let first_version = expected_version
        .checked_add(1)
        .ok_or(StoreError::IntegerRange {
            field: "first_version",
        })?;
    if expected_version == 0 {
        let created = stored_events.first().ok_or(StoreError::EmptyEventBatch)?;
        let SessionEvent::SessionCreated {
            owner,
            created_at_ms,
            ..
        } = &created.event
        else {
            return Err(DomainError::SessionNotCreated.into());
        };
        transaction.execute(
            "INSERT INTO event_streams (stream_id, current_version) VALUES (?1, ?2)",
            params![
                stream_id,
                to_sqlite_integer("stream_version", stream_version)?,
            ],
        )?;
        transaction.execute(
            "INSERT INTO session_create_receipts
                (authority_id, subject, command_id, fingerprint_version, request_hash,
                 stream_id, stream_version, creation_global_position)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)",
            params![
                &owner.authority_id,
                &owner.subject,
                command_id,
                fingerprint_version,
                request_hash,
                stream_id,
                to_sqlite_integer("creation_global_position", created.global_position)?,
            ],
        )?;
        transaction.execute(
            "INSERT INTO session_index
                (stream_id, authority_id, subject, creation_global_position,
                 created_at_ms, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                stream_id,
                &owner.authority_id,
                &owner.subject,
                to_sqlite_integer("creation_global_position", created.global_position)?,
                created_at_ms,
                session_status_sql(&rehydrated.state.status),
            ],
        )?;
    } else {
        let changed = transaction.execute(
            "UPDATE event_streams SET current_version = ?2 WHERE stream_id = ?1",
            params![
                stream_id,
                to_sqlite_integer("stream_version", stream_version)?,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::RehydrationIntegrity {
                stream_id: stream_id.into(),
                version: stream_version,
            });
        }
        let changed = transaction.execute(
            "UPDATE session_index SET status = ?2 WHERE stream_id = ?1",
            params![stream_id, session_status_sql(&rehydrated.state.status)],
        )?;
        if changed != 1 {
            return Err(StoreError::InvalidSessionCreateReceipt);
        }
    }
    transaction.execute(
        "INSERT INTO commands
            (stream_id, command_id, fingerprint_version, request_hash,
             first_version, last_version, event_count)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            stream_id,
            command_id,
            fingerprint_version,
            request_hash,
            to_sqlite_integer("first_version", first_version)?,
            to_sqlite_integer("last_version", stream_version)?,
            i64::try_from(effective_drafts.len()).map_err(|_| StoreError::IntegerRange {
                field: "event count"
            })?,
        ],
    )?;
    transaction.execute(
        "INSERT INTO integrity_anchors
            (stream_id, stream_version, event_prefix_digest_version,
             event_prefix_digest, state_schema_version, reducer_schema_version,
             state_digest_version, state_digest)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            stream_id,
            to_sqlite_integer("stream_version", stream_version)?,
            EVENT_PREFIX_DIGEST_VERSION,
            &rehydrated.prefix_digest,
            i64::from(STATE_SCHEMA_VERSION),
            i64::from(REDUCER_SCHEMA_VERSION),
            STATE_DIGEST_VERSION,
            state_digest(&rehydrated.state)?,
        ],
    )?;

    Ok(AppendedState {
        append: AppendResult {
            stream_id: stream_id.into(),
            command_id: command_id.into(),
            events: stored_events,
            stream_version,
            replayed: false,
        },
        state: rehydrated.state,
    })
}

#[derive(Debug)]
struct SessionCreation {
    record: EventRecord,
    owner: SessionOwner,
    created_at_ms: i64,
    selection: SessionSelection,
    command_fingerprint_version: i64,
    command_fingerprint: Vec<u8>,
}

#[derive(Debug)]
struct VerifiedOwnedStream {
    head: VerifiedStreamHead,
    creation: SessionCreation,
    rehydrated: RehydratedState,
}

fn verified_creation_event(
    connection: &Connection,
    stream_id: &str,
) -> Result<SessionCreation, StoreError> {
    let raw = connection
        .query_row(
            "SELECT global_position, stream_id, stream_version, event_id, command_id,
                    event_schema_version, event_type, payload,
                    event_fingerprint_version, event_fingerprint,
                    command_fingerprint_version, command_fingerprint
             FROM events WHERE stream_id = ?1 AND stream_version = 1",
            params![stream_id],
            |row| {
                Ok((
                    decode_persisted_event_row(row)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                ))
            },
        )
        .optional()?
        .ok_or(StoreError::InvalidSessionCreateReceipt)?;
    let event = decode_persisted_event(raw.0)?;
    let (owner, created_at_ms, selection) = match &event.record.event {
        SessionEvent::SessionCreated {
            owner,
            created_at_ms,
            selection,
            ..
        } => (owner.clone(), *created_at_ms, selection.clone()),
        _ => return Err(StoreError::InvalidSessionCreateReceipt),
    };
    if raw.1 != COMMAND_FINGERPRINT_VERSION
        || raw.2.len() != INTEGRITY_DIGEST_BYTES
        || event.record.stream_version != 1
    {
        return Err(StoreError::InvalidSessionCreateReceipt);
    }
    Ok(SessionCreation {
        record: event.record,
        owner,
        created_at_ms,
        selection,
        command_fingerprint_version: raw.1,
        command_fingerprint: raw.2,
    })
}

fn verified_owned_stream(
    connection: &Connection,
    owner: &SessionOwner,
    stream_id: &str,
) -> Result<VerifiedOwnedStream, StoreError> {
    owner.validate()?;
    require_clean_storage_metadata(connection)?;
    let projection = connection
        .query_row(
            "SELECT streams.current_version, sessions.creation_global_position,
                    sessions.created_at_ms, sessions.status
             FROM session_index AS sessions
             JOIN event_streams AS streams ON streams.stream_id = sessions.stream_id
             WHERE sessions.stream_id = ?1 AND sessions.authority_id = ?2
               AND sessions.subject = ?3",
            params![stream_id, &owner.authority_id, &owner.subject],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or(StoreError::SessionNotFound)?;
    let head = verified_stream_head(connection, stream_id)?
        .ok_or(StoreError::InvalidSessionCreateReceipt)?;
    let projected_version = from_sqlite_integer("current_version", projection.0)?;
    let projected_creation = from_sqlite_integer("creation_global_position", projection.1)?;
    let creation = verified_creation_event(connection, stream_id)?;
    let restored = rehydrate_verified_stream(connection, stream_id, &head)
        .map_err(|error| rehydrate_error_into_store_error(error, stream_id))?;
    let projected_status = session_status_from_sql(&projection.3)?;
    if projected_version != head.version
        || creation.owner != *owner
        || creation.created_at_ms != projection.2
        || creation.record.global_position != projected_creation
        || creation.record.stream_id != stream_id
        || restored.state.stream_version != head.version
        || restored.state.owner.as_ref() != Some(owner)
        || restored.state.created_at_ms != Some(creation.created_at_ms)
        || restored.state.status != projected_status
    {
        return Err(StoreError::InvalidSessionCreateReceipt);
    }
    Ok(VerifiedOwnedStream {
        head,
        creation,
        rehydrated: restored,
    })
}

fn lookup_session_create_in_view(
    connection: &Connection,
    owner: &SessionOwner,
    command: &SessionCreateCommand,
) -> Result<Option<SessionCreateResult>, StoreError> {
    owner.validate()?;
    require_clean_storage_metadata(connection)?;
    let receipt = connection
        .query_row(
            "SELECT fingerprint_version, request_hash, stream_id, stream_version,
                    creation_global_position
             FROM session_create_receipts
             WHERE authority_id = ?1 AND subject = ?2 AND command_id = ?3",
            params![&owner.authority_id, &owner.subject, &command.command_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((fingerprint_version, request_hash, stream_id, stream_version, creation_position)) =
        receipt
    else {
        return Ok(None);
    };
    if fingerprint_version != SESSION_CREATE_COMMAND_VERSION
        || !digest_matches(&request_hash, &command.request_hash)
    {
        return Err(StoreError::CommandIdempotencyConflict {
            command_id: command.command_id.clone(),
        });
    }
    // A create receipt is intentionally replayable from the immutable
    // version-one creation fact alone. Do not rehydrate the mutable tail here:
    // a later corruption must not turn an already-admitted fixed `201` replay
    // into a current-state read.
    let creation = verified_creation_event(connection, &stream_id)?;
    if from_sqlite_integer("create stream_version", stream_version)? != 1
        || from_sqlite_integer("creation_global_position", creation_position)?
            != creation.record.global_position
        || creation.owner != *owner
        || creation.record.command_id != command.command_id
        || creation.command_fingerprint_version != SESSION_CREATE_COMMAND_VERSION
        || !digest_matches(&creation.command_fingerprint, &command.request_hash)
    {
        return Err(StoreError::InvalidSessionCreateReceipt);
    }
    let state = SessionState::new(&stream_id).apply_record(&creation.record)?;
    state.validate()?;
    Ok(Some(SessionCreateResult {
        append: AppendResult {
            stream_id,
            command_id: command.command_id.clone(),
            events: vec![creation.record],
            stream_version: 1,
            replayed: true,
        },
        state,
    }))
}

fn session_status_sql(status: &SessionStatus) -> &'static str {
    match status {
        SessionStatus::Idle => "idle",
        SessionStatus::Active => "active",
    }
}

fn session_status_from_sql(status: &str) -> Result<SessionStatus, StoreError> {
    match status {
        "idle" => Ok(SessionStatus::Idle),
        "active" => Ok(SessionStatus::Active),
        _ => Err(StoreError::IncompatibleStorageSchema(
            "event stream status projection",
        )),
    }
}

fn session_projection_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<(String, i64, i64, i64, String)> {
    Ok((
        row.get::<_, String>(0)?,
        row.get::<_, i64>(1)?,
        row.get::<_, i64>(2)?,
        row.get::<_, i64>(3)?,
        row.get::<_, String>(4)?,
    ))
}

impl EventStore for SqliteEventStore {
    fn create_session(&self, create: &SessionCreate) -> Result<SessionCreateResult, StoreError> {
        create.owner.validate()?;
        create.selection.validate()?;
        if create.created_at_ms < 0 {
            return Err(DomainError::InvalidCreatedAt.into());
        }
        require_text("command_id", &create.command.command_id)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(replayed) =
            lookup_session_create_in_view(&transaction, &create.owner, &create.command)?
        {
            transaction.commit()?;
            return Ok(replayed);
        }

        let (session_id, appended) = loop {
            let candidate = Ulid::new().to_string();
            let exists = transaction
                .query_row(
                    "SELECT 1 FROM events WHERE stream_id = ?1 LIMIT 1",
                    params![&candidate],
                    |_row| Ok(()),
                )
                .optional()?
                .is_some();
            if exists {
                continue;
            }
            let event = SessionEvent::SessionCreated {
                schema_version: SESSION_CREATED_SCHEMA_VERSION,
                session_id: candidate.clone(),
                owner: create.owner.clone(),
                created_at_ms: create.created_at_ms,
                selection: create.selection.clone(),
            };
            let events = [EventDraft::new(
                format!("session-created:{candidate}"),
                event,
            )];
            validate_event_batch(&events)?;
            let appended = append_in_transaction(
                &transaction,
                &candidate,
                0,
                AppendCommand {
                    id: &create.command.command_id,
                    fingerprint_version: SESSION_CREATE_COMMAND_VERSION,
                    request_hash: &create.command.request_hash,
                },
                None,
                &events,
            )?;
            break (candidate, appended);
        };
        if appended.state.session_id != session_id || appended.state.stream_version != 1 {
            return Err(StoreError::InvalidSessionCreateReceipt);
        }
        mark_projections_clean(&transaction)?;
        transaction.commit()?;
        Ok(SessionCreateResult {
            append: appended.append,
            state: appended.state,
        })
    }

    fn lookup_session_create(
        &self,
        owner: &SessionOwner,
        command: &SessionCreateCommand,
    ) -> Result<Option<SessionCreateResult>, StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let result = lookup_session_create_in_view(&transaction, owner, command);
        transaction.commit()?;
        result
    }

    fn append_owned(
        &self,
        owner: &SessionOwner,
        stream_id: &str,
        expected_version: StreamVersion,
        command_id: &str,
        events: &[EventDraft],
    ) -> Result<AppendResult, StoreError> {
        require_text("stream_id", stream_id)?;
        require_text("command_id", command_id)?;
        validate_event_batch(events)?;
        let request_hash = hash_events(events)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let verified = verified_owned_stream(&transaction, owner, stream_id)?;
        let appended = append_in_transaction(
            &transaction,
            stream_id,
            expected_version,
            AppendCommand {
                id: command_id,
                fingerprint_version: COMMAND_FINGERPRINT_VERSION,
                request_hash: &request_hash,
            },
            Some(verified.rehydrated),
            events,
        )?;
        mark_projections_clean(&transaction)?;
        transaction.commit()?;
        Ok(appended.append)
    }

    fn rehydrate_owned(
        &self,
        owner: &SessionOwner,
        stream_id: &str,
    ) -> Result<SessionState, RehydrateError> {
        require_text("stream_id", stream_id)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(StoreError::from)?;
        let result = (|| {
            let verified = verified_owned_stream(&transaction, owner, stream_id)?;
            Ok(verified.rehydrated.state)
        })();
        transaction.commit().map_err(StoreError::from)?;
        result
    }

    fn read_stream_owned(
        &self,
        owner: &SessionOwner,
        stream_id: &str,
        after_version: StreamVersion,
    ) -> Result<Vec<EventRecord>, StoreError> {
        require_text("stream_id", stream_id)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let verified = verified_owned_stream(&transaction, owner, stream_id)?;
        let events = event_records(read_stored_events(
            &transaction,
            stream_id,
            after_version,
            verified.head.version,
        )?);
        transaction.commit()?;
        Ok(events)
    }

    fn read_session_events(
        &self,
        owner: &SessionOwner,
        stream_id: &str,
        after_position: GlobalPosition,
        limit: usize,
    ) -> Result<Vec<EventRecord>, StoreError> {
        require_text("stream_id", stream_id)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let verified = verified_owned_stream(&transaction, owner, stream_id)?;
        if limit == 0 {
            transaction.commit()?;
            return Ok(Vec::new());
        }
        let stored = {
            let mut statement = transaction.prepare(
                "SELECT global_position, stream_id, stream_version, event_id, command_id,
                        event_schema_version, event_type, payload,
                        event_fingerprint_version, event_fingerprint
                 FROM events
                 WHERE stream_id = ?1 AND global_position > ?2 AND stream_version <= ?3
                 ORDER BY global_position ASC LIMIT ?4",
            )?;
            let rows = statement.query_map(
                params![
                    stream_id,
                    to_sqlite_integer("after_position", after_position)?,
                    to_sqlite_integer("head stream_version", verified.head.version)?,
                    i64::try_from(limit)
                        .map_err(|_| StoreError::IntegerRange { field: "limit" })?,
                ],
                decode_persisted_event_row,
            )?;
            collect_persisted_events(rows)?
        };
        let events = event_records(stored);
        transaction.commit()?;
        Ok(events)
    }

    fn scan_owned_session_refs(
        &self,
        after_creation_position: GlobalPosition,
        limit: usize,
    ) -> Result<Vec<OwnedSessionRef>, StoreError> {
        if !(1..=MAX_OWNED_SESSION_SCAN_LIMIT).contains(&limit) {
            return Err(StoreError::InvalidOwnedSessionScanLimit);
        }
        let after_creation_position =
            to_sqlite_integer("after_creation_position", after_creation_position)?;
        let limit = i64::try_from(limit).map_err(|_| StoreError::IntegerRange {
            field: "owned session scan limit",
        })?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_clean_storage_metadata(&transaction)?;
        let projections = {
            let mut statement = transaction.prepare(
                "SELECT stream_id, authority_id, subject, creation_global_position
                 FROM session_index
                 WHERE creation_global_position > ?1
                 ORDER BY creation_global_position ASC
                 LIMIT ?2",
            )?;
            let rows = statement.query_map(params![after_creation_position, limit], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut sessions = Vec::with_capacity(projections.len());
        for (stream_id, authority_id, subject, creation_position) in projections {
            let creation_position =
                from_sqlite_integer("creation_global_position", creation_position)?;
            let owner = SessionOwner::new(authority_id, subject);
            let creation = verified_creation_event(&transaction, &stream_id)?;
            if creation.record.stream_id != stream_id
                || creation.owner != owner
                || creation.record.global_position != creation_position
            {
                return Err(StoreError::InvalidSessionCreateReceipt);
            }
            sessions.push(OwnedSessionRef {
                owner,
                session_id: stream_id,
                creation_global_position: creation_position,
            });
        }
        transaction.commit()?;
        Ok(sessions)
    }

    fn list_sessions(
        &self,
        owner: &SessionOwner,
        limit: usize,
    ) -> Result<Vec<SessionListItem>, StoreError> {
        Ok(self.list_sessions_page(owner, None, limit)?.items)
    }

    fn list_sessions_page(
        &self,
        owner: &SessionOwner,
        cursor: Option<&SessionListCursor>,
        limit: usize,
    ) -> Result<SessionListPage, StoreError> {
        owner.validate()?;
        if !(1..=MAX_SESSION_LIST_LIMIT).contains(&limit) {
            return Err(StoreError::InvalidSessionListLimit);
        }
        if cursor.is_some_and(|cursor| cursor.owner() != owner) {
            return Err(StoreError::InvalidSessionListCursor);
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_clean_storage_metadata(&transaction)?;
        let projection_limit =
            i64::try_from(limit + 1).map_err(|_| StoreError::IntegerRange { field: "limit" })?;
        let projections = if let Some(cursor) = cursor {
            let cursor_position = to_sqlite_integer(
                "session list cursor creation position",
                cursor.creation_global_position(),
            )?;
            let mut statement = transaction.prepare(
                "SELECT sessions.stream_id, streams.current_version,
                        sessions.creation_global_position, sessions.created_at_ms,
                        sessions.status
                 FROM session_index AS sessions
                 JOIN event_streams AS streams ON streams.stream_id = sessions.stream_id
                 WHERE sessions.authority_id = ?1 AND sessions.subject = ?2
                   AND (sessions.creation_global_position < ?3
                        OR (sessions.creation_global_position = ?3
                            AND sessions.stream_id < ?4))
                 ORDER BY sessions.creation_global_position DESC, sessions.stream_id DESC
                 LIMIT ?5",
            )?;
            let rows = statement.query_map(
                params![
                    &owner.authority_id,
                    &owner.subject,
                    cursor_position,
                    cursor.session_id(),
                    projection_limit,
                ],
                session_projection_row,
            )?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            let mut statement = transaction.prepare(
                "SELECT sessions.stream_id, streams.current_version,
                        sessions.creation_global_position, sessions.created_at_ms,
                        sessions.status
                 FROM session_index AS sessions
                 JOIN event_streams AS streams ON streams.stream_id = sessions.stream_id
                 WHERE sessions.authority_id = ?1 AND sessions.subject = ?2
                 ORDER BY sessions.creation_global_position DESC, sessions.stream_id DESC
                 LIMIT ?3",
            )?;
            let rows = statement.query_map(
                params![&owner.authority_id, &owner.subject, projection_limit],
                session_projection_row,
            )?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let has_more = projections.len() > limit;
        let projections = projections.into_iter().take(limit).collect::<Vec<_>>();
        let mut items = Vec::with_capacity(projections.len());
        for (stream_id, version, creation_position, created_at_ms, status) in projections {
            let verified = verified_owned_stream(&transaction, owner, &stream_id)?;
            let version = from_sqlite_integer("current_version", version)?;
            let creation_position =
                from_sqlite_integer("creation_global_position", creation_position)?;
            let status = session_status_from_sql(&status)?;
            if version != verified.head.version
                || creation_position != verified.creation.record.global_position
                || created_at_ms != verified.creation.created_at_ms
                || status != verified.rehydrated.state.status
            {
                return Err(StoreError::InvalidSessionCreateReceipt);
            }
            items.push(SessionListItem {
                session_id: stream_id,
                version,
                status,
                created_at_ms,
                creation_global_position: creation_position,
                selection: verified.creation.selection,
            });
        }
        let next_cursor = if has_more {
            let last = items.last().ok_or(StoreError::InvalidSessionListCursor)?;
            Some(SessionListCursor::new(
                owner,
                last.creation_global_position,
                last.session_id.clone(),
            )?)
        } else {
            None
        };
        transaction.commit()?;
        Ok(SessionListPage { items, next_cursor })
    }

    fn lookup_external_callback(
        &self,
        callback_id: &str,
    ) -> Result<Option<ExternalCallbackLookup>, StoreError> {
        require_text("callback_id", callback_id)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        require_clean_storage_metadata(&transaction)?;
        let stream_ids = {
            let mut statement = transaction.prepare(
                "SELECT DISTINCT stream_id
                 FROM events
                 WHERE event_type = 'async_tool_call_callback_planned'
                 ORDER BY stream_id ASC",
            )?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut found = None;
        for stream_id in stream_ids {
            let state = rehydrate_from_view(&transaction, &stream_id)
                .map_err(|error| rehydrate_error_into_store_error(error, &stream_id))?
                .state;
            let Some(binding) = state.callback_bindings.get(callback_id).cloned() else {
                continue;
            };
            let owner = state
                .owner
                .clone()
                .ok_or(StoreError::InvalidSessionCreateReceipt)?;
            let lookup = ExternalCallbackLookup {
                owner,
                session_id: state.session_id.clone(),
                binding,
                state,
            };
            if found.is_some() {
                return Err(StoreError::ExternalCallbackConflict(callback_id.into()));
            }
            found = Some(lookup);
        }
        transaction.commit()?;
        Ok(found)
    }

    fn write_snapshot(&self, snapshot: &SnapshotRecord) -> Result<(), StoreError> {
        require_text("stream_id", &snapshot.stream_id)?;
        if snapshot.encoding != SNAPSHOT_ENCODING_JSON {
            return Err(StoreError::UnsupportedSnapshotEncoding(
                snapshot.encoding.clone(),
            ));
        }
        if !snapshot.checksum_matches() {
            return Err(StoreError::InvalidSnapshotChecksum);
        }
        if snapshot_state(snapshot).is_none() {
            return Err(StoreError::SnapshotStateMismatch);
        }
        let stream_version = to_sqlite_integer("snapshot stream_version", snapshot.stream_version)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_clean_storage_metadata(&transaction)?;
        let current_version = verified_stream_head(&transaction, &snapshot.stream_id)?
            .ok_or(StoreError::SnapshotStreamMissing(
                snapshot.stream_id.clone(),
            ))?
            .version;
        if snapshot.stream_version > current_version {
            return Err(StoreError::SnapshotAheadOfStream {
                snapshot: snapshot.stream_version,
                stream: current_version,
            });
        }
        let anchor =
            read_integrity_anchor(&transaction, &snapshot.stream_id, snapshot.stream_version)?
                .filter(|anchor| {
                    anchor_is_current(anchor)
                        && anchor.state_schema_version == snapshot.state_schema_version
                        && anchor.reducer_schema_version == snapshot.reducer_schema_version
                })
                .ok_or_else(|| StoreError::InvalidIntegrityAnchor {
                    stream_id: snapshot.stream_id.clone(),
                    version: snapshot.stream_version,
                })?;
        if !digest_matches(&digest_bytes(&snapshot.payload), &anchor.state_digest) {
            return Err(StoreError::SnapshotStateMismatch);
        }
        transaction.execute(
            "INSERT INTO snapshots
                (stream_id, stream_version, state_schema_version, reducer_schema_version,
                 encoding, checksum, payload, event_prefix_digest_version,
                 event_prefix_digest, state_digest_version, state_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                &snapshot.stream_id,
                stream_version,
                i64::from(snapshot.state_schema_version),
                i64::from(snapshot.reducer_schema_version),
                &snapshot.encoding,
                &snapshot.checksum,
                &snapshot.payload,
                anchor.prefix_digest_version,
                &anchor.prefix_digest,
                anchor.state_digest_version,
                &anchor.state_digest,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }
}

#[derive(Debug)]
struct CommandProjection {
    fingerprint_version: i64,
    fingerprint: Vec<u8>,
    first_version: StreamVersion,
    last_version: StreamVersion,
    event_count: u64,
}

#[derive(Debug)]
struct CreateReceiptProjection {
    owner: SessionOwner,
    command_id: String,
    fingerprint_version: i64,
    fingerprint: Vec<u8>,
    stream_id: String,
    creation_global_position: GlobalPosition,
}

fn rebuild_projections_in_transaction(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    let mut stream_heads = BTreeMap::<String, StreamVersion>::new();
    let mut stream_states = BTreeMap::<String, SessionState>::new();
    let mut stream_prefixes = BTreeMap::<String, Vec<u8>>::new();
    let mut creation_positions = BTreeMap::<String, GlobalPosition>::new();
    let mut commands = BTreeMap::<(String, String), CommandProjection>::new();
    let mut receipts = BTreeMap::<(String, String, String), CreateReceiptProjection>::new();
    {
        let mut statement = transaction.prepare(
            "SELECT global_position, stream_id, stream_version, event_id, command_id,
                    event_schema_version, event_type, payload,
                    event_fingerprint_version, event_fingerprint,
                    command_fingerprint_version, command_fingerprint
             FROM events ORDER BY stream_id ASC, stream_version ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                decode_persisted_event_row(row)?,
                row.get::<_, i64>(10)?,
                row.get::<_, Vec<u8>>(11)?,
            ))
        })?;
        for row in rows {
            let (raw_event, fingerprint_version, fingerprint) = row?;
            let event = decode_persisted_event(raw_event)?;
            let stream_id = event.record.stream_id.clone();
            let version = event.record.stream_version;
            let command_id = event.record.command_id.clone();
            if fingerprint_version != COMMAND_FINGERPRINT_VERSION
                || fingerprint.len() != INTEGRITY_DIGEST_BYTES
            {
                return Err(StoreError::InconsistentCommandFingerprint {
                    stream_id,
                    command_id,
                });
            }
            let previous = stream_heads.get(&stream_id).copied().unwrap_or(0);
            if version
                != previous.checked_add(1).ok_or(StoreError::IntegerRange {
                    field: "stream_version",
                })?
            {
                return Err(StoreError::InvalidIntegrityAnchor { stream_id, version });
            }
            stream_heads.insert(stream_id.clone(), version);
            let state = stream_states
                .entry(stream_id.clone())
                .or_insert_with(|| SessionState::new(&stream_id));
            let prefix = stream_prefixes
                .entry(stream_id.clone())
                .or_insert_with(|| prefix_digest_seed(&stream_id));
            *prefix = extend_prefix_digest(prefix, &event.fingerprint);
            *state = state.apply_record(&event.record)?;
            if version == 1 {
                let SessionEvent::SessionCreated { owner, .. } = &event.record.event else {
                    return Err(StoreError::InvalidSessionCreateReceipt);
                };
                let receipt_key = (
                    owner.authority_id.clone(),
                    owner.subject.clone(),
                    command_id.clone(),
                );
                let receipt = CreateReceiptProjection {
                    owner: owner.clone(),
                    command_id: command_id.clone(),
                    fingerprint_version,
                    fingerprint: fingerprint.clone(),
                    stream_id: stream_id.clone(),
                    creation_global_position: event.record.global_position,
                };
                if receipts.insert(receipt_key, receipt).is_some()
                    || creation_positions
                        .insert(stream_id.clone(), event.record.global_position)
                        .is_some()
                {
                    return Err(StoreError::InvalidSessionCreateReceipt);
                }
            }
            let key = (stream_id.clone(), command_id.clone());
            match commands.get_mut(&key) {
                Some(projection) => {
                    if projection.fingerprint_version != fingerprint_version
                        || !digest_matches(&projection.fingerprint, &fingerprint)
                        || projection.last_version.checked_add(1) != Some(version)
                    {
                        return Err(StoreError::InconsistentCommandFingerprint {
                            stream_id,
                            command_id,
                        });
                    }
                    projection.last_version = version;
                    projection.event_count =
                        projection
                            .event_count
                            .checked_add(1)
                            .ok_or(StoreError::IntegerRange {
                                field: "event count",
                            })?;
                }
                None => {
                    commands.insert(
                        key,
                        CommandProjection {
                            fingerprint_version,
                            fingerprint,
                            first_version: version,
                            last_version: version,
                            event_count: 1,
                        },
                    );
                }
            }
        }
    }

    transaction.execute("DELETE FROM commands", [])?;
    transaction.execute("DELETE FROM session_create_receipts", [])?;
    transaction.execute("DELETE FROM session_index", [])?;
    transaction.execute("DELETE FROM event_streams", [])?;
    for (stream_id, head) in &stream_heads {
        let state = stream_states
            .get(stream_id)
            .ok_or(StoreError::InvalidSessionCreateReceipt)?;
        state.validate()?;
        let owner = state
            .owner
            .as_ref()
            .ok_or(StoreError::InvalidSessionCreateReceipt)?;
        let created_at_ms = state
            .created_at_ms
            .ok_or(StoreError::InvalidSessionCreateReceipt)?;
        let creation_position = creation_positions
            .get(stream_id)
            .copied()
            .ok_or(StoreError::InvalidSessionCreateReceipt)?;
        transaction.execute(
            "INSERT INTO event_streams (stream_id, current_version) VALUES (?1, ?2)",
            params![stream_id, to_sqlite_integer("current_version", *head)?],
        )?;
        transaction.execute(
            "INSERT INTO session_index
                (stream_id, authority_id, subject, creation_global_position,
                 created_at_ms, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                stream_id,
                &owner.authority_id,
                &owner.subject,
                to_sqlite_integer("creation_global_position", creation_position)?,
                created_at_ms,
                session_status_sql(&state.status),
            ],
        )?;
    }
    for ((stream_id, command_id), projection) in commands {
        transaction.execute(
            "INSERT INTO commands
                (stream_id, command_id, fingerprint_version, request_hash,
                 first_version, last_version, event_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                stream_id,
                command_id,
                projection.fingerprint_version,
                projection.fingerprint,
                to_sqlite_integer("first_version", projection.first_version)?,
                to_sqlite_integer("last_version", projection.last_version)?,
                to_sqlite_integer("event count", projection.event_count)?,
            ],
        )?;
    }
    for (_, receipt) in receipts {
        transaction.execute(
            "INSERT INTO session_create_receipts
                (authority_id, subject, command_id, fingerprint_version, request_hash,
                 stream_id, stream_version, creation_global_position)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)",
            params![
                receipt.owner.authority_id,
                receipt.owner.subject,
                receipt.command_id,
                receipt.fingerprint_version,
                receipt.fingerprint,
                receipt.stream_id,
                to_sqlite_integer("creation_global_position", receipt.creation_global_position,)?,
            ],
        )?;
    }
    for (stream_id, head) in stream_heads {
        let verified = verified_stream_head(transaction, &stream_id)?.ok_or_else(|| {
            StoreError::InvalidIntegrityAnchor {
                stream_id: stream_id.clone(),
                version: head,
            }
        })?;
        if verified.version != head {
            return Err(StoreError::RehydrationIntegrity {
                stream_id,
                version: verified.version,
            });
        }
        let state = stream_states
            .get(&stream_id)
            .ok_or(StoreError::InvalidSessionCreateReceipt)?;
        let prefix = stream_prefixes
            .get(&stream_id)
            .ok_or(StoreError::InvalidIntegrityAnchor {
                stream_id: stream_id.clone(),
                version: head,
            })?;
        if !digest_matches(prefix, &verified.anchor.prefix_digest)
            || !digest_matches(&state_digest(state)?, &verified.anchor.state_digest)
        {
            return Err(StoreError::RehydrationIntegrity {
                stream_id,
                version: head,
            });
        }
    }
    Ok(())
}

fn mark_projections_clean(connection: &Connection) -> Result<(), StoreError> {
    let changed = connection.execute(
        "UPDATE storage_metadata SET projections_dirty = 0,
            storage_schema_version = ?1, projection_schema_version = ?2
         WHERE singleton = 1",
        params![STORAGE_SCHEMA_VERSION, PROJECTION_SCHEMA_VERSION],
    )?;
    if changed != 1 {
        return Err(StoreError::IncompatibleStorageSchema(
            "storage metadata row",
        ));
    }
    Ok(())
}

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

#[derive(Clone, Debug)]
struct IntegrityAnchor {
    prefix_digest_version: i64,
    prefix_digest: Vec<u8>,
    state_schema_version: u32,
    reducer_schema_version: u32,
    state_digest_version: i64,
    state_digest: Vec<u8>,
}

#[derive(Debug)]
struct RehydratedState {
    state: SessionState,
    prefix_digest: Vec<u8>,
}

#[derive(Debug)]
struct SnapshotWithReferences {
    snapshot: SnapshotRecord,
    prefix_digest_version: i64,
    prefix_digest: Vec<u8>,
    state_digest_version: i64,
    state_digest: Vec<u8>,
}

#[derive(Debug)]
struct StoredEvent {
    record: EventRecord,
    fingerprint: Vec<u8>,
}

fn rehydrate_from_view(
    connection: &Connection,
    stream_id: &str,
) -> Result<RehydratedState, RehydrateError> {
    require_clean_storage_metadata(connection)?;
    let Some(head) = verified_stream_head(connection, stream_id)? else {
        return Ok(RehydratedState {
            state: SessionState::new(stream_id),
            prefix_digest: prefix_digest_seed(stream_id),
        });
    };

    rehydrate_verified_stream(connection, stream_id, &head)
}

fn rehydrate_verified_stream(
    connection: &Connection,
    stream_id: &str,
    head: &VerifiedStreamHead,
) -> Result<RehydratedState, RehydrateError> {
    let stream_head = head.version;
    let head_anchor = &head.anchor;

    let mut before = (stream_head, i64::MAX);
    while let Some(candidate) = next_snapshot_candidate(connection, stream_id, stream_head, before)?
    {
        before = (
            candidate.snapshot.stream_version,
            candidate.snapshot.snapshot_id.unwrap_or_default(),
        );
        let Some(snapshot_anchor) =
            read_integrity_anchor(connection, stream_id, candidate.snapshot.stream_version)?
        else {
            continue;
        };
        let Some(state) = validated_snapshot_state(&candidate, &snapshot_anchor) else {
            continue;
        };
        if !snapshot_prefix_matches_events(
            connection,
            stream_id,
            candidate.snapshot.stream_version,
            &snapshot_anchor,
        )? {
            continue;
        }
        let restored = replay_tail(
            connection,
            stream_id,
            stream_head,
            state,
            snapshot_anchor.prefix_digest.clone(),
        );
        if let Ok(restored) = restored {
            if restored_matches_anchor(&restored, head_anchor)? {
                return Ok(restored);
            }
        }
    }

    let restored = replay_tail(
        connection,
        stream_id,
        stream_head,
        SessionState::new(stream_id),
        prefix_digest_seed(stream_id),
    )?;
    if !restored_matches_anchor(&restored, head_anchor)? {
        return Err(StoreError::RehydrationIntegrity {
            stream_id: stream_id.into(),
            version: stream_head,
        }
        .into());
    }
    Ok(restored)
}

fn snapshot_prefix_matches_events(
    connection: &Connection,
    stream_id: &str,
    snapshot_version: StreamVersion,
    snapshot_anchor: &IntegrityAnchor,
) -> Result<bool, StoreError> {
    let previous_version = connection.query_row(
        "SELECT MAX(stream_version) FROM integrity_anchors
         WHERE stream_id = ?1 AND stream_version < ?2",
        params![
            stream_id,
            to_sqlite_integer("snapshot stream_version", snapshot_version)?
        ],
        |row| row.get::<_, Option<i64>>(0),
    )?;
    let (after_version, mut prefix_digest) = match previous_version {
        Some(version) => {
            let version = from_sqlite_integer("previous anchor stream_version", version)?;
            let Some(anchor) = read_integrity_anchor(connection, stream_id, version)? else {
                return Ok(false);
            };
            if !anchor_is_current(&anchor) {
                return Ok(false);
            }
            (version, anchor.prefix_digest)
        }
        None => (0, prefix_digest_seed(stream_id)),
    };
    let events = read_stored_events(connection, stream_id, after_version, snapshot_version)?;
    let mut expected_version = after_version;
    for event in events {
        expected_version = expected_version
            .checked_add(1)
            .ok_or(StoreError::IntegerRange {
                field: "stream_version",
            })?;
        if event.record.stream_version != expected_version {
            return Ok(false);
        }
        prefix_digest = extend_prefix_digest(&prefix_digest, &event.fingerprint);
    }
    Ok(expected_version == snapshot_version
        && digest_matches(&prefix_digest, &snapshot_anchor.prefix_digest))
}

fn replay_tail(
    connection: &Connection,
    stream_id: &str,
    head: StreamVersion,
    mut state: SessionState,
    mut prefix_digest: Vec<u8>,
) -> Result<RehydratedState, RehydrateError> {
    let after = state.stream_version;
    let events = read_stored_events(connection, stream_id, after, head)?;
    for event in events {
        prefix_digest = extend_prefix_digest(&prefix_digest, &event.fingerprint);
        state = state.apply_record(&event.record)?;
    }
    if state.stream_version != head {
        return Err(RehydrateError::IncompleteReplay {
            actual: state.stream_version,
            expected: head,
        });
    }
    Ok(RehydratedState {
        state,
        prefix_digest,
    })
}

fn restored_matches_anchor(
    restored: &RehydratedState,
    anchor: &IntegrityAnchor,
) -> Result<bool, StoreError> {
    Ok(anchor_is_current(anchor)
        && digest_matches(&restored.prefix_digest, &anchor.prefix_digest)
        && digest_matches(&state_digest(&restored.state)?, &anchor.state_digest))
}

fn anchor_is_current(anchor: &IntegrityAnchor) -> bool {
    anchor.prefix_digest_version == EVENT_PREFIX_DIGEST_VERSION
        && anchor.prefix_digest.len() == INTEGRITY_DIGEST_BYTES
        && anchor.state_schema_version == STATE_SCHEMA_VERSION
        && anchor.reducer_schema_version == REDUCER_SCHEMA_VERSION
        && anchor.state_digest_version == STATE_DIGEST_VERSION
        && anchor.state_digest.len() == INTEGRITY_DIGEST_BYTES
}

fn read_integrity_anchor(
    connection: &Connection,
    stream_id: &str,
    stream_version: StreamVersion,
) -> Result<Option<IntegrityAnchor>, StoreError> {
    let raw = connection
        .query_row(
            "SELECT event_prefix_digest_version, event_prefix_digest,
                    state_schema_version, reducer_schema_version,
                    state_digest_version, state_digest
             FROM integrity_anchors
             WHERE stream_id = ?1 AND stream_version = ?2",
            params![
                stream_id,
                to_sqlite_integer("stream_version", stream_version)?
            ],
            |row| {
                Ok((
                    row.get::<_, SqlValue>(0)?,
                    row.get::<_, SqlValue>(1)?,
                    row.get::<_, SqlValue>(2)?,
                    row.get::<_, SqlValue>(3)?,
                    row.get::<_, SqlValue>(4)?,
                    row.get::<_, SqlValue>(5)?,
                ))
            },
        )
        .optional()?;
    Ok(raw.and_then(|raw| {
        Some(IntegrityAnchor {
            prefix_digest_version: sqlite_i64(raw.0)?,
            prefix_digest: sqlite_blob(raw.1)?,
            state_schema_version: u32::try_from(sqlite_i64(raw.2)?).ok()?,
            reducer_schema_version: u32::try_from(sqlite_i64(raw.3)?).ok()?,
            state_digest_version: sqlite_i64(raw.4)?,
            state_digest: sqlite_blob(raw.5)?,
        })
    }))
}

fn require_integrity_anchor(
    connection: &Connection,
    stream_id: &str,
    stream_version: StreamVersion,
) -> Result<IntegrityAnchor, StoreError> {
    read_integrity_anchor(connection, stream_id, stream_version)?
        .filter(anchor_is_current)
        .ok_or_else(|| StoreError::InvalidIntegrityAnchor {
            stream_id: stream_id.into(),
            version: stream_version,
        })
}

fn next_snapshot_candidate(
    connection: &Connection,
    stream_id: &str,
    head: StreamVersion,
    before: (StreamVersion, i64),
) -> Result<Option<SnapshotWithReferences>, StoreError> {
    let raw = connection
        .query_row(
            "SELECT snapshot_id, stream_id, stream_version, state_schema_version,
                    reducer_schema_version, encoding, checksum, payload,
                    event_prefix_digest_version, event_prefix_digest,
                    state_digest_version, state_digest
             FROM snapshots
             WHERE stream_id = ?1 AND stream_version <= ?2
               AND state_schema_version = ?3 AND reducer_schema_version = ?4
               AND (stream_version < ?5 OR (stream_version = ?5 AND snapshot_id < ?6))
               AND typeof(snapshot_id) = 'integer'
               AND typeof(stream_id) = 'text'
               AND typeof(stream_version) = 'integer'
               AND typeof(state_schema_version) = 'integer'
               AND typeof(reducer_schema_version) = 'integer'
               AND typeof(encoding) = 'text'
               AND typeof(checksum) = 'text'
               AND typeof(payload) = 'blob'
               AND typeof(event_prefix_digest_version) = 'integer'
               AND typeof(event_prefix_digest) = 'blob'
               AND typeof(state_digest_version) = 'integer'
               AND typeof(state_digest) = 'blob'
             ORDER BY stream_version DESC, snapshot_id DESC LIMIT 1",
            params![
                stream_id,
                to_sqlite_integer("head stream_version", head)?,
                i64::from(STATE_SCHEMA_VERSION),
                i64::from(REDUCER_SCHEMA_VERSION),
                to_sqlite_integer("snapshot cursor version", before.0)?,
                before.1,
            ],
            |row| {
                Ok((
                    read_raw_snapshot(row)?,
                    row.get::<_, SqlValue>(8)?,
                    row.get::<_, SqlValue>(9)?,
                    row.get::<_, SqlValue>(10)?,
                    row.get::<_, SqlValue>(11)?,
                ))
            },
        )
        .optional()?;
    Ok(raw.and_then(|raw| {
        Some(SnapshotWithReferences {
            snapshot: decode_raw_snapshot(raw.0)?,
            prefix_digest_version: sqlite_i64(raw.1)?,
            prefix_digest: sqlite_blob(raw.2)?,
            state_digest_version: sqlite_i64(raw.3)?,
            state_digest: sqlite_blob(raw.4)?,
        })
    }))
}

fn validated_snapshot_state(
    candidate: &SnapshotWithReferences,
    anchor: &IntegrityAnchor,
) -> Option<SessionState> {
    if !anchor_is_current(anchor) {
        return None;
    }
    if candidate.prefix_digest_version != anchor.prefix_digest_version
        || !digest_matches(&candidate.prefix_digest, &anchor.prefix_digest)
        || candidate.state_digest_version != anchor.state_digest_version
        || !digest_matches(&candidate.state_digest, &anchor.state_digest)
        || !digest_matches(
            &digest_bytes(&candidate.snapshot.payload),
            &anchor.state_digest,
        )
    {
        return None;
    }
    snapshot_state(&candidate.snapshot)
}

fn read_stored_events(
    connection: &Connection,
    stream_id: &str,
    after_version: StreamVersion,
    through_version: StreamVersion,
) -> Result<Vec<StoredEvent>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT global_position, stream_id, stream_version, event_id, command_id,
                event_schema_version, event_type, payload,
                event_fingerprint_version, event_fingerprint
         FROM events
         WHERE stream_id = ?1 AND stream_version > ?2 AND stream_version <= ?3
         ORDER BY stream_version ASC",
    )?;
    let rows = statement.query_map(
        params![
            stream_id,
            to_sqlite_integer("after_version", after_version)?,
            to_sqlite_integer("through_version", through_version)?,
        ],
        decode_persisted_event_row,
    )?;
    collect_persisted_events(rows)
}

fn rehydrate_error_into_store_error(error: RehydrateError, stream_id: &str) -> StoreError {
    match error {
        RehydrateError::Store(error) => error,
        RehydrateError::Domain(error) => StoreError::Domain(error),
        RehydrateError::IncompleteReplay { expected, .. } => StoreError::RehydrationIntegrity {
            stream_id: stream_id.into(),
            version: expected,
        },
    }
}

#[derive(Serialize)]
struct EventBatchFingerprint<'a> {
    events: &'a [EventDraft],
}

fn hash_events(events: &[EventDraft]) -> Result<Vec<u8>, StoreError> {
    let bytes = canonical_json_bytes(&EventBatchFingerprint { events })?;
    Ok(digest_bytes(&bytes))
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, StoreError> {
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

fn hex_encode(bytes: &[u8]) -> String {
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

fn event_fingerprint(
    stream_id: &str,
    stream_version: StreamVersion,
    event_id: &str,
    command_id: &str,
    event_schema_version: u32,
    event_type: &str,
    payload: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"zode:event-fingerprint:v1");
    hash_field(&mut hasher, stream_id.as_bytes());
    hasher.update(stream_version.to_be_bytes());
    hash_field(&mut hasher, event_id.as_bytes());
    hash_field(&mut hasher, command_id.as_bytes());
    hasher.update(event_schema_version.to_be_bytes());
    hash_field(&mut hasher, event_type.as_bytes());
    hash_field(&mut hasher, payload);
    hasher.finalize().to_vec()
}

fn prefix_digest_seed(stream_id: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"zode:event-prefix:v1");
    hash_field(&mut hasher, stream_id.as_bytes());
    hasher.finalize().to_vec()
}

fn extend_prefix_digest(previous: &[u8], event_fingerprint: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"zode:event-prefix-link:v1");
    hash_field(&mut hasher, previous);
    hash_field(&mut hasher, event_fingerprint);
    hasher.finalize().to_vec()
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn state_digest(state: &SessionState) -> Result<Vec<u8>, StoreError> {
    Ok(digest_bytes(&serde_json::to_vec(state)?))
}

fn digest_bytes(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

fn digest_matches(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (*left ^ *right)
            })
            == 0
}

fn checksum(payload: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(payload))
}

fn snapshot_state(snapshot: &SnapshotRecord) -> Option<SessionState> {
    if snapshot.encoding != SNAPSHOT_ENCODING_JSON || !snapshot.checksum_matches() {
        return None;
    }
    let state = serde_json::from_slice::<SessionState>(&snapshot.payload).ok()?;
    (state.session_id == snapshot.stream_id
        && state.stream_version == snapshot.stream_version
        && state.validate().is_ok())
    .then_some(state)
}

fn require_text(field: &'static str, value: &str) -> Result<(), StoreError> {
    if value.is_empty() {
        Err(StoreError::EmptyField { field })
    } else {
        Ok(())
    }
}

fn to_sqlite_integer(field: &'static str, value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::IntegerRange { field })
}

fn from_sqlite_integer(field: &'static str, value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::CorruptInteger { field, value })
}

type RawEvent = (i64, String, i64, String, String, i64, String, Vec<u8>);
type RawPersistedEvent = (RawEvent, i64, Vec<u8>);

type RawSnapshot = (
    SqlValue,
    SqlValue,
    SqlValue,
    SqlValue,
    SqlValue,
    SqlValue,
    SqlValue,
    SqlValue,
);

fn read_raw_snapshot(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawSnapshot> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

fn decode_raw_snapshot(raw: RawSnapshot) -> Option<SnapshotRecord> {
    let (
        snapshot_id,
        stream_id,
        stream_version,
        state_schema,
        reducer_schema,
        encoding,
        checksum,
        payload,
    ) = raw;
    Some(SnapshotRecord {
        snapshot_id: Some(sqlite_i64(snapshot_id)?),
        stream_id: sqlite_string(stream_id)?,
        stream_version: u64::try_from(sqlite_i64(stream_version)?).ok()?,
        state_schema_version: u32::try_from(sqlite_i64(state_schema)?).ok()?,
        reducer_schema_version: u32::try_from(sqlite_i64(reducer_schema)?).ok()?,
        encoding: sqlite_string(encoding)?,
        checksum: sqlite_string(checksum)?,
        payload: sqlite_blob(payload)?,
    })
}

fn sqlite_i64(value: SqlValue) -> Option<i64> {
    match value {
        SqlValue::Integer(value) => Some(value),
        _ => None,
    }
}

fn sqlite_string(value: SqlValue) -> Option<String> {
    match value {
        SqlValue::Text(value) => Some(value),
        _ => None,
    }
}

fn sqlite_blob(value: SqlValue) -> Option<Vec<u8>> {
    match value {
        SqlValue::Blob(value) => Some(value),
        _ => None,
    }
}

fn decode_event_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawEvent> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

fn decode_persisted_event_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawPersistedEvent> {
    Ok((
        decode_event_row(row)?,
        row.get::<_, i64>(8)?,
        row.get::<_, Vec<u8>>(9)?,
    ))
}

fn decode_persisted_event(raw: RawPersistedEvent) -> Result<StoredEvent, StoreError> {
    let (raw_event, fingerprint_version, stored_fingerprint) = raw;
    let stream_version = from_sqlite_integer("stream_version", raw_event.2)?;
    let event_schema_version =
        u32::try_from(raw_event.5).map_err(|_| StoreError::CorruptInteger {
            field: "event_schema_version",
            value: raw_event.5,
        })?;
    let expected_fingerprint = event_fingerprint(
        &raw_event.1,
        stream_version,
        &raw_event.3,
        &raw_event.4,
        event_schema_version,
        &raw_event.6,
        &raw_event.7,
    );
    if fingerprint_version != EVENT_FINGERPRINT_VERSION
        || stored_fingerprint.len() != INTEGRITY_DIGEST_BYTES
        || !digest_matches(&stored_fingerprint, &expected_fingerprint)
    {
        return Err(StoreError::InvalidEventFingerprint {
            stream_id: raw_event.1,
            version: stream_version,
        });
    }
    Ok(StoredEvent {
        record: decode_raw_event(raw_event)?,
        fingerprint: expected_fingerprint,
    })
}

fn collect_persisted_events<I>(rows: I) -> Result<Vec<StoredEvent>, StoreError>
where
    I: Iterator<Item = rusqlite::Result<RawPersistedEvent>>,
{
    rows.map(|row| decode_persisted_event(row?)).collect()
}

fn event_records(events: Vec<StoredEvent>) -> Vec<EventRecord> {
    events.into_iter().map(|event| event.record).collect()
}

fn decode_raw_event(raw: RawEvent) -> Result<EventRecord, StoreError> {
    let (
        global_position,
        stream_id,
        stream_version,
        event_id,
        command_id,
        event_schema_version,
        stored_type,
        payload,
    ) = raw;
    if global_position <= 0 {
        return Err(StoreError::CorruptInteger {
            field: "global_position",
            value: global_position,
        });
    }
    require_text("stream_id", &stream_id)?;
    require_text("event_id", &event_id)?;
    require_text("command_id", &command_id)?;
    require_text("event_type", &stored_type)?;
    if payload.len() > 1024 * 1024 {
        return Err(StoreError::IncompatibleStorageSchema(
            "stored event payload bound",
        ));
    }
    let event_schema_version =
        u32::try_from(event_schema_version).map_err(|_| StoreError::CorruptInteger {
            field: "event_schema_version",
            value: event_schema_version,
        })?;
    if event_schema_version != EVENT_SCHEMA_VERSION {
        return Err(StoreError::UnsupportedEventSchema(event_schema_version));
    }
    let event: SessionEvent = serde_json::from_slice(&payload)?;
    let decoded_type = event.kind().to_owned();
    if stored_type != decoded_type {
        return Err(StoreError::EventTypeMismatch {
            stored: stored_type,
            decoded: decoded_type,
        });
    }
    event.validate()?;
    Ok(EventRecord {
        stream_id,
        stream_version: from_sqlite_integer("stream_version", stream_version)?,
        global_position: from_sqlite_integer("global_position", global_position)?,
        event_id,
        command_id,
        event_schema_version,
        event,
    })
}

fn read_events_by_command(
    transaction: &Transaction<'_>,
    stream_id: &str,
    command_id: &str,
    through_version: StreamVersion,
) -> Result<Vec<EventRecord>, StoreError> {
    let mut statement = transaction.prepare(
        "SELECT global_position, stream_id, stream_version, event_id, command_id,
                event_schema_version, event_type, payload,
                event_fingerprint_version, event_fingerprint
         FROM events
         WHERE stream_id = ?1 AND command_id = ?2 AND stream_version <= ?3
         ORDER BY stream_version ASC",
    )?;
    let rows = statement.query_map(
        params![
            stream_id,
            command_id,
            to_sqlite_integer("through_version", through_version)?
        ],
        decode_persisted_event_row,
    )?;
    Ok(event_records(collect_persisted_events(rows)?))
}
