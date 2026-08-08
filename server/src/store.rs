use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use fs2::FileExt;
use getrandom::fill as fill_random;
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::config::ServerConfig;

const CONTROL_SCHEMA_VERSION: i64 = 1;
const SUBJECT_KEY_BYTES: usize = 32;
const DIGEST_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const MAX_SECRET_FILE_BYTES: usize = 128 * 1024;
const MAX_ENDPOINTS_PER_LIST: usize = 100;
const SECRET_MAGIC: &[u8] = b"zode.server-secret.v1\0";

const CONTROL_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS server_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    server_authority_id TEXT NOT NULL CHECK (length(server_authority_id) BETWEEN 1 AND 256),
    subject_key_version INTEGER NOT NULL CHECK (subject_key_version > 0),
    subject_key_fingerprint BLOB NOT NULL CHECK (length(subject_key_fingerprint) = 32)
) STRICT;

CREATE TABLE IF NOT EXISTS endpoint_create_operations (
    actor_key BLOB NOT NULL CHECK (length(actor_key) = 32),
    command_key BLOB NOT NULL CHECK (length(command_key) = 32),
    request_fingerprint BLOB NOT NULL CHECK (length(request_fingerprint) = 32),
    phase TEXT NOT NULL CHECK (phase IN ('pending', 'complete')),
    label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 256),
    base_url TEXT NOT NULL CHECK (length(base_url) BETWEEN 1 AND 2048),
    secret_ref TEXT NOT NULL CHECK (length(secret_ref) = 64),
    endpoint_id TEXT,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    PRIMARY KEY (actor_key, command_key),
    CHECK (
        (phase = 'pending' AND endpoint_id IS NULL) OR
        (phase = 'complete' AND endpoint_id IS NOT NULL)
    )
) WITHOUT ROWID, STRICT;

CREATE TABLE IF NOT EXISTS endpoints (
    endpoint_id TEXT PRIMARY KEY CHECK (length(endpoint_id) BETWEEN 1 AND 256),
    label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 256),
    kind TEXT NOT NULL DEFAULT 'remote' CHECK (kind IN ('local', 'remote')),
    base_url TEXT NOT NULL CHECK (length(base_url) BETWEEN 1 AND 2048),
    controller_authority_id TEXT NOT NULL
        CHECK (length(controller_authority_id) BETWEEN 1 AND 256),
    controller_credential_revision INTEGER NOT NULL
        CHECK (controller_credential_revision > 0),
    protocol_version TEXT NOT NULL CHECK (length(protocol_version) BETWEEN 1 AND 128),
    secret_ref TEXT NOT NULL UNIQUE CHECK (length(secret_ref) = 64),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    provider_adapter_kinds TEXT NOT NULL DEFAULT '[]',
    tools TEXT NOT NULL DEFAULT '[]'
) STRICT;

CREATE TABLE IF NOT EXISTS local_endpoint_bootstrap (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    phase TEXT NOT NULL CHECK (phase IN ('pending', 'complete')),
    secret_fingerprint BLOB NOT NULL CHECK (length(secret_fingerprint) = 32)
) STRICT;

CREATE TABLE IF NOT EXISTS provider_descriptor_revisions (
    provider TEXT NOT NULL CHECK (length(provider) BETWEEN 1 AND 128),
    revision INTEGER NOT NULL CHECK (revision > 0),
    kind TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 128),
    base_url TEXT NOT NULL CHECK (length(base_url) BETWEEN 1 AND 2048),
    models_json TEXT NOT NULL CHECK (length(models_json) BETWEEN 2 AND 65536),
    options_json TEXT NOT NULL CHECK (length(options_json) BETWEEN 2 AND 65536),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    PRIMARY KEY (provider, revision)
) WITHOUT ROWID, STRICT;

CREATE TABLE IF NOT EXISTS provider_descriptor_operations (
    actor_key BLOB NOT NULL CHECK (length(actor_key) = 32),
    provider TEXT NOT NULL CHECK (length(provider) BETWEEN 1 AND 128),
    command_key BLOB NOT NULL CHECK (length(command_key) = 32),
    request_fingerprint BLOB NOT NULL CHECK (length(request_fingerprint) = 32),
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (actor_key, provider, command_key),
    FOREIGN KEY (provider, revision)
        REFERENCES provider_descriptor_revisions(provider, revision)
) WITHOUT ROWID, STRICT;

CREATE TABLE IF NOT EXISTS auth_profile_create_operations (
    actor_key BLOB NOT NULL CHECK (length(actor_key) = 32),
    provider TEXT NOT NULL CHECK (length(provider) BETWEEN 1 AND 128),
    command_key BLOB NOT NULL CHECK (length(command_key) = 32),
    request_fingerprint BLOB NOT NULL CHECK (length(request_fingerprint) = 32),
    phase TEXT NOT NULL CHECK (phase IN ('pending', 'distributing', 'complete')),
    profile_id TEXT NOT NULL CHECK (length(profile_id) BETWEEN 1 AND 128),
    label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 256),
    secret_ref TEXT NOT NULL CHECK (length(secret_ref) = 64),
    sharing_json TEXT NOT NULL CHECK (length(sharing_json) BETWEEN 2 AND 65536),
    make_default INTEGER NOT NULL CHECK (make_default IN (0, 1)),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    PRIMARY KEY (actor_key, provider, command_key),
    UNIQUE (profile_id)
) WITHOUT ROWID, STRICT;

CREATE TABLE IF NOT EXISTS auth_profiles (
    profile_id TEXT PRIMARY KEY CHECK (length(profile_id) BETWEEN 1 AND 128),
    provider TEXT NOT NULL CHECK (length(provider) BETWEEN 1 AND 128),
    kind TEXT NOT NULL CHECK (kind = 'api_key'),
    label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 256),
    revision INTEGER NOT NULL CHECK (revision > 0),
    descriptor_revision INTEGER NOT NULL CHECK (descriptor_revision > 0),
    secret_ref TEXT NOT NULL UNIQUE CHECK (length(secret_ref) = 64),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    deleted_at_ms INTEGER,
    FOREIGN KEY (provider, descriptor_revision)
        REFERENCES provider_descriptor_revisions(provider, revision)
) STRICT;

CREATE TABLE IF NOT EXISTS auth_profile_sharing_revisions (
    profile_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    mode TEXT NOT NULL CHECK (mode IN ('none', 'selected', 'all_current')),
    endpoint_ids_json TEXT NOT NULL CHECK (length(endpoint_ids_json) BETWEEN 2 AND 65536),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    PRIMARY KEY (profile_id, revision),
    FOREIGN KEY (profile_id) REFERENCES auth_profiles(profile_id)
) WITHOUT ROWID, STRICT;

CREATE TABLE IF NOT EXISTS auth_profile_delete_operations (
    actor_key BLOB NOT NULL CHECK (length(actor_key) = 32),
    provider TEXT NOT NULL CHECK (length(provider) BETWEEN 1 AND 128),
    profile_id TEXT NOT NULL CHECK (length(profile_id) BETWEEN 1 AND 128),
    command_key BLOB NOT NULL CHECK (length(command_key) = 32),
    request_fingerprint BLOB NOT NULL CHECK (length(request_fingerprint) = 32),
    tombstone_revision INTEGER NOT NULL CHECK (tombstone_revision > 0),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    PRIMARY KEY (actor_key, provider, command_key)
) WITHOUT ROWID, STRICT;

CREATE TABLE IF NOT EXISTS auth_profile_tombstones (
    profile_id TEXT NOT NULL CHECK (length(profile_id) BETWEEN 1 AND 128),
    provider TEXT NOT NULL CHECK (length(provider) BETWEEN 1 AND 128),
    endpoint_id TEXT NOT NULL CHECK (length(endpoint_id) BETWEEN 1 AND 256),
    revision INTEGER NOT NULL CHECK (revision > 0),
    operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 256),
    status TEXT NOT NULL CHECK (status IN ('pending', 'removed', 'unreachable')),
    observed_revision INTEGER,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    PRIMARY KEY (profile_id, endpoint_id),
    UNIQUE (operation_id)
) WITHOUT ROWID, STRICT;

CREATE TABLE IF NOT EXISTS provider_default_profile_revisions (
    provider TEXT NOT NULL CHECK (length(provider) BETWEEN 1 AND 128),
    revision INTEGER NOT NULL CHECK (revision > 0),
    profile_id TEXT,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    PRIMARY KEY (provider, revision),
    FOREIGN KEY (profile_id) REFERENCES auth_profiles(profile_id)
) WITHOUT ROWID, STRICT;

CREATE TABLE IF NOT EXISTS provider_default_profile_operations (
    actor_key BLOB NOT NULL CHECK (length(actor_key) = 32), provider TEXT NOT NULL CHECK (length(provider) BETWEEN 1 AND 128), command_key BLOB NOT NULL CHECK (length(command_key) = 32), request_fingerprint BLOB NOT NULL CHECK (length(request_fingerprint) = 32), profile_id TEXT NOT NULL CHECK (length(profile_id) BETWEEN 1 AND 128),
    PRIMARY KEY (actor_key, provider, command_key), FOREIGN KEY (profile_id) REFERENCES auth_profiles(profile_id)
) WITHOUT ROWID, STRICT;

CREATE TABLE IF NOT EXISTS auth_replica_operations (
    profile_id TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 256),
    status TEXT NOT NULL CHECK (status IN ('pending', 'ready', 'unreachable')),
    observed_revision INTEGER,
    PRIMARY KEY (profile_id, endpoint_id, revision),
    UNIQUE (operation_id),
    FOREIGN KEY (profile_id) REFERENCES auth_profiles(profile_id),
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(endpoint_id)
) WITHOUT ROWID, STRICT;
"#;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub(crate) enum StartupError {
    #[error("missing Access subject key")]
    MissingSubjectKey,
    #[error("invalid Access subject key")]
    InvalidSubjectKey,
    #[error("Server stores are already owned")]
    AlreadyOwned,
    #[error("Server control store is unavailable")]
    StoreUnavailable,
    #[error("Server control store integrity check failed")]
    StoreIntegrity,
    #[error("Server authority binding is incompatible")]
    AuthorityMismatch,
}

impl StartupError {
    pub(crate) fn code_and_phase(&self) -> (&'static str, &'static str) {
        match self {
            Self::MissingSubjectKey => ("missing_subject_key", "access_subject_key"),
            Self::InvalidSubjectKey => ("invalid_subject_key", "access_subject_key"),
            Self::AlreadyOwned => ("server_already_owned", "server_store_lock"),
            Self::StoreUnavailable => ("control_store_unavailable", "control_store"),
            Self::StoreIntegrity => ("control_store_integrity", "control_store"),
            Self::AuthorityMismatch => ("server_authority_mismatch", "control_store"),
        }
    }
}

#[derive(Clone, Copy)]
enum ControlDatabaseState {
    New,
    Initialized,
}

#[derive(Debug, Error)]
pub(crate) enum StoreError {
    #[error("management command conflicts with an existing receipt")]
    Conflict,
    #[error("management resource was not found")]
    NotFound,
    #[error("control store integrity check failed")]
    Integrity,
    #[error("control store operation failed")]
    Internal,
}

pub(crate) struct KeyMaterial {
    subject: [u8; SUBJECT_KEY_BYTES],
    encryption: [u8; SUBJECT_KEY_BYTES],
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        self.subject.fill(0);
        self.encryption.fill(0);
    }
}

impl KeyMaterial {
    pub(crate) fn digest(&self, domain: &[u8], fields: &[&[u8]]) -> [u8; DIGEST_BYTES] {
        keyed_digest(&self.subject, domain, fields)
    }

    pub(crate) fn actor_key(&self, kind: &str, actor: &str) -> [u8; DIGEST_BYTES] {
        self.digest(b"access-actor-v1", &[kind.as_bytes(), actor.as_bytes()])
    }

    pub(crate) fn endpoint_subject(&self, actor_key: &[u8; DIGEST_BYTES]) -> String {
        format!("v1:{}", hex(actor_key))
    }

    fn seal(&self, reference: &str, plaintext: &[u8]) -> Result<Vec<u8>, StoreError> {
        let cipher = XChaCha20Poly1305::new((&self.encryption).into());
        let mut nonce = [0_u8; NONCE_BYTES];
        fill_random(&mut nonce).map_err(|_| StoreError::Internal)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: reference.as_bytes(),
                },
            )
            .map_err(|_| StoreError::Internal)?;
        let mut result = Vec::with_capacity(SECRET_MAGIC.len() + NONCE_BYTES + ciphertext.len());
        result.extend_from_slice(SECRET_MAGIC);
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn open(&self, reference: &str, encoded: &[u8]) -> Result<Vec<u8>, StoreError> {
        let Some(encoded) = encoded.strip_prefix(SECRET_MAGIC) else {
            return Err(StoreError::Integrity);
        };
        let (nonce, ciphertext) = encoded
            .split_at_checked(NONCE_BYTES)
            .ok_or(StoreError::Integrity)?;
        XChaCha20Poly1305::new((&self.encryption).into())
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: reference.as_bytes(),
                },
            )
            .map_err(|_| StoreError::Integrity)
    }
}

pub(crate) struct ControlStore {
    database: Mutex<Connection>,
    database_path: PathBuf,
    database_identity: [u8; 16],
    secret_directory: PathBuf,
    authority_id: String,
    keys: Arc<KeyMaterial>,
    _secret_ownership: File,
    _database_ownership: File,
}

pub(crate) enum BeginEndpointCreate {
    Pending(EndpointCreateOperation),
    Complete(EndpointCreateOperation, Box<EndpointRecord>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalBootstrapPhase {
    Pending,
    Complete,
}

pub(crate) struct EndpointCreateOperation {
    pub(crate) actor_key: [u8; DIGEST_BYTES],
    pub(crate) command_key: [u8; DIGEST_BYTES],
    pub(crate) request_fingerprint: [u8; DIGEST_BYTES],
    pub(crate) label: String,
    pub(crate) base_url: String,
    pub(crate) secret_ref: String,
    pub(crate) created_at_ms: i64,
}

pub(crate) struct EndpointCreateCompletion {
    pub(crate) endpoint_id: String,
    pub(crate) controller_authority_id: String,
    pub(crate) controller_credential_revision: u64,
    pub(crate) protocol_version: String,
    pub(crate) provider_adapter_kinds: Vec<String>,
    pub(crate) tools: Vec<String>,
}

pub(crate) struct LocalEndpointCommit {
    pub(crate) endpoint_id: String,
    pub(crate) base_url: String,
    pub(crate) controller_authority_id: String,
    pub(crate) controller_credential_revision: u64,
    pub(crate) protocol_version: String,
    pub(crate) provider_adapter_kinds: Vec<String>,
    pub(crate) tools: Vec<String>,
    pub(crate) secret_ref: String,
    pub(crate) observed_at_ms: i64,
}

pub(crate) struct ProviderDescriptorWrite {
    pub(crate) provider: String,
    pub(crate) kind: String,
    pub(crate) base_url: String,
    pub(crate) models_json: String,
    pub(crate) options_json: String,
    pub(crate) actor_key: [u8; DIGEST_BYTES],
    pub(crate) command_key: [u8; DIGEST_BYTES],
    pub(crate) request_fingerprint: [u8; DIGEST_BYTES],
    pub(crate) created_at_ms: i64,
}

#[derive(Clone)]
pub(crate) struct ProviderDescriptorRecord {
    pub(crate) provider: String,
    pub(crate) revision: u64,
    pub(crate) kind: String,
    pub(crate) base_url: String,
    pub(crate) models_json: String,
    pub(crate) options_json: String,
}

pub(crate) struct ProfileCreateWrite {
    pub(crate) actor_key: [u8; DIGEST_BYTES],
    pub(crate) provider: String,
    pub(crate) command_key: [u8; DIGEST_BYTES],
    pub(crate) request_fingerprint: [u8; DIGEST_BYTES],
    pub(crate) profile_id: String,
    pub(crate) label: String,
    pub(crate) secret_ref: String,
    pub(crate) sharing_json: String,
    pub(crate) make_default: bool,
    pub(crate) created_at_ms: i64,
}

pub(crate) struct ProviderDefaultProfileWrite {
    pub(crate) actor_key: [u8; DIGEST_BYTES],
    pub(crate) provider: String,
    pub(crate) command_key: [u8; DIGEST_BYTES],
    pub(crate) request_fingerprint: [u8; DIGEST_BYTES],
    pub(crate) profile_id: String,
    pub(crate) created_at_ms: i64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ProfileCreatePhase {
    Pending,
    Distributing,
    Complete,
}

#[derive(Clone)]
pub(crate) struct ProfileCreateOperation {
    pub(crate) actor_key: [u8; DIGEST_BYTES],
    pub(crate) provider: String,
    pub(crate) command_key: [u8; DIGEST_BYTES],
    pub(crate) request_fingerprint: [u8; DIGEST_BYTES],
    pub(crate) phase: ProfileCreatePhase,
    pub(crate) profile_id: String,
    pub(crate) label: String,
    pub(crate) secret_ref: String,
    pub(crate) sharing_json: String,
    pub(crate) make_default: bool,
    pub(crate) created_at_ms: i64,
}

#[derive(Clone)]
pub(crate) struct AuthProfileRecord {
    pub(crate) profile_id: String,
    pub(crate) provider: String,
    pub(crate) kind: String,
    pub(crate) label: String,
    pub(crate) revision: u64,
    pub(crate) descriptor_revision: u64,
    pub(crate) secret_ref: String,
    pub(crate) sharing_mode: String,
    pub(crate) endpoint_ids_json: String,
    pub(crate) is_default: bool,
    pub(crate) deleted_at_ms: Option<i64>,
}

#[derive(Clone)]
pub(crate) struct AuthReplicaRecord {
    pub(crate) profile_id: String,
    pub(crate) endpoint_id: String,
    pub(crate) provider: String,
    pub(crate) revision: u64,
    pub(crate) operation_id: String,
    pub(crate) status: String,
    pub(crate) observed_revision: Option<u64>,
}

#[derive(Clone)]
pub(crate) struct ProfileDeleteWrite {
    pub(crate) actor_key: [u8; DIGEST_BYTES],
    pub(crate) provider: String,
    pub(crate) profile_id: String,
    pub(crate) command_key: [u8; DIGEST_BYTES],
    pub(crate) request_fingerprint: [u8; DIGEST_BYTES],
    pub(crate) created_at_ms: i64,
}

#[derive(Clone)]
pub(crate) struct AuthTombstoneRecord {
    pub(crate) profile_id: String,
    pub(crate) provider: String,
    pub(crate) endpoint_id: String,
    pub(crate) revision: u64,
    pub(crate) operation_id: String,
    pub(crate) status: String,
    pub(crate) observed_revision: Option<u64>,
}

#[derive(Clone)]
pub(crate) struct AuthTombstoneDispatchRecord {
    pub(crate) tombstone: AuthTombstoneRecord,
    pub(crate) secret_ref: String,
}

#[derive(Clone)]
pub(crate) struct EndpointRecord {
    pub(crate) endpoint_id: String,
    pub(crate) label: String,
    pub(crate) kind: String,
    pub(crate) base_url: String,
    pub(crate) controller_authority_id: String,
    pub(crate) controller_credential_revision: u64,
    pub(crate) protocol_version: String,
    pub(crate) provider_adapter_kinds: Vec<String>,
    pub(crate) tools: Vec<String>,
    pub(crate) secret_ref: String,
    pub(crate) created_at_ms: i64,
}

impl ControlStore {
    pub(crate) fn open(config: &ServerConfig) -> Result<Self, StartupError> {
        validate_secret_directory(config.secret_directory())?;
        let secret_ownership = acquire_secret_ownership(config.secret_directory())?;
        let keys = Arc::new(read_key_material(config.access().subject_key_file())?);
        let database = acquire_database_ownership(
            config.control_database(),
            config.secret_directory(),
            config.access().subject_key_version(),
            config.server_authority_id(),
            &keys,
        )?;
        let store = Self {
            database: Mutex::new(database.connection),
            database_path: database.path,
            database_identity: database.database_identity,
            secret_directory: config.secret_directory().to_path_buf(),
            authority_id: config.server_authority_id().to_owned(),
            keys,
            _secret_ownership: secret_ownership,
            _database_ownership: database.lock,
        };
        store.initialize(config.access().subject_key_version(), database.state)?;
        Ok(store)
    }

    pub(crate) fn keys(&self) -> Arc<KeyMaterial> {
        Arc::clone(&self.keys)
    }

    pub(crate) fn authority_id(&self) -> &str {
        &self.authority_id
    }

    pub(crate) fn begin_local_endpoint_bootstrap(
        &self,
        fingerprint: &[u8; DIGEST_BYTES],
    ) -> Result<LocalBootstrapPhase, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Internal)?;
        let existing = transaction
            .query_row(
                "SELECT phase, secret_fingerprint
                 FROM local_endpoint_bootstrap WHERE singleton = 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|_| StoreError::Internal)?;
        let phase = match existing {
            Some((phase, stored)) => {
                if !equal_digest(&stored, fingerprint) {
                    return Err(StoreError::Integrity);
                }
                match phase.as_str() {
                    "pending" => LocalBootstrapPhase::Pending,
                    "complete" => LocalBootstrapPhase::Complete,
                    _ => return Err(StoreError::Integrity),
                }
            }
            None => {
                transaction
                    .execute(
                        "INSERT INTO local_endpoint_bootstrap (
                            singleton, phase, secret_fingerprint
                         ) VALUES (1, 'pending', ?1)",
                        [&fingerprint[..]],
                    )
                    .map_err(|_| StoreError::Internal)?;
                LocalBootstrapPhase::Pending
            }
        };
        transaction.commit().map_err(|_| StoreError::Internal)?;
        Ok(phase)
    }

    pub(crate) fn local_endpoint_bootstrap_phase(
        &self,
    ) -> Result<Option<LocalBootstrapPhase>, StoreError> {
        let connection = self.connection()?;
        let phase = connection
            .query_row(
                "SELECT phase FROM local_endpoint_bootstrap WHERE singleton = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| StoreError::Internal)?;
        phase
            .map(|phase| match phase.as_str() {
                "pending" => Ok(LocalBootstrapPhase::Pending),
                "complete" => Ok(LocalBootstrapPhase::Complete),
                _ => Err(StoreError::Integrity),
            })
            .transpose()
    }

    pub(crate) fn commit_local_endpoint(
        &self,
        fingerprint: &[u8; DIGEST_BYTES],
        commit: LocalEndpointCommit,
    ) -> Result<EndpointRecord, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Internal)?;
        let bootstrap = transaction
            .query_row(
                "SELECT phase, secret_fingerprint
                 FROM local_endpoint_bootstrap WHERE singleton = 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|_| StoreError::Internal)?
            .ok_or(StoreError::Integrity)?;
        if !matches!(bootstrap.0.as_str(), "pending" | "complete")
            || !equal_digest(&bootstrap.1, fingerprint)
        {
            return Err(StoreError::Integrity);
        }

        let existing_local = transaction
            .query_row(
                "SELECT endpoint_id, label, base_url, controller_authority_id,
                        controller_credential_revision, protocol_version, secret_ref, created_at_ms,
                        provider_adapter_kinds, tools, kind
                 FROM endpoints WHERE kind = 'local'",
                [],
                endpoint_record_from_row,
            )
            .optional()
            .map_err(|_| StoreError::Internal)?;
        let revision = i64::try_from(commit.controller_credential_revision)
            .map_err(|_| StoreError::Integrity)?;
        let providers_json = serde_json::to_string(&commit.provider_adapter_kinds)
            .map_err(|_| StoreError::Integrity)?;
        let tools_json = serde_json::to_string(&commit.tools).map_err(|_| StoreError::Integrity)?;
        let created_at_ms = if let Some(existing) = existing_local {
            if existing.endpoint_id != commit.endpoint_id
                || existing.kind != "local"
                || existing.base_url != commit.base_url
                || existing.controller_authority_id != commit.controller_authority_id
                || existing.secret_ref != commit.secret_ref
            {
                return Err(StoreError::Conflict);
            }
            transaction
                .execute(
                    "UPDATE endpoints
                     SET controller_credential_revision = ?2,
                         protocol_version = ?3,
                         provider_adapter_kinds = ?4,
                         tools = ?5,
                         disabled = 0
                    WHERE endpoint_id = ?1 AND kind = 'local'",
                    params![
                        &commit.endpoint_id,
                        revision,
                        &commit.protocol_version,
                        &providers_json,
                        &tools_json,
                    ],
                )
                .map_err(|_| StoreError::Internal)?;
            existing.created_at_ms
        } else {
            transaction
                .execute(
                    "INSERT INTO endpoints (
                        endpoint_id, label, kind, base_url, controller_authority_id,
                        controller_credential_revision, protocol_version, secret_ref,
                        created_at_ms, disabled, provider_adapter_kinds, tools
                     ) VALUES (?1, 'Local Endpoint', 'local', ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, ?9)",
                    params![
                        &commit.endpoint_id,
                        &commit.base_url,
                        &commit.controller_authority_id,
                        revision,
                        &commit.protocol_version,
                        &commit.secret_ref,
                        commit.observed_at_ms,
                        &providers_json,
                        &tools_json,
                    ],
                )
                .map_err(|error| {
                    if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                        StoreError::Conflict
                    } else {
                        StoreError::Internal
                    }
                })?;
            commit.observed_at_ms
        };
        transaction
            .execute(
                "UPDATE local_endpoint_bootstrap SET phase = 'complete'
                 WHERE singleton = 1 AND secret_fingerprint = ?1",
                [&fingerprint[..]],
            )
            .map_err(|_| StoreError::Internal)?;
        transaction.commit().map_err(|_| StoreError::Internal)?;
        Ok(EndpointRecord {
            endpoint_id: commit.endpoint_id,
            label: "Local Endpoint".to_owned(),
            kind: "local".to_owned(),
            base_url: commit.base_url,
            controller_authority_id: commit.controller_authority_id,
            controller_credential_revision: commit.controller_credential_revision,
            protocol_version: commit.protocol_version,
            provider_adapter_kinds: commit.provider_adapter_kinds,
            tools: commit.tools,
            secret_ref: commit.secret_ref,
            created_at_ms,
        })
    }

    pub(crate) fn begin_endpoint_create(
        &self,
        operation: EndpointCreateOperation,
    ) -> Result<BeginEndpointCreate, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Internal)?;
        let existing = transaction
            .query_row(
                "SELECT request_fingerprint, phase, label, base_url, secret_ref, endpoint_id, created_at_ms
                 FROM endpoint_create_operations
                 WHERE actor_key = ?1 AND command_key = ?2",
                params![&operation.actor_key[..], &operation.command_key[..]],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| StoreError::Internal)?;
        if let Some((fingerprint, phase, label, base_url, secret_ref, endpoint_id, created_at_ms)) =
            existing
        {
            if !equal_digest(&fingerprint, &operation.request_fingerprint) {
                return Err(StoreError::Conflict);
            }
            let prior = EndpointCreateOperation {
                actor_key: operation.actor_key,
                command_key: operation.command_key,
                request_fingerprint: operation.request_fingerprint,
                label,
                base_url,
                secret_ref,
                created_at_ms,
            };
            return match (phase.as_str(), endpoint_id) {
                ("pending", None) => Ok(BeginEndpointCreate::Pending(prior)),
                ("complete", Some(endpoint_id)) => self
                    .read_endpoint(&transaction, &endpoint_id)
                    .map(|record| BeginEndpointCreate::Complete(prior, Box::new(record))),
                _ => Err(StoreError::Integrity),
            };
        }
        transaction
            .execute(
                "INSERT INTO endpoint_create_operations (
                    actor_key, command_key, request_fingerprint, phase, label,
                    base_url, secret_ref, endpoint_id, created_at_ms
                 ) VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?6, NULL, ?7)",
                params![
                    &operation.actor_key[..],
                    &operation.command_key[..],
                    &operation.request_fingerprint[..],
                    &operation.label,
                    &operation.base_url,
                    &operation.secret_ref,
                    operation.created_at_ms,
                ],
            )
            .map_err(|_| StoreError::Internal)?;
        transaction.commit().map_err(|_| StoreError::Internal)?;
        Ok(BeginEndpointCreate::Pending(operation))
    }

    pub(crate) fn stage_endpoint_secret(
        &self,
        reference: &str,
        secret: &[u8],
    ) -> Result<(), StoreError> {
        self.stage_secret("endpoints", reference, secret)
    }

    pub(crate) fn stage_provider_secret(
        &self,
        reference: &str,
        secret: &[u8],
    ) -> Result<(), StoreError> {
        self.stage_secret("providers", reference, secret)
    }

    fn stage_secret(
        &self,
        namespace: &str,
        reference: &str,
        secret: &[u8],
    ) -> Result<(), StoreError> {
        if reference.len() != 64 || !reference.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(StoreError::Integrity);
        }
        let directory = self.secret_directory.join(namespace);
        ensure_private_secret_namespace(&directory)?;
        let path = directory.join(reference);
        if path.exists() {
            let encoded =
                read_bounded(&path, MAX_SECRET_FILE_BYTES).map_err(|_| StoreError::Internal)?;
            let mut existing = self.keys.open(reference, &encoded)?;
            let matches =
                existing.len() == secret.len() && bool::from(existing.as_slice().ct_eq(secret));
            existing.fill(0);
            if matches {
                return Ok(());
            }
            return Err(StoreError::Conflict);
        }

        let encoded = self.keys.seal(reference, secret)?;
        let temporary = directory.join(format!(".{reference}.pending"));
        if temporary.exists() {
            let pending = read_bounded(&temporary, MAX_SECRET_FILE_BYTES)
                .map_err(|_| StoreError::Internal)?;
            let mut existing = self.keys.open(reference, &pending)?;
            let matches =
                existing.len() == secret.len() && bool::from(existing.as_slice().ct_eq(secret));
            existing.fill(0);
            if !matches {
                return Err(StoreError::Conflict);
            }
            fs::rename(&temporary, &path).map_err(|_| StoreError::Internal)?;
            return sync_directory(&directory).map_err(|_| StoreError::Internal);
        }
        let mut file = private_create_new(&temporary).map_err(|_| StoreError::Internal)?;
        file.write_all(&encoded).map_err(|_| StoreError::Internal)?;
        file.sync_all().map_err(|_| StoreError::Internal)?;
        fs::rename(&temporary, &path).map_err(|_| StoreError::Internal)?;
        sync_directory(&directory).map_err(|_| StoreError::Internal)
    }

    pub(crate) fn load_endpoint_secret(
        &self,
        reference: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.load_secret("endpoints", reference)
    }

    pub(crate) fn load_provider_secret(
        &self,
        reference: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.load_secret("providers", reference)
    }

    pub(crate) fn remove_provider_secret(&self, reference: &str) -> Result<(), StoreError> {
        if reference.len() != 64 || !reference.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(StoreError::Integrity);
        }
        let path = self.secret_directory.join("providers").join(reference);
        match fs::remove_file(&path) {
            Ok(()) => sync_directory(path.parent().ok_or(StoreError::Integrity)?)
                .map_err(|_| StoreError::Internal),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(StoreError::Internal),
        }
    }

    fn load_secret(&self, namespace: &str, reference: &str) -> Result<Option<Vec<u8>>, StoreError> {
        if reference.len() != 64 || !reference.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(StoreError::Integrity);
        }
        let path = self.secret_directory.join(namespace).join(reference);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(StoreError::Internal),
        };
        if !metadata.file_type().is_file() {
            return Err(StoreError::Integrity);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(StoreError::Integrity);
            }
        }
        let encoded =
            read_bounded(&path, MAX_SECRET_FILE_BYTES).map_err(|_| StoreError::Internal)?;
        self.keys.open(reference, &encoded).map(Some)
    }

    pub(crate) fn complete_endpoint_create(
        &self,
        operation: &EndpointCreateOperation,
        completion: EndpointCreateCompletion,
    ) -> Result<EndpointRecord, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Internal)?;
        let existing = transaction
            .query_row(
                "SELECT request_fingerprint, phase, endpoint_id
                 FROM endpoint_create_operations
                 WHERE actor_key = ?1 AND command_key = ?2",
                params![&operation.actor_key[..], &operation.command_key[..]],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| StoreError::Internal)?
            .ok_or(StoreError::Integrity)?;
        if !equal_digest(&existing.0, &operation.request_fingerprint) {
            return Err(StoreError::Conflict);
        }
        if existing.1 == "complete" {
            let prior_id = existing.2.ok_or(StoreError::Integrity)?;
            return self.read_endpoint(&transaction, &prior_id);
        }
        if existing.1 != "pending" || existing.2.is_some() {
            return Err(StoreError::Integrity);
        }
        let record = EndpointRecord {
            endpoint_id: completion.endpoint_id,
            label: operation.label.clone(),
            kind: "remote".to_owned(),
            base_url: operation.base_url.clone(),
            controller_authority_id: completion.controller_authority_id,
            controller_credential_revision: completion.controller_credential_revision,
            protocol_version: completion.protocol_version,
            provider_adapter_kinds: completion.provider_adapter_kinds,
            tools: completion.tools,
            secret_ref: operation.secret_ref.clone(),
            created_at_ms: operation.created_at_ms,
        };
        transaction
            .execute(
                "INSERT INTO endpoints (
                    endpoint_id, label, base_url, controller_authority_id,
                    controller_credential_revision, protocol_version, secret_ref,
                    created_at_ms, disabled, provider_adapter_kinds, tools
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, ?10)",
                params![
                    &record.endpoint_id,
                    &record.label,
                    &operation.base_url,
                    &record.controller_authority_id,
                    i64::try_from(record.controller_credential_revision)
                        .map_err(|_| StoreError::Integrity)?,
                    &record.protocol_version,
                    &operation.secret_ref,
                    record.created_at_ms,
                    serde_json::to_string(&record.provider_adapter_kinds)
                        .map_err(|_| StoreError::Integrity)?,
                    serde_json::to_string(&record.tools).map_err(|_| StoreError::Integrity)?,
                ],
            )
            .map_err(|error| {
                if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                    StoreError::Conflict
                } else {
                    StoreError::Internal
                }
            })?;
        let changed = transaction
            .execute(
                "UPDATE endpoint_create_operations
                 SET phase = 'complete', endpoint_id = ?3
                 WHERE actor_key = ?1 AND command_key = ?2 AND phase = 'pending'",
                params![
                    &operation.actor_key[..],
                    &operation.command_key[..],
                    &record.endpoint_id,
                ],
            )
            .map_err(|_| StoreError::Internal)?;
        if changed != 1 {
            return Err(StoreError::Integrity);
        }
        transaction.commit().map_err(|_| StoreError::Internal)?;
        Ok(record)
    }

    pub(crate) fn list_endpoints(&self) -> Result<Vec<EndpointRecord>, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| StoreError::Internal)?;
        let mut statement = transaction
            .prepare(
                "SELECT endpoint_id, label, base_url, controller_authority_id,
                        controller_credential_revision, protocol_version, secret_ref, created_at_ms,
                        provider_adapter_kinds, tools, kind
                 FROM endpoints
                 ORDER BY created_at_ms ASC, endpoint_id ASC
                 LIMIT ?1",
            )
            .map_err(|_| StoreError::Internal)?;
        let rows = statement
            .query_map(
                [i64::try_from(MAX_ENDPOINTS_PER_LIST + 1).expect("bounded limit")],
                endpoint_record_from_row,
            )
            .map_err(|_| StoreError::Internal)?;
        let records = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| StoreError::Integrity)?;
        if records.len() > MAX_ENDPOINTS_PER_LIST {
            return Err(StoreError::Internal);
        }
        Ok(records)
    }

    pub(crate) fn get_endpoint(
        &self,
        endpoint_id: &str,
    ) -> Result<Option<EndpointRecord>, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| StoreError::Internal)?;
        transaction
            .query_row(
                "SELECT endpoint_id, label, base_url, controller_authority_id,
                        controller_credential_revision, protocol_version, secret_ref, created_at_ms,
                        provider_adapter_kinds, tools, kind
                 FROM endpoints WHERE endpoint_id = ?1",
                [endpoint_id],
                endpoint_record_from_row,
            )
            .optional()
            .map_err(|_| StoreError::Internal)
    }

    pub(crate) fn put_provider_descriptor(
        &self,
        write: ProviderDescriptorWrite,
    ) -> Result<ProviderDescriptorRecord, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Internal)?;
        let existing = transaction
            .query_row(
                "SELECT request_fingerprint, revision
                 FROM provider_descriptor_operations
                 WHERE actor_key = ?1 AND provider = ?2 AND command_key = ?3",
                params![
                    &write.actor_key[..],
                    &write.provider,
                    &write.command_key[..]
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(|_| StoreError::Internal)?;
        if let Some((fingerprint, revision)) = existing {
            if !equal_digest(&fingerprint, &write.request_fingerprint) {
                return Err(StoreError::Conflict);
            }
            return read_provider_descriptor(&transaction, &write.provider, revision);
        }
        let revision = transaction
            .query_row(
                "SELECT COALESCE(MAX(revision), 0) + 1
                 FROM provider_descriptor_revisions WHERE provider = ?1",
                [&write.provider],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| StoreError::Internal)?;
        transaction
            .execute(
                "INSERT INTO provider_descriptor_revisions (
                    provider, revision, kind, base_url, models_json, options_json, created_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    &write.provider,
                    revision,
                    &write.kind,
                    &write.base_url,
                    &write.models_json,
                    &write.options_json,
                    write.created_at_ms,
                ],
            )
            .map_err(|_| StoreError::Internal)?;
        transaction
            .execute(
                "INSERT INTO provider_descriptor_operations (
                    actor_key, provider, command_key, request_fingerprint, revision
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    &write.actor_key[..],
                    &write.provider,
                    &write.command_key[..],
                    &write.request_fingerprint[..],
                    revision,
                ],
            )
            .map_err(|_| StoreError::Internal)?;
        let record = read_provider_descriptor(&transaction, &write.provider, revision)?;
        transaction.commit().map_err(|_| StoreError::Internal)?;
        Ok(record)
    }

    pub(crate) fn list_provider_descriptors(
        &self,
    ) -> Result<Vec<ProviderDescriptorRecord>, StoreError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT descriptor.provider, descriptor.revision, descriptor.kind,
                        descriptor.base_url, descriptor.models_json, descriptor.options_json
                 FROM provider_descriptor_revisions AS descriptor
                 INNER JOIN (
                    SELECT provider, MAX(revision) AS revision
                    FROM provider_descriptor_revisions GROUP BY provider
                 ) AS latest
                    ON latest.provider = descriptor.provider
                   AND latest.revision = descriptor.revision
                 ORDER BY descriptor.provider ASC
                 LIMIT 101",
            )
            .map_err(|_| StoreError::Internal)?;
        let records = statement
            .query_map([], provider_descriptor_from_row)
            .map_err(|_| StoreError::Internal)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| StoreError::Integrity)?;
        if records.len() > 100 {
            return Err(StoreError::Internal);
        }
        Ok(records)
    }

    pub(crate) fn get_provider_descriptor_revision(
        &self,
        provider: &str,
        revision: u64,
    ) -> Result<Option<ProviderDescriptorRecord>, StoreError> {
        let revision = i64::try_from(revision).map_err(|_| StoreError::Integrity)?;
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT provider, revision, kind, base_url, models_json, options_json
                 FROM provider_descriptor_revisions
                 WHERE provider = ?1 AND revision = ?2",
                params![provider, revision],
                provider_descriptor_from_row,
            )
            .optional()
            .map_err(|_| StoreError::Internal)
    }

    pub(crate) fn begin_profile_create(
        &self,
        write: ProfileCreateWrite,
    ) -> Result<ProfileCreateOperation, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Internal)?;
        let existing = transaction
            .query_row(
                "SELECT request_fingerprint, phase, profile_id, label, secret_ref,
                        sharing_json, make_default, created_at_ms
                 FROM auth_profile_create_operations
                 WHERE actor_key = ?1 AND provider = ?2 AND command_key = ?3",
                params![
                    &write.actor_key[..],
                    &write.provider,
                    &write.command_key[..]
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| StoreError::Internal)?;
        if let Some((
            fingerprint,
            phase,
            profile_id,
            label,
            secret_ref,
            sharing_json,
            make_default,
            created_at_ms,
        )) = existing
        {
            if !equal_digest(&fingerprint, &write.request_fingerprint) {
                return Err(StoreError::Conflict);
            }
            return Ok(ProfileCreateOperation {
                actor_key: write.actor_key,
                provider: write.provider,
                command_key: write.command_key,
                request_fingerprint: write.request_fingerprint,
                phase: parse_profile_phase(&phase)?,
                profile_id,
                label,
                secret_ref,
                sharing_json,
                make_default: make_default != 0,
                created_at_ms,
            });
        }
        let descriptor_exists = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM provider_descriptor_revisions WHERE provider = ?1
                 )",
                [&write.provider],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| StoreError::Internal)?
            != 0;
        if !descriptor_exists {
            return Err(StoreError::Integrity);
        }
        transaction
            .execute(
                "INSERT INTO auth_profile_create_operations (
                    actor_key, provider, command_key, request_fingerprint, phase,
                    profile_id, label, secret_ref, sharing_json, make_default, created_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    &write.actor_key[..],
                    &write.provider,
                    &write.command_key[..],
                    &write.request_fingerprint[..],
                    &write.profile_id,
                    &write.label,
                    &write.secret_ref,
                    &write.sharing_json,
                    if write.make_default { 1_i64 } else { 0_i64 },
                    write.created_at_ms,
                ],
            )
            .map_err(|_| StoreError::Internal)?;
        transaction.commit().map_err(|_| StoreError::Internal)?;
        Ok(ProfileCreateOperation {
            actor_key: write.actor_key,
            provider: write.provider,
            command_key: write.command_key,
            request_fingerprint: write.request_fingerprint,
            phase: ProfileCreatePhase::Pending,
            profile_id: write.profile_id,
            label: write.label,
            secret_ref: write.secret_ref,
            sharing_json: write.sharing_json,
            make_default: write.make_default,
            created_at_ms: write.created_at_ms,
        })
    }

    pub(crate) fn commit_profile_create(
        &self,
        operation: &ProfileCreateOperation,
    ) -> Result<AuthProfileRecord, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Internal)?;
        let persisted = transaction
            .query_row(
                "SELECT request_fingerprint, phase FROM auth_profile_create_operations
                 WHERE actor_key = ?1 AND provider = ?2 AND command_key = ?3",
                params![
                    &operation.actor_key[..],
                    &operation.provider,
                    &operation.command_key[..]
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|_| StoreError::Internal)?
            .ok_or(StoreError::Integrity)?;
        if !equal_digest(&persisted.0, &operation.request_fingerprint) {
            return Err(StoreError::Conflict);
        }
        if persisted.1 != "pending" {
            return read_auth_profile(&transaction, &operation.profile_id);
        }
        let sharing: serde_json::Value =
            serde_json::from_str(&operation.sharing_json).map_err(|_| StoreError::Integrity)?;
        let mode = sharing["mode"].as_str().ok_or(StoreError::Integrity)?;
        let endpoint_ids = sharing["endpoint_ids"]
            .as_array()
            .ok_or(StoreError::Integrity)?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(StoreError::Integrity)
            })
            .collect::<Result<Vec<_>, _>>()?;
        for endpoint_id in &endpoint_ids {
            let exists = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM endpoints WHERE endpoint_id = ?1 AND disabled = 0)",
                    [endpoint_id],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|_| StoreError::Internal)?
                != 0;
            if !exists {
                return Err(StoreError::Integrity);
            }
        }
        let descriptor_revision = transaction
            .query_row(
                "SELECT MAX(revision) FROM provider_descriptor_revisions WHERE provider = ?1",
                [&operation.provider],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| StoreError::Internal)?;
        transaction
            .execute(
                "INSERT INTO auth_profiles (
                    profile_id, provider, kind, label, revision, descriptor_revision,
                    secret_ref, created_at_ms, deleted_at_ms
                 ) VALUES (?1, ?2, 'api_key', ?3, 1, ?4, ?5, ?6, NULL)",
                params![
                    &operation.profile_id,
                    &operation.provider,
                    &operation.label,
                    descriptor_revision,
                    &operation.secret_ref,
                    operation.created_at_ms,
                ],
            )
            .map_err(|_| StoreError::Internal)?;
        transaction
            .execute(
                "INSERT INTO auth_profile_sharing_revisions (
                    profile_id, revision, mode, endpoint_ids_json, created_at_ms
                 ) VALUES (?1, 1, ?2, ?3, ?4)",
                params![
                    &operation.profile_id,
                    mode,
                    serde_json::to_string(&endpoint_ids).map_err(|_| StoreError::Integrity)?,
                    operation.created_at_ms,
                ],
            )
            .map_err(|_| StoreError::Internal)?;
        if operation.make_default {
            let default_revision = transaction
                .query_row(
                    "SELECT COALESCE(MAX(revision), 0) + 1
                     FROM provider_default_profile_revisions WHERE provider = ?1",
                    [&operation.provider],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|_| StoreError::Internal)?;
            transaction
                .execute(
                    "INSERT INTO provider_default_profile_revisions (
                        provider, revision, profile_id, created_at_ms
                     ) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        &operation.provider,
                        default_revision,
                        &operation.profile_id,
                        operation.created_at_ms,
                    ],
                )
                .map_err(|_| StoreError::Internal)?;
        }
        for endpoint_id in endpoint_ids {
            let operation_id = format!(
                "profile:{}:endpoint:{endpoint_id}:revision:1",
                operation.profile_id
            );
            transaction
                .execute(
                    "INSERT INTO auth_replica_operations (
                        profile_id, endpoint_id, revision, operation_id, status, observed_revision
                     ) VALUES (?1, ?2, 1, ?3, 'pending', NULL)",
                    params![&operation.profile_id, endpoint_id, operation_id],
                )
                .map_err(|_| StoreError::Internal)?;
        }
        transaction
            .execute(
                "UPDATE auth_profile_create_operations SET phase = 'distributing'
                 WHERE actor_key = ?1 AND provider = ?2 AND command_key = ?3 AND phase = 'pending'",
                params![
                    &operation.actor_key[..],
                    &operation.provider,
                    &operation.command_key[..]
                ],
            )
            .map_err(|_| StoreError::Internal)?;
        let record = read_auth_profile(&transaction, &operation.profile_id)?;
        transaction.commit().map_err(|_| StoreError::Internal)?;
        Ok(record)
    }

    pub(crate) fn mark_replica_ready(
        &self,
        profile_id: &str,
        endpoint_id: &str,
        revision: u64,
    ) -> Result<(), StoreError> {
        let revision = i64::try_from(revision).map_err(|_| StoreError::Integrity)?;
        let connection = self.connection()?;
        let changed = connection
            .execute(
                "UPDATE auth_replica_operations
                 SET status = 'ready', observed_revision = ?3
                 WHERE profile_id = ?1 AND endpoint_id = ?2 AND revision = ?3",
                params![profile_id, endpoint_id, revision],
            )
            .map_err(|_| StoreError::Internal)?;
        if changed != 1 {
            return Err(StoreError::Integrity);
        }
        Ok(())
    }

    pub(crate) fn complete_profile_create(
        &self,
        operation: &ProfileCreateOperation,
    ) -> Result<AuthProfileRecord, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Internal)?;
        let pending = transaction
            .query_row(
                "SELECT COUNT(*) FROM auth_replica_operations
                 WHERE profile_id = ?1 AND revision = 1 AND status != 'ready'",
                [&operation.profile_id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| StoreError::Internal)?;
        if pending != 0 {
            return Err(StoreError::Integrity);
        }
        transaction
            .execute(
                "UPDATE auth_profile_create_operations SET phase = 'complete'
                 WHERE actor_key = ?1 AND provider = ?2 AND command_key = ?3
                   AND phase IN ('distributing', 'complete')",
                params![
                    &operation.actor_key[..],
                    &operation.provider,
                    &operation.command_key[..]
                ],
            )
            .map_err(|_| StoreError::Internal)?;
        let record = read_auth_profile(&transaction, &operation.profile_id)?;
        transaction.commit().map_err(|_| StoreError::Internal)?;
        Ok(record)
    }

    pub(crate) fn set_provider_default_profile(
        &self,
        write: ProviderDefaultProfileWrite,
    ) -> Result<(AuthProfileRecord, bool), StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Internal)?;
        let existing = transaction
            .query_row(
                "SELECT request_fingerprint, profile_id
                 FROM provider_default_profile_operations
                 WHERE actor_key = ?1 AND provider = ?2 AND command_key = ?3",
                params![
                    &write.actor_key[..],
                    &write.provider,
                    &write.command_key[..]
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|_| StoreError::Internal)?;
        if let Some((fingerprint, profile_id)) = existing {
            if !equal_digest(&fingerprint, &write.request_fingerprint) {
                return Err(StoreError::Conflict);
            }
            let record = read_auth_profile_optional(&transaction, &profile_id)?
                .ok_or(StoreError::Integrity)?;
            return Ok((record, true));
        }
        let profile_exists = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM auth_profiles
                    WHERE profile_id = ?1 AND provider = ?2 AND deleted_at_ms IS NULL
                )",
                params![&write.profile_id, &write.provider],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| StoreError::Internal)?
            != 0;
        if !profile_exists {
            return Err(StoreError::NotFound);
        }
        let revision = transaction
            .query_row(
                "SELECT COALESCE(MAX(revision), 0) + 1
                 FROM provider_default_profile_revisions WHERE provider = ?1",
                [&write.provider],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| StoreError::Internal)?;
        transaction
            .execute(
                "INSERT INTO provider_default_profile_revisions (
                    provider, revision, profile_id, created_at_ms
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    &write.provider,
                    revision,
                    &write.profile_id,
                    write.created_at_ms
                ],
            )
            .map_err(|_| StoreError::Internal)?;
        transaction
            .execute(
                "INSERT INTO provider_default_profile_operations (
                    actor_key, provider, command_key, request_fingerprint, profile_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    &write.actor_key[..],
                    &write.provider,
                    &write.command_key[..],
                    &write.request_fingerprint[..],
                    &write.profile_id,
                ],
            )
            .map_err(|_| StoreError::Internal)?;
        let record = read_auth_profile(&transaction, &write.profile_id)?;
        transaction.commit().map_err(|_| StoreError::Internal)?;
        Ok((record, false))
    }

    pub(crate) fn begin_profile_delete(
        &self,
        write: ProfileDeleteWrite,
    ) -> Result<(u64, AuthProfileRecord, Vec<AuthTombstoneRecord>), StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Internal)?;
        let existing = transaction
            .query_row(
                "SELECT request_fingerprint, profile_id, tombstone_revision
                 FROM auth_profile_delete_operations
                 WHERE actor_key = ?1 AND provider = ?2 AND command_key = ?3",
                params![
                    &write.actor_key[..],
                    &write.provider,
                    &write.command_key[..]
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| StoreError::Internal)?;
        if let Some((fingerprint, profile_id, revision)) = existing {
            if !equal_digest(&fingerprint, &write.request_fingerprint)
                || profile_id != write.profile_id
            {
                return Err(StoreError::Conflict);
            }
            let record = read_auth_profile(&transaction, &profile_id)?;
            if record.provider != write.provider || record.deleted_at_ms.is_none() {
                return Err(StoreError::Integrity);
            }
            let tombstones = read_auth_profile_tombstones(&transaction, &profile_id)?;
            let revision = u64::try_from(revision).map_err(|_| StoreError::Integrity)?;
            transaction.commit().map_err(|_| StoreError::Internal)?;
            return Ok((revision, record, tombstones));
        }

        let record = read_auth_profile_optional(&transaction, &write.profile_id)?
            .ok_or(StoreError::NotFound)?;
        if record.provider != write.provider || record.deleted_at_ms.is_some() {
            return Err(StoreError::NotFound);
        }
        let current_tombstone_revision = transaction
            .query_row(
                "SELECT COALESCE(MAX(revision), 0)
                 FROM auth_profile_tombstones WHERE profile_id = ?1",
                [&write.profile_id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| StoreError::Internal)?;
        let profile_revision = i64::try_from(record.revision).map_err(|_| StoreError::Integrity)?;
        let tombstone_revision = profile_revision
            .max(current_tombstone_revision)
            .checked_add(1)
            .ok_or(StoreError::Integrity)?;
        if record.is_default {
            let default_revision = transaction
                .query_row(
                    "SELECT COALESCE(MAX(revision), 0) + 1
                     FROM provider_default_profile_revisions WHERE provider = ?1",
                    [&write.provider],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|_| StoreError::Internal)?;
            transaction
                .execute(
                    "INSERT INTO provider_default_profile_revisions (
                        provider, revision, profile_id, created_at_ms
                     ) VALUES (?1, ?2, NULL, ?3)",
                    params![&write.provider, default_revision, write.created_at_ms],
                )
                .map_err(|_| StoreError::Internal)?;
        }
        transaction
            .execute(
                "UPDATE auth_profiles SET deleted_at_ms = ?2
                 WHERE profile_id = ?1 AND deleted_at_ms IS NULL",
                params![&write.profile_id, write.created_at_ms],
            )
            .map_err(|_| StoreError::Internal)?;
        let endpoint_ids = transaction
            .prepare(
                "SELECT endpoint_id FROM auth_replica_operations
                 WHERE profile_id = ?1 ORDER BY endpoint_id ASC",
            )
            .map_err(|_| StoreError::Internal)?
            .query_map([&write.profile_id], |row| row.get::<_, String>(0))
            .map_err(|_| StoreError::Internal)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| StoreError::Integrity)?;
        for endpoint_id in endpoint_ids {
            let operation_id = format!(
                "profile:{}:endpoint:{endpoint_id}:tombstone:{tombstone_revision}",
                write.profile_id
            );
            transaction
                .execute(
                    "INSERT INTO auth_profile_tombstones (
                        profile_id, provider, endpoint_id, revision, operation_id,
                        status, observed_revision, created_at_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, 'pending', NULL, ?6)",
                    params![
                        &write.profile_id,
                        &write.provider,
                        endpoint_id,
                        tombstone_revision,
                        operation_id,
                        write.created_at_ms,
                    ],
                )
                .map_err(|_| StoreError::Internal)?;
        }
        transaction
            .execute(
                "INSERT INTO auth_profile_delete_operations (
                    actor_key, provider, profile_id, command_key,
                    request_fingerprint, tombstone_revision, created_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    &write.actor_key[..],
                    &write.provider,
                    &write.profile_id,
                    &write.command_key[..],
                    &write.request_fingerprint[..],
                    tombstone_revision,
                    write.created_at_ms,
                ],
            )
            .map_err(|_| StoreError::Internal)?;
        let record = read_auth_profile(&transaction, &write.profile_id)?;
        let tombstones = read_auth_profile_tombstones(&transaction, &write.profile_id)?;
        let revision = u64::try_from(tombstone_revision).map_err(|_| StoreError::Integrity)?;
        transaction.commit().map_err(|_| StoreError::Internal)?;
        Ok((revision, record, tombstones))
    }

    pub(crate) fn mark_profile_tombstone(
        &self,
        profile_id: &str,
        endpoint_id: &str,
        revision: u64,
        status: &str,
        observed_revision: Option<u64>,
    ) -> Result<(), StoreError> {
        if !matches!(status, "pending" | "removed" | "unreachable") {
            return Err(StoreError::Integrity);
        }
        let revision = i64::try_from(revision).map_err(|_| StoreError::Integrity)?;
        let observed_revision = observed_revision
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StoreError::Integrity)?;
        let connection = self.connection()?;
        let changed = connection
            .execute(
                "UPDATE auth_profile_tombstones
                 SET status = ?4, observed_revision = ?5
                 WHERE profile_id = ?1 AND endpoint_id = ?2 AND revision = ?3",
                params![profile_id, endpoint_id, revision, status, observed_revision],
            )
            .map_err(|_| StoreError::Internal)?;
        if changed != 1 {
            return Err(StoreError::Integrity);
        }
        Ok(())
    }

    pub(crate) fn get_auth_profile(
        &self,
        profile_id: &str,
    ) -> Result<Option<AuthProfileRecord>, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| StoreError::Internal)?;
        read_auth_profile_optional(&transaction, profile_id)
    }

    pub(crate) fn list_auth_profiles(
        &self,
        provider: &str,
    ) -> Result<Vec<AuthProfileRecord>, StoreError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(&format!(
                "{} WHERE profile.provider = ?1 ORDER BY profile.created_at_ms ASC, profile.profile_id ASC LIMIT 101",
                AUTH_PROFILE_SELECT
            ))
            .map_err(|_| StoreError::Internal)?;
        let records = statement
            .query_map([provider], auth_profile_from_row)
            .map_err(|_| StoreError::Internal)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| StoreError::Integrity)?;
        let records = records
            .into_iter()
            .filter(|record| record.deleted_at_ms.is_none())
            .collect::<Vec<_>>();
        if records.len() > 100 {
            return Err(StoreError::Internal);
        }
        Ok(records)
    }

    pub(crate) fn list_auth_replicas(
        &self,
        profile_id: &str,
    ) -> Result<Vec<AuthReplicaRecord>, StoreError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT replica.profile_id, replica.endpoint_id, profile.provider,
                        replica.revision, replica.operation_id, replica.status,
                        replica.observed_revision
                 FROM auth_replica_operations AS replica
                 INNER JOIN auth_profiles AS profile ON profile.profile_id = replica.profile_id
                 WHERE replica.profile_id = ?1
                 ORDER BY replica.endpoint_id ASC",
            )
            .map_err(|_| StoreError::Internal)?;
        let mut records = statement
            .query_map([profile_id], auth_replica_from_row)
            .map_err(|_| StoreError::Internal)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| StoreError::Integrity)?;
        let tombstones = read_auth_profile_tombstones_connection(&connection, profile_id)?;
        for tombstone in tombstones {
            if let Some(existing) = records
                .iter_mut()
                .find(|record| record.endpoint_id == tombstone.endpoint_id)
            {
                existing.revision = tombstone.revision;
                existing.operation_id = tombstone.operation_id.clone();
                existing.status = tombstone.status.clone();
                existing.observed_revision = tombstone.observed_revision;
            } else {
                records.push(AuthReplicaRecord {
                    profile_id: tombstone.profile_id,
                    endpoint_id: tombstone.endpoint_id,
                    provider: tombstone.provider,
                    revision: tombstone.revision,
                    operation_id: tombstone.operation_id,
                    status: tombstone.status,
                    observed_revision: tombstone.observed_revision,
                });
            }
        }
        records.sort_by(|left, right| left.endpoint_id.cmp(&right.endpoint_id));
        Ok(records)
    }

    pub(crate) fn list_deleted_provider_secret_refs(&self) -> Result<Vec<String>, StoreError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT secret_ref FROM auth_profiles
                 WHERE deleted_at_ms IS NOT NULL ORDER BY profile_id ASC",
            )
            .map_err(|_| StoreError::Internal)?;
        let records = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|_| StoreError::Internal)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| StoreError::Integrity)?;
        Ok(records)
    }

    pub(crate) fn list_auth_tombstones_for_reconciliation(
        &self,
    ) -> Result<Vec<AuthTombstoneDispatchRecord>, StoreError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT tomb.profile_id, tomb.provider, tomb.endpoint_id,
                        tomb.revision, tomb.operation_id, tomb.status,
                        tomb.observed_revision, profile.secret_ref
                 FROM auth_profile_tombstones AS tomb
                 INNER JOIN auth_profiles AS profile
                    ON profile.profile_id = tomb.profile_id
                 WHERE tomb.status <> 'removed'
                   AND profile.deleted_at_ms IS NOT NULL
                 ORDER BY tomb.profile_id ASC, tomb.endpoint_id ASC",
            )
            .map_err(|_| StoreError::Internal)?;
        let records = statement
            .query_map([], |row| {
                let revision = u64::try_from(row.get::<_, i64>(3)?).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        3,
                        rusqlite::types::Type::Integer,
                        Box::new(error),
                    )
                })?;
                let observed_revision = row
                    .get::<_, Option<i64>>(6)?
                    .map(|value| {
                        u64::try_from(value).map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                6,
                                rusqlite::types::Type::Integer,
                                Box::new(error),
                            )
                        })
                    })
                    .transpose()?;
                Ok(AuthTombstoneDispatchRecord {
                    tombstone: AuthTombstoneRecord {
                        profile_id: row.get(0)?,
                        provider: row.get(1)?,
                        endpoint_id: row.get(2)?,
                        revision,
                        operation_id: row.get(4)?,
                        status: row.get(5)?,
                        observed_revision,
                    },
                    secret_ref: row.get(7)?,
                })
            })
            .map_err(|_| StoreError::Internal)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| StoreError::Integrity)?;
        Ok(records)
    }

    fn initialize(
        &self,
        subject_key_version: u64,
        database_state: ControlDatabaseState,
    ) -> Result<(), StartupError> {
        if !self.database_path_matches_owner() {
            return Err(StartupError::StoreIntegrity);
        }
        let connection = self
            .database
            .lock()
            .map_err(|_| StartupError::StoreUnavailable)?;
        if matches!(database_state, ControlDatabaseState::Initialized) {
            validate_server_metadata(
                &connection,
                &self.authority_id,
                subject_key_version,
                &self.keys,
            )?;
        }
        configure_connection(&connection).map_err(|_| StartupError::StoreUnavailable)?;
        connection
            .execute_batch(CONTROL_SCHEMA)
            .map_err(|_| StartupError::StoreUnavailable)?;
        ensure_endpoint_capability_columns(&connection)?;
        ensure_auth_profile_columns(&connection)?;
        if matches!(database_state, ControlDatabaseState::New) {
            let version =
                i64::try_from(subject_key_version).map_err(|_| StartupError::AuthorityMismatch)?;
            let fingerprint = self.keys.digest(b"subject-key-fingerprint-v1", &[]);
            connection
                .execute(
                    "INSERT INTO server_metadata (
                        singleton, schema_version, server_authority_id,
                        subject_key_version, subject_key_fingerprint
                     ) VALUES (1, ?1, ?2, ?3, ?4)",
                    params![
                        CONTROL_SCHEMA_VERSION,
                        &self.authority_id,
                        version,
                        &fingerprint[..],
                    ],
                )
                .map_err(|_| StartupError::StoreUnavailable)?;
        }
        Ok(())
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, StoreError> {
        if !self.database_path_matches_owner() {
            return Err(StoreError::Internal);
        }
        self.database.lock().map_err(|_| StoreError::Internal)
    }

    fn database_path_matches_owner(&self) -> bool {
        fs::symlink_metadata(&self.database_path)
            .map(|metadata| {
                metadata.file_type().is_file() && lock_identity(&metadata) == self.database_identity
            })
            .unwrap_or(false)
    }

    fn read_endpoint(
        &self,
        connection: &rusqlite::Transaction<'_>,
        endpoint_id: &str,
    ) -> Result<EndpointRecord, StoreError> {
        connection
            .query_row(
                "SELECT endpoint_id, label, base_url, controller_authority_id,
                        controller_credential_revision, protocol_version, secret_ref, created_at_ms,
                        provider_adapter_kinds, tools, kind
                 FROM endpoints WHERE endpoint_id = ?1",
                [endpoint_id],
                endpoint_record_from_row,
            )
            .optional()
            .map_err(|_| StoreError::Internal)?
            .ok_or(StoreError::Integrity)
    }
}

fn ensure_private_secret_namespace(path: &Path) -> Result<(), StoreError> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => sync_directory(path.parent().ok_or(StoreError::Integrity)?)
            .map_err(|_| StoreError::Internal)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(StoreError::Internal),
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| StoreError::Internal)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(StoreError::Integrity);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(StoreError::Integrity);
        }
    }
    Ok(())
}

fn read_provider_descriptor(
    transaction: &rusqlite::Transaction<'_>,
    provider: &str,
    revision: i64,
) -> Result<ProviderDescriptorRecord, StoreError> {
    transaction
        .query_row(
            "SELECT provider, revision, kind, base_url, models_json, options_json
             FROM provider_descriptor_revisions
             WHERE provider = ?1 AND revision = ?2",
            params![provider, revision],
            provider_descriptor_from_row,
        )
        .optional()
        .map_err(|_| StoreError::Internal)?
        .ok_or(StoreError::Integrity)
}

fn provider_descriptor_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<ProviderDescriptorRecord> {
    let revision = row.get::<_, i64>(1)?;
    let revision = u64::try_from(revision).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            1,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })?;
    Ok(ProviderDescriptorRecord {
        provider: row.get(0)?,
        revision,
        kind: row.get(2)?,
        base_url: row.get(3)?,
        models_json: row.get(4)?,
        options_json: row.get(5)?,
    })
}

const AUTH_PROFILE_SELECT: &str =
    "SELECT profile.profile_id, profile.provider, profile.kind, profile.label,
            profile.revision, profile.descriptor_revision, profile.secret_ref,
            sharing.mode, sharing.endpoint_ids_json,
            CASE WHEN defaults.profile_id = profile.profile_id THEN 1 ELSE 0 END,
            profile.deleted_at_ms
     FROM auth_profiles AS profile
     INNER JOIN auth_profile_sharing_revisions AS sharing
        ON sharing.profile_id = profile.profile_id
       AND sharing.revision = (
            SELECT MAX(candidate.revision)
            FROM auth_profile_sharing_revisions AS candidate
            WHERE candidate.profile_id = profile.profile_id
       )
     LEFT JOIN provider_default_profile_revisions AS defaults
        ON defaults.provider = profile.provider
       AND defaults.revision = (
            SELECT MAX(candidate.revision)
            FROM provider_default_profile_revisions AS candidate
            WHERE candidate.provider = profile.provider
       )";

fn read_auth_profile(
    transaction: &rusqlite::Transaction<'_>,
    profile_id: &str,
) -> Result<AuthProfileRecord, StoreError> {
    read_auth_profile_optional(transaction, profile_id)?.ok_or(StoreError::Integrity)
}

fn read_auth_profile_optional(
    transaction: &rusqlite::Transaction<'_>,
    profile_id: &str,
) -> Result<Option<AuthProfileRecord>, StoreError> {
    transaction
        .query_row(
            &format!("{AUTH_PROFILE_SELECT} WHERE profile.profile_id = ?1"),
            [profile_id],
            auth_profile_from_row,
        )
        .optional()
        .map_err(|_| StoreError::Internal)
}

fn auth_profile_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuthProfileRecord> {
    let revision = positive_u64(row, 4)?;
    let descriptor_revision = positive_u64(row, 5)?;
    Ok(AuthProfileRecord {
        profile_id: row.get(0)?,
        provider: row.get(1)?,
        kind: row.get(2)?,
        label: row.get(3)?,
        revision,
        descriptor_revision,
        secret_ref: row.get(6)?,
        sharing_mode: row.get(7)?,
        endpoint_ids_json: row.get(8)?,
        is_default: row.get::<_, i64>(9)? != 0,
        deleted_at_ms: row.get(10)?,
    })
}

fn read_auth_profile_tombstones(
    transaction: &rusqlite::Transaction<'_>,
    profile_id: &str,
) -> Result<Vec<AuthTombstoneRecord>, StoreError> {
    read_auth_profile_tombstones_connection(transaction, profile_id)
}

fn read_auth_profile_tombstones_connection(
    connection: &Connection,
    profile_id: &str,
) -> Result<Vec<AuthTombstoneRecord>, StoreError> {
    let mut statement = connection
        .prepare(
            "SELECT profile_id, provider, endpoint_id, revision, operation_id,
                    status, observed_revision
             FROM auth_profile_tombstones
             WHERE profile_id = ?1 ORDER BY endpoint_id ASC",
        )
        .map_err(|_| StoreError::Internal)?;
    let records = statement
        .query_map([profile_id], |row| {
            let revision = u64::try_from(row.get::<_, i64>(3)?).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    3,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })?;
            let observed_revision = row
                .get::<_, Option<i64>>(6)?
                .map(|value| {
                    u64::try_from(value).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            6,
                            rusqlite::types::Type::Integer,
                            Box::new(error),
                        )
                    })
                })
                .transpose()?;
            Ok(AuthTombstoneRecord {
                profile_id: row.get(0)?,
                provider: row.get(1)?,
                endpoint_id: row.get(2)?,
                revision,
                operation_id: row.get(4)?,
                status: row.get(5)?,
                observed_revision,
            })
        })
        .map_err(|_| StoreError::Internal)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| StoreError::Integrity)?;
    Ok(records)
}

fn auth_replica_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuthReplicaRecord> {
    let revision = positive_u64(row, 3)?;
    let observed_revision = row
        .get::<_, Option<i64>>(6)?
        .map(|value| {
            u64::try_from(value).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    6,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })
        })
        .transpose()?;
    Ok(AuthReplicaRecord {
        profile_id: row.get(0)?,
        endpoint_id: row.get(1)?,
        provider: row.get(2)?,
        revision,
        operation_id: row.get(4)?,
        status: row.get(5)?,
        observed_revision,
    })
}

fn positive_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value = row.get::<_, i64>(index)?;
    u64::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn parse_profile_phase(value: &str) -> Result<ProfileCreatePhase, StoreError> {
    match value {
        "pending" => Ok(ProfileCreatePhase::Pending),
        "distributing" => Ok(ProfileCreatePhase::Distributing),
        "complete" => Ok(ProfileCreatePhase::Complete),
        _ => Err(StoreError::Integrity),
    }
}

fn endpoint_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EndpointRecord> {
    let revision = row.get::<_, i64>(4)?;
    let revision = u64::try_from(revision).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })?;
    Ok(EndpointRecord {
        endpoint_id: row.get(0)?,
        label: row.get(1)?,
        kind: row.get(10)?,
        base_url: row.get(2)?,
        controller_authority_id: row.get(3)?,
        controller_credential_revision: revision,
        protocol_version: row.get(5)?,
        provider_adapter_kinds: parse_string_list(row.get(8)?, 8)?,
        tools: parse_string_list(row.get(9)?, 9)?,
        secret_ref: row.get(6)?,
        created_at_ms: row.get(7)?,
    })
}

fn parse_string_list(value: String, column: usize) -> rusqlite::Result<Vec<String>> {
    serde_json::from_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

fn ensure_endpoint_capability_columns(connection: &Connection) -> Result<(), StartupError> {
    let mut statement = connection
        .prepare("PRAGMA table_info(endpoints)")
        .map_err(|_| StartupError::StoreUnavailable)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|_| StartupError::StoreUnavailable)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| StartupError::StoreUnavailable)?;
    for (column, declaration) in [
        ("provider_adapter_kinds", "TEXT NOT NULL DEFAULT '[]'"),
        ("tools", "TEXT NOT NULL DEFAULT '[]'"),
        (
            "kind",
            "TEXT NOT NULL DEFAULT 'remote' CHECK (kind IN ('local', 'remote'))",
        ),
    ] {
        if columns.iter().any(|value| value == column) {
            continue;
        }
        let sql = format!("ALTER TABLE endpoints ADD COLUMN {column} {declaration}");
        connection
            .execute(&sql, [])
            .map_err(|_| StartupError::StoreUnavailable)?;
    }
    connection
        .execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS one_local_endpoint
             ON endpoints(kind) WHERE kind = 'local'",
            [],
        )
        .map_err(|_| StartupError::StoreUnavailable)?;
    Ok(())
}

fn ensure_auth_profile_columns(connection: &Connection) -> Result<(), StartupError> {
    let mut statement = connection
        .prepare("PRAGMA table_info(auth_profiles)")
        .map_err(|_| StartupError::StoreUnavailable)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|_| StartupError::StoreUnavailable)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| StartupError::StoreUnavailable)?;
    if !columns.iter().any(|value| value == "deleted_at_ms") {
        connection
            .execute(
                "ALTER TABLE auth_profiles ADD COLUMN deleted_at_ms INTEGER",
                [],
            )
            .map_err(|_| StartupError::StoreUnavailable)?;
    }
    Ok(())
}

fn validate_server_metadata(
    connection: &Connection,
    authority_id: &str,
    subject_key_version: u64,
    keys: &KeyMaterial,
) -> Result<(), StartupError> {
    let (schema, authority, version, stored_fingerprint) = connection
        .query_row(
            "SELECT schema_version, server_authority_id, subject_key_version,
                    subject_key_fingerprint
             FROM server_metadata WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| StartupError::StoreIntegrity)?
        .ok_or(StartupError::StoreIntegrity)?;
    let expected_version =
        i64::try_from(subject_key_version).map_err(|_| StartupError::AuthorityMismatch)?;
    let fingerprint = keys.digest(b"subject-key-fingerprint-v1", &[]);
    if schema != CONTROL_SCHEMA_VERSION
        || authority != authority_id
        || version != expected_version
        || !equal_digest(&stored_fingerprint, &fingerprint)
    {
        return Err(StartupError::AuthorityMismatch);
    }
    Ok(())
}

fn configure_connection(connection: &Connection) -> rusqlite::Result<()> {
    connection.busy_timeout(Duration::from_secs(2))?;
    connection.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;",
    )?;
    Ok(())
}

fn read_key_material(path: &Path) -> Result<KeyMaterial, StartupError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            StartupError::MissingSubjectKey
        } else {
            StartupError::InvalidSubjectKey
        }
    })?;
    if !metadata.file_type().is_file() {
        return Err(StartupError::InvalidSubjectKey);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(StartupError::InvalidSubjectKey);
        }
    }
    let mut bytes =
        read_bounded(path, SUBJECT_KEY_BYTES + 1).map_err(|_| StartupError::InvalidSubjectKey)?;
    if bytes.len() != SUBJECT_KEY_BYTES {
        bytes.fill(0);
        return Err(StartupError::InvalidSubjectKey);
    }
    let mut subject = [0_u8; SUBJECT_KEY_BYTES];
    subject.copy_from_slice(&bytes);
    bytes.fill(0);
    let encryption = keyed_digest(&subject, b"secret-encryption-key-v1", &[]);
    Ok(KeyMaterial {
        subject,
        encryption,
    })
}

fn validate_secret_directory(path: &Path) -> Result<(), StartupError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| StartupError::StoreUnavailable)?;
    if !metadata.file_type().is_dir() {
        return Err(StartupError::StoreUnavailable);
    }
    Ok(())
}

fn acquire_secret_ownership(secret_directory: &Path) -> Result<File, StartupError> {
    let file = File::open(secret_directory).map_err(|_| StartupError::StoreUnavailable)?;
    if !file
        .metadata()
        .map_err(|_| StartupError::StoreUnavailable)?
        .is_dir()
    {
        return Err(StartupError::StoreUnavailable);
    }
    file.try_lock_exclusive().map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            StartupError::AlreadyOwned
        } else {
            StartupError::StoreUnavailable
        }
    })?;
    Ok(file)
}

struct DatabaseOwnership {
    connection: Connection,
    path: PathBuf,
    database_identity: [u8; 16],
    lock: File,
    state: ControlDatabaseState,
}

fn acquire_database_ownership(
    path: &Path,
    marker_directory: &Path,
    subject_key_version: u64,
    authority_id: &str,
    keys: &KeyMaterial,
) -> Result<DatabaseOwnership, StartupError> {
    if matches!(
        fs::symlink_metadata(path),
        Ok(metadata) if metadata.file_type().is_symlink()
    ) {
        return Err(StartupError::StoreUnavailable);
    }
    let state = if fs::symlink_metadata(path).is_ok() {
        validate_existing_database(
            path,
            marker_directory,
            subject_key_version,
            authority_id,
            keys,
        )?;
        ControlDatabaseState::Initialized
    } else {
        ControlDatabaseState::New
    };
    let database_file = open_private_rw(path).map_err(|_| StartupError::StoreUnavailable)?;
    let database_metadata = database_file
        .metadata()
        .map_err(|_| StartupError::StoreUnavailable)?;
    if !database_metadata.is_file() {
        return Err(StartupError::StoreUnavailable);
    }
    #[cfg(unix)]
    if std::os::unix::fs::MetadataExt::nlink(&database_metadata) != 1 {
        return Err(StartupError::AlreadyOwned);
    }
    let canonical = fs::canonicalize(path).map_err(|_| StartupError::StoreUnavailable)?;
    let file_name = canonical
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(StartupError::StoreUnavailable)?;
    let lock_path = canonical.with_file_name(format!("{file_name}.server.lock"));
    let anchor_path = canonical.with_file_name(format!("{file_name}.server.lock.anchor"));
    let database = Connection::open(&canonical).map_err(|_| StartupError::StoreUnavailable)?;
    if lock_identity(&fs::symlink_metadata(&canonical).map_err(|_| StartupError::StoreUnavailable)?)
        != lock_identity(&database_metadata)
    {
        return Err(StartupError::StoreIntegrity);
    }
    let lock = open_private_rw(&lock_path).map_err(|_| StartupError::StoreUnavailable)?;
    let lock_metadata =
        fs::symlink_metadata(&lock_path).map_err(|_| StartupError::StoreUnavailable)?;
    if !lock_metadata.file_type().is_file() {
        return Err(StartupError::StoreUnavailable);
    }
    match fs::symlink_metadata(&anchor_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(StartupError::StoreUnavailable);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            if std::os::unix::fs::MetadataExt::nlink(&lock_metadata) != 1 {
                return Err(StartupError::AlreadyOwned);
            }
            fs::hard_link(&lock_path, &anchor_path).map_err(|_| StartupError::StoreUnavailable)?;
        }
        Err(_) => return Err(StartupError::StoreUnavailable),
    }
    let anchor_metadata =
        fs::symlink_metadata(&anchor_path).map_err(|_| StartupError::StoreUnavailable)?;
    if lock_identity(&lock_metadata) != lock_identity(&anchor_metadata) {
        return Err(StartupError::AlreadyOwned);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if anchor_metadata.nlink() != 2
            || anchor_metadata.permissions().mode() & 0o077 != 0
            || lock_metadata.permissions().mode() & 0o077 != 0
        {
            return Err(StartupError::StoreUnavailable);
        }
    }
    lock.try_lock_exclusive().map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            StartupError::AlreadyOwned
        } else {
            StartupError::StoreUnavailable
        }
    })?;
    connection_exclusive(&database)?;
    let database_identity = lock_identity(&database_metadata);
    ensure_database_identity(
        &canonical,
        marker_directory,
        matches!(state, ControlDatabaseState::New),
        &database_identity,
        &lock_identity(&anchor_metadata),
    )?;
    Ok(DatabaseOwnership {
        connection: database,
        path: canonical,
        database_identity,
        lock,
        state,
    })
}

fn validate_existing_database(
    database: &Path,
    marker_directory: &Path,
    subject_key_version: u64,
    authority_id: &str,
    keys: &KeyMaterial,
) -> Result<(), StartupError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(database).map_err(|_| StartupError::StoreIntegrity)?;
        if metadata.nlink() != 1 {
            return Err(StartupError::AlreadyOwned);
        }
    }
    let canonical_database =
        fs::canonicalize(database).map_err(|_| StartupError::StoreIntegrity)?;
    let file_name = canonical_database
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(StartupError::StoreIntegrity)?;
    let lock_path = canonical_database.with_file_name(format!("{file_name}.server.lock"));
    if existing_lock_is_busy(&lock_path)? {
        return Err(StartupError::AlreadyOwned);
    }
    let wal_path = PathBuf::from(format!("{}-wal", database.display()));
    let shm_path = PathBuf::from(format!("{}-shm", database.display()));
    let wal_exists = fs::symlink_metadata(&wal_path).is_ok();
    let shm_exists = fs::symlink_metadata(&shm_path).is_ok();
    let wal_nonempty = fs::metadata(&wal_path)
        .map(|metadata| metadata.len() > 0)
        .unwrap_or(false);
    if (wal_exists && !sqlite_sidecar_is_private(&wal_path))
        || (shm_exists && !sqlite_sidecar_is_private(&shm_path))
        || (wal_nonempty && !shm_exists)
    {
        return Err(StartupError::StoreIntegrity);
    }
    let connection = if wal_nonempty {
        Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)
    } else {
        Connection::open_with_flags(
            sqlite_immutable_uri(database)?,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )
    }
    .map_err(|_| StartupError::StoreIntegrity)?;
    validate_server_metadata(&connection, authority_id, subject_key_version, keys)?;
    let anchor_path = database.with_file_name(format!("{file_name}.server.lock.anchor"));
    let lock_metadata = fs::symlink_metadata(&lock_path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            StartupError::AlreadyOwned
        } else {
            StartupError::StoreUnavailable
        }
    })?;
    let anchor_metadata = fs::symlink_metadata(&anchor_path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            StartupError::AlreadyOwned
        } else {
            StartupError::StoreUnavailable
        }
    })?;
    if !lock_metadata.file_type().is_file()
        || !anchor_metadata.file_type().is_file()
        || lock_identity(&lock_metadata) != lock_identity(&anchor_metadata)
    {
        return Err(StartupError::AlreadyOwned);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if lock_metadata.nlink() != 2
            || anchor_metadata.nlink() != 2
            || lock_metadata.permissions().mode() & 0o077 != 0
            || anchor_metadata.permissions().mode() & 0o077 != 0
        {
            return Err(StartupError::AlreadyOwned);
        }
    }
    let database_identity = fs::symlink_metadata(database)
        .map(|metadata| lock_identity(&metadata))
        .map_err(|_| StartupError::StoreIntegrity)?;
    let lock_identity = lock_identity(&lock_metadata);
    let expected = [database_identity.as_slice(), lock_identity.as_slice()].concat();
    for path in [
        PathBuf::from(format!("{}.server-owner", database.display())),
        marker_directory.join(".server-owner"),
    ] {
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StartupError::AlreadyOwned
            } else {
                StartupError::StoreUnavailable
            }
        })?;
        if !metadata.file_type().is_file()
            || read_bounded(&path, expected.len()).map_err(|_| StartupError::AlreadyOwned)?
                != expected
        {
            return Err(StartupError::AlreadyOwned);
        }
    }
    Ok(())
}

fn existing_lock_is_busy(path: &Path) -> Result<bool, StartupError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(StartupError::StoreUnavailable),
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(StartupError::AlreadyOwned);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(StartupError::AlreadyOwned);
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| StartupError::StoreUnavailable)?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(true),
        Err(_) => Err(StartupError::StoreUnavailable),
    }
}

fn ensure_database_identity(
    database: &Path,
    marker_directory: &Path,
    allow_create: bool,
    database_identity: &[u8; 16],
    lock_identity: &[u8; 16],
) -> Result<(), StartupError> {
    let expected = [database_identity.as_slice(), lock_identity.as_slice()].concat();
    let paths = [
        PathBuf::from(format!("{}.server-owner", database.display())),
        marker_directory.join(".server-owner"),
    ];
    let mut missing = Vec::new();
    for path in paths {
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file()
                    || read_bounded(&path, expected.len())
                        .map_err(|_| StartupError::StoreUnavailable)?
                        != expected
                {
                    return Err(StartupError::AlreadyOwned);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !allow_create {
                    return Err(StartupError::AlreadyOwned);
                }
                missing.push(path);
            }
            Err(_) => return Err(StartupError::StoreUnavailable),
        }
    }
    for path in missing {
        let mut file = private_create_new(&path).map_err(|_| StartupError::StoreUnavailable)?;
        file.write_all(&expected)
            .and_then(|_| file.sync_all())
            .map_err(|_| StartupError::StoreUnavailable)?;
        sync_directory(path.parent().ok_or(StartupError::StoreUnavailable)?)
            .map_err(|_| StartupError::StoreUnavailable)?;
    }
    Ok(())
}

fn sqlite_immutable_uri(path: &Path) -> Result<String, StartupError> {
    let path = path.to_str().ok_or(StartupError::StoreIntegrity)?;
    Ok(format!(
        "file:{}?immutable=1",
        path.replace('%', "%25")
            .replace('?', "%3F")
            .replace('#', "%23")
    ))
}

#[cfg(unix)]
fn sqlite_sidecar_is_private(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file() && metadata.nlink() == 1)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn sqlite_sidecar_is_private(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
}

#[cfg(unix)]
fn lock_identity(metadata: &fs::Metadata) -> [u8; 16] {
    use std::os::unix::fs::MetadataExt;
    let mut identity = [0_u8; 16];
    identity[..8].copy_from_slice(&metadata.dev().to_le_bytes());
    identity[8..].copy_from_slice(&metadata.ino().to_le_bytes());
    identity
}

#[cfg(not(unix))]
fn lock_identity(metadata: &fs::Metadata) -> [u8; 16] {
    let mut identity = [0_u8; 16];
    identity[..8].copy_from_slice(&metadata.len().to_le_bytes());
    identity
}

fn open_private_rw(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn connection_exclusive(connection: &Connection) -> Result<(), StartupError> {
    connection
        .busy_timeout(Duration::ZERO)
        .map_err(|_| StartupError::StoreUnavailable)?;
    connection
        .pragma_update(None, "locking_mode", "EXCLUSIVE")
        .map_err(|_| StartupError::StoreUnavailable)?;
    connection
        .execute_batch("BEGIN EXCLUSIVE; COMMIT;")
        .map_err(|error| match error.sqlite_error_code() {
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
                StartupError::AlreadyOwned
            }
            _ => StartupError::StoreUnavailable,
        })?;
    Ok(())
}

fn private_create_new(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn read_bounded(path: &Path, max_bytes: usize) -> std::io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut bytes = Vec::with_capacity(max_bytes + 1);
    file.take((max_bytes + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeds configured bound",
        ));
    }
    Ok(bytes)
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

fn keyed_digest(key: &[u8], domain: &[u8], fields: &[&[u8]]) -> [u8; DIGEST_BYTES] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("fixed HMAC key is valid");
    update_field(&mut mac, domain);
    for field in fields {
        update_field(&mut mac, field);
    }
    mac.finalize().into_bytes().into()
}

fn update_field(mac: &mut HmacSha256, value: &[u8]) {
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
}

fn equal_digest(stored: &[u8], expected: &[u8; DIGEST_BYTES]) -> bool {
    stored.len() == expected.len() && bool::from(stored.ct_eq(expected.as_slice()))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}
