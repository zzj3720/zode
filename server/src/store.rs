use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use fs2::FileExt;
use getrandom::fill as fill_random;
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json;
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
            Self::AuthorityMismatch => ("server_authority_mismatch", "control_store"),
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum StoreError {
    #[error("management command conflicts with an existing receipt")]
    Conflict,
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
    database: PathBuf,
    secret_directory: PathBuf,
    authority_id: String,
    keys: Arc<KeyMaterial>,
    _ownership: File,
}

pub(crate) enum BeginEndpointCreate {
    Pending(EndpointCreateOperation),
    Complete(EndpointCreateOperation, EndpointRecord),
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
        let ownership = acquire_ownership(config.control_database())?;
        let keys = Arc::new(read_key_material(config.access().subject_key_file())?);
        let store = Self {
            database: config.control_database().to_path_buf(),
            secret_directory: config.secret_directory().to_path_buf(),
            authority_id: config.server_authority_id().to_owned(),
            keys,
            _ownership: ownership,
        };
        store.initialize(config.access().subject_key_version())?;
        Ok(store)
    }

    pub(crate) fn keys(&self) -> Arc<KeyMaterial> {
        Arc::clone(&self.keys)
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_local_endpoint(
        &self,
        fingerprint: &[u8; DIGEST_BYTES],
        endpoint_id: &str,
        base_url: &str,
        controller_authority_id: &str,
        controller_credential_revision: u64,
        protocol_version: &str,
        provider_adapter_kinds: &[String],
        tools: &[String],
        secret_ref: &str,
        observed_at_ms: i64,
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
        let revision = i64::try_from(controller_credential_revision)
            .map_err(|_| StoreError::Integrity)?;
        let providers_json =
            serde_json::to_string(provider_adapter_kinds).map_err(|_| StoreError::Integrity)?;
        let tools_json = serde_json::to_string(tools).map_err(|_| StoreError::Integrity)?;
        let created_at_ms = if let Some(existing) = existing_local {
            if existing.endpoint_id != endpoint_id
                || existing.kind != "local"
                || existing.base_url != base_url
                || existing.controller_authority_id != controller_authority_id
                || existing.secret_ref != secret_ref
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
                        endpoint_id,
                        revision,
                        protocol_version,
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
                        endpoint_id,
                        base_url,
                        controller_authority_id,
                        revision,
                        protocol_version,
                        secret_ref,
                        observed_at_ms,
                        &providers_json,
                        &tools_json,
                    ],
                )
                .map_err(|error| {
                    if error.sqlite_error_code()
                        == Some(rusqlite::ErrorCode::ConstraintViolation)
                    {
                        StoreError::Conflict
                    } else {
                        StoreError::Internal
                    }
                })?;
            observed_at_ms
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
            endpoint_id: endpoint_id.to_owned(),
            label: "Local Endpoint".to_owned(),
            kind: "local".to_owned(),
            base_url: base_url.to_owned(),
            controller_authority_id: controller_authority_id.to_owned(),
            controller_credential_revision,
            protocol_version: protocol_version.to_owned(),
            provider_adapter_kinds: provider_adapter_kinds.to_vec(),
            tools: tools.to_vec(),
            secret_ref: secret_ref.to_owned(),
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
                    .map(|record| BeginEndpointCreate::Complete(prior, record)),
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
        if reference.len() != 64 || !reference.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(StoreError::Integrity);
        }
        let directory = self.secret_directory.join("endpoints");
        fs::create_dir_all(&directory).map_err(|_| StoreError::Internal)?;
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

    pub(crate) fn complete_endpoint_create(
        &self,
        operation: &EndpointCreateOperation,
        endpoint_id: &str,
        controller_authority_id: &str,
        controller_credential_revision: u64,
        protocol_version: &str,
        provider_adapter_kinds: &[String],
        tools: &[String],
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
            endpoint_id: endpoint_id.to_owned(),
            label: operation.label.clone(),
            kind: "remote".to_owned(),
            base_url: operation.base_url.clone(),
            controller_authority_id: controller_authority_id.to_owned(),
            controller_credential_revision,
            protocol_version: protocol_version.to_owned(),
            provider_adapter_kinds: provider_adapter_kinds.to_vec(),
            tools: tools.to_vec(),
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

    fn initialize(&self, subject_key_version: u64) -> Result<(), StartupError> {
        let connection = self.startup_connection()?;
        connection
            .execute_batch(CONTROL_SCHEMA)
            .map_err(|_| StartupError::StoreUnavailable)?;
        ensure_endpoint_capability_columns(&connection)?;
        let existing = connection
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
            .map_err(|_| StartupError::StoreUnavailable)?;
        let fingerprint = self.keys.digest(b"subject-key-fingerprint-v1", &[]);
        match existing {
            None => {
                let version = i64::try_from(subject_key_version)
                    .map_err(|_| StartupError::AuthorityMismatch)?;
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
            Some((schema, authority, version, stored_fingerprint)) => {
                let expected_version = i64::try_from(subject_key_version)
                    .map_err(|_| StartupError::AuthorityMismatch)?;
                if schema != CONTROL_SCHEMA_VERSION
                    || authority != self.authority_id
                    || version != expected_version
                    || !equal_digest(&stored_fingerprint, &fingerprint)
                {
                    return Err(StartupError::AuthorityMismatch);
                }
            }
        }
        Ok(())
    }

    fn startup_connection(&self) -> Result<Connection, StartupError> {
        let connection =
            Connection::open(&self.database).map_err(|_| StartupError::StoreUnavailable)?;
        configure_connection(&connection).map_err(|_| StartupError::StoreUnavailable)?;
        Ok(connection)
    }

    fn connection(&self) -> Result<Connection, StoreError> {
        let connection = Connection::open(&self.database).map_err(|_| StoreError::Internal)?;
        configure_connection(&connection).map_err(|_| StoreError::Internal)?;
        Ok(connection)
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
        (
            "provider_adapter_kinds",
            "TEXT NOT NULL DEFAULT '[]'",
        ),
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

fn acquire_ownership(control_database: &Path) -> Result<File, StartupError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(control_database)
        .map_err(|_| StartupError::StoreUnavailable)?;
    if !file
        .metadata()
        .map_err(|_| StartupError::StoreUnavailable)?
        .is_file()
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
