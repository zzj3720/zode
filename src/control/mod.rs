mod files;
mod rotation;
use self::rotation::RotationStore;
use axum::http::{header, HeaderMap};
use std::{
    cell::RefCell,
    fs::File,
    path::{Path, PathBuf},
    sync::{Mutex, RwLock},
};
use thiserror::Error;
pub(crate) const MAX_CONTROL_SECRET_BYTES: usize = 64 * 1024;
pub(crate) const MAX_ENDPOINT_ID_BYTES: usize = 64;
pub(crate) const MAX_SUBJECT_BYTES: usize = 512;
pub(crate) const MAX_AUTHORIZATION_BYTES: usize = MAX_CONTROL_SECRET_BYTES + 7;
pub(crate) const MAX_ROTATION_REQUEST_BYTES: usize = 128 * 1024;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 1024;
#[derive(Clone)]
pub struct ControllerAuthSpec {
    authority_id: String,
    revision: u64,
    secret_file: PathBuf,
}
impl ControllerAuthSpec {
    pub fn new(authority_id: String, revision: u64, secret_file: PathBuf) -> Self {
        Self {
            authority_id,
            revision,
            secret_file,
        }
    }
}
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ControllerAuthRotationRequest {
    pub(crate) schema: String,
    pub(crate) authority_id: String,
    pub(crate) revision: u64,
    pub(crate) secret: ControllerAuthSecretEnvelope,
}
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ControllerAuthSecretEnvelope {
    pub(crate) encoding: String,
    pub(crate) payload: String,
}
#[derive(Debug, Error)]
pub enum ControlInitError {
    #[error("endpoint control storage is unavailable")]
    Storage(#[source] std::io::Error),
    #[error("endpoint stores are already owned by another process")]
    AlreadyOwned,
    #[error("endpoint control configuration is invalid")]
    Invalid,
}
#[derive(Debug)]
pub enum ControlAuthError {
    Unauthenticated,
    Malformed,
    PayloadTooLarge,
}
#[derive(Debug)]
pub(crate) enum ControlRotationError {
    Invalid,
    PayloadTooLarge,
    Conflict,
    Internal,
}
impl From<ControlInitError> for ControlRotationError {
    fn from(_: ControlInitError) -> Self {
        Self::Internal
    }
}
pub struct ControlState {
    endpoint_id: String,
    runtime_store_path: PathBuf,
    credential_replica_directory: Option<PathBuf>,
    authorities: RwLock<Vec<Authority>>,
    rotation: Mutex<RotationStore>,
    _locks: Vec<File>,
}
struct Authority {
    authority_id: String,
    revision: u64,
    secret: Vec<u8>,
}
pub struct ControlContext {
    authority_id: String,
    revision: u64,
    subject: String,
}
impl ControlState {
    pub fn open(
        runtime_store_path: &Path,
        credential_replica_directory: Option<&Path>,
        specs: Vec<ControllerAuthSpec>,
    ) -> Result<Self, ControlInitError> {
        let (database_lock, canonical_store, allow_create) =
            files::acquire_database_lock(runtime_store_path)?;
        let mut locks = vec![database_lock];
        let canonical_credentials = if let Some(directory) = credential_replica_directory {
            let (lock, canonical) = files::acquire_directory_lock(directory)?;
            locks.push(lock);
            Some(canonical)
        } else {
            None
        };
        let control_directory = files::open_control_directory(&canonical_store, allow_create)?;
        if canonical_credentials.as_deref() == Some(control_directory.as_path()) {
            return Err(ControlInitError::Invalid);
        }
        let (endpoint_id, identity_created) = files::load_or_create_identity(
            &files::append_suffix(&canonical_store, ".endpoint-id"),
            allow_create,
        )?;
        let mut rotation = RotationStore::open(control_directory, allow_create)?;
        let persisted =
            rotation.initialize(&endpoint_id, &specs, allow_create, identity_created)?;
        let authorities = persisted
            .into_iter()
            .map(|authority| Authority {
                authority_id: authority.authority_id,
                revision: authority.revision,
                secret: authority.secret,
            })
            .collect();
        Ok(Self {
            endpoint_id,
            runtime_store_path: canonical_store,
            credential_replica_directory: canonical_credentials,
            authorities: RwLock::new(authorities),
            rotation: Mutex::new(rotation),
            _locks: locks,
        })
    }
    pub fn endpoint_id(&self) -> &str {
        &self.endpoint_id
    }
    pub fn runtime_store_path(&self) -> &Path {
        &self.runtime_store_path
    }

    /// Return the exact canonical credential sidecar directory that was
    /// locked during startup.  The composition root must pass this path to
    /// the replica adapter instead of resolving the configured pathname a
    /// second time after the lock has been acquired.
    pub fn credential_replica_directory(&self) -> Option<&Path> {
        self.credential_replica_directory.as_deref()
    }
    pub fn authenticate(&self, headers: &HeaderMap) -> Result<ControlContext, ControlAuthError> {
        let controller = self.authenticate_controller(headers)?;
        let subject = read_subject(headers)?;
        Ok(ControlContext {
            authority_id: controller.authority_id,
            revision: controller.revision,
            subject,
        })
    }
    pub fn authenticate_controller(
        &self,
        headers: &HeaderMap,
    ) -> Result<ControllerContext, ControlAuthError> {
        let authorities = self
            .authorities
            .read()
            .map_err(|_| ControlAuthError::Unauthenticated)?;
        let authority = authenticate_bearer(&authorities, headers)?;
        Ok(ControllerContext {
            authority_id: authority.authority_id,
            revision: authority.revision,
        })
    }
    pub(crate) fn rotate(
        &self,
        context: &ControllerContext,
        idempotency_key: &str,
        request: &ControllerAuthRotationRequest,
    ) -> Result<rotation::RotationOutcome, ControlRotationError> {
        if idempotency_key.is_empty() || idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
            return Err(if idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
                ControlRotationError::PayloadTooLarge
            } else {
                ControlRotationError::Invalid
            });
        }
        rotation::validate_request(&context.authority_id, request)?;
        let mut rotation = self
            .rotation
            .lock()
            .map_err(|_| ControlRotationError::Internal)?;
        rotation
            .ensure_root_current()
            .map_err(|_| ControlRotationError::Internal)?;
        let authorities = self
            .authorities
            .read()
            .map_err(|_| ControlRotationError::Internal)?;
        let authority = authorities
            .iter()
            .find(|authority| authority.authority_id == context.authority_id)
            .ok_or(ControlRotationError::Internal)?;
        if authority.revision != context.revision {
            return Err(ControlRotationError::Conflict);
        }
        let candidate = request.secret.payload.as_bytes();
        if authorities.iter().any(|other| {
            other.authority_id != context.authority_id
                && files::constant_time_equal(candidate, &other.secret)
        }) {
            return Err(ControlRotationError::Conflict);
        }
        let current_revision = authority.revision;
        drop(authorities);
        let promotion_guard = RefCell::new(None);
        rotation.rotate(
            &rotation::RotationInput {
                authority_id: &context.authority_id,
                subject: "",
                idempotency_key,
                current_revision,
            },
            request,
            || {
                *promotion_guard.borrow_mut() = Some(
                    self.authorities
                        .write()
                        .map_err(|_| ControlRotationError::Internal)?,
                );
                Ok(())
            },
            |secret| {
                let mut authorities = promotion_guard
                    .borrow_mut()
                    .take()
                    .ok_or(ControlRotationError::Internal)?;
                let authority = authorities
                    .iter_mut()
                    .find(|authority| authority.authority_id == context.authority_id)
                    .ok_or(ControlRotationError::Internal)?;
                authority.revision = request.revision;
                authority.secret = secret.to_vec();
                Ok(())
            },
        )
    }
}
impl ControlContext {
    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
}
fn authenticate_bearer(
    authorities: &[Authority],
    headers: &HeaderMap,
) -> Result<AuthorityMatch, ControlAuthError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Err(ControlAuthError::Unauthenticated);
    };
    if values.next().is_some() {
        return Err(ControlAuthError::Unauthenticated);
    }
    if value.as_bytes().len() > MAX_AUTHORIZATION_BYTES {
        return Err(ControlAuthError::PayloadTooLarge);
    }
    let Some(token) = value.as_bytes().strip_prefix(b"Bearer ") else {
        return Err(ControlAuthError::Unauthenticated);
    };
    if !files::validate_bearer_token(token) {
        return Err(ControlAuthError::Unauthenticated);
    }
    let mut matched = None;
    for authority in authorities {
        if files::constant_time_equal(token, &authority.secret) {
            if matched.is_some() {
                return Err(ControlAuthError::Unauthenticated);
            }
            matched = Some(AuthorityMatch {
                authority_id: authority.authority_id.clone(),
                revision: authority.revision,
            });
        }
    }
    matched.ok_or(ControlAuthError::Unauthenticated)
}
struct AuthorityMatch {
    authority_id: String,
    revision: u64,
}

pub struct ControllerContext {
    authority_id: String,
    revision: u64,
}

impl ControllerContext {
    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }
}

fn read_subject(headers: &HeaderMap) -> Result<String, ControlAuthError> {
    let mut values = headers.get_all("zode-subject").iter();
    let Some(value) = values.next() else {
        return Err(ControlAuthError::Malformed);
    };
    if values.next().is_some() {
        return Err(ControlAuthError::Malformed);
    }
    if value.as_bytes().len() > MAX_SUBJECT_BYTES {
        return Err(ControlAuthError::PayloadTooLarge);
    }
    let value = std::str::from_utf8(value.as_bytes()).map_err(|_| ControlAuthError::Malformed)?;
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(ControlAuthError::Malformed);
    }
    Ok(value.to_owned())
}
