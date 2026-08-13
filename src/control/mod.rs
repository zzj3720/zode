mod files;
use std::{
    fs::File,
    path::{Path, PathBuf},
};
use thiserror::Error;

pub(crate) const MAX_ENDPOINT_ID_BYTES: usize = 64;

#[derive(Debug, Error)]
pub enum ControlInitError {
    #[error("endpoint control storage is unavailable")]
    Storage(#[source] std::io::Error),
    #[error("endpoint stores are already owned by another process")]
    AlreadyOwned,
    #[error("endpoint control configuration is invalid")]
    Invalid,
}

pub struct ControlState {
    endpoint_id: String,
    runtime_store_path: PathBuf,
    credential_replica_directory: Option<PathBuf>,
    _locks: Vec<File>,
}

impl ControlState {
    pub fn open(
        runtime_store_path: &Path,
        credential_replica_directory: Option<&Path>,
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
        let (endpoint_id, _) = files::load_or_create_identity(
            &files::append_suffix(&canonical_store, ".endpoint-id"),
            allow_create,
        )?;
        Ok(Self {
            endpoint_id,
            runtime_store_path: canonical_store,
            credential_replica_directory: canonical_credentials,
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
}
