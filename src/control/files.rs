use super::{ControlInitError, MAX_CONTROL_SECRET_BYTES, MAX_ENDPOINT_ID_BYTES};
use axum::http::HeaderValue;
use fs2::FileExt;
use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Write},
    path::{Path, PathBuf},
};
use ulid::Ulid;

const PRIVATE_FILE_MODE: u32 = 0o600;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

enum OpenMode {
    Read,
    ReadWrite,
    ReadWriteCreate,
    ReadWriteCreateNew,
}

enum LinkPolicy {
    Follow,
    NoFollow,
}

/// The pathname of a sidecar directory is not its identity.  A controller
/// operation must keep using the exact directory that was admitted during
/// startup, even if somebody renames it and installs a new directory at the
/// old pathname while the process is alive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    canonical: PathBuf,
}

pub(crate) fn capture_directory_identity(
    path: &Path,
) -> Result<DirectoryIdentity, ControlInitError> {
    let metadata = fs::symlink_metadata(path).map_err(ControlInitError::Storage)?;
    if !metadata.is_dir() {
        return Err(ControlInitError::Invalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(DirectoryIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(DirectoryIdentity {
            canonical: fs::canonicalize(path).map_err(ControlInitError::Storage)?,
        })
    }
}

pub(crate) fn acquire_database_lock(
    path: &Path,
) -> Result<(File, PathBuf, bool), ControlInitError> {
    let database = open_file(path, OpenMode::ReadWriteCreate, LinkPolicy::Follow)?;
    let metadata = database.metadata().map_err(ControlInitError::Storage)?;
    let canonical = fs::canonicalize(path).map_err(ControlInitError::Storage)?;
    let lock = open_lock_file(&append_suffix(&canonical, ".endpoint.lock"))?;
    try_exclusive(&lock)?;
    Ok((lock, canonical, metadata.len() == 0))
}

pub(crate) fn acquire_directory_lock(path: &Path) -> Result<(File, PathBuf), ControlInitError> {
    fs::create_dir_all(path).map_err(ControlInitError::Storage)?;
    let canonical = fs::canonicalize(path).map_err(ControlInitError::Storage)?;
    let lock = open_lock_file(&canonical.join(".endpoint.lock"))?;
    try_exclusive(&lock)?;
    Ok((lock, canonical))
}

pub(crate) fn open_control_directory(
    runtime_store: &Path,
    allow_create: bool,
) -> Result<PathBuf, ControlInitError> {
    let directory = append_suffix(runtime_store, ".controller-auth");
    if allow_create {
        match fs::create_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(ControlInitError::Storage(error)),
        }
    } else if !directory.is_dir() {
        return Err(ControlInitError::Invalid);
    }
    ensure_private_directory(&directory)?;
    fs::canonicalize(directory).map_err(ControlInitError::Storage)
}

pub(crate) fn ensure_private_directory(path: &Path) -> Result<(), ControlInitError> {
    let metadata = fs::symlink_metadata(path).map_err(ControlInitError::Storage)?;
    if !metadata.is_dir() {
        return Err(ControlInitError::Invalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            let mut permissions = metadata.permissions();
            permissions.set_mode(PRIVATE_DIRECTORY_MODE);
            fs::set_permissions(path, permissions).map_err(ControlInitError::Storage)?;
        }
    }
    Ok(())
}

pub(crate) fn read_private_file(path: &Path, maximum: usize) -> Result<Vec<u8>, ControlInitError> {
    let file = open_file(path, OpenMode::Read, LinkPolicy::NoFollow)?;
    let metadata = file.metadata().map_err(ControlInitError::Storage)?;
    if !is_private_file(&metadata) {
        return Err(ControlInitError::Invalid);
    }
    read_bounded(&file, maximum)
}

pub(crate) fn open_private_for_append(path: &Path) -> Result<File, ControlInitError> {
    open_file(path, OpenMode::ReadWriteCreate, LinkPolicy::NoFollow)
}

pub(crate) fn open_private_for_update(path: &Path) -> Result<File, ControlInitError> {
    open_file(path, OpenMode::ReadWrite, LinkPolicy::NoFollow)
}

pub(crate) fn create_private_file(path: &Path, bytes: &[u8]) -> Result<(), ControlInitError> {
    let mut file = open_file(path, OpenMode::ReadWriteCreateNew, LinkPolicy::NoFollow)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(ControlInitError::Storage)?;
    sync_parent(path)
}

pub(crate) fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), ControlInitError> {
    let temporary = append_suffix(path, &format!(".tmp-{}", Ulid::new()));
    let result = (|| {
        create_private_file(&temporary, bytes)?;
        fs::rename(&temporary, path).map_err(ControlInitError::Storage)?;
        sync_parent(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub(crate) fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

pub(crate) fn remove_best_effort(path: &Path) {
    let _ = fs::remove_file(path);
}

pub(crate) fn sync_parent(path: &Path) -> Result<(), ControlInitError> {
    #[cfg(unix)]
    {
        let parent = path.parent().ok_or(ControlInitError::Invalid)?;
        File::open(parent)
            .and_then(|file| file.sync_all())
            .map_err(ControlInitError::Storage)?;
    }
    Ok(())
}

pub(crate) fn is_private_file(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        true
    }
}

pub(crate) fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && subtle::ConstantTimeEq::ct_eq(left, right).into()
}

pub(crate) fn validate_bearer_token(bytes: &[u8]) -> bool {
    if bytes.is_empty()
        || bytes.len() > MAX_CONTROL_SECRET_BYTES
        || bytes.iter().any(u8::is_ascii_whitespace)
    {
        return false;
    }
    let mut authorization = Vec::with_capacity(b"Bearer ".len() + bytes.len());
    authorization.extend_from_slice(b"Bearer ");
    authorization.extend_from_slice(bytes);
    HeaderValue::from_bytes(&authorization).is_ok()
}

pub(crate) fn load_or_create_identity(
    path: &Path,
    allow_create: bool,
) -> Result<(String, bool), ControlInitError> {
    if let Some(identity) = read_identity(path)? {
        return Ok((identity, false));
    }
    if !allow_create {
        return Err(ControlInitError::Invalid);
    }
    let identity = Ulid::new().to_string();
    atomic_replace(path, identity.as_bytes())?;
    let identity = read_identity(path)?.ok_or(ControlInitError::Invalid)?;
    Ok((identity, true))
}

fn read_identity(path: &Path) -> Result<Option<String>, ControlInitError> {
    let bytes = match read_private_file(path, MAX_ENDPOINT_ID_BYTES) {
        Ok(bytes) => bytes,
        Err(ControlInitError::Storage(error)) if error.kind() == ErrorKind::NotFound => {
            return Ok(None)
        }
        Err(error) => return Err(error),
    };
    let identity = String::from_utf8(bytes).map_err(|_| ControlInitError::Invalid)?;
    if identity.is_empty() || Ulid::from_string(&identity).is_err() {
        return Err(ControlInitError::Invalid);
    }
    Ok(Some(identity))
}

fn open_lock_file(path: &Path) -> Result<File, ControlInitError> {
    open_file(path, OpenMode::ReadWriteCreate, LinkPolicy::NoFollow)
}

fn try_exclusive(file: &File) -> Result<(), ControlInitError> {
    file.try_lock_exclusive().map_err(|error| {
        if error.kind() == ErrorKind::WouldBlock {
            ControlInitError::AlreadyOwned
        } else {
            ControlInitError::Storage(error)
        }
    })
}

fn open_file(
    path: &Path,
    mode: OpenMode,
    link_policy: LinkPolicy,
) -> Result<File, ControlInitError> {
    let mut options = OpenOptions::new();
    options.read(true);
    match mode {
        OpenMode::Read => {}
        OpenMode::ReadWrite => {
            options.write(true);
        }
        OpenMode::ReadWriteCreate => {
            options.write(true).create(true);
        }
        OpenMode::ReadWriteCreateNew => {
            options.write(true).create_new(true);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(PRIVATE_FILE_MODE);
        if matches!(link_policy, LinkPolicy::NoFollow) {
            options.custom_flags(libc::O_NOFOLLOW);
        }
    }
    let file = options.open(path).map_err(ControlInitError::Storage)?;
    let metadata = file.metadata().map_err(ControlInitError::Storage)?;
    if !metadata.is_file() {
        return Err(ControlInitError::Invalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(ControlInitError::Invalid);
        }
    }
    if !matches!(mode, OpenMode::Read) {
        set_private_permissions(&file)?;
    }
    Ok(file)
}

fn set_private_permissions(file: &File) -> Result<(), ControlInitError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = file
            .metadata()
            .map_err(ControlInitError::Storage)?
            .permissions();
        permissions.set_mode(PRIVATE_FILE_MODE);
        file.set_permissions(permissions)
            .map_err(ControlInitError::Storage)?;
    }
    Ok(())
}

fn read_bounded(file: &File, maximum: usize) -> Result<Vec<u8>, ControlInitError> {
    let mut bytes = Vec::with_capacity(maximum + 1);
    file.try_clone()
        .map_err(ControlInitError::Storage)?
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(ControlInitError::Storage)?;
    if bytes.len() > maximum {
        return Err(ControlInitError::Invalid);
    }
    Ok(bytes)
}
