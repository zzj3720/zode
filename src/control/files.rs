use super::{ControlInitError, MAX_ENDPOINT_ID_BYTES};
use fs2::FileExt;
use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Write},
    path::{Path, PathBuf},
};
use ulid::Ulid;

const PRIVATE_FILE_MODE: u32 = 0o600;

enum OpenMode {
    Read,
    ReadWriteCreate,
    ReadWriteCreateNew,
}

enum LinkPolicy {
    Follow,
    NoFollow,
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

pub(crate) fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
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

fn read_private_file(path: &Path, maximum: usize) -> Result<Vec<u8>, ControlInitError> {
    let file = open_file(path, OpenMode::Read, LinkPolicy::NoFollow)?;
    let metadata = file.metadata().map_err(ControlInitError::Storage)?;
    if !is_private_file(&metadata) {
        return Err(ControlInitError::Invalid);
    }
    read_bounded(&file, maximum)
}

fn create_private_file(path: &Path, bytes: &[u8]) -> Result<(), ControlInitError> {
    let mut file = open_file(path, OpenMode::ReadWriteCreateNew, LinkPolicy::NoFollow)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(ControlInitError::Storage)?;
    sync_parent(path)
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), ControlInitError> {
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

fn sync_parent(path: &Path) -> Result<(), ControlInitError> {
    #[cfg(unix)]
    {
        let parent = path.parent().ok_or(ControlInitError::Invalid)?;
        File::open(parent)
            .and_then(|file| file.sync_all())
            .map_err(ControlInitError::Storage)?;
    }
    Ok(())
}

fn is_private_file(metadata: &fs::Metadata) -> bool {
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
