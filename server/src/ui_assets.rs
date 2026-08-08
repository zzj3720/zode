use std::{
    collections::HashMap,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    body::{Body, Bytes},
    http::{header, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use thiserror::Error;

use crate::config::UiMode;

const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_TREE_BYTES: usize = 64 * 1024 * 1024;
const MAX_FILES: usize = 512;

#[derive(Debug, Error)]
pub(crate) enum UiAssetsError {
    #[error("cannot preload UI assets")]
    Read(#[source] std::io::Error),
    #[error("UI asset tree exceeds its bound")]
    TooLarge,
    #[error("UI asset tree is invalid")]
    InvalidTree,
    #[error("UI index.html is invalid")]
    InvalidIndex,
    #[error("UI asset configuration is invalid")]
    InvalidConfig,
}

#[derive(Clone)]
struct UiFile {
    bytes: Bytes,
    content_type: &'static str,
    cache_control: &'static str,
}

#[derive(Clone)]
pub(crate) struct UiAssets {
    files: HashMap<String, UiFile>,
    index: UiFile,
}

impl UiAssets {
    pub(crate) fn load(
        mode: UiMode,
        directory: Option<&Path>,
    ) -> Result<Option<Arc<Self>>, UiAssetsError> {
        let directory = match (mode, directory) {
            (UiMode::ApiOnly, None) => return Ok(None),
            (UiMode::ApiOnly, Some(_)) | (UiMode::Assets, None) => {
                return Err(UiAssetsError::InvalidConfig)
            }
            (UiMode::Assets, Some(directory)) => directory,
        };
        let root_metadata = fs::symlink_metadata(directory).map_err(UiAssetsError::Read)?;
        if !root_metadata.file_type().is_dir() || root_metadata.file_type().is_symlink() {
            return Err(UiAssetsError::InvalidTree);
        }

        let mut paths = Vec::new();
        collect_files(directory, directory, &mut paths)?;
        if paths.is_empty() || paths.len() > MAX_FILES {
            return Err(UiAssetsError::InvalidTree);
        }
        paths.sort();

        let mut files = HashMap::new();
        let mut total = 0_usize;
        for (public_path, disk_path) in paths {
            let bytes = read_bounded_file(&disk_path)?;
            total = total.saturating_add(bytes.len());
            if total > MAX_TREE_BYTES {
                return Err(UiAssetsError::TooLarge);
            }
            let content_type = content_type(&public_path).ok_or(UiAssetsError::InvalidTree)?;
            let cache_control = if public_path == "/index.html" {
                "no-cache"
            } else {
                "public, max-age=31536000, immutable"
            };
            files.insert(
                public_path,
                UiFile {
                    bytes: Bytes::from(bytes),
                    content_type,
                    cache_control,
                },
            );
        }
        let index = files
            .get("/index.html")
            .filter(|file| !file.bytes.is_empty())
            .cloned()
            .ok_or(UiAssetsError::InvalidIndex)?;
        Ok(Some(Arc::new(Self { files, index })))
    }

    pub(crate) fn response(&self, method: &Method, path: &str, headers: &HeaderMap) -> Response {
        if method != Method::GET && method != Method::HEAD {
            return StatusCode::NOT_FOUND.into_response();
        }
        if let Some(file) = self.files.get(path) {
            return file_response(file, method == Method::HEAD);
        }
        if history_route(path, headers) {
            return file_response(&self.index, method == Method::HEAD);
        }
        StatusCode::NOT_FOUND.into_response()
    }
}

fn collect_files(
    root: &Path,
    directory: &Path,
    output: &mut Vec<(String, PathBuf)>,
) -> Result<(), UiAssetsError> {
    let mut entries = fs::read_dir(directory)
        .map_err(UiAssetsError::Read)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(UiAssetsError::Read)?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(UiAssetsError::Read)?;
        if metadata.file_type().is_symlink() {
            return Err(UiAssetsError::InvalidTree);
        }
        if metadata.file_type().is_dir() {
            collect_files(root, &path, output)?;
            continue;
        }
        if !metadata.file_type().is_file() || output.len() >= MAX_FILES {
            return Err(UiAssetsError::InvalidTree);
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| UiAssetsError::InvalidTree)?;
        let components = relative
            .components()
            .map(|component| {
                component
                    .as_os_str()
                    .to_str()
                    .filter(|part| !part.is_empty() && *part != "." && *part != "..")
                    .ok_or(UiAssetsError::InvalidTree)
            })
            .collect::<Result<Vec<_>, _>>()?;
        output.push((format!("/{}", components.join("/")), path));
    }
    Ok(())
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>, UiAssetsError> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(UiAssetsError::Read)?
        .take((MAX_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(UiAssetsError::Read)?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(UiAssetsError::TooLarge);
    }
    Ok(bytes)
}

fn content_type(path: &str) -> Option<&'static str> {
    match Path::new(path).extension().and_then(|value| value.to_str()) {
        Some("html") => Some("text/html; charset=utf-8"),
        Some("js") | Some("mjs") => Some("text/javascript; charset=utf-8"),
        Some("css") => Some("text/css; charset=utf-8"),
        Some("json") => Some("application/json"),
        Some("svg") => Some("image/svg+xml"),
        Some("png") => Some("image/png"),
        Some("webp") => Some("image/webp"),
        Some("woff") => Some("font/woff"),
        Some("woff2") => Some("font/woff2"),
        Some("ttf") => Some("font/ttf"),
        _ => None,
    }
}

fn history_route(path: &str, headers: &HeaderMap) -> bool {
    if path == "/"
        || path.starts_with("/v1")
        || path.starts_with("/assets/")
        || path.contains("..")
        || path.contains('\\')
        || path.chars().any(char::is_control)
    {
        return path == "/";
    }
    headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            value
                .split(',')
                .map(str::trim)
                .any(|media| media.starts_with("text/html") || media == "*/*")
        })
}

fn file_response(file: &UiFile, head: bool) -> Response {
    let body = if head {
        Body::empty()
    } else {
        Body::from(file.bytes.clone())
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, file.content_type)
        .header(header::CACHE_CONTROL, file.cache_control)
        .header(header::REFERRER_POLICY, "no-referrer")
        .body(body)
        .expect("static UI response is valid")
}
