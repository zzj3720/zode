use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    path::Path,
    sync::Arc,
};

use axum::{
    body::Bytes,
    http::header,
    response::{IntoResponse, Response},
};
use thiserror::Error;

use crate::config::UiMode;

const MAX_INDEX_BYTES: usize = 128 * 1024;

#[derive(Debug, Error)]
pub(crate) enum UiAssetsError {
    #[error("cannot preload UI index.html")]
    Read(#[source] std::io::Error),
    #[error("UI index.html is too large")]
    TooLarge,
    #[error("UI index.html is empty")]
    InvalidIndex,
    #[error("UI asset configuration is invalid")]
    InvalidConfig,
}

#[derive(Clone)]
pub(crate) struct UiAssets {
    files: HashMap<&'static str, Bytes>,
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
        let mut bytes = Vec::with_capacity(MAX_INDEX_BYTES + 1);
        let file = File::open(directory.join("index.html")).map_err(UiAssetsError::Read)?;
        file.take((MAX_INDEX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(UiAssetsError::Read)?;
        if bytes.len() > MAX_INDEX_BYTES {
            return Err(UiAssetsError::TooLarge);
        }
        if bytes.is_empty() {
            return Err(UiAssetsError::InvalidIndex);
        }

        let mut files = HashMap::new();
        files.insert("/", Bytes::from(bytes));
        Ok(Some(Arc::new(Self { files })))
    }

    pub(crate) fn root_response(&self) -> Response {
        let body = self.files.get("/").expect("preloaded UI root").clone();
        (
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::CACHE_CONTROL, "no-cache"),
            ],
            body,
        )
            .into_response()
    }
}
