use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    future::Future,
    io::{Read, Write},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};

use futures_util::StreamExt;
use reqwest::Client;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::domain::{BlobRef, CompletionMode, DurablePayload};
use crate::runtime::{
    BlobStore, BlobStoreError, RetryDispatchPolicy, RunningRestartPolicy, ToolDefinition,
    ToolError, ToolExecutionCompletion, ToolExecutionResult, ToolExecutor, ToolInvocation,
};

const MAX_TOOL_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_TOOL_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// Content-addressed immutable file blobs.  The runtime writes the resulting
/// reference into the event only after this adapter has durably created the
/// file, so a failed write can never leave a dangling BlobRef.
pub struct FileBlobStore {
    directory: PathBuf,
}

impl FileBlobStore {
    pub fn open(directory: impl Into<PathBuf>) -> std::io::Result<Self> {
        let directory = directory.into();
        fs::create_dir_all(&directory)?;
        let metadata = fs::symlink_metadata(&directory)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "blob directory is not a real directory",
            ));
        }
        Ok(Self { directory })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }
}

impl BlobStore for FileBlobStore {
    fn put(&self, bytes: &[u8], media_type: Option<&str>) -> Result<BlobRef, BlobStoreError> {
        let digest = Sha256::digest(bytes);
        let blob_id = format!("sha256:{digest:x}");
        let path = self.directory.join(&blob_id);
        let created = match create_blob_file(&path, bytes) {
            Ok(created) => created,
            Err(_) => return Err(BlobStoreError),
        };
        if !created {
            verify_existing_blob(&path, bytes, digest.as_slice())?;
        }
        Ok(BlobRef {
            blob_id,
            byte_len: bytes.len() as u64,
            sha256: format!("sha256:{digest:x}"),
            media_type: media_type.map(str::to_owned),
        })
    }
}

fn create_blob_file(path: &Path, bytes: &[u8]) -> std::io::Result<bool> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(bytes)?;
            file.sync_all()?;
            if let Some(parent) = path.parent() {
                let directory = OpenOptions::new().read(true).open(parent)?;
                directory.sync_all()?;
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error),
    }
}

fn verify_existing_blob(
    path: &Path,
    expected: &[u8],
    expected_digest: &[u8],
) -> Result<(), BlobStoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| BlobStoreError)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BlobStoreError);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 || metadata.mode() & 0o777 != 0o600 {
            return Err(BlobStoreError);
        }
    }
    if metadata.len() != expected.len() as u64 {
        return Err(BlobStoreError);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|_| BlobStoreError)?;
    let mut actual = Vec::with_capacity(expected.len());
    file.read_to_end(&mut actual).map_err(|_| BlobStoreError)?;
    if actual != expected {
        return Err(BlobStoreError);
    }
    let actual_digest = Sha256::digest(&actual);
    if actual_digest.as_slice() != expected_digest {
        return Err(BlobStoreError);
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct HttpToolSpec {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub adapter_url: String,
    pub completion_mode: CompletionMode,
    pub auto_wait_seconds: Option<u32>,
    pub running_restart: RunningRestartPolicy,
    pub retry_dispatch: RetryDispatchPolicy,
}

pub struct HttpToolExecutor {
    client: Client,
    specs: HashMap<String, HttpToolSpec>,
    blob_store: Option<Arc<dyn BlobStore>>,
}

impl HttpToolExecutor {
    pub fn new(specs: Vec<HttpToolSpec>) -> Self {
        Self {
            client: Client::new(),
            specs: specs
                .into_iter()
                .map(|spec| (spec.name.clone(), spec))
                .collect(),
            blob_store: None,
        }
    }

    pub fn new_with_blob_store(specs: Vec<HttpToolSpec>, blob_store: Arc<dyn BlobStore>) -> Self {
        let mut executor = Self::new(specs);
        executor.blob_store = Some(blob_store);
        executor
    }
}

impl ToolExecutor for HttpToolExecutor {
    fn definitions(&self, selected: &[String]) -> Result<Vec<ToolDefinition>, ToolError> {
        let mut definitions = Vec::with_capacity(selected.len());
        for name in selected {
            if name == crate::runtime::WAIT_FOR_TOOL_NAME {
                return Err(ToolError::InvalidSelection);
            }
            let Some(spec) = self.specs.get(name) else {
                return Err(ToolError::InvalidSelection);
            };
            definitions.push(ToolDefinition {
                name: spec.name.clone(),
                description: spec.description.clone(),
                input_schema: spec.input_schema.clone(),
                completion_mode: spec.completion_mode.clone(),
                auto_wait_seconds: spec.auto_wait_seconds,
                running_restart: spec.running_restart,
                retry_dispatch: spec.retry_dispatch,
            });
        }
        Ok(definitions)
    }

    fn execute<'a>(
        &'a self,
        invocation: ToolInvocation,
    ) -> Pin<Box<dyn Future<Output = Result<ToolExecutionResult, ToolError>> + Send + 'a>> {
        Box::pin(async move {
            let Some(spec) = self.specs.get(&invocation.tool_name) else {
                return Err(ToolError::InvalidSelection);
            };
            let mut payload = json!({
                "tool_call_id": invocation.tool_call_id,
                "tool_name": invocation.tool_name,
                "input": invocation.input,
            });
            if let Some(callback_url) = invocation.callback_url.as_deref() {
                payload["callback_url"] = Value::String(callback_url.to_owned());
            }
            let mut request = self.client.post(&spec.adapter_url).json(&payload);
            if let Some(bearer) = invocation.callback_bearer.as_deref() {
                request = request.bearer_auth(bearer);
            }
            let response = request.send().await.map_err(|_| ToolError::Unavailable)?;
            if !response.status().is_success() {
                return Ok(ToolExecutionResult {
                    content: "tool execution failed".to_owned(),
                    is_error: true,
                    completion: ToolExecutionCompletion::Response,
                    auto_wait_seconds: spec.auto_wait_seconds,
                    result: None,
                });
            }
            if response
                .content_length()
                .is_some_and(|length| length > MAX_TOOL_OUTPUT_BYTES as u64)
            {
                return Err(ToolError::Unavailable);
            }
            let mut body_bytes = Vec::new();
            let mut body_stream = response.bytes_stream();
            while let Some(chunk) = body_stream.next().await {
                let chunk = chunk.map_err(|_| ToolError::Unavailable)?;
                if body_bytes.len().saturating_add(chunk.len()) > MAX_TOOL_OUTPUT_BYTES {
                    return Err(ToolError::Unavailable);
                }
                body_bytes.extend_from_slice(&chunk);
            }
            let body =
                serde_json::from_slice::<Value>(&body_bytes).map_err(|_| ToolError::Unavailable)?;
            let content = body
                .get("result")
                .and_then(|result| result.get("content"))
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| body.to_string());
            let (content, result) =
                if matches!(spec.completion_mode, CompletionMode::ExternalCallback) {
                    ("async_running".to_owned(), None)
                } else if content.len() > MAX_TOOL_RESPONSE_BYTES {
                    let Some(blob_store) = self.blob_store.clone() else {
                        return Err(ToolError::Unavailable);
                    };
                    let bytes = content.as_bytes().to_vec();
                    let blob = tokio::task::spawn_blocking(move || {
                        blob_store.put(&bytes, Some("text/plain; charset=utf-8"))
                    })
                    .await
                    .map_err(|_| ToolError::Unavailable)?
                    .map_err(|_| ToolError::Unavailable)?;
                    (
                        "tool output stored in immutable blob".to_owned(),
                        Some(DurablePayload::BlobRef(blob)),
                    )
                } else {
                    (content, None)
                };
            Ok(ToolExecutionResult {
                content,
                is_error: false,
                completion: if matches!(spec.completion_mode, CompletionMode::ExternalCallback) {
                    ToolExecutionCompletion::AsyncRunning
                } else {
                    ToolExecutionCompletion::Response
                },
                auto_wait_seconds: spec.auto_wait_seconds,
                result,
            })
        })
    }
}
