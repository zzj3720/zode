use std::{
    collections::HashSet,
    fs::File,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use url::Url;

const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;
const MAX_SCHEMA_BYTES: usize = 64;
const MAX_LISTEN_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_KIND_BYTES: usize = 64;
const MAX_URL_BYTES: usize = 4 * 1024;
const MAX_TOOL_FOREGROUND_MS: u64 = 86_400_000;
const MAX_SNAPSHOT_EVENTS: u64 = 1_000_000_000;
const MAX_ROUNDS_PER_ACTIVATION: u64 = 10_000;
const MAX_MODEL_STEP_ATTEMPTS: u64 = 64;
const MAX_MODEL_RETRY_MS: u64 = 3_600_000;
const MAX_MODEL_STREAM_IDLE_TIMEOUT_MS: u64 = 86_400_000;
const MAX_AUTO_WAIT_TIMEOUT_SECONDS: u64 = 600;
const MAX_NAME_BYTES: usize = 128;
const MAX_AUTHORITY_ID_BYTES: usize = 64;
const MAX_DESCRIPTION_BYTES: usize = 8 * 1024;
const MAX_INPUT_SCHEMA_BYTES: usize = 64 * 1024;
const MAX_LIST_ITEMS: usize = 1_024;
const PROVIDER_ADAPTER_OPENAI_COMPATIBLE: &str = "openai_compatible";
const PROVIDER_ADAPTER_ANTHROPIC: &str = "anthropic";

pub(crate) const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:3000";
pub(crate) const DEFAULT_RUNTIME_STORE: &str = "zode.sqlite3";

#[derive(Debug, Error)]
pub(crate) enum ConfigError {
    #[error("cannot read configuration file")]
    Read(#[source] std::io::Error),
    #[error("configuration JSON is invalid")]
    Json(#[source] serde_json::Error),
    #[error("invalid configuration: {0}")]
    Invalid(&'static str),
}

/// Fully typed, non-secret Endpoint composition data.
///
/// The JSON representation is kept on this one type so an old alias or a
/// second provider registry cannot silently become another configuration
/// authority. Runtime/provider/auth adapters consume the validated values;
/// this module itself only parses, validates, and resolves paths.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EndpointConfig {
    schema: String,
    #[serde(default)]
    listen: Option<String>,
    #[serde(default = "default_runtime_store")]
    runtime_store: RuntimeStoreConfig,
    #[serde(default)]
    credential_replica_store: Option<FileStoreConfig>,
    #[serde(default)]
    blob_store: Option<FileStoreConfig>,
    #[serde(default)]
    controller_auth: Vec<ControllerAuthConfig>,
    #[serde(default)]
    runtime: RuntimeConfig,
    #[serde(default)]
    provider_execution: Option<ProviderExecutionConfig>,
    #[serde(default)]
    callback: Option<CallbackConfig>,
    #[serde(default)]
    tools: Vec<ToolConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeStoreConfig {
    kind: String,
    path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileStoreConfig {
    kind: String,
    directory: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControllerAuthConfig {
    authority_id: String,
    revision: u64,
    kind: String,
    secret_file: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RuntimeConfig {
    tool_foreground_ms: u64,
    snapshot_every_events: Option<u64>,
    max_rounds_per_activation: u64,
    model_step_max_attempts: u64,
    model_retry_base_ms: u64,
    model_retry_max_ms: u64,
    model_stream_idle_timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderExecutionConfig {
    adapter_kinds: Vec<String>,
    allowed_base_url_origins: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CallbackConfig {
    allowed_public_origins: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolConfig {
    name: String,
    description: String,
    input_schema: Value,
    completion_mode: CompletionMode,
    auto_wait_timeout_seconds: u64,
    recovery: RecoveryConfig,
    adapter: ToolAdapterConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CompletionMode {
    Response,
    ExternalCallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RunningRestart {
    UnknownOutcome,
    RuntimeRestarted,
    AwaitCallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RetryDispatch {
    Never,
    SameInvocationKeyDeduplicated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryConfig {
    on_running_restart: RunningRestart,
    retry_dispatch: RetryDispatch,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolAdapterConfig {
    kind: String,
    url: String,
}

impl EndpointConfig {
    pub(crate) fn load(
        config_path: Option<&Path>,
        listen_override: Option<&str>,
        database_override: Option<&Path>,
        snapshot_override: Option<u64>,
    ) -> Result<Self, ConfigError> {
        let mut config = match config_path {
            Some(path) => {
                let mut value = Self::read_value(path)?;
                apply_json_overrides(
                    &mut value,
                    listen_override,
                    database_override,
                    snapshot_override,
                )?;
                serde_json::from_value(value).map_err(ConfigError::Json)?
            }
            None => Self::development_defaults(),
        };
        if config_path.is_none() {
            config.apply_overrides(listen_override, database_override, snapshot_override)?;
        }
        let base = config_path
            .map(config_directory)
            .unwrap_or_else(|| Path::new("."));
        config.validate_and_resolve(base, config_path.is_some())?;
        Ok(config)
    }

    pub(crate) fn listen_addr(&self) -> Result<SocketAddr, ConfigError> {
        self.listen
            .as_deref()
            .unwrap_or(DEFAULT_LISTEN_ADDR)
            .parse()
            .map_err(|_| ConfigError::Invalid("listen must be a valid socket address"))
    }

    pub(crate) fn runtime_store_path(&self) -> &Path {
        &self.runtime_store.path
    }

    pub(crate) fn runtime_options(&self) -> zode::runtime::RuntimeOptions {
        zode::runtime::RuntimeOptions {
            snapshot_every: self.runtime.snapshot_every_events,
            tool_foreground: Duration::from_millis(self.runtime.tool_foreground_ms),
            max_rounds_per_activation: self.runtime.max_rounds_per_activation as u32,
            model_step_max_attempts: self.runtime.model_step_max_attempts as u32,
            model_retry_base: Duration::from_millis(self.runtime.model_retry_base_ms),
            model_retry_max: Duration::from_millis(self.runtime.model_retry_max_ms),
            model_stream_idle_timeout: Duration::from_millis(
                self.runtime.model_stream_idle_timeout_ms,
            ),
        }
    }

    pub(crate) fn controller_auth_specs(&self) -> Vec<zode::control::ControllerAuthSpec> {
        self.controller_auth
            .iter()
            .map(|auth| {
                zode::control::ControllerAuthSpec::new(
                    auth.authority_id.clone(),
                    auth.revision,
                    auth.secret_file.clone(),
                )
            })
            .collect()
    }

    pub(crate) fn credential_replica_directory(&self) -> Option<&Path> {
        self.credential_replica_store
            .as_ref()
            .map(|store| store.directory.as_path())
    }

    pub(crate) fn blob_store_directory(&self) -> Option<&Path> {
        self.blob_store
            .as_ref()
            .map(|store| store.directory.as_path())
    }

    pub(crate) fn provider_execution_policy(&self) -> (Vec<String>, Vec<String>) {
        self.provider_execution
            .as_ref()
            .map(|execution| {
                (
                    execution.adapter_kinds.clone(),
                    execution.allowed_base_url_origins.clone(),
                )
            })
            .unwrap_or_default()
    }

    pub(crate) fn tool_specs(&self) -> Vec<zode::tools::HttpToolSpec> {
        self.tools
            .iter()
            .map(|tool| zode::tools::HttpToolSpec {
                name: tool.name.clone(),
                description: tool.description.clone(),
                input_schema: tool.input_schema.clone(),
                adapter_url: tool.adapter.url.clone(),
                completion_mode: match tool.completion_mode {
                    CompletionMode::Response => zode::domain::CompletionMode::ProcessLocal,
                    CompletionMode::ExternalCallback => {
                        zode::domain::CompletionMode::ExternalCallback
                    }
                },
                auto_wait_seconds: Some(tool.auto_wait_timeout_seconds as u32),
                running_restart: match tool.recovery.on_running_restart {
                    RunningRestart::UnknownOutcome => {
                        zode::runtime::RunningRestartPolicy::UnknownOutcome
                    }
                    RunningRestart::RuntimeRestarted => {
                        zode::runtime::RunningRestartPolicy::RuntimeRestarted
                    }
                    RunningRestart::AwaitCallback => {
                        zode::runtime::RunningRestartPolicy::AwaitCallback
                    }
                },
                retry_dispatch: match tool.recovery.retry_dispatch {
                    RetryDispatch::Never => zode::runtime::RetryDispatchPolicy::Never,
                    RetryDispatch::SameInvocationKeyDeduplicated => {
                        zode::runtime::RetryDispatchPolicy::SameInvocationKeyDeduplicated
                    }
                },
            })
            .collect()
    }

    pub(crate) fn capability_tools(&self) -> Vec<zode::api::CapabilityTool> {
        self.tools
            .iter()
            .map(|tool| zode::api::CapabilityTool {
                name: tool.name.clone(),
                completion_mode: match tool.completion_mode {
                    CompletionMode::Response => "response".to_owned(),
                    CompletionMode::ExternalCallback => "external_callback".to_owned(),
                },
            })
            .collect()
    }

    fn read_value(path: &Path) -> Result<Value, ConfigError> {
        let file = File::open(path).map_err(ConfigError::Read)?;
        let mut bytes = Vec::with_capacity(MAX_CONFIG_BYTES + 1);
        file.take((MAX_CONFIG_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(ConfigError::Read)?;
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::Invalid("configuration file is too large"));
        }
        serde_json::from_slice(&bytes).map_err(ConfigError::Json)
    }

    fn development_defaults() -> Self {
        Self {
            schema: "zode.config.v1".to_owned(),
            listen: Some(DEFAULT_LISTEN_ADDR.to_owned()),
            runtime_store: RuntimeStoreConfig {
                kind: "sqlite".to_owned(),
                path: PathBuf::from(DEFAULT_RUNTIME_STORE),
            },
            credential_replica_store: None,
            blob_store: None,
            controller_auth: Vec::new(),
            runtime: RuntimeConfig::default(),
            provider_execution: None,
            callback: None,
            tools: Vec::new(),
        }
    }

    fn apply_overrides(
        &mut self,
        listen_override: Option<&str>,
        database_override: Option<&Path>,
        snapshot_override: Option<u64>,
    ) -> Result<(), ConfigError> {
        if let Some(listen_override) = listen_override {
            self.listen = Some(listen_override.to_owned());
        }
        if let Some(database_override) = database_override {
            self.runtime_store.path = resolve_cli_path(database_override)?;
        }
        if let Some(snapshot_override) = snapshot_override {
            self.runtime.snapshot_every_events = Some(snapshot_override);
        }
        Ok(())
    }

    fn validate_and_resolve(
        &mut self,
        base: &Path,
        require_controller_auth: bool,
    ) -> Result<(), ConfigError> {
        validate_bounded_string(&self.schema, MAX_SCHEMA_BYTES, "schema")?;
        if self.schema != "zode.config.v1" {
            return Err(ConfigError::Invalid("schema must be zode.config.v1"));
        }
        if let Some(listen) = self.listen.as_deref() {
            validate_bounded_string(listen, MAX_LISTEN_BYTES, "listen")?;
        }
        self.listen_addr()?;

        validate_bounded_string(&self.runtime_store.kind, MAX_KIND_BYTES, "store kind")?;
        if self.runtime_store.kind != "sqlite" {
            return Err(ConfigError::Invalid("runtime_store.kind must be sqlite"));
        }
        self.runtime_store.path =
            resolve_path(base, &self.runtime_store.path, "runtime_store.path")?;

        if let Some(store) = &mut self.credential_replica_store {
            validate_file_store(store, base, "credential_replica_store")?;
        }
        if let Some(store) = &mut self.blob_store {
            validate_file_store(store, base, "blob_store")?;
        }

        validate_controller_auth(base, &mut self.controller_auth)?;
        if require_controller_auth && self.controller_auth.is_empty() {
            return Err(ConfigError::Invalid(
                "controller_auth must contain at least one authority",
            ));
        }
        validate_runtime(&self.runtime)?;
        if let Some(execution) = &mut self.provider_execution {
            validate_provider_execution(execution)?;
        }
        if let Some(callback) = &mut self.callback {
            validate_callback(callback)?;
        }
        validate_tools(
            &mut self.tools,
            self.callback
                .as_ref()
                .is_some_and(|callback| !callback.allowed_public_origins.is_empty()),
        )?;
        validate_store_identity(
            &self.runtime_store.path,
            self.credential_replica_store
                .as_ref()
                .map(|store| store.directory.as_path()),
            self.blob_store
                .as_ref()
                .map(|store| store.directory.as_path()),
            &self.controller_auth,
        )
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            tool_foreground_ms: 3_000,
            snapshot_every_events: None,
            max_rounds_per_activation: 32,
            model_step_max_attempts: 3,
            model_retry_base_ms: 500,
            model_retry_max_ms: 5_000,
            model_stream_idle_timeout_ms: 30_000,
        }
    }
}

fn default_runtime_store() -> RuntimeStoreConfig {
    RuntimeStoreConfig {
        kind: "sqlite".to_owned(),
        path: PathBuf::from(DEFAULT_RUNTIME_STORE),
    }
}

fn config_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn apply_json_overrides(
    value: &mut Value,
    listen_override: Option<&str>,
    database_override: Option<&Path>,
    snapshot_override: Option<u64>,
) -> Result<(), ConfigError> {
    let object = value
        .as_object_mut()
        .ok_or(ConfigError::Invalid("configuration root must be an object"))?;

    if let Some(listen) = listen_override {
        object.insert("listen".to_owned(), Value::String(listen.to_owned()));
    }

    if let Some(database) = database_override {
        let database = cli_path_string(database)?;
        let runtime_store = match object.get_mut("runtime_store") {
            Some(runtime_store) => runtime_store
                .as_object_mut()
                .ok_or(ConfigError::Invalid("runtime_store must be an object"))?,
            None => {
                object.insert(
                    "runtime_store".to_owned(),
                    serde_json::json!({"kind": "sqlite", "path": database}),
                );
                return apply_snapshot_override(object, snapshot_override);
            }
        };
        runtime_store.insert("path".to_owned(), Value::String(database));
    }

    apply_snapshot_override(object, snapshot_override)
}

fn apply_snapshot_override(
    object: &mut serde_json::Map<String, Value>,
    snapshot_override: Option<u64>,
) -> Result<(), ConfigError> {
    let Some(snapshot_every) = snapshot_override else {
        return Ok(());
    };
    let runtime = match object.get_mut("runtime") {
        Some(runtime) => runtime
            .as_object_mut()
            .ok_or(ConfigError::Invalid("runtime must be an object"))?,
        None => {
            object.insert("runtime".to_owned(), Value::Object(serde_json::Map::new()));
            object
                .get_mut("runtime")
                .and_then(Value::as_object_mut)
                .ok_or(ConfigError::Invalid("runtime must be an object"))?
        }
    };
    runtime.insert(
        "snapshot_every_events".to_owned(),
        Value::Number(snapshot_every.into()),
    );
    Ok(())
}

fn cli_path_string(path: &Path) -> Result<String, ConfigError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or(ConfigError::Invalid("CLI path must be valid UTF-8"))
}

fn validate_file_store(
    store: &mut FileStoreConfig,
    base: &Path,
    field: &'static str,
) -> Result<(), ConfigError> {
    validate_bounded_string(&store.kind, MAX_KIND_BYTES, "store kind")?;
    if store.kind != "files" {
        return Err(match field {
            "blob_store" => ConfigError::Invalid("blob_store.kind must be files"),
            _ => ConfigError::Invalid("credential_replica_store.kind must be files"),
        });
    }
    store.directory = resolve_path(base, &store.directory, field)?;
    Ok(())
}

fn resolve_path(base: &Path, raw: &Path, field: &'static str) -> Result<PathBuf, ConfigError> {
    if raw.as_os_str().is_empty()
        || raw.to_string_lossy().contains('\0')
        || raw.to_string_lossy().len() > MAX_PATH_BYTES
    {
        return Err(match field {
            "runtime_store.path" => ConfigError::Invalid("runtime_store.path is invalid"),
            "--database" => ConfigError::Invalid("--database path is invalid"),
            _ => ConfigError::Invalid("store path is invalid"),
        });
    }
    let joined = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        base.join(raw)
    };
    absolute_normalized_path(&joined)
}

fn resolve_cli_path(raw: &Path) -> Result<PathBuf, ConfigError> {
    if raw.as_os_str().is_empty()
        || raw.to_string_lossy().contains('\0')
        || raw.to_string_lossy().len() > MAX_PATH_BYTES
    {
        return Err(ConfigError::Invalid("--database path is invalid"));
    }
    absolute_normalized_path(raw)
}

fn absolute_normalized_path(path: &Path) -> Result<PathBuf, ConfigError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| ConfigError::Invalid("cannot determine process working directory"))?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    Ok(normalized)
}

fn validate_controller_auth(
    base: &Path,
    values: &mut [ControllerAuthConfig],
) -> Result<(), ConfigError> {
    if values.len() > MAX_LIST_ITEMS {
        return Err(ConfigError::Invalid("controller_auth has too many entries"));
    }
    let mut authorities = HashSet::new();
    for value in &mut *values {
        validate_name(&value.authority_id)?;
        if value.authority_id.len() > MAX_AUTHORITY_ID_BYTES {
            return Err(ConfigError::Invalid(
                "controller_auth.authority_id is too long",
            ));
        }
        validate_bounded_string(&value.kind, MAX_KIND_BYTES, "controller auth kind")?;
        if value.kind != "bearer_secret_file" {
            return Err(ConfigError::Invalid(
                "controller_auth.kind must be bearer_secret_file",
            ));
        }
        if value.revision == 0 {
            return Err(ConfigError::Invalid(
                "controller_auth.revision must be positive",
            ));
        }
        if !authorities.insert(&value.authority_id) {
            return Err(ConfigError::Invalid(
                "controller_auth has duplicate authority_id",
            ));
        }
        value.secret_file = resolve_path(base, &value.secret_file, "controller_auth.secret_file")?;
    }
    Ok(())
}

fn validate_runtime(runtime: &RuntimeConfig) -> Result<(), ConfigError> {
    validate_positive(
        runtime.tool_foreground_ms,
        MAX_TOOL_FOREGROUND_MS,
        "runtime.tool_foreground_ms",
    )?;
    validate_optional_positive(
        runtime.snapshot_every_events,
        MAX_SNAPSHOT_EVENTS,
        "runtime.snapshot_every_events",
    )?;
    validate_positive(
        runtime.max_rounds_per_activation,
        MAX_ROUNDS_PER_ACTIVATION,
        "runtime.max_rounds_per_activation",
    )?;
    validate_positive(
        runtime.model_step_max_attempts,
        MAX_MODEL_STEP_ATTEMPTS,
        "runtime.model_step_max_attempts",
    )?;
    validate_at_most(runtime.model_retry_base_ms, MAX_MODEL_RETRY_MS)?;
    validate_positive(
        runtime.model_retry_max_ms,
        MAX_MODEL_RETRY_MS,
        "runtime.model_retry_max_ms",
    )?;
    validate_positive(
        runtime.model_stream_idle_timeout_ms,
        MAX_MODEL_STREAM_IDLE_TIMEOUT_MS,
        "runtime.model_stream_idle_timeout_ms",
    )?;
    if runtime.model_retry_base_ms > runtime.model_retry_max_ms {
        return Err(ConfigError::Invalid(
            "runtime.model_retry_base_ms must not exceed model_retry_max_ms",
        ));
    }
    Ok(())
}

fn validate_provider_execution(config: &mut ProviderExecutionConfig) -> Result<(), ConfigError> {
    parse_unique_names(&config.adapter_kinds)?;
    if config.adapter_kinds.iter().any(|kind| {
        kind != PROVIDER_ADAPTER_OPENAI_COMPATIBLE && kind != PROVIDER_ADAPTER_ANTHROPIC
    }) {
        return Err(ConfigError::Invalid(
            "provider_execution contains an unsupported adapter kind",
        ));
    }
    config.adapter_kinds.sort();
    config.allowed_base_url_origins = parse_origins(&config.allowed_base_url_origins)?;
    Ok(())
}

fn validate_callback(config: &mut CallbackConfig) -> Result<(), ConfigError> {
    config.allowed_public_origins = parse_origins(&config.allowed_public_origins)?;
    Ok(())
}

fn validate_tools(
    values: &mut [ToolConfig],
    callback_policy_enabled: bool,
) -> Result<(), ConfigError> {
    if values.len() > MAX_LIST_ITEMS {
        return Err(ConfigError::Invalid("tools has too many entries"));
    }
    let mut names = HashSet::new();
    for value in &mut *values {
        validate_name(&value.name)?;
        validate_bounded_string(
            &value.description,
            MAX_DESCRIPTION_BYTES,
            "tool description",
        )?;
        if value.name == "wait_for" {
            return Err(ConfigError::Invalid(
                "tools contains the reserved wait_for name",
            ));
        }
        if !names.insert(&value.name) {
            return Err(ConfigError::Invalid("tools has duplicate name"));
        }
        if !value.input_schema.is_object()
            || serde_json::to_vec(&value.input_schema)
                .map_err(|_| ConfigError::Invalid("tools.input_schema is invalid"))?
                .len()
                > MAX_INPUT_SCHEMA_BYTES
        {
            return Err(ConfigError::Invalid(
                "tools.input_schema must be a bounded object",
            ));
        }
        jsonschema::validator_for(&value.input_schema)
            .map_err(|_| ConfigError::Invalid("tools.input_schema is invalid"))?;
        validate_positive(
            value.auto_wait_timeout_seconds,
            MAX_AUTO_WAIT_TIMEOUT_SECONDS,
            "tools.auto_wait_timeout_seconds",
        )?;
        if matches!(value.completion_mode, CompletionMode::Response)
            && matches!(
                value.recovery.on_running_restart,
                RunningRestart::AwaitCallback
            )
        {
            return Err(ConfigError::Invalid(
                "response tools cannot await an external callback after restart",
            ));
        }
        if matches!(value.completion_mode, CompletionMode::ExternalCallback)
            && !matches!(
                value.recovery.on_running_restart,
                RunningRestart::AwaitCallback
            )
        {
            return Err(ConfigError::Invalid(
                "external_callback tools must await callback after restart",
            ));
        }
        if matches!(value.completion_mode, CompletionMode::ExternalCallback)
            && !callback_policy_enabled
        {
            return Err(ConfigError::Invalid(
                "external_callback tools require a callback outbound policy",
            ));
        }
        if matches!(
            value.recovery.retry_dispatch,
            RetryDispatch::SameInvocationKeyDeduplicated
        ) {
            return Err(ConfigError::Invalid(
                "HTTP tools cannot claim deduplicated retry dispatch",
            ));
        }
        if matches!(value.completion_mode, CompletionMode::Response)
            && matches!(
                value.recovery.on_running_restart,
                RunningRestart::RuntimeRestarted
            )
        {
            return Err(ConfigError::Invalid(
                "HTTP response tools cannot use runtime_restarted recovery",
            ));
        }
        validate_bounded_string(&value.adapter.kind, MAX_KIND_BYTES, "tool adapter kind")?;
        if value.adapter.kind != "http" {
            return Err(ConfigError::Invalid("tools.adapter.kind must be http"));
        }
        value.adapter.url = parse_http_url(&value.adapter.url, true)?.to_string();
    }
    values.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(())
}

fn parse_origins(values: &[String]) -> Result<Vec<String>, ConfigError> {
    if values.len() > MAX_LIST_ITEMS {
        return Err(ConfigError::Invalid("origin list is too large"));
    }
    let mut seen = HashSet::new();
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        validate_bounded_string(value, MAX_URL_BYTES, "origin")?;
        let origin = parse_http_url(value, false)?.origin().ascii_serialization();
        if !seen.insert(origin.clone()) {
            return Err(ConfigError::Invalid("origin list contains duplicates"));
        }
        normalized.push(origin);
    }
    normalized.sort();
    Ok(normalized)
}

fn parse_http_url(raw: &str, allow_path: bool) -> Result<Url, ConfigError> {
    validate_bounded_string(raw, MAX_URL_BYTES, "URL")?;
    let url = Url::parse(raw).map_err(|_| ConfigError::Invalid("URL is invalid"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port() == Some(0)
        || (!allow_path && url.path() != "" && url.path() != "/")
    {
        return Err(ConfigError::Invalid("URL or origin is invalid"));
    }
    Ok(url)
}

fn validate_name(value: &str) -> Result<(), ConfigError> {
    if value.trim().is_empty()
        || value.trim() != value
        || value.len() > MAX_NAME_BYTES
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return Err(ConfigError::Invalid("configuration name is invalid"));
    }
    Ok(())
}

fn validate_bounded_string(
    value: &str,
    maximum: usize,
    _field: &'static str,
) -> Result<(), ConfigError> {
    if value.len() > maximum || value.contains('\0') {
        return Err(ConfigError::Invalid("configuration text is invalid"));
    }
    Ok(())
}

fn parse_unique_names(values: &[String]) -> Result<(), ConfigError> {
    if values.len() > MAX_LIST_ITEMS {
        return Err(ConfigError::Invalid("name list is too large"));
    }
    let mut seen = HashSet::new();
    for value in values {
        validate_name(value)?;
        if !seen.insert(value) {
            return Err(ConfigError::Invalid("name list contains duplicates"));
        }
    }
    Ok(())
}

fn validate_store_identity(
    runtime_store: &Path,
    credential_store: Option<&Path>,
    blob_store: Option<&Path>,
    authorities: &[ControllerAuthConfig],
) -> Result<(), ConfigError> {
    let store_paths = [credential_store, blob_store]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    for (index, left) in store_paths.iter().enumerate() {
        if paths_overlap(left, runtime_store)
            || store_paths
                .iter()
                .skip(index + 1)
                .any(|right| paths_overlap(left, right))
        {
            return Err(ConfigError::Invalid(
                "configured stores must have distinct identities",
            ));
        }
    }

    let protected = [
        path_with_suffix(runtime_store, ".endpoint.lock"),
        path_with_suffix(runtime_store, ".endpoint-id"),
        path_with_suffix(runtime_store, ".controller-auth"),
    ];
    let mut secret_paths: Vec<PathBuf> = Vec::with_capacity(authorities.len());
    for authority in authorities {
        let path = &authority.secret_file;
        if paths_overlap(path, runtime_store)
            || store_paths.iter().any(|store| paths_overlap(path, store))
            || protected.iter().any(|sidecar| paths_overlap(path, sidecar))
            || secret_paths.iter().any(|other| paths_overlap(path, other))
        {
            return Err(ConfigError::Invalid(
                "controller auth secret files must have distinct identities",
            ));
        }
        secret_paths.push(path.to_path_buf());
    }
    if store_paths.iter().any(|store| {
        protected
            .iter()
            .any(|sidecar| paths_overlap(store, sidecar))
    }) {
        return Err(ConfigError::Invalid(
            "configured store overlaps a controller sidecar",
        ));
    }
    Ok(())
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn validate_optional_positive(
    value: Option<u64>,
    maximum: u64,
    _field: &'static str,
) -> Result<(), ConfigError> {
    if let Some(value) = value {
        validate_positive(value, maximum, "numeric configuration")?;
    }
    Ok(())
}

fn validate_positive(value: u64, maximum: u64, _field: &'static str) -> Result<u64, ConfigError> {
    if value == 0 || value > maximum {
        return Err(ConfigError::Invalid(
            "numeric configuration is out of bounds",
        ));
    }
    Ok(value)
}

fn validate_at_most(value: u64, maximum: u64) -> Result<(), ConfigError> {
    if value > maximum {
        return Err(ConfigError::Invalid(
            "numeric configuration is out of bounds",
        ));
    }
    Ok(())
}
