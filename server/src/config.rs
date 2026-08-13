use std::{
    collections::HashSet,
    env,
    fs::{self, File},
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use thiserror::Error;
use url::{Host, Url};

const CONFIG_SCHEMA: &str = "zode.server-config.v1";
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_ID_BYTES: usize = 256;
const MAX_URL_BYTES: usize = 2 * 1024;
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_AUDIENCES: usize = 16;
const MAX_PROVIDER_AUTH_ADAPTERS: usize = 64;
const MAX_OAUTH_SCOPES: usize = 64;

#[derive(Debug, Error)]
pub(crate) enum ConfigError {
    #[error("cannot read server configuration")]
    Read(#[source] std::io::Error),
    #[error("server configuration JSON is invalid")]
    Json(#[source] serde_json::Error),
    #[error("invalid server configuration: {0}")]
    Invalid(&'static str),
    #[error("server configuration is missing required origins")]
    MissingOrigin,
    #[error("server configuration contains an invalid origin")]
    InvalidOrigin,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerConfig {
    schema: String,
    listen: String,
    management_origin: Option<String>,
    callback_origin: Option<String>,
    server_authority_id: String,
    deployment: Deployment,
    #[serde(default)]
    local_endpoint: Option<LocalEndpointConfig>,
    ui_mode: UiMode,
    ui_assets_directory: Option<PathBuf>,
    control_database: PathBuf,
    secret_directory: PathBuf,
    access: AccessConfig,
    #[serde(default)]
    provider_auth_adapters: Vec<ProviderAuthAdapterConfig>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Deployment {
    ServerOnly,
    AllInOne,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalEndpointConfig {
    executable: PathBuf,
    config: PathBuf,
    listen: String,
}

#[derive(Deserialize)]
struct EndpointPreflightConfig {
    schema: String,
    #[serde(default = "default_endpoint_runtime_store")]
    runtime_store: EndpointStorePath,
    credential_replica_store: Option<EndpointStoreDirectory>,
    blob_store: Option<EndpointStoreDirectory>,
}

#[derive(Deserialize)]
struct EndpointStorePath {
    kind: String,
    path: PathBuf,
}

#[derive(Deserialize)]
struct EndpointStoreDirectory {
    kind: String,
    directory: PathBuf,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UiMode {
    Assets,
    ApiOnly,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccessConfig {
    issuer: String,
    audiences: Vec<String>,
    jwks_url: String,
    subject_key_file: PathBuf,
    subject_key_version: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderAuthAdapterConfig {
    provider: String,
    kind: String,
    authorization_endpoint: String,
    token_endpoint: String,
    client_id: String,
    client_secret_file: Option<PathBuf>,
    #[serde(default)]
    scopes: Vec<String>,
    refresh_recovery: RefreshRecovery,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RefreshRecovery {
    SameOperationIdIdempotent,
    ExactResultReconcile,
    None,
}

impl ServerConfig {
    pub(crate) fn load(path: &Path) -> Result<Self, ConfigError> {
        let file = File::open(path).map_err(ConfigError::Read)?;
        let mut bytes = Vec::with_capacity(MAX_CONFIG_BYTES + 1);
        file.take((MAX_CONFIG_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(ConfigError::Read)?;
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::Invalid("configuration file is too large"));
        }

        let mut config: Self = serde_json::from_slice(&bytes).map_err(ConfigError::Json)?;
        config.validate_and_resolve(config_directory(path)?)?;
        Ok(config)
    }

    pub(crate) fn listen_addr(&self) -> Result<SocketAddr, ConfigError> {
        self.listen
            .parse()
            .map_err(|_| ConfigError::Invalid("listen must be a socket address"))
    }

    pub(crate) fn server_authority_id(&self) -> &str {
        &self.server_authority_id
    }

    pub(crate) fn deployment(&self) -> Deployment {
        self.deployment
    }

    pub(crate) fn management_origin(&self) -> &str {
        self.management_origin
            .as_deref()
            .expect("validated config has management origin")
    }

    pub(crate) fn callback_origin(&self) -> &str {
        self.callback_origin
            .as_deref()
            .expect("validated config has callback origin")
    }

    pub(crate) fn management_authority(&self) -> String {
        canonical_http_origin(self.management_origin())
            .expect("validated config has canonical management origin")
            .authority
    }

    pub(crate) fn management_default_port(&self) -> u16 {
        canonical_http_origin(self.management_origin())
            .expect("validated config has canonical management origin")
            .default_port
    }

    pub(crate) fn callback_authority(&self) -> String {
        canonical_http_origin(self.callback_origin())
            .expect("validated config has canonical callback origin")
            .authority
    }

    pub(crate) fn callback_default_port(&self) -> u16 {
        canonical_http_origin(self.callback_origin())
            .expect("validated config has canonical callback origin")
            .default_port
    }

    pub(crate) fn local_endpoint(&self) -> Option<&LocalEndpointConfig> {
        self.local_endpoint.as_ref()
    }

    pub(crate) fn ui_mode(&self) -> UiMode {
        self.ui_mode
    }

    pub(crate) fn ui_assets_directory(&self) -> Option<&Path> {
        self.ui_assets_directory.as_deref()
    }

    pub(crate) fn control_database(&self) -> &Path {
        &self.control_database
    }

    pub(crate) fn secret_directory(&self) -> &Path {
        &self.secret_directory
    }

    pub(crate) fn access(&self) -> &AccessConfig {
        &self.access
    }

    pub(crate) fn provider_auth_adapters(&self) -> &[ProviderAuthAdapterConfig] {
        &self.provider_auth_adapters
    }

    fn validate_and_resolve(&mut self, base: PathBuf) -> Result<(), ConfigError> {
        if self.schema != CONFIG_SCHEMA {
            return Err(ConfigError::Invalid("schema must be zode.server-config.v1"));
        }
        let management = canonical_http_origin(
            self.management_origin
                .as_deref()
                .ok_or(ConfigError::MissingOrigin)?,
        )?;
        let callback = canonical_http_origin(
            self.callback_origin
                .as_deref()
                .ok_or(ConfigError::MissingOrigin)?,
        )?;
        if management.authority == callback.authority {
            return Err(ConfigError::InvalidOrigin);
        }
        self.management_origin = Some(management.serialized);
        self.callback_origin = Some(callback.serialized);
        self.listen_addr()?;
        validate_text(
            &self.server_authority_id,
            MAX_ID_BYTES,
            "server_authority_id is invalid",
        )?;
        match self.deployment {
            Deployment::ServerOnly if self.local_endpoint.is_some() => {
                return Err(ConfigError::Invalid(
                    "server_only deployment forbids local_endpoint",
                ));
            }
            Deployment::AllInOne if self.local_endpoint.is_none() => {
                return Err(ConfigError::Invalid(
                    "all_in_one deployment requires local_endpoint",
                ));
            }
            Deployment::ServerOnly | Deployment::AllInOne => {}
        }

        match self.ui_mode {
            UiMode::Assets => {
                self.ui_assets_directory = Some(resolve_confined_path(
                    &base,
                    self.ui_assets_directory
                        .as_deref()
                        .ok_or(ConfigError::Invalid(
                            "assets mode requires ui_assets_directory",
                        ))?,
                    "ui_assets_directory must be a directory path",
                )?);
            }
            UiMode::ApiOnly => {
                if self.ui_assets_directory.is_some() {
                    return Err(ConfigError::Invalid(
                        "api_only mode forbids ui_assets_directory",
                    ));
                }
            }
        }

        self.control_database = resolve_path(
            &base,
            &self.control_database,
            "control_database must be a file path",
        )?;
        self.secret_directory = resolve_path(
            &base,
            &self.secret_directory,
            "secret_directory must be a directory path",
        )?;
        self.access.subject_key_file = resolve_path(
            &base,
            &self.access.subject_key_file,
            "access.subject_key_file must be a file path",
        )?;
        if self.control_database == self.secret_directory
            || self.control_database == self.access.subject_key_file
            || self.secret_directory == self.access.subject_key_file
        {
            return Err(ConfigError::Invalid(
                "control and secret paths must be distinct",
            ));
        }
        let public_listen = self.listen_addr()?;
        if let Some(local) = &mut self.local_endpoint {
            local.validate_and_resolve(
                &base,
                &self.server_authority_id,
                public_listen,
                &self.control_database,
                &self.secret_directory,
            )?;
        }

        self.access.validate()?;
        if self.provider_auth_adapters.len() > MAX_PROVIDER_AUTH_ADAPTERS {
            return Err(ConfigError::Invalid(
                "provider_auth_adapters contains too many entries",
            ));
        }
        let mut providers = HashSet::with_capacity(self.provider_auth_adapters.len());
        for adapter in &mut self.provider_auth_adapters {
            adapter.validate_and_resolve(&base)?;
            if !providers.insert(adapter.provider.as_str()) {
                return Err(ConfigError::Invalid(
                    "provider_auth_adapters contains a duplicate provider",
                ));
            }
        }
        Ok(())
    }
}

impl ProviderAuthAdapterConfig {
    pub(crate) fn provider(&self) -> &str {
        &self.provider
    }

    pub(crate) fn authorization_endpoint(&self) -> &str {
        &self.authorization_endpoint
    }

    pub(crate) fn token_endpoint(&self) -> &str {
        &self.token_endpoint
    }

    pub(crate) fn client_id(&self) -> &str {
        &self.client_id
    }

    pub(crate) fn client_secret_file(&self) -> Option<&Path> {
        self.client_secret_file.as_deref()
    }

    pub(crate) fn scopes(&self) -> &[String] {
        &self.scopes
    }

    pub(crate) fn refresh_recovery(&self) -> RefreshRecovery {
        self.refresh_recovery
    }

    fn validate_and_resolve(&mut self, base: &Path) -> Result<(), ConfigError> {
        if self.kind != "oauth2_authorization_code_pkce"
            || !valid_identifier(&self.provider, MAX_ID_BYTES)
        {
            return Err(ConfigError::Invalid(
                "provider_auth_adapters contains an invalid adapter",
            ));
        }
        if self.refresh_recovery == RefreshRecovery::ExactResultReconcile {
            return Err(ConfigError::Invalid(
                "generic OAuth adapter refresh recovery is unsupported",
            ));
        }
        self.authorization_endpoint = validate_oauth_endpoint(&self.authorization_endpoint)?;
        self.token_endpoint = validate_oauth_endpoint(&self.token_endpoint)?;
        validate_text(
            &self.client_id,
            MAX_ID_BYTES,
            "provider auth client_id is invalid",
        )?;
        if self.scopes.len() > MAX_OAUTH_SCOPES {
            return Err(ConfigError::Invalid(
                "provider auth scopes contains too many entries",
            ));
        }
        let mut previous = None;
        for scope in &self.scopes {
            validate_text(scope, MAX_ID_BYTES, "provider auth scope is invalid")?;
            if previous.is_some_and(|value: &str| value >= scope.as_str()) {
                return Err(ConfigError::Invalid(
                    "provider auth scopes must be sorted and unique",
                ));
            }
            previous = Some(scope.as_str());
        }
        if let Some(configured) = &self.client_secret_file {
            let resolved =
                resolve_path(base, configured, "provider auth client secret is invalid")?;
            require_private_regular_file(&resolved, "provider auth client secret is invalid")?;
            self.client_secret_file = Some(resolved);
        }
        Ok(())
    }
}

impl RefreshRecovery {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::SameOperationIdIdempotent => "same_operation_id_idempotent",
            Self::ExactResultReconcile => "exact_result_reconcile",
            Self::None => "none",
        }
    }
}

struct CanonicalHttpOrigin {
    serialized: String,
    authority: String,
    default_port: u16,
}

fn canonical_http_origin(value: &str) -> Result<CanonicalHttpOrigin, ConfigError> {
    if value.is_empty()
        || value.len() > MAX_URL_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ConfigError::InvalidOrigin);
    }
    let url = Url::parse(value).map_err(|_| ConfigError::InvalidOrigin)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.host().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ConfigError::InvalidOrigin);
    }
    match url.scheme() {
        "https" => {}
        "http" if is_loopback(&url) => {}
        _ => return Err(ConfigError::InvalidOrigin),
    }
    let host = match url.host().ok_or(ConfigError::InvalidOrigin)? {
        Host::Domain(domain) => domain.to_owned(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => format!("[{address}]"),
    };
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    Ok(CanonicalHttpOrigin {
        serialized: url.origin().ascii_serialization(),
        authority,
        default_port: url
            .port_or_known_default()
            .expect("validated HTTP origin has a known default port"),
    })
}

impl Deployment {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ServerOnly => "server_only",
            Self::AllInOne => "all_in_one",
        }
    }
}

impl LocalEndpointConfig {
    pub(crate) fn executable(&self) -> &Path {
        &self.executable
    }

    pub(crate) fn config(&self) -> &Path {
        &self.config
    }

    pub(crate) fn listen_addr(&self) -> SocketAddr {
        self.listen
            .parse()
            .expect("validated local Endpoint listen address")
    }

    pub(crate) fn origin(&self) -> String {
        format!("http://{}", self.listen_addr())
    }

    fn validate_and_resolve(
        &mut self,
        server_base: &Path,
        _server_authority_id: &str,
        public_listen: SocketAddr,
        control_database: &Path,
        secret_directory: &Path,
    ) -> Result<(), ConfigError> {
        self.executable = resolve_path(
            server_base,
            &self.executable,
            "local_endpoint.executable is invalid",
        )?;
        self.config = resolve_path(
            server_base,
            &self.config,
            "local_endpoint.config is invalid",
        )?;
        require_regular_file(&self.executable, "local_endpoint.executable is unavailable")?;
        require_regular_file(&self.config, "local_endpoint.config is unavailable")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fs::metadata(&self.executable)
                .map_err(ConfigError::Read)?
                .permissions()
                .mode()
                & 0o111
                == 0
            {
                return Err(ConfigError::Invalid(
                    "local_endpoint.executable is not executable",
                ));
            }
        }

        validate_text(&self.listen, 256, "local_endpoint.listen is invalid")?;
        let listen = self
            .listen
            .parse::<SocketAddr>()
            .map_err(|_| ConfigError::Invalid("local_endpoint.listen is invalid"))?;
        if !listen.ip().is_loopback() || listen.port() == 0 || listen == public_listen {
            return Err(ConfigError::Invalid(
                "local_endpoint.listen must be a distinct non-zero loopback address",
            ));
        }

        let endpoint_base = self
            .config
            .parent()
            .ok_or(ConfigError::Invalid("local_endpoint.config is invalid"))?;
        let endpoint = read_endpoint_preflight(&self.config)?;
        if endpoint.schema != "zode.config.v1"
            || endpoint.runtime_store.kind != "sqlite"
            || endpoint
                .credential_replica_store
                .as_ref()
                .is_some_and(|store| store.kind != "files")
            || endpoint
                .blob_store
                .as_ref()
                .is_some_and(|store| store.kind != "files")
        {
            return Err(ConfigError::Invalid(
                "local_endpoint.config has an incompatible store schema",
            ));
        }
        let runtime_store = resolve_path(
            endpoint_base,
            &endpoint.runtime_store.path,
            "local Endpoint runtime store path is invalid",
        )?;
        let credential_store = endpoint
            .credential_replica_store
            .as_ref()
            .map(|store| {
                resolve_path(
                    endpoint_base,
                    &store.directory,
                    "local Endpoint credential store path is invalid",
                )
            })
            .transpose()?;
        let blob_store = endpoint
            .blob_store
            .as_ref()
            .map(|store| {
                resolve_path(
                    endpoint_base,
                    &store.directory,
                    "local Endpoint blob store path is invalid",
                )
            })
            .transpose()?;
        let endpoint_paths = [
            Some(runtime_store.as_path()),
            credential_store.as_deref(),
            blob_store.as_deref(),
        ];
        if endpoint_paths.into_iter().flatten().any(|path| {
            paths_overlap(path, control_database) || paths_overlap(path, secret_directory)
        }) {
            return Err(ConfigError::Invalid(
                "Server and local Endpoint stores must be separate",
            ));
        }
        Ok(())
    }
}

impl AccessConfig {
    pub(crate) fn issuer(&self) -> &str {
        &self.issuer
    }

    pub(crate) fn audiences(&self) -> &[String] {
        &self.audiences
    }

    pub(crate) fn jwks_url(&self) -> &str {
        &self.jwks_url
    }

    pub(crate) fn subject_key_file(&self) -> &Path {
        &self.subject_key_file
    }

    pub(crate) fn subject_key_version(&self) -> u64 {
        self.subject_key_version
    }

    fn validate(&self) -> Result<(), ConfigError> {
        validate_text(&self.issuer, MAX_URL_BYTES, "access.issuer is invalid")?;
        let issuer = validate_access_url(&self.issuer)?;
        if issuer.path() != "/" || issuer.query().is_some() || issuer.fragment().is_some() {
            return Err(ConfigError::Invalid(
                "access.issuer must contain only an origin",
            ));
        }

        validate_text(&self.jwks_url, MAX_URL_BYTES, "access.jwks_url is invalid")?;
        let jwks = validate_access_url(&self.jwks_url)?;
        if jwks.query().is_some() || jwks.fragment().is_some() {
            return Err(ConfigError::Invalid(
                "access.jwks_url must not contain a query or fragment",
            ));
        }

        if self.audiences.is_empty() || self.audiences.len() > MAX_AUDIENCES {
            return Err(ConfigError::Invalid(
                "access.audiences must contain between 1 and 16 values",
            ));
        }
        let mut unique = HashSet::with_capacity(self.audiences.len());
        for audience in &self.audiences {
            validate_text(audience, MAX_ID_BYTES, "access audience is invalid")?;
            if !unique.insert(audience.as_str()) {
                return Err(ConfigError::Invalid(
                    "access.audiences must not contain duplicates",
                ));
            }
        }
        if self.subject_key_version == 0 {
            return Err(ConfigError::Invalid(
                "access.subject_key_version must be positive",
            ));
        }
        Ok(())
    }
}

fn validate_access_url(value: &str) -> Result<Url, ConfigError> {
    let url = Url::parse(value).map_err(|_| ConfigError::Invalid("access URL is invalid"))?;
    if !url.username().is_empty() || url.password().is_some() || url.host().is_none() {
        return Err(ConfigError::Invalid(
            "access URL must not contain credentials and must have a host",
        ));
    }
    match url.scheme() {
        "https" => {}
        "http" if is_loopback(&url) => {}
        _ => {
            return Err(ConfigError::Invalid(
                "access URL must use HTTPS or loopback HTTP",
            ));
        }
    }
    Ok(url)
}

fn validate_oauth_endpoint(value: &str) -> Result<String, ConfigError> {
    validate_text(value, MAX_URL_BYTES, "provider auth endpoint is invalid")?;
    let url =
        Url::parse(value).map_err(|_| ConfigError::Invalid("provider auth endpoint is invalid"))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.host().is_none()
        || url.path() == "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ConfigError::Invalid("provider auth endpoint is invalid"));
    }
    match url.scheme() {
        "https" => {}
        "http" if is_loopback(&url) => {}
        _ => return Err(ConfigError::Invalid("provider auth endpoint is invalid")),
    }
    Ok(url.to_string())
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

fn validate_text(value: &str, max_bytes: usize, error: &'static str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(ConfigError::Invalid(error))
    } else {
        Ok(())
    }
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn config_directory(config_path: &Path) -> Result<PathBuf, ConfigError> {
    let current = env::current_dir().map_err(ConfigError::Read)?;
    let absolute = if config_path.is_absolute() {
        config_path.to_path_buf()
    } else {
        current.join(config_path)
    };
    Ok(absolute.parent().map(Path::to_path_buf).unwrap_or(current))
}

fn resolve_path(
    base: &Path,
    configured: &Path,
    error: &'static str,
) -> Result<PathBuf, ConfigError> {
    if configured.as_os_str().is_empty()
        || configured.file_name().is_none()
        || configured.to_string_lossy().len() > MAX_PATH_BYTES
        || configured.to_string_lossy().contains('\0')
    {
        return Err(ConfigError::Invalid(error));
    }
    let path = if configured.is_absolute() {
        configured.to_path_buf()
    } else {
        base.join(configured)
    };
    Ok(normalize_path(&path))
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

fn resolve_confined_path(
    base: &Path,
    configured: &Path,
    error: &'static str,
) -> Result<PathBuf, ConfigError> {
    let resolved = resolve_path(base, configured, error)?;
    let base = normalize_path(base);
    if resolved == base || !resolved.starts_with(&base) {
        return Err(ConfigError::Invalid(error));
    }
    let base_real = fs::canonicalize(&base).map_err(ConfigError::Read)?;
    let resolved_real = fs::canonicalize(&resolved).map_err(ConfigError::Read)?;
    if resolved_real == base_real || !resolved_real.starts_with(&base_real) {
        return Err(ConfigError::Invalid(error));
    }
    let relative = resolved
        .strip_prefix(&base)
        .map_err(|_| ConfigError::Invalid(error))?;
    let mut cursor = base;
    for component in relative.components() {
        cursor.push(component.as_os_str());
        if fs::symlink_metadata(&cursor)
            .map_err(ConfigError::Read)?
            .file_type()
            .is_symlink()
        {
            return Err(ConfigError::Invalid(error));
        }
    }
    Ok(resolved)
}

fn require_regular_file(path: &Path, error: &'static str) -> Result<(), ConfigError> {
    let metadata = fs::symlink_metadata(path).map_err(ConfigError::Read)?;
    if !metadata.file_type().is_file() {
        return Err(ConfigError::Invalid(error));
    }
    Ok(())
}

fn require_private_regular_file(path: &Path, error: &'static str) -> Result<(), ConfigError> {
    require_regular_file(path, error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = fs::symlink_metadata(path).map_err(ConfigError::Read)?;
        if metadata.nlink() != 1 || metadata.permissions().mode() & 0o077 != 0 {
            return Err(ConfigError::Invalid(error));
        }
    }
    Ok(())
}

fn read_endpoint_preflight(path: &Path) -> Result<EndpointPreflightConfig, ConfigError> {
    let file = File::open(path).map_err(ConfigError::Read)?;
    let mut bytes = Vec::with_capacity(MAX_CONFIG_BYTES + 1);
    file.take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(ConfigError::Read)?;
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::Invalid(
            "local Endpoint configuration file is too large",
        ));
    }
    serde_json::from_slice(&bytes).map_err(ConfigError::Json)
}

fn default_endpoint_runtime_store() -> EndpointStorePath {
    EndpointStorePath {
        kind: "sqlite".to_owned(),
        path: PathBuf::from("zode.sqlite3"),
    }
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}
