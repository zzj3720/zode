use serde::Deserialize;

pub const MAX_REPLICA_REQUEST_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplicaProbe {
    pub credential_schema: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicaPortError {
    Invalid,
    Unavailable,
    Disabled,
    SecretUnavailable,
    Conflict,
    NotFound,
    Backend,
}

/// One provider-attempt secret. Not Clone/Serialize so it cannot enter
/// session state, events, or a later retry.
pub struct SecretLease {
    revision: u64,
    credential_schema: String,
    secret: String,
}

impl SecretLease {
    pub fn new(revision: u64, credential_schema: String, secret: String) -> Self {
        Self {
            revision,
            credential_schema,
            secret,
        }
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn credential_schema(&self) -> &str {
        &self.credential_schema
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }
}

impl std::fmt::Debug for SecretLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretLease")
            .field("revision", &self.revision)
            .field("credential_schema", &self.credential_schema)
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplicaMetadata {
    pub authority_id: String,
    pub profile_id: String,
    pub provider: String,
    pub revision: u64,
    pub expires_at_ms: Option<i64>,
    pub status: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplicaProvisionOutcome {
    pub status: u16,
    pub metadata: ReplicaMetadata,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaInstallRequest {
    pub schema: String,
    pub authority_id: String,
    pub provider: String,
    pub kind: String,
    pub revision: u64,
    pub credential_schema: String,
    #[serde(default)]
    pub expires_at_ms: Option<i64>,
    pub secret: ReplicaSecretEnvelope,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaSecretEnvelope {
    pub encoding: String,
    pub payload: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaTombstoneRequest {
    pub schema: String,
    pub authority_id: String,
    pub provider: String,
    pub revision: u64,
}

/// Provision (install/tombstone/read/list) and resolve (probe_ready/resolve)
/// are two roles of one replica store. Secrets never enter events.
pub trait ReplicaPort: Send + Sync {
    fn probe_ready(
        &self,
        authority_id: &str,
        profile_id: &str,
        provider: &str,
        minimum_revision: u64,
    ) -> Result<ReplicaProbe, ReplicaPortError>;

    fn resolve(
        &self,
        authority_id: &str,
        profile_id: &str,
        provider: &str,
        minimum_revision: u64,
    ) -> Result<SecretLease, ReplicaPortError>;

    fn install(
        &self,
        profile_id: &str,
        authority_id: &str,
        idempotency_key: &str,
        request: ReplicaInstallRequest,
    ) -> Result<ReplicaProvisionOutcome, ReplicaPortError>;

    fn tombstone(
        &self,
        profile_id: &str,
        authority_id: &str,
        idempotency_key: &str,
        request: ReplicaTombstoneRequest,
    ) -> Result<ReplicaProvisionOutcome, ReplicaPortError>;

    fn read(
        &self,
        authority_id: &str,
        profile_id: &str,
    ) -> Result<ReplicaMetadata, ReplicaPortError>;

    fn list(&self, authority_id: &str) -> Result<Vec<ReplicaMetadata>, ReplicaPortError>;
}
