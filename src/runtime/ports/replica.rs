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
    Backend,
}

pub trait ReplicaPort: Send + Sync {
    fn probe(
        &self,
        authority_id: &str,
        profile_id: &str,
        provider: &str,
        minimum_revision: u64,
    ) -> Result<ReplicaProbe, ReplicaPortError>;
}
