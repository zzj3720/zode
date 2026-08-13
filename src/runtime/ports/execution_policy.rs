use crate::domain::ProviderExecutionSelection;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionPolicyError {
    Invalid,
}

pub trait ExecutionPolicyPort: Send + Sync {
    fn validate_descriptor(
        &self,
        descriptor: &ProviderExecutionSelection,
    ) -> Result<(), ExecutionPolicyError>;

    fn credential_schema(&self, adapter_kind: &str) -> Option<&'static str>;
}
