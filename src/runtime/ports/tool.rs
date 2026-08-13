use std::{future::Future, pin::Pin};

use super::super::{ToolDefinition, ToolError, ToolExecutionResult, ToolInvocation};

pub trait ToolPort: Send + Sync {
    fn definitions(&self, selected: &[String]) -> Result<Vec<ToolDefinition>, ToolError>;

    fn execute<'a>(
        &'a self,
        invocation: ToolInvocation,
    ) -> Pin<Box<dyn Future<Output = Result<ToolExecutionResult, ToolError>> + Send + 'a>>;
}

pub use ToolPort as ToolExecutor;
