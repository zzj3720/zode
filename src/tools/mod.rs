use std::{collections::HashMap, future::Future, pin::Pin};

use futures_util::StreamExt;
use reqwest::Client;
use serde_json::{json, Value};

use crate::runtime::{
    ToolDefinition, ToolError, ToolExecutionResult, ToolExecutor, ToolInvocation,
};

const MAX_TOOL_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct HttpToolSpec {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub adapter_url: String,
}

pub struct HttpToolExecutor {
    client: Client,
    specs: HashMap<String, HttpToolSpec>,
}

impl HttpToolExecutor {
    pub fn new(specs: Vec<HttpToolSpec>) -> Self {
        Self {
            client: Client::new(),
            specs: specs
                .into_iter()
                .map(|spec| (spec.name.clone(), spec))
                .collect(),
        }
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
            let response = self
                .client
                .post(&spec.adapter_url)
                .json(&json!({
                    "tool_call_id": invocation.tool_call_id,
                    "tool_name": invocation.tool_name,
                    "input": invocation.input,
                }))
                .send()
                .await
                .map_err(|_| ToolError::Unavailable)?;
            if !response.status().is_success() {
                return Ok(ToolExecutionResult {
                    content: "tool execution failed".to_owned(),
                    is_error: true,
                });
            }
            if response
                .content_length()
                .is_some_and(|length| length > MAX_TOOL_RESPONSE_BYTES as u64)
            {
                return Err(ToolError::Unavailable);
            }
            let mut body_bytes = Vec::new();
            let mut body_stream = response.bytes_stream();
            while let Some(chunk) = body_stream.next().await {
                let chunk = chunk.map_err(|_| ToolError::Unavailable)?;
                if body_bytes.len().saturating_add(chunk.len()) > MAX_TOOL_RESPONSE_BYTES {
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
            Ok(ToolExecutionResult {
                content,
                is_error: false,
            })
        })
    }
}
