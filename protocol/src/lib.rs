//! Versioned Server--Endpoint wire contracts.
//!
//! This crate deliberately contains no runtime, storage, provider, access, or
//! secret-bearing types. It is the small shared boundary used by the two
//! independently deployable processes.

use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

pub const ENDPOINT_PROTOCOL_V1: &str = "zode.endpoint.v1";
pub const IDENTITY_SCHEMA_V1: &str = "zode.identity.v1";
pub const HEALTH_SCHEMA_V1: &str = "zode.endpoint-health.v1";
pub const CAPABILITIES_SCHEMA_V1: &str = "zode.endpoint-capabilities.v1";
pub const ERROR_SCHEMA_V1: &str = "zode.error.v1";

pub const MAX_ENDPOINT_ID_BYTES: usize = 256;
pub const MAX_AUTHORITY_ID_BYTES: usize = 256;
pub const MAX_PROTOCOL_VERSION_BYTES: usize = 128;
pub const MAX_SCHEMA_BYTES: usize = 128;
pub const MAX_CAPABILITY_NAME_BYTES: usize = 128;
pub const MAX_CAPABILITY_ITEMS: usize = 1_024;
pub const MAX_CAPABILITY_TOOLS: usize = 1_024;
pub const MAX_ERROR_CODE_BYTES: usize = 64;
pub const MAX_ERROR_MESSAGE_BYTES: usize = 256;
pub const MAX_HEALTH_BODY_BYTES: usize = 4 * 1024;
pub const MAX_CAPABILITIES_BODY_BYTES: usize = 1024 * 1024;

pub const MAX_SESSION_REQUEST_BYTES: u64 = 262_144;
pub const MAX_AUTH_REPLICA_REQUEST_BYTES: u64 = 131_072;
pub const MAX_INLINE_TOOL_OUTPUT_BYTES: u64 = 65_536;
pub const WAIT_FOR_MIN_SECONDS: u64 = 1;
pub const WAIT_FOR_DEFAULT_SECONDS: u64 = 60;
pub const WAIT_FOR_MAX_SECONDS: u64 = 600;

pub const PROVIDER_HTTP_CAPABILITY: &str = "provider_http";
pub const TOOL_HTTP_CAPABILITY: &str = "tool_http";
pub const EXTERNAL_CALLBACK_CAPABILITY: &str = "external_callback";
pub const WAIT_FOR_TOOL: &str = "wait_for";
pub const AUTH_REPLICA_CREDENTIAL_SCHEMA_V1: &str = "openai-compatible.api-key.v1";

/// The authenticated Endpoint identity returned by `/v1/identity`.
///
/// Deserialization intentionally permits unknown fields. A newer Endpoint may
/// add non-breaking identity metadata while an older Server still consumes the
/// v1 fields it understands.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EndpointIdentity {
    pub schema: String,
    pub protocol_version: String,
    pub endpoint_id: String,
    pub authority_id: String,
    pub revision: u64,
}

impl EndpointIdentity {
    pub fn v1(endpoint_id: impl Into<String>, authority_id: impl Into<String>, revision: u64) -> Self {
        Self {
            schema: IDENTITY_SCHEMA_V1.to_owned(),
            protocol_version: ENDPOINT_PROTOCOL_V1.to_owned(),
            endpoint_id: endpoint_id.into(),
            authority_id: authority_id.into(),
            revision,
        }
    }

    pub fn validate(&self) -> Result<(), CompatibilityError> {
        if self.schema != IDENTITY_SCHEMA_V1 {
            return Err(CompatibilityError::UnsupportedSchema {
                field: "identity.schema",
                value: self.schema.clone(),
            });
        }
        validate_protocol_version(&self.protocol_version)?;
        validate_text(&self.endpoint_id, MAX_ENDPOINT_ID_BYTES, "identity.endpoint_id")?;
        validate_text(&self.authority_id, MAX_AUTHORITY_ID_BYTES, "identity.authority_id")?;
        if self.revision == 0 {
            return Err(CompatibilityError::Invalid("identity.revision must be positive"));
        }
        Ok(())
    }
}

/// The bounded readiness projection returned by `/v1/health`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EndpointHealth {
    pub schema: String,
    pub protocol_version: String,
    pub endpoint_id: String,
    pub status: String,
}

impl EndpointHealth {
    pub fn ready(endpoint_id: impl Into<String>) -> Self {
        Self {
            schema: HEALTH_SCHEMA_V1.to_owned(),
            protocol_version: ENDPOINT_PROTOCOL_V1.to_owned(),
            endpoint_id: endpoint_id.into(),
            status: "ready".to_owned(),
        }
    }

    pub fn validate(&self) -> Result<(), CompatibilityError> {
        if self.schema != HEALTH_SCHEMA_V1 {
            return Err(CompatibilityError::UnsupportedSchema {
                field: "health.schema",
                value: self.schema.clone(),
            });
        }
        validate_protocol_version(&self.protocol_version)?;
        validate_text(&self.endpoint_id, MAX_ENDPOINT_ID_BYTES, "health.endpoint_id")?;
        if self.status != "ready" {
            return Err(CompatibilityError::Invalid("health.status is not ready"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CapabilityTool {
    pub name: String,
    pub completion_mode: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CapabilityLimits {
    pub max_session_request_bytes: u64,
    pub max_auth_replica_request_bytes: u64,
    pub max_inline_tool_output_bytes: u64,
    pub wait_for_min_seconds: u64,
    pub wait_for_default_seconds: u64,
    pub wait_for_max_seconds: u64,
}

impl Default for CapabilityLimits {
    fn default() -> Self {
        Self {
            max_session_request_bytes: MAX_SESSION_REQUEST_BYTES,
            max_auth_replica_request_bytes: MAX_AUTH_REPLICA_REQUEST_BYTES,
            max_inline_tool_output_bytes: MAX_INLINE_TOOL_OUTPUT_BYTES,
            wait_for_min_seconds: WAIT_FOR_MIN_SECONDS,
            wait_for_default_seconds: WAIT_FOR_DEFAULT_SECONDS,
            wait_for_max_seconds: WAIT_FOR_MAX_SECONDS,
        }
    }
}

impl CapabilityLimits {
    fn validate(&self) -> Result<(), CompatibilityError> {
        if self.max_session_request_bytes < MAX_SESSION_REQUEST_BYTES
            || self.max_auth_replica_request_bytes < MAX_AUTH_REPLICA_REQUEST_BYTES
            || self.max_inline_tool_output_bytes < MAX_INLINE_TOOL_OUTPUT_BYTES
            || self.wait_for_min_seconds != WAIT_FOR_MIN_SECONDS
            || self.wait_for_default_seconds != WAIT_FOR_DEFAULT_SECONDS
            || self.wait_for_max_seconds != WAIT_FOR_MAX_SECONDS
        {
            return Err(CompatibilityError::IncompatibleLimits);
        }
        Ok(())
    }
}

/// Non-secret Endpoint capabilities used during Server admission and probe.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EndpointCapabilities {
    pub schema: String,
    pub protocol_version: String,
    pub endpoint_id: String,
    pub provider_adapter_kinds: Vec<String>,
    pub auth_replica_credential_schemas: Vec<String>,
    pub outbound_capabilities: Vec<String>,
    pub built_in_tools: Vec<String>,
    pub tools: Vec<CapabilityTool>,
    pub limits: CapabilityLimits,
}

impl EndpointCapabilities {
    #[allow(clippy::too_many_arguments)]
    pub fn v1(
        endpoint_id: impl Into<String>,
        provider_adapter_kinds: Vec<String>,
        auth_replica_credential_schemas: Vec<String>,
        outbound_capabilities: Vec<String>,
        built_in_tools: Vec<String>,
        tools: Vec<CapabilityTool>,
    ) -> Self {
        let mut value = Self {
            schema: CAPABILITIES_SCHEMA_V1.to_owned(),
            protocol_version: ENDPOINT_PROTOCOL_V1.to_owned(),
            endpoint_id: endpoint_id.into(),
            provider_adapter_kinds,
            auth_replica_credential_schemas,
            outbound_capabilities,
            built_in_tools,
            tools,
            limits: CapabilityLimits::default(),
        };
        value.sort_public_arrays();
        value
    }

    pub fn sort_public_arrays(&mut self) {
        self.provider_adapter_kinds.sort();
        self.auth_replica_credential_schemas.sort();
        self.outbound_capabilities.sort();
        self.built_in_tools.sort();
        self.tools.sort_by(|left, right| left.name.cmp(&right.name));
    }

    pub fn validate(&self) -> Result<(), CompatibilityError> {
        if self.schema != CAPABILITIES_SCHEMA_V1 {
            return Err(CompatibilityError::UnsupportedSchema {
                field: "capabilities.schema",
                value: self.schema.clone(),
            });
        }
        validate_protocol_version(&self.protocol_version)?;
        validate_text(
            &self.endpoint_id,
            MAX_ENDPOINT_ID_BYTES,
            "capabilities.endpoint_id",
        )?;
        validate_sorted_names(
            &self.provider_adapter_kinds,
            "capabilities.provider_adapter_kinds",
        )?;
        validate_sorted_names(
            &self.auth_replica_credential_schemas,
            "capabilities.auth_replica_credential_schemas",
        )?;
        validate_sorted_names(
            &self.outbound_capabilities,
            "capabilities.outbound_capabilities",
        )?;
        validate_sorted_names(&self.built_in_tools, "capabilities.built_in_tools")?;
        if self.tools.len() > MAX_CAPABILITY_TOOLS {
            return Err(CompatibilityError::BoundsExceeded(
                "capabilities.tools has too many entries",
            ));
        }
        let mut previous = None;
        for tool in &self.tools {
            validate_text(&tool.name, MAX_CAPABILITY_NAME_BYTES, "capabilities.tool.name")?;
            if previous.is_some_and(|name| name >= tool.name.as_str()) {
                return Err(CompatibilityError::Invalid(
                    "capabilities.tools must be sorted and unique",
                ));
            }
            if tool.completion_mode != "response"
                && tool.completion_mode != "external_callback"
            {
                return Err(CompatibilityError::Invalid(
                    "capabilities.tool.completion_mode is unsupported",
                ));
            }
            previous = Some(tool.name.as_str());
        }
        self.limits.validate()
    }

}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiatedEndpointProtocol {
    pub protocol_version: &'static str,
}

/// Compatibility is deliberately strict at the protocol/schema boundary.
/// Additive fields are ignored by serde, but a different major protocol or
/// DTO schema is never silently downgraded.
pub fn negotiate_endpoint_protocol(
    identity: &EndpointIdentity,
    capabilities: &EndpointCapabilities,
) -> Result<NegotiatedEndpointProtocol, CompatibilityError> {
    identity.validate()?;
    capabilities.validate()?;
    if capabilities.protocol_version != identity.protocol_version {
        return Err(CompatibilityError::ProtocolMismatch);
    }
    if capabilities.endpoint_id != identity.endpoint_id {
        return Err(CompatibilityError::EndpointIdMismatch);
    }
    Ok(NegotiatedEndpointProtocol {
        protocol_version: ENDPOINT_PROTOCOL_V1,
    })
}

fn validate_protocol_version(value: &str) -> Result<(), CompatibilityError> {
    if value != ENDPOINT_PROTOCOL_V1 {
        return Err(CompatibilityError::UnsupportedProtocol {
            value: value.to_owned(),
        });
    }
    validate_text(value, MAX_PROTOCOL_VERSION_BYTES, "protocol_version")
}

fn validate_sorted_names(values: &[String], field: &'static str) -> Result<(), CompatibilityError> {
    if values.len() > MAX_CAPABILITY_ITEMS {
        return Err(CompatibilityError::BoundsExceeded(field));
    }
    let mut previous = None;
    for value in values {
        validate_text(value, MAX_CAPABILITY_NAME_BYTES, field)?;
        if previous.is_some_and(|name| name >= value.as_str()) {
            return Err(CompatibilityError::Invalid(
                "capability arrays must be sorted and unique",
            ));
        }
        previous = Some(value.as_str());
    }
    Ok(())
}

fn validate_text(
    value: &str,
    maximum: usize,
    field: &'static str,
) -> Result<(), CompatibilityError> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(CompatibilityError::BoundsExceeded(field))
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompatibilityError {
    Invalid(&'static str),
    BoundsExceeded(&'static str),
    UnsupportedSchema { field: &'static str, value: String },
    UnsupportedProtocol { value: String },
    ProtocolMismatch,
    EndpointIdMismatch,
    IncompatibleLimits,
}

impl fmt::Display for CompatibilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) | Self::BoundsExceeded(message) => formatter.write_str(message),
            Self::UnsupportedSchema { field, .. } => {
                write!(formatter, "unsupported schema in {field}")
            }
            Self::UnsupportedProtocol { .. } => formatter.write_str("unsupported protocol version"),
            Self::ProtocolMismatch => formatter.write_str("identity and capabilities protocol mismatch"),
            Self::EndpointIdMismatch => formatter.write_str("identity and capabilities Endpoint ID mismatch"),
            Self::IncompatibleLimits => formatter.write_str("Endpoint capability limits are incompatible"),
        }
    }
}

impl Error for CompatibilityError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ErrorDocument {
    pub error: PublicError,
}

impl ErrorDocument {
    pub fn new(code: impl Into<String>, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            error: PublicError {
                code: code.into(),
                message: message.into(),
                retryable,
            },
        }
    }

    pub fn validate(&self) -> Result<(), CompatibilityError> {
        validate_text(&self.error.code, MAX_ERROR_CODE_BYTES, "error.code")?;
        validate_text(&self.error.message, MAX_ERROR_MESSAGE_BYTES, "error.message")
    }
}

pub fn encode_json_bounded<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, serde_json::Error> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > maximum {
        return Err(<serde_json::Error as serde::de::Error>::custom(
            "encoded wire body exceeds its public bound",
        ));
    }
    Ok(bytes)
}
