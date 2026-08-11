use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Error, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::support::TestResult;

const TRACE_SCHEMA: &str = "zode.deepswe-event-trace.v1";
const TRACE_DERIVATION: &str =
    "real_endpoint_replay_of_retained_first_live_provider_and_tool_boundaries";
const MAX_TRACE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeepSweEventTrace {
    schema: String,
    source: DeepSweEventTraceSource,
    events: Vec<DeepSweEvent>,
    integrity_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeepSweEventTraceSource {
    provider_fixture_sha256: String,
    derivation: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DeepSweEvent {
    stream_version: u64,
    event_schema_version: u32,
    event_type: String,
    payload: Value,
}

#[derive(Clone, Debug)]
pub struct DeepSweToolExchange {
    pub tool_call_id: String,
    pub command: String,
    pub result_content: String,
}

#[derive(Serialize)]
struct DeepSweEventTraceDigest<'a> {
    schema: &'a str,
    source: &'a DeepSweEventTraceSource,
    events: &'a [DeepSweEvent],
}

impl DeepSweEventTrace {
    pub fn read_stopped_database(
        database: &Path,
        provider_fixture_sha256: &str,
    ) -> TestResult<Self> {
        let connection = Connection::open_with_flags(
            database,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let mut streams = connection.prepare("SELECT DISTINCT stream_id FROM events")?;
        let stream_ids = streams
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        if stream_ids.len() != 1 {
            return Err(
                Error::other("DeepSWE event trace must contain exactly one session").into(),
            );
        }

        let mut statement = connection.prepare(
            "SELECT stream_version, event_schema_version, event_type, payload
             FROM events WHERE stream_id = ?1 ORDER BY stream_version ASC",
        )?;
        let events = statement
            .query_map([&stream_ids[0]], |row| {
                let stream_version = row.get::<_, i64>(0)?;
                let event_schema_version = row.get::<_, i64>(1)?;
                let event_type = row.get::<_, String>(2)?;
                let payload = row.get::<_, Vec<u8>>(3)?;
                Ok((stream_version, event_schema_version, event_type, payload))
            })?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(
                |(stream_version, event_schema_version, event_type, payload)| {
                    Ok(DeepSweEvent {
                        stream_version: u64::try_from(stream_version).map_err(|_| {
                            Error::other("DeepSWE event trace has an invalid stream version")
                        })?,
                        event_schema_version: u32::try_from(event_schema_version).map_err(
                            |_| Error::other("DeepSWE event trace has an invalid schema version"),
                        )?,
                        event_type,
                        payload: serde_json::from_slice(&payload)?,
                    })
                },
            )
            .collect::<TestResult<Vec<_>>>()?;
        let mut trace = Self {
            schema: TRACE_SCHEMA.to_owned(),
            source: DeepSweEventTraceSource {
                provider_fixture_sha256: provider_fixture_sha256.to_owned(),
                derivation: TRACE_DERIVATION.to_owned(),
            },
            events,
            integrity_sha256: String::new(),
        };
        trace.validate(provider_fixture_sha256)?;
        trace.integrity_sha256 = trace.calculate_integrity()?;
        Ok(trace)
    }

    pub fn load(
        path: &Path,
        expected_file_sha256: &str,
        expected_provider_sha256: &str,
        forbidden: &[&str],
    ) -> TestResult<Self> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Error::other("DeepSWE event trace must be a regular file").into());
        }
        if metadata.len() > MAX_TRACE_BYTES {
            return Err(Error::other("DeepSWE event trace exceeds its byte bound").into());
        }
        let bytes = fs::read(path)?;
        if sha256_hex(&bytes) != expected_file_sha256 {
            return Err(Error::other("DeepSWE event trace file digest is invalid").into());
        }
        reject_forbidden(&bytes, forbidden)?;
        let trace: Self = serde_json::from_slice(&bytes)?;
        trace.validate(expected_provider_sha256)?;
        if trace.integrity_sha256 != trace.calculate_integrity()? {
            return Err(Error::other("DeepSWE event trace integrity is invalid").into());
        }
        Ok(trace)
    }

    pub fn promote_immutable(&self, path: &Path, forbidden: &[&str]) -> TestResult<String> {
        if path.exists() {
            return Err(Error::other("DeepSWE event trace destination already exists").into());
        }
        self.validate(&self.source.provider_fixture_sha256)?;
        if self.integrity_sha256 != self.calculate_integrity()? {
            return Err(Error::other("DeepSWE event trace integrity is invalid").into());
        }
        let bytes = serde_json::to_vec(self)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_TRACE_BYTES {
            return Err(Error::other("DeepSWE event trace exceeds its byte bound").into());
        }
        reject_forbidden(&bytes, forbidden)?;
        let file_sha256 = sha256_hex(&bytes);
        let parent = path
            .parent()
            .ok_or_else(|| Error::other("DeepSWE event trace has no parent directory"))?;
        fs::create_dir_all(parent)?;
        let temporary = temporary_path(path);
        let result = (|| -> TestResult<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o444))?;
            fs::hard_link(&temporary, path)?;
            File::open(parent)?.sync_all()?;
            Ok(())
        })();
        let _ = fs::remove_file(&temporary);
        result?;
        Ok(file_sha256)
    }

    pub fn instruction(&self) -> TestResult<String> {
        let mut instructions = self.events.iter().filter_map(|event| {
            (event.event_type == "delivery_queued"
                && event
                    .payload
                    .pointer("/delivery/kind")
                    .and_then(Value::as_str)
                    == Some("user_input"))
            .then(|| {
                event
                    .payload
                    .pointer("/delivery/payload/Inline/content")
                    .and_then(Value::as_str)
            })
            .flatten()
        });
        let instruction = instructions
            .next()
            .ok_or_else(|| Error::other("DeepSWE event trace has no user instruction"))?;
        if instructions.next().is_some() {
            return Err(Error::other("DeepSWE event trace has multiple user instructions").into());
        }
        Ok(instruction.to_owned())
    }

    pub fn tool_exchanges(&self) -> TestResult<Vec<DeepSweToolExchange>> {
        let mut exchanges = Vec::<DeepSweToolExchange>::new();
        let mut indexes = HashMap::<String, usize>::new();
        let mut completed = Vec::<bool>::new();
        for event in &self.events {
            match event.event_type.as_str() {
                "async_tool_call_started" => {
                    let tool_call_id = required_string(&event.payload, "/record/tool_call_id")?;
                    let tool_name = required_string(&event.payload, "/record/tool_name")?;
                    if tool_name != "shell" {
                        return Err(Error::other(
                            "DeepSWE event trace contains an unexpected tool",
                        )
                        .into());
                    }
                    let command = required_string(&event.payload, "/record/input/Inline/command")?;
                    if indexes.contains_key(tool_call_id) {
                        return Err(Error::other(
                            "DeepSWE event trace repeats a tool-call identity",
                        )
                        .into());
                    }
                    indexes.insert(tool_call_id.to_owned(), exchanges.len());
                    exchanges.push(DeepSweToolExchange {
                        tool_call_id: tool_call_id.to_owned(),
                        command: command.to_owned(),
                        result_content: String::new(),
                    });
                    completed.push(false);
                }
                "async_tool_call_completed" => {
                    let tool_call_id = required_string(&event.payload, "/tool_call_id")?;
                    let index = indexes.get(tool_call_id).copied().ok_or_else(|| {
                        Error::other("DeepSWE tool completion has no matching start")
                    })?;
                    if completed[index] {
                        return Err(
                            Error::other("DeepSWE event trace repeats a tool completion").into(),
                        );
                    }
                    exchanges[index].result_content =
                        required_string(&event.payload, "/result/Inline/content")?.to_owned();
                    completed[index] = true;
                }
                _ => {}
            }
        }
        if exchanges.is_empty() || completed.iter().any(|value| !value) {
            return Err(Error::other("DeepSWE event trace has incomplete tool outcomes").into());
        }
        Ok(exchanges)
    }

    pub fn assert_matches_stopped_database(&self, database: &Path) -> TestResult<()> {
        let actual = Self::read_stopped_database(database, &self.source.provider_fixture_sha256)?;
        if self.events.len() != actual.events.len() {
            return Err(Error::other(format!(
                "DeepSWE event replay produced {} events; expected {}",
                actual.events.len(),
                self.events.len()
            ))
            .into());
        }
        let expected = canonical_events(&self.events)?;
        let observed = canonical_events(&actual.events)?;
        for (index, (expected, observed)) in expected.iter().zip(&observed).enumerate() {
            if expected != observed {
                let field = if expected.event_type != observed.event_type {
                    "event_type".to_owned()
                } else if expected.event_schema_version != observed.event_schema_version {
                    "event_schema_version".to_owned()
                } else {
                    first_value_difference(&expected.payload, &observed.payload, "payload")
                        .unwrap_or_else(|| "event".to_owned())
                };
                return Err(Error::other(format!(
                    "DeepSWE event replay diverged at stream version {} field {} (expected {} {}, observed {} {})",
                    index + 1,
                    field,
                    expected.event_type,
                    value_digest(&expected.payload)?,
                    observed.event_type,
                    value_digest(&observed.payload)?
                ))
                .into());
            }
        }
        Ok(())
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn tool_count(&self) -> TestResult<usize> {
        Ok(self.tool_exchanges()?.len())
    }

    fn calculate_integrity(&self) -> TestResult<String> {
        Ok(sha256_hex(&serde_json::to_vec(&DeepSweEventTraceDigest {
            schema: &self.schema,
            source: &self.source,
            events: &self.events,
        })?))
    }

    fn validate(&self, expected_provider_sha256: &str) -> TestResult<()> {
        if self.schema != TRACE_SCHEMA
            || self.source.derivation != TRACE_DERIVATION
            || self.source.provider_fixture_sha256 != expected_provider_sha256
            || self.events.is_empty()
        {
            return Err(Error::other("DeepSWE event trace envelope is invalid").into());
        }
        for (index, event) in self.events.iter().enumerate() {
            if event.stream_version != u64::try_from(index + 1)?
                || event.event_schema_version == 0
                || event.event_type.is_empty()
                || event
                    .payload
                    .get("type")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
            {
                return Err(Error::other("DeepSWE event trace sequence is invalid").into());
            }
        }
        let _ = self.instruction()?;
        let _ = self.tool_exchanges()?;
        Ok(())
    }
}

pub fn file_sha256(path: &Path) -> TestResult<String> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::other("DeepSWE fixture must be a regular file").into());
    }
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn canonical_events(events: &[DeepSweEvent]) -> TestResult<Vec<DeepSweEvent>> {
    let mut normalizer = EventNormalizer::default();
    events
        .iter()
        .cloned()
        .map(|mut event| {
            normalizer.normalize(&mut event.payload, None)?;
            Ok(event)
        })
        .collect()
}

#[derive(Default)]
struct EventNormalizer {
    identities: HashMap<String, String>,
}

impl EventNormalizer {
    fn normalize(&mut self, value: &mut Value, field: Option<&str>) -> TestResult<()> {
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    self.normalize(value, Some(key))?;
                }
            }
            Value::Array(values) => {
                for value in values {
                    self.normalize(value, field)?;
                }
            }
            Value::Number(_) if field.is_some_and(is_clock_field) => {
                *value = Value::String("@clock".to_owned());
            }
            Value::String(text) if field.is_some_and(is_identity_field) => {
                let next = self.identities.len() + 1;
                let replacement = self
                    .identities
                    .entry(text.clone())
                    .or_insert_with(|| format!("@identity:{next}"))
                    .clone();
                *text = replacement;
            }
            Value::String(text) if field == Some("base_url") => {
                let parsed = url::Url::parse(text)?;
                *text = format!("https://provider.invalid{}", parsed.path());
            }
            _ => {}
        }
        Ok(())
    }
}

fn is_clock_field(field: &str) -> bool {
    field.ends_with("_at_ms") || field == "not_before_ms"
}

fn is_identity_field(field: &str) -> bool {
    field.ends_with("_fingerprint")
        || matches!(
            field,
            "session_id"
                | "delivery_id"
                | "message_id"
                | "materialized_message_id"
                | "activation_id"
                | "round_id"
                | "request_id"
                | "attempt_id"
                | "failed_attempt_id"
                | "next_attempt_id"
                | "result_message_id"
                | "dedupe_key"
        )
}

fn required_string<'a>(value: &'a Value, pointer: &str) -> TestResult<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::other(format!("DeepSWE event trace is missing {pointer}")).into())
}

fn value_digest(value: &Value) -> TestResult<String> {
    Ok(sha256_hex(&serde_json::to_vec(value)?))
}

fn first_value_difference(expected: &Value, observed: &Value, path: &str) -> Option<String> {
    match (expected, observed) {
        (Value::Object(expected), Value::Object(observed)) => {
            for key in expected.keys().chain(observed.keys()) {
                let next = format!("{path}.{key}");
                match (expected.get(key), observed.get(key)) {
                    (Some(expected), Some(observed)) => {
                        if let Some(difference) = first_value_difference(expected, observed, &next)
                        {
                            return Some(difference);
                        }
                    }
                    _ => return Some(next),
                }
            }
            None
        }
        (Value::Array(expected), Value::Array(observed)) => {
            for (index, (expected, observed)) in expected.iter().zip(observed).enumerate() {
                let next = format!("{path}[{index}]");
                if let Some(difference) = first_value_difference(expected, observed, &next) {
                    return Some(difference);
                }
            }
            (expected.len() != observed.len()).then(|| format!("{path}.length"))
        }
        _ => (expected != observed).then(|| path.to_owned()),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn reject_forbidden(bytes: &[u8], forbidden: &[&str]) -> TestResult<()> {
    if forbidden
        .iter()
        .filter(|value| !value.is_empty())
        .any(|value| {
            bytes
                .windows(value.len())
                .any(|window| window == value.as_bytes())
        })
    {
        return Err(Error::other("DeepSWE event trace contains credential material").into());
    }
    Ok(())
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(format!(".tmp-{}", std::process::id()));
    PathBuf::from(temporary)
}
