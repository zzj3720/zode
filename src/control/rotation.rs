use super::{
    files, ControlInitError, ControlRotationError, ControllerAuthRotationRequest,
    ControllerAuthSpec, MAX_CONTROL_SECRET_BYTES, MAX_ENDPOINT_ID_BYTES,
};
use getrandom::fill as fill_random;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{ErrorKind, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

type HmacSha256 = Hmac<Sha256>;

const KEY_BYTES: usize = 32;
const MAX_JOURNAL_BYTES: usize = 8 * 1024 * 1024;
const MAX_RECEIPT_BYTES: usize = 64 * 1024;
const MAX_INITIALIZATION_BYTES: usize = 64 * 1024;
const JOURNAL_FILE: &str = "operations.jsonl";
const INITIALIZATION_FILE: &str = "initialization.json";
const POINTER_SCHEMA: &str = "zode.controller-auth.pointer.v1";
const INITIALIZATION_SCHEMA: &str = "zode.controller-auth.initialization.v1";
const ROTATION_MARKER: &[u8] = b"zode.controller-auth.rotated.v1\n";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum JournalPhase {
    Intent,
    Receipt,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalRecord {
    operation_id: String,
    authority_id: String,
    revision: u64,
    fingerprint: String,
    secret_ref: String,
    phase: JournalPhase,
    status: u16,
    response: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ActivePointer {
    schema: String,
    authority_id: String,
    revision: u64,
    operation_id: Option<String>,
    secret_ref: String,
    fingerprint: Option<String>,
    response: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct InitializationAuthority {
    authority_id: String,
    revision: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InitializationFact {
    schema: String,
    endpoint_id: String,
    authorities: Vec<InitializationAuthority>,
}

#[derive(Clone)]
pub(crate) struct PersistedAuthority {
    pub(crate) authority_id: String,
    pub(crate) revision: u64,
    pub(crate) secret: Vec<u8>,
}

pub(crate) struct RotationOutcome {
    pub(crate) status: u16,
    pub(crate) body: String,
}

pub(crate) struct RotationInput<'a> {
    pub(crate) authority_id: &'a str,
    pub(crate) subject: &'a str,
    pub(crate) idempotency_key: &'a str,
    pub(crate) current_revision: u64,
}

pub(crate) struct RotationStore {
    root: PathBuf,
    root_identity: files::DirectoryIdentity,
    key: Vec<u8>,
    records: Vec<JournalRecord>,
    key_created: bool,
}

impl RotationStore {
    pub(crate) fn open(root: PathBuf, allow_create: bool) -> Result<Self, ControlInitError> {
        files::ensure_private_directory(&root)?;
        let root_identity = files::capture_directory_identity(&root)?;
        let (key, key_created) = load_or_create_key(&root.join("fingerprint.key"), allow_create)?;
        let records = load_journal(&root.join(JOURNAL_FILE))?;
        Ok(Self {
            root,
            root_identity,
            key,
            records,
            key_created,
        })
    }

    /// Fail closed if the sidecar pathname no longer names the directory that
    /// was admitted at startup.  Re-checking the directory identity around
    /// mutation/linearization is what prevents a pathname swap from making a
    /// rotation acknowledge state split across two directories.
    pub(crate) fn ensure_root_current(&self) -> Result<(), ControlInitError> {
        let current = files::capture_directory_identity(&self.root)?;
        if current != self.root_identity {
            return Err(ControlInitError::Invalid);
        }
        Ok(())
    }

    pub(crate) fn initialize(
        &mut self,
        endpoint_id: &str,
        specs: &[ControllerAuthSpec],
        allow_create: bool,
        identity_created: bool,
    ) -> Result<Vec<PersistedAuthority>, ControlInitError> {
        self.ensure_root_current()?;
        let expected = initial_authorities(specs)?;
        if let Some(fact) = self.load_initialization()? {
            validate_initialization(&fact, endpoint_id, &expected)?;
            self.reconcile()?;
            return self.current_authorities(&expected);
        }

        if !(allow_create && identity_created && self.key_created) {
            return Err(ControlInitError::Invalid);
        }
        self.ensure_unclaimed()?;

        let mut bootstrap = Vec::with_capacity(specs.len());
        for spec in specs {
            let secret = files::read_private_file(&spec.secret_file, MAX_CONTROL_SECRET_BYTES)?;
            if !files::validate_bearer_token(&secret)
                || bootstrap.iter().any(|(_, other): &(String, Vec<u8>)| {
                    files::constant_time_equal(&secret, other)
                })
            {
                return Err(ControlInitError::Invalid);
            }
            bootstrap.push((spec.authority_id.clone(), secret));
        }

        for (authority_id, secret) in &bootstrap {
            let revision = expected
                .iter()
                .find(|authority| authority.authority_id == *authority_id)
                .map(|authority| authority.revision)
                .ok_or(ControlInitError::Invalid)?;
            let secret_ref = expected_current_secret_ref(authority_id, revision);
            files::create_private_file(&self.root.join(secret_ref), secret)?;
        }

        let fact = InitializationFact {
            schema: INITIALIZATION_SCHEMA.to_owned(),
            endpoint_id: endpoint_id.to_owned(),
            authorities: expected,
        };
        let bytes = serde_json::to_vec(&fact).map_err(|_| ControlInitError::Invalid)?;
        files::create_private_file(&self.initialization_path(), &bytes)?;
        self.current_authorities(&fact.authorities)
    }

    pub(crate) fn rotate<Before, After>(
        &mut self,
        input: &RotationInput<'_>,
        request: &ControllerAuthRotationRequest,
        mut before_promotion: Before,
        mut after_promotion: After,
    ) -> Result<RotationOutcome, ControlRotationError>
    where
        Before: FnMut() -> Result<(), ControlRotationError>,
        After: FnMut(&[u8]) -> Result<(), ControlRotationError>,
    {
        self.ensure_root_current()
            .map_err(|_| ControlRotationError::Internal)?;
        let fingerprint = self.fingerprint(request)?;
        let operation_id =
            self.operation_id(input.authority_id, input.subject, input.idempotency_key);
        if let Some(receipt) = self.load_receipt(&operation_id, input.authority_id)? {
            if !same_fingerprint(&receipt.fingerprint, &fingerprint) {
                return Err(ControlRotationError::Conflict);
            }
            return outcome_for_record(&receipt);
        }

        let existing = self.latest_for(&operation_id).cloned();
        if let Some(record) = &existing {
            if !same_fingerprint(&record.fingerprint, &fingerprint) {
                return Err(ControlRotationError::Conflict);
            }
            if record.phase == JournalPhase::Receipt {
                return outcome_for_record(record);
            }
        }

        let current = self
            .load_pointer(input.authority_id)
            .map_err(|_| ControlRotationError::Internal)?
            .unwrap_or_else(|| ActivePointer {
                schema: POINTER_SCHEMA.to_owned(),
                authority_id: input.authority_id.to_owned(),
                revision: input.current_revision,
                operation_id: None,
                secret_ref: expected_current_secret_ref(input.authority_id, input.current_revision),
                fingerprint: None,
                response: response_for(200, input.authority_id, input.current_revision),
            });
        if !current.authority_id.eq(input.authority_id) {
            return Err(ControlRotationError::Internal);
        }

        if !same_operation_pointer(&current, &operation_id, &fingerprint)
            && (current.revision >= request.revision || request.revision <= input.current_revision)
        {
            let intent = existing.unwrap_or_else(|| JournalRecord {
                operation_id: operation_id.clone(),
                authority_id: input.authority_id.to_owned(),
                revision: request.revision,
                fingerprint: fingerprint.clone(),
                secret_ref: expected_secret_ref(
                    input.authority_id,
                    request.revision,
                    &operation_id,
                ),
                phase: JournalPhase::Intent,
                status: 0,
                response: None,
            });
            if self.latest_for(&operation_id).is_none() {
                self.append_record(intent.clone())?;
            }
            let outcome = self.complete_receipt(&intent, 409, None)?;
            return Ok(outcome);
        }

        let secret_ref = existing
            .as_ref()
            .map(|record| record.secret_ref.clone())
            .unwrap_or_else(|| {
                expected_secret_ref(input.authority_id, request.revision, &operation_id)
            });
        let candidate = request.secret.payload.as_bytes();
        self.stage_secret(&secret_ref, candidate)?;

        let intent = if let Some(record) = existing {
            record
        } else {
            let record = JournalRecord {
                operation_id: operation_id.clone(),
                authority_id: input.authority_id.to_owned(),
                revision: request.revision,
                fingerprint: fingerprint.clone(),
                secret_ref: secret_ref.clone(),
                phase: JournalPhase::Intent,
                status: 0,
                response: None,
            };
            self.append_record(record.clone())?;
            record
        };

        if same_pointer_record(&current, &intent) {
            if !self.rotation_marker(input.authority_id)? {
                return Err(ControlRotationError::Internal);
            }
            return self.finish_pointer(
                current,
                candidate,
                false,
                &mut before_promotion,
                &mut after_promotion,
            );
        }

        let pointer = ActivePointer {
            schema: POINTER_SCHEMA.to_owned(),
            authority_id: input.authority_id.to_owned(),
            revision: request.revision,
            operation_id: Some(operation_id),
            secret_ref,
            fingerprint: Some(fingerprint),
            response: response_for(200, input.authority_id, request.revision),
        };
        self.ensure_rotation_marker(input.authority_id)
            .map_err(|_| ControlRotationError::Internal)?;
        before_promotion()?;
        self.promote_pointer(&pointer)
            .map_err(|_| ControlRotationError::Internal)?;
        self.ensure_root_current()
            .map_err(|_| ControlRotationError::Internal)?;
        self.finish_pointer(
            pointer,
            candidate,
            true,
            &mut before_promotion,
            &mut after_promotion,
        )
    }

    fn finish_pointer<Before, After>(
        &mut self,
        pointer: ActivePointer,
        candidate: &[u8],
        fenced: bool,
        before_promotion: &mut Before,
        after_promotion: &mut After,
    ) -> Result<RotationOutcome, ControlRotationError>
    where
        Before: FnMut() -> Result<(), ControlRotationError>,
        After: FnMut(&[u8]) -> Result<(), ControlRotationError>,
    {
        let operation_id = pointer
            .operation_id
            .as_deref()
            .ok_or(ControlRotationError::Internal)?;
        let record = self
            .latest_for(operation_id)
            .cloned()
            .ok_or(ControlRotationError::Internal)?;
        if !same_pointer_record(&pointer, &record) {
            return Err(ControlRotationError::Internal);
        }
        let secret = self
            .read_secret(&pointer.secret_ref)
            .map_err(|_| ControlRotationError::Internal)?;
        if !files::constant_time_equal(&secret, candidate) {
            return Err(ControlRotationError::Conflict);
        }
        if record.phase == JournalPhase::Receipt {
            return outcome_for_record(&record);
        }
        if !fenced {
            before_promotion()?;
        }
        after_promotion(&secret)?;
        let outcome = self.complete_receipt(&record, 200, Some(&secret))?;
        self.ensure_root_current()
            .map_err(|_| ControlRotationError::Internal)?;
        Ok(outcome)
    }

    fn reconcile(&mut self) -> Result<(), ControlInitError> {
        self.ensure_root_current()?;
        let pointers = self.load_manifests()?;
        for pointer in &pointers {
            let rotated = self.rotation_marker(&pointer.authority_id)?;
            if pointer.operation_id.is_some() != rotated {
                return Err(ControlInitError::Invalid);
            }
            self.reconcile_pointer(pointer)?;
        }

        let pending = self
            .latest_records()
            .into_values()
            .filter(|record| record.phase == JournalPhase::Intent)
            .collect::<Vec<_>>();
        for record in pending {
            if self
                .latest_for(&record.operation_id)
                .is_none_or(|latest| latest.phase != JournalPhase::Intent)
            {
                continue;
            }
            self.reconcile_intent(record)?;
        }
        let pointers = self.load_manifests()?;
        self.remove_orphan_secrets(&pointers)?;
        self.ensure_root_current()
    }

    fn reconcile_pointer(&mut self, pointer: &ActivePointer) -> Result<(), ControlInitError> {
        self.read_secret(&pointer.secret_ref)?;
        let Some(operation_id) = pointer.operation_id.as_deref() else {
            if pointer.fingerprint.is_some() {
                return Err(ControlInitError::Invalid);
            }
            return Ok(());
        };
        let record = self.latest_for(operation_id).cloned();
        match record {
            Some(record) => {
                if !same_pointer_record(pointer, &record) {
                    return Err(ControlInitError::Invalid);
                }
                match record.phase {
                    JournalPhase::Intent => {
                        self.complete_receipt(&record, 200, None)
                            .map_err(|_| ControlInitError::Invalid)?;
                    }
                    JournalPhase::Receipt if record.status == 200 => {
                        self.persist_receipt(&record)?;
                        self.compact_journal(Some(operation_id))?;
                    }
                    JournalPhase::Receipt => return Err(ControlInitError::Invalid),
                }
                Ok(())
            }
            None => {
                let receipt = self
                    .load_receipt(operation_id, &pointer.authority_id)?
                    .ok_or(ControlInitError::Invalid)?;
                if !same_pointer_record(pointer, &receipt) || receipt.status != 200 {
                    return Err(ControlInitError::Invalid);
                }
                Ok(())
            }
        }
    }

    fn reconcile_intent(&mut self, record: JournalRecord) -> Result<(), ControlInitError> {
        let staged = self.read_secret(&record.secret_ref)?;
        let current = self.load_pointer(&record.authority_id)?;
        if current
            .as_ref()
            .is_some_and(|pointer| same_pointer_record(pointer, &record))
        {
            return Ok(());
        }
        if current
            .as_ref()
            .is_some_and(|pointer| pointer.revision >= record.revision)
        {
            self.complete_receipt(&record, 409, Some(&staged))
                .map_err(|_| ControlInitError::Invalid)?;
            files::remove_best_effort(&self.root.join(&record.secret_ref));
            return Ok(());
        }

        let pointer = ActivePointer {
            schema: POINTER_SCHEMA.to_owned(),
            authority_id: record.authority_id.clone(),
            revision: record.revision,
            operation_id: Some(record.operation_id.clone()),
            secret_ref: record.secret_ref.clone(),
            fingerprint: Some(record.fingerprint.clone()),
            response: response_for(200, &record.authority_id, record.revision),
        };
        self.ensure_rotation_marker(&record.authority_id)?;
        self.promote_pointer(&pointer)?;
        self.complete_receipt(&record, 200, Some(&staged))
            .map_err(|_| ControlInitError::Invalid)?;
        Ok(())
    }

    fn complete_receipt(
        &mut self,
        intent: &JournalRecord,
        status: u16,
        secret: Option<&[u8]>,
    ) -> Result<RotationOutcome, ControlRotationError> {
        if intent.phase != JournalPhase::Intent {
            return Err(ControlRotationError::Internal);
        }
        let receipt = JournalRecord {
            operation_id: intent.operation_id.clone(),
            authority_id: intent.authority_id.clone(),
            revision: intent.revision,
            fingerprint: intent.fingerprint.clone(),
            secret_ref: intent.secret_ref.clone(),
            phase: JournalPhase::Receipt,
            status,
            response: Some(response_for(status, &intent.authority_id, intent.revision)),
        };
        self.append_record(receipt.clone())
            .map_err(|_| ControlRotationError::Internal)?;
        self.persist_receipt(&receipt)
            .map_err(|_| ControlRotationError::Internal)?;
        self.compact_journal(if status == 200 {
            Some(intent.operation_id.as_str())
        } else {
            None
        })
        .map_err(|_| ControlRotationError::Internal)?;
        if status != 200 && secret.is_some() {
            files::remove_best_effort(&self.root.join(&intent.secret_ref));
        }
        Ok(RotationOutcome {
            status,
            body: receipt.response.ok_or(ControlRotationError::Internal)?,
        })
    }

    fn persist_receipt(&self, record: &JournalRecord) -> Result<(), ControlInitError> {
        validate_record(record)?;
        if record.phase != JournalPhase::Receipt {
            return Err(ControlInitError::Invalid);
        }
        let path = self.receipt_path(&record.operation_id);
        let bytes = serde_json::to_vec(record).map_err(|_| ControlInitError::Invalid)?;
        match files::create_private_file(&path, &bytes) {
            Ok(()) => Ok(()),
            Err(ControlInitError::Storage(error)) if error.kind() == ErrorKind::AlreadyExists => {
                let existing = self
                    .load_receipt(&record.operation_id, &record.authority_id)?
                    .ok_or(ControlInitError::Invalid)?;
                if same_receipt(&existing, record) {
                    Ok(())
                } else {
                    Err(ControlInitError::Invalid)
                }
            }
            Err(error) => Err(error),
        }
    }

    fn compact_journal(&mut self, current_operation: Option<&str>) -> Result<(), ControlInitError> {
        for record in self.records.clone() {
            if record.phase == JournalPhase::Receipt {
                self.persist_receipt(&record)?;
            }
        }
        let latest = self.latest_records();
        let mut retained = Vec::new();
        for record in &self.records {
            let Some(last) = latest.get(&record.operation_id) else {
                return Err(ControlInitError::Invalid);
            };
            let keep = match record.phase {
                JournalPhase::Intent => {
                    last.phase == JournalPhase::Intent
                        || (current_operation.is_some_and(|operation| {
                            files::constant_time_equal(
                                operation.as_bytes(),
                                record.operation_id.as_bytes(),
                            )
                        }) && last.phase == JournalPhase::Receipt)
                }
                JournalPhase::Receipt => {
                    current_operation.is_some_and(|operation| {
                        files::constant_time_equal(
                            operation.as_bytes(),
                            record.operation_id.as_bytes(),
                        )
                    }) && last.phase == JournalPhase::Receipt
                }
            };
            if keep {
                retained.push(record.clone());
            }
        }
        let mut bytes = Vec::new();
        for record in &retained {
            serde_json::to_writer(&mut bytes, record).map_err(|_| ControlInitError::Invalid)?;
            bytes.push(b'\n');
        }
        files::atomic_replace(&self.root.join(JOURNAL_FILE), &bytes)?;
        self.records = retained;
        Ok(())
    }

    fn append_record(&mut self, record: JournalRecord) -> Result<(), ControlInitError> {
        let mut next = self.records.clone();
        next.push(record.clone());
        validate_history(&next)?;
        let path = self.root.join(JOURNAL_FILE);
        let mut file = files::open_private_for_append(&path)?;
        let was_empty = file.metadata().map_err(ControlInitError::Storage)?.len() == 0;
        file.seek(SeekFrom::End(0))
            .map_err(ControlInitError::Storage)?;
        serde_json::to_writer(&mut file, &record).map_err(|_| ControlInitError::Invalid)?;
        file.write_all(b"\n")
            .and_then(|_| file.sync_all())
            .map_err(ControlInitError::Storage)?;
        if was_empty {
            files::sync_parent(&path)?;
        }
        self.records.push(record);
        Ok(())
    }

    fn stage_secret(&self, secret_ref: &str, candidate: &[u8]) -> Result<(), ControlRotationError> {
        let path = self.root.join(secret_ref);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let existing = self
                    .read_secret(secret_ref)
                    .map_err(|_| ControlRotationError::Internal)?;
                if files::constant_time_equal(&existing, candidate) {
                    Ok(())
                } else {
                    Err(ControlRotationError::Conflict)
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                files::create_private_file(&path, candidate)
                    .map_err(|_| ControlRotationError::Internal)
            }
            Err(_) => Err(ControlRotationError::Internal),
        }
    }

    fn promote_pointer(&self, pointer: &ActivePointer) -> Result<(), ControlInitError> {
        let path = self.pointer_path(&pointer.authority_id);
        validate_pointer(&self.root, &path, pointer)?;
        let bytes = serde_json::to_vec(pointer).map_err(|_| ControlInitError::Invalid)?;
        files::atomic_replace(&path, &bytes)
    }

    fn current_authorities(
        &self,
        expected: &[InitializationAuthority],
    ) -> Result<Vec<PersistedAuthority>, ControlInitError> {
        let pointers = self.load_manifests()?;
        if pointers.len() > expected.len() {
            return Err(ControlInitError::Invalid);
        }
        let expected_ids = expected
            .iter()
            .map(|authority| authority.authority_id.as_str())
            .collect::<HashSet<_>>();
        if pointers
            .iter()
            .any(|pointer| !expected_ids.contains(pointer.authority_id.as_str()))
        {
            return Err(ControlInitError::Invalid);
        }
        let mut authorities = Vec::with_capacity(expected.len());
        for authority in expected {
            let current = self.load_pointer(&authority.authority_id)?;
            match current {
                Some(pointer) => {
                    let rotated = self.rotation_marker(&authority.authority_id)?;
                    if pointer.operation_id.is_some() != rotated {
                        return Err(ControlInitError::Invalid);
                    }
                    if pointer.revision < authority.revision {
                        return Err(ControlInitError::Invalid);
                    }
                    authorities.push(PersistedAuthority {
                        authority_id: authority.authority_id.clone(),
                        revision: pointer.revision,
                        secret: self.read_secret(&pointer.secret_ref)?,
                    });
                }
                None => {
                    if self.rotation_marker(&authority.authority_id)? {
                        return Err(ControlInitError::Invalid);
                    }
                    authorities.push(PersistedAuthority {
                        authority_id: authority.authority_id.clone(),
                        revision: authority.revision,
                        secret: self.read_secret(&expected_current_secret_ref(
                            &authority.authority_id,
                            authority.revision,
                        ))?,
                    });
                }
            }
        }
        Ok(authorities)
    }

    fn load_initialization(&self) -> Result<Option<InitializationFact>, ControlInitError> {
        let path = self.initialization_path();
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let bytes = files::read_private_file(&path, MAX_INITIALIZATION_BYTES)?;
                let fact = serde_json::from_slice(&bytes).map_err(|_| ControlInitError::Invalid)?;
                Ok(Some(fact))
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(ControlInitError::Storage(error)),
        }
    }

    fn ensure_unclaimed(&self) -> Result<(), ControlInitError> {
        for entry in fs::read_dir(&self.root).map_err(ControlInitError::Storage)? {
            let path = entry.map_err(ControlInitError::Storage)?.path();
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(ControlInitError::Invalid)?;
            if name != "fingerprint.key" {
                return Err(ControlInitError::Invalid);
            }
        }
        Ok(())
    }

    fn rotation_marker(&self, authority_id: &str) -> Result<bool, ControlInitError> {
        let path = self.rotation_marker_path(authority_id);
        match fs::symlink_metadata(&path) {
            Ok(_) => Ok(files::read_private_file(&path, ROTATION_MARKER.len())? == ROTATION_MARKER),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(ControlInitError::Storage(error)),
        }
    }

    fn ensure_rotation_marker(&self, authority_id: &str) -> Result<(), ControlInitError> {
        if self.rotation_marker(authority_id)? {
            return Ok(());
        }
        files::create_private_file(&self.rotation_marker_path(authority_id), ROTATION_MARKER)
    }

    fn read_secret(&self, secret_ref: &str) -> Result<Vec<u8>, ControlInitError> {
        let secret =
            files::read_private_file(&self.root.join(secret_ref), MAX_CONTROL_SECRET_BYTES)?;
        if !files::validate_bearer_token(&secret) {
            return Err(ControlInitError::Invalid);
        }
        Ok(secret)
    }

    fn remove_orphan_secrets(&self, pointers: &[ActivePointer]) -> Result<(), ControlInitError> {
        let mut referenced = pointers
            .iter()
            .map(|pointer| pointer.secret_ref.clone())
            .collect::<HashSet<_>>();
        for record in self.latest_records().into_values() {
            if record.phase == JournalPhase::Intent {
                referenced.insert(record.secret_ref);
            }
        }
        for entry in fs::read_dir(&self.root).map_err(ControlInitError::Storage)? {
            let path = entry.map_err(ControlInitError::Storage)?.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if name.starts_with("secret-") && !referenced.contains(name) {
                files::remove_best_effort(&path);
            }
        }
        Ok(())
    }

    fn load_receipt(
        &self,
        operation_id: &str,
        expected_authority_id: &str,
    ) -> Result<Option<JournalRecord>, ControlInitError> {
        let path = self.receipt_path(operation_id);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let bytes = files::read_private_file(&path, MAX_RECEIPT_BYTES)?;
                let receipt: JournalRecord =
                    serde_json::from_slice(&bytes).map_err(|_| ControlInitError::Invalid)?;
                validate_record(&receipt)?;
                if receipt.phase != JournalPhase::Receipt {
                    return Err(ControlInitError::Invalid);
                }
                if receipt.authority_id != expected_authority_id {
                    return Err(ControlInitError::Invalid);
                }
                if !files::constant_time_equal(
                    receipt.operation_id.as_bytes(),
                    operation_id.as_bytes(),
                ) {
                    return Err(ControlInitError::Invalid);
                }
                Ok(Some(receipt))
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(ControlInitError::Storage(error)),
        }
    }

    fn fingerprint(
        &self,
        request: &ControllerAuthRotationRequest,
    ) -> Result<String, ControlRotationError> {
        let bytes = serde_json::to_vec(request).map_err(|_| ControlRotationError::Internal)?;
        Ok(self.digest(b"rotation-fingerprint:v1", &bytes))
    }

    fn operation_id(&self, authority_id: &str, subject: &str, key: &str) -> String {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"zode.controller-auth.rotate.v1");
        bytes.push(0);
        bytes.extend_from_slice(authority_id.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(subject.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(key.as_bytes());
        self.digest(b"rotation-operation:v1", &bytes)
    }

    fn digest(&self, purpose: &[u8], bytes: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("fixed HMAC key size");
        mac.update(purpose);
        mac.update(&[0]);
        mac.update(bytes);
        format!(
            "hmac-sha256:v1:{}",
            encode_digest(mac.finalize().into_bytes().as_ref())
        )
    }

    fn pointer_path(&self, authority_id: &str) -> PathBuf {
        self.root.join(format!(
            "active-{}.manifest",
            authority_file_key(authority_id)
        ))
    }

    fn initialization_path(&self) -> PathBuf {
        self.root.join(INITIALIZATION_FILE)
    }

    fn receipt_path(&self, operation_id: &str) -> PathBuf {
        self.root
            .join(format!("receipt-{}.json", operation_file_key(operation_id)))
    }

    fn rotation_marker_path(&self, authority_id: &str) -> PathBuf {
        self.root.join(format!(
            "rotated-{}.marker",
            authority_file_key(authority_id)
        ))
    }

    fn load_manifests(&self) -> Result<Vec<ActivePointer>, ControlInitError> {
        let mut pointers = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(ControlInitError::Storage)? {
            let path = entry.map_err(ControlInitError::Storage)?.path();
            let is_manifest = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("active-") && name.ends_with(".manifest"));
            if is_manifest {
                pointers.push(self.load_pointer_path(&path)?);
            }
        }
        Ok(pointers)
    }

    fn load_pointer(&self, authority_id: &str) -> Result<Option<ActivePointer>, ControlInitError> {
        let path = self.pointer_path(authority_id);
        match fs::symlink_metadata(&path) {
            Ok(_) => self.load_pointer_path(&path).map(Some),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(ControlInitError::Storage(error)),
        }
    }

    fn load_pointer_path(&self, path: &Path) -> Result<ActivePointer, ControlInitError> {
        let bytes = files::read_private_file(path, 16 * 1024)?;
        let pointer: ActivePointer =
            serde_json::from_slice(&bytes).map_err(|_| ControlInitError::Invalid)?;
        validate_pointer(&self.root, path, &pointer)?;
        Ok(pointer)
    }

    fn latest_for(&self, operation_id: &str) -> Option<&JournalRecord> {
        self.records.iter().rfind(|record| {
            files::constant_time_equal(record.operation_id.as_bytes(), operation_id.as_bytes())
        })
    }

    fn latest_records(&self) -> HashMap<String, JournalRecord> {
        let mut latest = HashMap::new();
        for record in &self.records {
            latest.insert(record.operation_id.clone(), record.clone());
        }
        latest
    }
}

pub(crate) fn validate_request(
    authenticated_authority: &str,
    request: &ControllerAuthRotationRequest,
) -> Result<(), ControlRotationError> {
    if request.schema != "zode.controller-auth.rotate.v1"
        || request.authority_id != authenticated_authority
        || request.secret.encoding != "application/zode-secret-envelope"
        || request.revision == 0
    {
        return Err(ControlRotationError::Invalid);
    }
    let secret = request.secret.payload.as_bytes();
    if secret.len() > MAX_CONTROL_SECRET_BYTES {
        return Err(ControlRotationError::PayloadTooLarge);
    }
    if !files::validate_bearer_token(secret) {
        return Err(ControlRotationError::Invalid);
    }
    Ok(())
}

fn initial_authorities(
    specs: &[ControllerAuthSpec],
) -> Result<Vec<InitializationAuthority>, ControlInitError> {
    let mut authorities = Vec::with_capacity(specs.len());
    let mut ids = HashSet::new();
    for spec in specs {
        if spec.authority_id.is_empty()
            || spec.authority_id.len() > MAX_ENDPOINT_ID_BYTES
            || spec.revision == 0
            || !ids.insert(spec.authority_id.clone())
        {
            return Err(ControlInitError::Invalid);
        }
        authorities.push(InitializationAuthority {
            authority_id: spec.authority_id.clone(),
            revision: spec.revision,
        });
    }
    authorities.sort_by(|left, right| left.authority_id.cmp(&right.authority_id));
    Ok(authorities)
}

fn validate_initialization(
    fact: &InitializationFact,
    endpoint_id: &str,
    expected: &[InitializationAuthority],
) -> Result<(), ControlInitError> {
    if fact.schema != INITIALIZATION_SCHEMA
        || fact.endpoint_id != endpoint_id
        || fact.endpoint_id.is_empty()
        || fact.endpoint_id.len() > MAX_ENDPOINT_ID_BYTES
        || fact.authorities != expected
    {
        return Err(ControlInitError::Invalid);
    }
    Ok(())
}

fn validate_history(records: &[JournalRecord]) -> Result<(), ControlInitError> {
    let mut latest = HashMap::<String, &JournalRecord>::new();
    for record in records {
        validate_record(record)?;
        if let Some(previous) = latest.get(&record.operation_id) {
            if !same_operation_metadata(previous, record)
                || previous.phase != JournalPhase::Intent
                || record.phase != JournalPhase::Receipt
            {
                return Err(ControlInitError::Invalid);
            }
        } else if record.phase != JournalPhase::Intent {
            return Err(ControlInitError::Invalid);
        }
        latest.insert(record.operation_id.clone(), record);
    }
    Ok(())
}

fn validate_record(record: &JournalRecord) -> Result<(), ControlInitError> {
    if !valid_digest(&record.operation_id)
        || !valid_digest(&record.fingerprint)
        || record.authority_id.is_empty()
        || record.revision == 0
        || record.secret_ref
            != expected_secret_ref(&record.authority_id, record.revision, &record.operation_id)
    {
        return Err(ControlInitError::Invalid);
    }
    match record.phase {
        JournalPhase::Intent if record.status == 0 && record.response.is_none() => Ok(()),
        JournalPhase::Receipt => {
            let response = record
                .response
                .as_deref()
                .ok_or(ControlInitError::Invalid)?;
            if !matches!(record.status, 200 | 409)
                || response != response_for(record.status, &record.authority_id, record.revision)
            {
                return Err(ControlInitError::Invalid);
            }
            Ok(())
        }
        _ => Err(ControlInitError::Invalid),
    }
}

fn validate_pointer(
    root: &Path,
    path: &Path,
    pointer: &ActivePointer,
) -> Result<(), ControlInitError> {
    if pointer.schema != POINTER_SCHEMA
        || pointer.authority_id.is_empty()
        || pointer.revision == 0
        || pointer.response != response_for(200, &pointer.authority_id, pointer.revision)
        || path
            != root.join(format!(
                "active-{}.manifest",
                authority_file_key(&pointer.authority_id)
            ))
    {
        return Err(ControlInitError::Invalid);
    }
    match (&pointer.operation_id, &pointer.fingerprint) {
        (None, None)
            if pointer.secret_ref
                == expected_current_secret_ref(&pointer.authority_id, pointer.revision) =>
        {
            Ok(())
        }
        (Some(operation_id), Some(fingerprint))
            if valid_digest(operation_id)
                && valid_digest(fingerprint)
                && pointer.secret_ref
                    == expected_secret_ref(
                        &pointer.authority_id,
                        pointer.revision,
                        operation_id,
                    ) =>
        {
            Ok(())
        }
        _ => Err(ControlInitError::Invalid),
    }
}

fn same_pointer_record(pointer: &ActivePointer, record: &JournalRecord) -> bool {
    pointer.authority_id == record.authority_id
        && pointer.revision == record.revision
        && pointer.secret_ref == record.secret_ref
        && pointer.operation_id.as_deref().is_some_and(|operation_id| {
            files::constant_time_equal(operation_id.as_bytes(), record.operation_id.as_bytes())
        })
        && pointer
            .fingerprint
            .as_deref()
            .is_some_and(|fingerprint| same_fingerprint(fingerprint, &record.fingerprint))
}

fn same_operation_pointer(pointer: &ActivePointer, operation_id: &str, fingerprint: &str) -> bool {
    pointer
        .operation_id
        .as_deref()
        .is_some_and(|value| files::constant_time_equal(value.as_bytes(), operation_id.as_bytes()))
        && pointer.fingerprint.as_deref().is_some_and(|value| {
            files::constant_time_equal(value.as_bytes(), fingerprint.as_bytes())
        })
}

fn same_operation_metadata(left: &JournalRecord, right: &JournalRecord) -> bool {
    files::constant_time_equal(left.operation_id.as_bytes(), right.operation_id.as_bytes())
        && left.authority_id == right.authority_id
        && left.revision == right.revision
        && same_fingerprint(&left.fingerprint, &right.fingerprint)
        && left.secret_ref == right.secret_ref
}

fn same_receipt(left: &JournalRecord, right: &JournalRecord) -> bool {
    left.phase == JournalPhase::Receipt
        && right.phase == JournalPhase::Receipt
        && same_operation_metadata(left, right)
        && left.status == right.status
        && left.response == right.response
}

fn same_fingerprint(left: &str, right: &str) -> bool {
    files::constant_time_equal(left.as_bytes(), right.as_bytes())
}

fn outcome_for_record(record: &JournalRecord) -> Result<RotationOutcome, ControlRotationError> {
    Ok(RotationOutcome {
        status: record.status,
        body: record
            .response
            .clone()
            .ok_or(ControlRotationError::Internal)?,
    })
}

fn expected_current_secret_ref(authority_id: &str, revision: u64) -> String {
    format!(
        "current-{}-{revision}.secret",
        authority_file_key(authority_id)
    )
}

fn expected_secret_ref(authority_id: &str, revision: u64, operation_id: &str) -> String {
    format!(
        "secret-{}-{revision}-{}.secret",
        authority_file_key(authority_id),
        operation_file_key(operation_id)
    )
}

fn response_for(status: u16, authority_id: &str, revision: u64) -> String {
    if status == 200 {
        serde_json::json!({
            "schema": "zode.controller-auth.v1",
            "authority_id": authority_id,
            "revision": revision,
            "status": "ready",
        })
        .to_string()
    } else {
        serde_json::json!({
            "schema": "zode.controller-auth.v1",
            "status": "conflict",
        })
        .to_string()
    }
}

fn valid_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("hmac-sha256:v1:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn load_or_create_key(
    path: &Path,
    allow_create: bool,
) -> Result<(Vec<u8>, bool), ControlInitError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            let key = files::read_private_file(path, KEY_BYTES)?;
            if key.len() != KEY_BYTES {
                return Err(ControlInitError::Invalid);
            }
            Ok((key, false))
        }
        Err(error) if error.kind() == ErrorKind::NotFound && allow_create => {
            let mut key = vec![0_u8; KEY_BYTES];
            fill_random(&mut key).map_err(|_| ControlInitError::Invalid)?;
            files::create_private_file(path, &key)?;
            Ok((key, true))
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Err(ControlInitError::Invalid),
        Err(error) => Err(ControlInitError::Storage(error)),
    }
}

fn load_journal(path: &Path) -> Result<Vec<JournalRecord>, ControlInitError> {
    let bytes = match fs::symlink_metadata(path) {
        Ok(_) => files::read_private_file(path, MAX_JOURNAL_BYTES)?,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(ControlInitError::Storage(error)),
    };
    let mut records = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        let Some(relative_end) = bytes[cursor..].iter().position(|byte| *byte == b'\n') else {
            let tail = &bytes[cursor..];
            match serde_json::from_slice::<serde_json::Value>(tail) {
                Ok(value) => {
                    let record =
                        serde_json::from_value(value).map_err(|_| ControlInitError::Invalid)?;
                    records.push(record);
                    repair_journal_tail(path, bytes.len(), true)?;
                }
                Err(_) => repair_journal_tail(path, cursor, false)?,
            }
            break;
        };
        let end = cursor + relative_end;
        let line = &bytes[cursor..end];
        if !line.is_empty() {
            records.push(serde_json::from_slice(line).map_err(|_| ControlInitError::Invalid)?);
        }
        cursor = end + 1;
    }
    validate_history(&records)?;
    Ok(records)
}

fn repair_journal_tail(
    path: &Path,
    length: usize,
    add_newline: bool,
) -> Result<(), ControlInitError> {
    let mut file = files::open_private_for_update(path)?;
    file.set_len(length as u64)
        .map_err(ControlInitError::Storage)?;
    if add_newline {
        file.seek(SeekFrom::End(0))
            .and_then(|_| file.write_all(b"\n"))
            .map_err(ControlInitError::Storage)?;
    }
    file.sync_all().map_err(ControlInitError::Storage)
}

fn authority_file_key(authority_id: &str) -> String {
    encode_digest(Sha256::digest(authority_id.as_bytes()).as_ref())
}

fn operation_file_key(operation_id: &str) -> String {
    encode_digest(Sha256::digest(operation_id.as_bytes()).as_ref())
}

fn encode_digest(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}
