use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;
use serde_json::{json, Value};
use thiserror::Error;
use tokio::sync::Notify;
use url::{Host, Url};

use crate::{
    access::ActorContext,
    catalog::{Catalog, CatalogError},
    store::{
        hex, AuthProfileRecord, AuthReplicaRecord, ControlStore, ProfileCreateOperation,
        ProfileCreatePhase, ProfileCreateWrite, ProfileDeleteWrite, ProviderDefaultProfileWrite,
        ProviderDescriptorRecord, ProviderDescriptorWrite, StoreError,
    },
};

const MAX_PROVIDER_BYTES: usize = 128;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
const MAX_MODELS: usize = 256;
const MAX_MODEL_BYTES: usize = 256;
const MAX_OPTIONS_BYTES: usize = 64 * 1024;
const MAX_PROFILE_LABEL_BYTES: usize = 256;
const MAX_API_KEY_BYTES: usize = 64 * 1024;
const MAX_ENDPOINTS_PER_SHARING: usize = 100;
const TOMBSTONE_RECONCILIATION_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Error)]
pub(crate) enum ProviderError {
    #[error("provider request is invalid")]
    Invalid,
    #[error("provider profile was not found")]
    NotFound,
    #[error("provider request is too large")]
    PayloadTooLarge,
    #[error("provider command conflicts with an existing operation")]
    Conflict,
    #[error("provider authority failed")]
    Internal,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PutProviderDescriptorRequest {
    kind: String,
    base_url: String,
    models: Vec<String>,
    options: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateAuthProfileRequest {
    kind: String,
    label: String,
    api_key: String,
    #[serde(default)]
    make_default: bool,
    sharing: SharingRequest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SetDefaultAuthProfileRequest {
    pub(crate) profile_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SharingRequest {
    mode: String,
    #[serde(default)]
    endpoint_ids: Vec<String>,
}

pub(crate) struct ProviderAuthority {
    store: Arc<ControlStore>,
    catalog: Arc<Catalog>,
    reconcile_signal: Arc<Notify>,
}

struct Secret(Vec<u8>);

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl ProviderAuthority {
    pub(crate) fn new(store: Arc<ControlStore>, catalog: Arc<Catalog>) -> Self {
        Self {
            store,
            catalog,
            reconcile_signal: Arc::new(Notify::new()),
        }
    }

    pub(crate) fn spawn_tombstone_reconciler(self: &Arc<Self>) {
        let authority = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                let tombstones_pending = authority
                    .reconcile_profile_tombstones()
                    .await
                    .unwrap_or(true);
                let profiles_pending = authority
                    .reconcile_profile_creates()
                    .await
                    .unwrap_or(true);
                if tombstones_pending || profiles_pending {
                    tokio::time::sleep(TOMBSTONE_RECONCILIATION_INTERVAL).await;
                } else {
                    authority.reconcile_signal.notified().await;
                }
            }
        });
    }

    async fn reconcile_profile_tombstones(&self) -> Result<bool, ProviderError> {
        let store = Arc::clone(&self.store);
        let (secret_refs, tombstones) = tokio::task::spawn_blocking(move || {
            Ok::<_, StoreError>((
                store.list_deleted_provider_secret_refs()?,
                store.list_auth_tombstones_for_reconciliation()?,
            ))
        })
        .await
        .map_err(|_| ProviderError::Internal)?
        .map_err(map_store_error)?;
        let secret_ref_count = secret_refs.len();
        let mut cleaned = BTreeSet::new();
        for secret_ref in secret_refs {
            let store = Arc::clone(&self.store);
            let reference = secret_ref.clone();
            if tokio::task::spawn_blocking(move || store.remove_provider_secret(&reference))
                .await
                .map_err(|_| ProviderError::Internal)?
                .map_err(map_store_error)
                .is_ok()
            {
                cleaned.insert(secret_ref);
            }
        }
        let cleanup_pending = cleaned.len() != secret_ref_count;
        let dispatchable = tombstones
            .into_iter()
            .filter(|(_, secret_ref)| cleaned.contains(secret_ref))
            .map(|(replica, _)| replica)
            .collect::<Vec<_>>();
        let tombstones_pending = self.dispatch_tombstones(&dispatchable).await?;
        Ok(cleanup_pending || tombstones_pending)
    }

    async fn reconcile_profile_creates(&self) -> Result<bool, ProviderError> {
        let store = Arc::clone(&self.store);
        let profile_ids = tokio::task::spawn_blocking(move || store.list_distributing_profile_ids())
            .await
            .map_err(|_| ProviderError::Internal)?
            .map_err(map_store_error)?;
        let pending = !profile_ids.is_empty();
        for profile_id in profile_ids {
            if self.distribute_profile(&profile_id).await.is_ok() {
                let store = Arc::clone(&self.store);
                let _ = tokio::task::spawn_blocking(move || {
                    store.complete_profile_create_by_id(&profile_id)
                })
                .await
                .map_err(|_| ProviderError::Internal)?;
            }
        }
        Ok(pending)
    }

    async fn dispatch_tombstones(
        &self,
        tombstones: &[AuthReplicaRecord],
    ) -> Result<bool, ProviderError> {
        let pending = tombstones
            .iter()
            .any(|tombstone| tombstone.kind == "tombstone" && tombstone.status != "removed");
        for tombstone in tombstones
            .iter()
            .filter(|tombstone| tombstone.kind == "tombstone" && tombstone.status != "removed")
        {
            let (status, observed_revision) = self.dispatch_tombstone(tombstone).await;
            let store = Arc::clone(&self.store);
            let profile_id = tombstone.profile_id.clone();
            let endpoint_id = tombstone.endpoint_id.clone();
            let revision = tombstone.revision;
            tokio::task::spawn_blocking(move || {
                store.mark_tombstone_replica(
                    &profile_id,
                    &endpoint_id,
                    revision,
                    status,
                    observed_revision,
                )
            })
            .await
            .map_err(|_| ProviderError::Internal)?
            .map_err(map_store_error)?;
        }
        Ok(pending)
    }

    async fn dispatch_tombstone(
        &self,
        tombstone: &AuthReplicaRecord,
    ) -> (&'static str, Option<u64>) {
        let body = json!({
            "schema": "zode.auth-replica.tombstone.v1",
            "authority_id": self.store.authority_id(),
            "provider": tombstone.provider,
            "revision": tombstone.revision,
        });
        match self
            .catalog
            .install_auth_replica(
                &tombstone.endpoint_id,
                &tombstone.profile_id,
                &tombstone.operation_id,
                body,
            )
            .await
        {
            Ok(response)
                if response["schema"] == "zode.auth-replica.v1"
                    && response["auth_profile_id"] == tombstone.profile_id
                    && response["authority_id"] == self.store.authority_id()
                    && response["provider"] == tombstone.provider
                    && response["status"] == "tombstoned"
                    && response["revision"].as_u64().unwrap_or_default() >= tombstone.revision =>
            {
                ("removed", response["revision"].as_u64())
            }
            Ok(response) => ("unreachable", response["revision"].as_u64()),
            Err(_) => ("unreachable", None),
        }
    }

    pub(crate) async fn put_descriptor(
        &self,
        actor: &ActorContext,
        idempotency_key: &str,
        provider: &str,
        mut request: PutProviderDescriptorRequest,
    ) -> Result<Value, ProviderError> {
        if !valid_identifier(provider, MAX_PROVIDER_BYTES)
            || !valid_text(idempotency_key, MAX_IDEMPOTENCY_KEY_BYTES)
            || request.kind != "openai_compatible"
            || request.models.is_empty()
            || request.models.len() > MAX_MODELS
            || request
                .models
                .iter()
                .any(|model| !valid_text(model, MAX_MODEL_BYTES))
            || request.options.keys().any(|key| sensitive_option_key(key))
            || contains_sensitive_option(&request.options)
        {
            return Err(ProviderError::Invalid);
        }
        request.base_url = normalize_base_url(&request.base_url)?;
        let models_json =
            serde_json::to_string(&request.models).map_err(|_| ProviderError::Invalid)?;
        let options_json =
            serde_json::to_string(&request.options).map_err(|_| ProviderError::Invalid)?;
        if models_json.len() > MAX_OPTIONS_BYTES || options_json.len() > MAX_OPTIONS_BYTES {
            return Err(ProviderError::PayloadTooLarge);
        }
        let keys = self.store.keys();
        let command_key = keys.digest(
            b"provider-descriptor-command-v1",
            &[provider.as_bytes(), idempotency_key.as_bytes()],
        );
        let request_fingerprint = keys.digest(
            b"provider-descriptor-request-v1",
            &[
                provider.as_bytes(),
                request.kind.as_bytes(),
                request.base_url.as_bytes(),
                models_json.as_bytes(),
                options_json.as_bytes(),
            ],
        );
        let write = ProviderDescriptorWrite {
            provider: provider.to_owned(),
            kind: request.kind,
            base_url: request.base_url,
            models_json,
            options_json,
            actor_key: *actor.actor_key(),
            command_key,
            request_fingerprint,
            created_at_ms: unix_millis()?,
        };
        let store = Arc::clone(&self.store);
        let record = tokio::task::spawn_blocking(move || store.put_provider_descriptor(write))
            .await
            .map_err(|_| ProviderError::Internal)?
            .map_err(map_store_error)?;
        descriptor_response(&record)
    }

    pub(crate) async fn list(&self) -> Result<Value, ProviderError> {
        let store = Arc::clone(&self.store);
        let records = tokio::task::spawn_blocking(move || {
            let descriptors = store.list_provider_descriptors()?;
            let mut records = Vec::with_capacity(descriptors.len());
            for descriptor in descriptors {
                let profiles = store.list_auth_profiles(&descriptor.provider)?;
                records.push((descriptor, profiles));
            }
            Ok::<_, StoreError>(records)
        })
        .await
        .map_err(|_| ProviderError::Internal)?
        .map_err(map_store_error)?;
        let providers = records
            .iter()
            .map(|(record, profiles)| {
                let default_profile_id = profiles
                    .iter()
                    .find(|profile| profile.is_default)
                    .map(|profile| profile.profile_id.clone());
                Ok(json!({
                    "provider": record.provider,
                    "descriptor": descriptor_value(record)?,
                    "default_profile_id": default_profile_id,
                    "auth_status": if profiles.is_empty() { "unconfigured" } else { "ready" },
                    "auth_profile_count": profiles.len(),
                }))
            })
            .collect::<Result<Vec<_>, ProviderError>>()?;
        Ok(json!({
            "schema": "zode.providers.v1",
            "providers": providers,
        }))
    }

    pub(crate) async fn create_profile(
        &self,
        actor: &ActorContext,
        idempotency_key: &str,
        provider: &str,
        mut request: CreateAuthProfileRequest,
    ) -> Result<Value, ProviderError> {
        if !valid_identifier(provider, MAX_PROVIDER_BYTES)
            || !valid_text(idempotency_key, MAX_IDEMPOTENCY_KEY_BYTES)
            || request.kind != "api_key"
            || !valid_text(&request.label, MAX_PROFILE_LABEL_BYTES)
            || request.api_key.is_empty()
            || request.api_key.len() > MAX_API_KEY_BYTES
            || request.api_key.contains('\0')
        {
            return Err(if request.api_key.len() > MAX_API_KEY_BYTES {
                ProviderError::PayloadTooLarge
            } else {
                ProviderError::Invalid
            });
        }
        normalize_sharing(&mut request.sharing)?;
        let sharing_json = serde_json::to_string(&json!({
            "mode": request.sharing.mode,
            "endpoint_ids": request.sharing.endpoint_ids,
        }))
        .map_err(|_| ProviderError::Invalid)?;
        let keys = self.store.keys();
        let command_key = keys.digest(
            b"auth-profile-create-command-v1",
            &[provider.as_bytes(), idempotency_key.as_bytes()],
        );
        let request_fingerprint = keys.digest(
            b"auth-profile-create-request-v1",
            &[
                provider.as_bytes(),
                request.kind.as_bytes(),
                request.label.as_bytes(),
                request.api_key.as_bytes(),
                if request.make_default {
                    b"default"
                } else {
                    b"not-default"
                },
                sharing_json.as_bytes(),
            ],
        );
        let profile_id = random_profile_id()?;
        let secret_ref = hex(&keys.digest(
            b"auth-profile-secret-reference-v1",
            &[provider.as_bytes(), profile_id.as_bytes(), b"1"],
        ));
        let write = ProfileCreateWrite {
            actor_key: *actor.actor_key(),
            provider: provider.to_owned(),
            command_key,
            request_fingerprint,
            profile_id,
            label: request.label,
            secret_ref,
            sharing_json,
            make_default: request.make_default,
            created_at_ms: unix_millis()?,
        };
        let store = Arc::clone(&self.store);
        let operation = tokio::task::spawn_blocking(move || store.begin_profile_create(write))
            .await
            .map_err(|_| ProviderError::Internal)?
            .map_err(map_store_error)?;
        let profile = match operation.phase {
            ProfileCreatePhase::Pending => {
                let store = Arc::clone(&self.store);
                let reference = operation.secret_ref.clone();
                let secret = Secret(request.api_key.into_bytes());
                tokio::task::spawn_blocking(move || {
                    store.stage_provider_secret(&reference, &secret.0)
                })
                .await
                .map_err(|_| ProviderError::Internal)?
                .map_err(map_store_error)?;
                let store = Arc::clone(&self.store);
                let operation_for_commit = operation.clone();
                let profile = tokio::task::spawn_blocking(move || {
                    store.commit_profile_create(&operation_for_commit)
                })
                .await
                .map_err(|_| ProviderError::Internal)?
                .map_err(map_store_error)?;
                self.spawn_profile_distribution(operation);
                profile
            }
            ProfileCreatePhase::Distributing | ProfileCreatePhase::Complete => {
                let store = Arc::clone(&self.store);
                let profile_id = operation.profile_id.clone();
                let profile = tokio::task::spawn_blocking(move || {
                    store
                        .get_auth_profile(&profile_id)
                        .map_err(map_store_error)
                        .and_then(|record| record.ok_or(ProviderError::Internal))
                })
                .await
                .map_err(|_| ProviderError::Internal)??;
                if operation.phase == ProfileCreatePhase::Distributing {
                    self.spawn_profile_distribution(operation);
                }
                profile
            }
        };
        self.profile_response(&profile).await
    }

    fn spawn_profile_distribution(&self, operation: ProfileCreateOperation) {
        self.reconcile_signal.notify_one();
        let store = Arc::clone(&self.store);
        let catalog = Arc::clone(&self.catalog);
        tokio::spawn(async move {
            let authority = Self {
                store: Arc::clone(&store),
                catalog,
                reconcile_signal: Arc::new(Notify::new()),
            };
            if authority.distribute_profile(&operation.profile_id).await.is_ok() {
                let _ = tokio::task::spawn_blocking(move || {
                    store.complete_profile_create(&operation)
                })
                .await;
            }
        });
    }

    pub(crate) async fn list_profiles(&self, provider: &str) -> Result<Value, ProviderError> {
        if !valid_identifier(provider, MAX_PROVIDER_BYTES) {
            return Err(ProviderError::Invalid);
        }
        let store = Arc::clone(&self.store);
        let provider = provider.to_owned();
        let profiles = tokio::task::spawn_blocking(move || store.list_auth_profiles(&provider))
            .await
            .map_err(|_| ProviderError::Internal)?
            .map_err(map_store_error)?;
        let mut items = Vec::with_capacity(profiles.len());
        for profile in profiles {
            items.push(self.profile_response(&profile).await?);
        }
        Ok(json!({
            "schema": "zode.auth-profiles.v1",
            "items": items,
        }))
    }

    pub(crate) async fn set_default_profile(
        &self,
        actor: &ActorContext,
        idempotency_key: &str,
        provider: &str,
        request: SetDefaultAuthProfileRequest,
    ) -> Result<Value, ProviderError> {
        if !valid_identifier(provider, MAX_PROVIDER_BYTES)
            || !valid_text(idempotency_key, MAX_IDEMPOTENCY_KEY_BYTES)
            || !valid_identifier(&request.profile_id, 128)
        {
            return Err(ProviderError::Invalid);
        }
        let keys = self.store.keys();
        let command_key = keys.digest(
            b"auth-profile-default-command-v1",
            &[provider.as_bytes(), idempotency_key.as_bytes()],
        );
        let request_fingerprint = keys.digest(
            b"auth-profile-default-request-v1",
            &[provider.as_bytes(), request.profile_id.as_bytes()],
        );
        let write = ProviderDefaultProfileWrite {
            actor_key: *actor.actor_key(),
            provider: provider.to_owned(),
            command_key,
            request_fingerprint,
            profile_id: request.profile_id,
            created_at_ms: unix_millis()?,
        };
        let store = Arc::clone(&self.store);
        let (profile, replayed) =
            tokio::task::spawn_blocking(move || store.set_provider_default_profile(write))
                .await
                .map_err(|_| ProviderError::Internal)?
                .map_err(map_store_error)?;
        let mut response = self.profile_response(&profile).await?;
        if replayed {
            response["is_default"] = Value::Bool(true);
        }
        Ok(response)
    }

    pub(crate) async fn delete_profile(
        &self,
        actor: &ActorContext,
        idempotency_key: &str,
        provider: &str,
        profile_id: &str,
    ) -> Result<Value, ProviderError> {
        if !valid_identifier(provider, MAX_PROVIDER_BYTES)
            || !valid_text(idempotency_key, MAX_IDEMPOTENCY_KEY_BYTES)
            || !valid_identifier(profile_id, 128)
        {
            return Err(ProviderError::Invalid);
        }
        let keys = self.store.keys();
        let command_key = keys.digest(
            b"auth-profile-delete-command-v1",
            &[
                provider.as_bytes(),
                profile_id.as_bytes(),
                idempotency_key.as_bytes(),
            ],
        );
        let request_fingerprint = keys.digest(
            b"auth-profile-delete-request-v1",
            &[provider.as_bytes(), profile_id.as_bytes()],
        );
        let actor_key = *actor.actor_key();
        let write = ProfileDeleteWrite {
            actor_key,
            provider: provider.to_owned(),
            profile_id: profile_id.to_owned(),
            command_key,
            request_fingerprint,
            created_at_ms: unix_millis()?,
        };
        let store = Arc::clone(&self.store);
        let (_revision, profile, tombstones, receipt) =
            tokio::task::spawn_blocking(move || store.begin_profile_delete(write))
                .await
                .map_err(|_| ProviderError::Internal)?
                .map_err(map_store_error)?;
        if let Some(receipt) = receipt {
            return serde_json::from_str(&receipt).map_err(|_| ProviderError::Internal);
        }
        self.reconcile_signal.notify_one();
        let store = Arc::clone(&self.store);
        let secret_ref = profile.secret_ref.clone();
        tokio::task::spawn_blocking(move || store.remove_provider_secret(&secret_ref))
            .await
            .map_err(|_| ProviderError::Internal)?
            .map_err(map_store_error)?;
        self.dispatch_tombstones(&tombstones).await?;
        let store = Arc::clone(&self.store);
        let profile_id_owned = profile_id.to_owned();
        let replicas =
            tokio::task::spawn_blocking(move || store.list_auth_replicas(&profile_id_owned))
                .await
                .map_err(|_| ProviderError::Internal)?
                .map_err(map_store_error)?;
        let pending = replicas.iter().any(|replica| replica.status != "removed");
        let response = json!({
            "schema": "zode.auth-profile-delete.v1",
            "provider": provider,
            "auth_profile_id": profile_id,
            "status": if pending { "removal_pending" } else { "deleted" },
            "distribution": replica_list_value(&replicas, self.store.authority_id()),
        });
        let response_json =
            serde_json::to_string(&response).map_err(|_| ProviderError::Internal)?;
        let store = Arc::clone(&self.store);
        let provider_owned = provider.to_owned();
        let persisted = tokio::task::spawn_blocking(move || {
            store.complete_profile_delete(&actor_key, &provider_owned, &command_key, &response_json)
        })
        .await
        .map_err(|_| ProviderError::Internal)?
        .map_err(map_store_error)?;
        serde_json::from_str(&persisted).map_err(|_| ProviderError::Internal)
    }

    pub(crate) async fn list_replicas(&self, profile_id: &str) -> Result<Value, ProviderError> {
        let store = Arc::clone(&self.store);
        let profile_id = profile_id.to_owned();
        let replicas = tokio::task::spawn_blocking(move || store.list_auth_replicas(&profile_id))
            .await
            .map_err(|_| ProviderError::Internal)?
            .map_err(map_store_error)?;
        Ok(replica_list_response(replicas, self.store.authority_id()))
    }

    async fn distribute_profile(&self, profile_id: &str) -> Result<(), ProviderError> {
        let store = Arc::clone(&self.store);
        let profile_id_owned = profile_id.to_owned();
        let (profile, replicas, secret) = tokio::task::spawn_blocking(move || {
            let profile = store
                .get_auth_profile(&profile_id_owned)?
                .ok_or(StoreError::Integrity)?;
            let replicas = store.list_auth_replicas(&profile_id_owned)?;
            let secret = store
                .load_provider_secret(&profile.secret_ref)?
                .ok_or(StoreError::Integrity)?;
            Ok::<_, StoreError>((profile, replicas, secret))
        })
        .await
        .map_err(|_| ProviderError::Internal)?
        .map_err(map_store_error)?;
        let secret = Secret(secret);
        let secret_text = std::str::from_utf8(&secret.0).map_err(|_| ProviderError::Internal)?;
        for replica in replicas
            .iter()
            .filter(|replica| replica.kind == "install" && replica.status != "ready")
        {
            let response = self
                .catalog
                .install_auth_replica(
                    &replica.endpoint_id,
                    &profile.profile_id,
                    &replica.operation_id,
                    json!({
                        "schema": "zode.auth-replica.install.v1",
                        "authority_id": self.store.authority_id(),
                        "provider": profile.provider,
                        "kind": "api_key",
                        "revision": profile.revision,
                        "credential_schema": "openai-compatible.api-key.v1",
                        "expires_at_ms": Value::Null,
                        "secret": {
                            "encoding": "application/zode-secret-envelope",
                            "payload": secret_text,
                        }
                    }),
                )
                .await
                .map_err(map_catalog_error)?;
            if response["schema"] != "zode.auth-replica.v1"
                || response["auth_profile_id"] != profile.profile_id
                || response["authority_id"] != self.store.authority_id()
                || response["provider"] != profile.provider
                || response["revision"] != profile.revision
                || response["status"] != "ready"
            {
                return Err(ProviderError::Internal);
            }
            let store = Arc::clone(&self.store);
            let profile_id = profile.profile_id.clone();
            let endpoint_id = replica.endpoint_id.clone();
            let revision = profile.revision;
            tokio::task::spawn_blocking(move || {
                store.mark_replica_ready(&profile_id, &endpoint_id, revision)
            })
            .await
            .map_err(|_| ProviderError::Internal)?
            .map_err(map_store_error)?;
        }
        Ok(())
    }

    async fn profile_response(&self, profile: &AuthProfileRecord) -> Result<Value, ProviderError> {
        let store = Arc::clone(&self.store);
        let profile_id = profile.profile_id.clone();
        let replicas = tokio::task::spawn_blocking(move || store.list_auth_replicas(&profile_id))
            .await
            .map_err(|_| ProviderError::Internal)?
            .map_err(map_store_error)?;
        let endpoint_ids: Value = serde_json::from_str(&profile.endpoint_ids_json)
            .map_err(|_| ProviderError::Internal)?;
        let status = if replicas.iter().any(|replica| replica.status == "unreachable") {
            "unreachable"
        } else if replicas.iter().all(|replica| replica.status == "ready") {
            "ready"
        } else {
            "pending"
        };
        Ok(json!({
            "schema": "zode.auth-profile.v1",
            "auth_profile_id": profile.profile_id,
            "profile_id": profile.profile_id,
            "provider": profile.provider,
            "kind": profile.kind,
            "label": profile.label,
            "status": status,
            "revision": profile.revision,
            "descriptor_revision": profile.descriptor_revision,
            "expires_at_ms": Value::Null,
            "is_default": profile.is_default,
            "sharing": {
                "mode": profile.sharing_mode,
                "endpoint_ids": endpoint_ids,
            },
            "distribution": replica_list_value(&replicas, self.store.authority_id()),
        }))
    }
}

fn descriptor_response(record: &ProviderDescriptorRecord) -> Result<Value, ProviderError> {
    let descriptor = descriptor_value(record)?;
    Ok(json!({
        "schema": "zode.provider-descriptor.v1",
        "provider": record.provider,
        "revision": descriptor["revision"],
        "kind": descriptor["kind"],
        "base_url": descriptor["base_url"],
        "models": descriptor["models"],
        "options": descriptor["options"],
    }))
}

fn descriptor_value(record: &ProviderDescriptorRecord) -> Result<Value, ProviderError> {
    let models: Value =
        serde_json::from_str(&record.models_json).map_err(|_| ProviderError::Internal)?;
    let options: Value =
        serde_json::from_str(&record.options_json).map_err(|_| ProviderError::Internal)?;
    Ok(json!({
        "revision": record.revision,
        "kind": record.kind,
        "base_url": record.base_url,
        "models": models,
        "options": options,
    }))
}

fn normalize_base_url(value: &str) -> Result<String, ProviderError> {
    if value.is_empty() || value.len() > 2 * 1024 {
        return Err(if value.len() > 2 * 1024 {
            ProviderError::PayloadTooLarge
        } else {
            ProviderError::Invalid
        });
    }
    let mut url = Url::parse(value).map_err(|_| ProviderError::Invalid)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (url.scheme() != "https" && !(url.scheme() == "http" && is_loopback(&url)))
    {
        return Err(ProviderError::Invalid);
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string().trim_end_matches('/').to_owned())
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

fn valid_identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !value.chars().any(char::is_control)
        && value.trim() == value
}

fn sensitive_option_key(value: &str) -> bool {
    let key = value.to_ascii_lowercase().replace('-', "_");
    key == "authorization"
        || key == "headers"
        || key.contains("api_key")
        || key.contains("access_token")
        || key.contains("refresh_token")
        || key.contains("secret")
}

fn contains_sensitive_option(options: &BTreeMap<String, Value>) -> bool {
    options.values().any(sensitive_value)
}

fn normalize_sharing(sharing: &mut SharingRequest) -> Result<(), ProviderError> {
    if sharing.endpoint_ids.len() > MAX_ENDPOINTS_PER_SHARING
        || sharing
            .endpoint_ids
            .iter()
            .any(|endpoint_id| !valid_text(endpoint_id, 256))
    {
        return Err(ProviderError::Invalid);
    }
    sharing.endpoint_ids.sort();
    sharing.endpoint_ids.dedup();
    match sharing.mode.as_str() {
        "none" if sharing.endpoint_ids.is_empty() => Ok(()),
        "selected" if !sharing.endpoint_ids.is_empty() => Ok(()),
        _ => Err(ProviderError::Invalid),
    }
}

fn random_profile_id() -> Result<String, ProviderError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| ProviderError::Internal)?;
    Ok(format!("profile-{}", hex(&bytes)))
}

fn replica_list_response(replicas: Vec<AuthReplicaRecord>, authority_id: &str) -> Value {
    json!({
        "schema": "zode.auth-replicas.v1",
        "items": replica_list_value(&replicas, authority_id),
    })
}

fn replica_list_value(replicas: &[AuthReplicaRecord], authority_id: &str) -> Vec<Value> {
    replicas
        .iter()
        .map(|replica| {
            json!({
                "auth_profile_id": replica.profile_id,
                "endpoint_id": replica.endpoint_id,
                "authority_id": authority_id,
                "provider": replica.provider,
                "revision": replica.revision,
                "installed_revision": replica.observed_revision,
                "status": replica.status,
                "observed_revision": replica.observed_revision,
            })
        })
        .collect()
}

fn sensitive_value(value: &Value) -> bool {
    match value {
        Value::Object(object) => object
            .iter()
            .any(|(key, value)| sensitive_option_key(key) || sensitive_value(value)),
        Value::Array(values) => values.iter().any(sensitive_value),
        _ => false,
    }
}

fn unix_millis() -> Result<i64, ProviderError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .ok_or(ProviderError::Internal)
}

fn map_store_error(error: StoreError) -> ProviderError {
    match error {
        StoreError::Conflict => ProviderError::Conflict,
        StoreError::NotFound => ProviderError::NotFound,
        StoreError::Integrity | StoreError::Internal => ProviderError::Internal,
    }
}

fn map_catalog_error(error: CatalogError) -> ProviderError {
    match error {
        CatalogError::Invalid | CatalogError::NotFound | CatalogError::PayloadTooLarge => {
            ProviderError::Invalid
        }
        CatalogError::Conflict => ProviderError::Conflict,
        CatalogError::EndpointUnavailable | CatalogError::Internal => ProviderError::Internal,
    }
}
