use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use futures_util::StreamExt;
use reqwest::{redirect::Policy, Client, Response as ProviderResponse};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::{Mutex, Notify};
use url::{Host, Url};
use zeroize::Zeroize;

use crate::{
    access::ActorContext,
    catalog::{Catalog, CatalogError},
    config::ProviderAuthAdapterConfig,
    store::{
        hex, AuthProfileRecord, AuthRefreshRecord, AuthRefreshSuccess, AuthRefreshWrite,
        AuthReplicaRecord, ControlStore, OAuthAttemptRecord, OAuthAttemptSuccess,
        OAuthAttemptWrite, OAuthTicketRedemption, OAuthTicketWrite, ProfileCreatePhase,
        ProfileCreateWrite, ProfileDeleteWrite, ProfileRotationWrite, ProfileSharingWrite,
        ProviderControlEvent, ProviderDefaultProfileWrite, ProviderDescriptorRecord,
        ProviderDescriptorWrite, StoreError,
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
const OAUTH_ATTEMPT_LIFETIME_MS: i64 = 15 * 60 * 1000;
const OAUTH_TICKET_LIFETIME_MS: i64 = 5 * 60 * 1000;
const PROVIDER_AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_OAUTH_CODE_BYTES: usize = 16 * 1024;
const MAX_OAUTH_CAPABILITY_BYTES: usize = 1024;
const MAX_OAUTH_RESPONSE_BYTES: usize = 128 * 1024;

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
    #[error("the original provider profile response receipt is unavailable")]
    ReceiptUnavailable,
    #[error("the auth profile requires relogin")]
    ReauthRequired,
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
    #[serde(default)]
    label: Option<String>,
    api_key: String,
    #[serde(default)]
    make_default: bool,
    #[serde(default)]
    sharing: Option<SharingRequest>,
    #[serde(default)]
    replace_auth_profile_id: Option<String>,
}

impl CreateAuthProfileRequest {
    pub(crate) fn is_replacement(&self) -> bool {
        self.replace_auth_profile_id.is_some()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SetDefaultAuthProfileRequest {
    pub(crate) profile_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StartOAuthAttemptRequest {
    label: String,
    #[serde(default)]
    make_default: bool,
    sharing: SharingRequest,
    #[serde(default)]
    replace_auth_profile_id: Option<String>,
}

#[derive(Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    token_type: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

impl Drop for OAuthTokenResponse {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.token_type.zeroize();
    }
}

#[derive(Deserialize, Serialize)]
struct StoredOAuthCredential {
    schema: String,
    access_token: String,
    refresh_token: Option<String>,
    token_type: String,
    expires_at_ms: Option<i64>,
}

enum RefreshDispatchError {
    Unknown,
    Rejected,
    Internal,
}

impl Drop for StoredOAuthCredential {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.token_type.zeroize();
    }
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
    auth_adapters: BTreeMap<String, ProviderAuthAdapterConfig>,
    management_origin: String,
    provider_client: Client,
    secret_store_lock: Mutex<()>,
    reconcile_signal: Arc<Notify>,
    control_signal: Arc<Notify>,
}

struct Secret(Vec<u8>);

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl ProviderAuthority {
    pub(crate) fn new(
        store: Arc<ControlStore>,
        catalog: Arc<Catalog>,
        auth_adapters: &[ProviderAuthAdapterConfig],
        management_origin: String,
    ) -> Result<Self, ProviderError> {
        store
            .cleanup_unreferenced_provider_secrets()
            .map_err(map_store_error)?;
        let provider_client = Client::builder()
            .redirect(Policy::none())
            .timeout(PROVIDER_AUTH_TIMEOUT)
            .build()
            .map_err(|_| ProviderError::Internal)?;
        Ok(Self {
            store,
            catalog,
            auth_adapters: auth_adapters
                .iter()
                .cloned()
                .map(|adapter| (adapter.provider().to_owned(), adapter))
                .collect(),
            management_origin,
            provider_client,
            secret_store_lock: Mutex::new(()),
            reconcile_signal: Arc::new(Notify::new()),
            control_signal: Arc::new(Notify::new()),
        })
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
                    .reconcile_profile_distributions()
                    .await
                    .unwrap_or(true);
                let refreshes_pending = authority.reconcile_auth_refreshes().await.unwrap_or(true);
                let secret_cleanup_pending = authority
                    .reconcile_provider_secret_cleanup()
                    .await
                    .unwrap_or(true);
                if tombstones_pending
                    || profiles_pending
                    || refreshes_pending
                    || secret_cleanup_pending
                {
                    tokio::time::sleep(TOMBSTONE_RECONCILIATION_INTERVAL).await;
                } else {
                    authority.reconcile_signal.notified().await;
                }
            }
        });
    }

    async fn reconcile_provider_secret_cleanup(&self) -> Result<bool, ProviderError> {
        let _guard = self.secret_store_lock.lock().await;
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.cleanup_unreferenced_provider_secrets())
            .await
            .map_err(|_| ProviderError::Internal)?
            .map_err(map_store_error)?;
        Ok(false)
    }

    pub(crate) async fn observe_endpoint_unreachable(
        &self,
        endpoint_id: &str,
    ) -> Result<(), ProviderError> {
        let store = Arc::clone(&self.store);
        let endpoint_id = endpoint_id.to_owned();
        tokio::task::spawn_blocking(move || store.mark_endpoint_replicas_unreachable(&endpoint_id))
            .await
            .map_err(|_| ProviderError::Internal)?
            .map_err(map_store_error)?;
        self.reconcile_signal.notify_one();
        Ok(())
    }

    pub(crate) fn request_reconciliation(&self) {
        self.reconcile_signal.notify_one();
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
            .filter(|(_, secret_ref)| {
                secret_ref
                    .as_ref()
                    .map(|secret_ref| cleaned.contains(secret_ref))
                    .unwrap_or(true)
            })
            .map(|(replica, _)| replica)
            .collect::<Vec<_>>();
        let tombstones_pending = self.dispatch_tombstones(&dispatchable).await?;
        Ok(cleanup_pending || tombstones_pending)
    }

    async fn reconcile_profile_distributions(&self) -> Result<bool, ProviderError> {
        let store = Arc::clone(&self.store);
        let profile_ids =
            tokio::task::spawn_blocking(move || store.list_pending_profile_distribution_ids())
                .await
                .map_err(|_| ProviderError::Internal)?
                .map_err(map_store_error)?;
        let pending = !profile_ids.is_empty();
        for profile_id in profile_ids {
            if self.distribute_profile(&profile_id).await.is_ok() {
                let store = Arc::clone(&self.store);
                let _ =
                    tokio::task::spawn_blocking(move || store.complete_profile_create(&profile_id))
                        .await
                        .map_err(|_| ProviderError::Internal)?;
            }
        }
        Ok(pending)
    }

    async fn reconcile_auth_refreshes(&self) -> Result<bool, ProviderError> {
        let store = Arc::clone(&self.store);
        let operations = tokio::task::spawn_blocking(move || store.list_pending_auth_refreshes())
            .await
            .map_err(|_| ProviderError::Internal)?
            .map_err(map_store_error)?;
        for operation in &operations {
            if operation.status == "dispatching"
                && !matches!(operation.recovery.as_str(), "same_operation_id_idempotent")
            {
                self.finish_refresh_unknown(operation).await?;
                continue;
            }
            let _ = self.dispatch_auth_refresh(operation.clone()).await;
        }
        Ok(!operations.is_empty())
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
                    "auth_methods": if self.auth_adapters.contains_key(&record.provider) {
                        json!(["api_key", "oauth"])
                    } else {
                        json!(["api_key"])
                    },
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

    pub(crate) async fn start_oauth_attempt(
        &self,
        actor: &ActorContext,
        idempotency_key: &str,
        provider: &str,
        mut request: StartOAuthAttemptRequest,
    ) -> Result<Value, ProviderError> {
        if !valid_identifier(provider, MAX_PROVIDER_BYTES)
            || !valid_text(idempotency_key, MAX_IDEMPOTENCY_KEY_BYTES)
            || !valid_text(&request.label, MAX_PROFILE_LABEL_BYTES)
            || request
                .replace_auth_profile_id
                .as_ref()
                .is_some_and(|profile_id| !valid_identifier(profile_id, 128))
            || !self.auth_adapters.contains_key(provider)
        {
            return Err(ProviderError::Invalid);
        }
        normalize_sharing(&mut request.sharing)?;
        let sharing_json = serde_json::to_string(&json!({
            "mode": request.sharing.mode,
            "endpoint_ids": request.sharing.endpoint_ids,
        }))
        .map_err(|_| ProviderError::Invalid)?;
        let keys = self.store.keys();
        let command_key = keys.digest(
            b"oauth-attempt-command-v1",
            &[provider.as_bytes(), idempotency_key.as_bytes()],
        );
        let request_fingerprint = keys.digest(
            b"oauth-attempt-request-v1",
            &[
                provider.as_bytes(),
                request.label.as_bytes(),
                if request.make_default {
                    b"default"
                } else {
                    b"not-default"
                },
                sharing_json.as_bytes(),
                request
                    .replace_auth_profile_id
                    .as_deref()
                    .unwrap_or("")
                    .as_bytes(),
            ],
        );
        let attempt_id = random_resource_id("oauth-attempt")?;
        let profile_id = request
            .replace_auth_profile_id
            .clone()
            .unwrap_or(random_profile_id()?);
        let created_at_ms = unix_millis()?;
        let expires_at_ms = created_at_ms
            .checked_add(OAUTH_ATTEMPT_LIFETIME_MS)
            .ok_or(ProviderError::Internal)?;
        let event_json = serde_json::to_string(&json!({
            "schema": "zode.oauth-attempt-event.v1",
            "type": "attempt_started",
            "attempt_id": attempt_id,
            "status": "active",
        }))
        .map_err(|_| ProviderError::Internal)?;
        let write = OAuthAttemptWrite {
            attempt_id,
            actor_key: *actor.actor_key(),
            provider: provider.to_owned(),
            command_key,
            request_fingerprint,
            profile_id,
            replace_profile_id: request.replace_auth_profile_id,
            label: request.label,
            sharing_json,
            make_default: request.make_default,
            created_at_ms,
            expires_at_ms,
        };
        let store = Arc::clone(&self.store);
        let attempt =
            tokio::task::spawn_blocking(move || store.begin_oauth_attempt(write, &event_json))
                .await
                .map_err(|_| ProviderError::Internal)?
                .map_err(map_store_error)?;
        self.control_signal.notify_waiters();
        oauth_attempt_value(&attempt)
    }

    pub(crate) async fn get_oauth_attempt(
        &self,
        actor: &ActorContext,
        attempt_id: &str,
    ) -> Result<Value, ProviderError> {
        let attempt = self.load_oauth_attempt(actor, attempt_id).await?;
        oauth_attempt_value(&attempt)
    }

    pub(crate) async fn mint_oauth_ticket(
        &self,
        actor: &ActorContext,
        idempotency_key: &str,
        attempt_id: &str,
    ) -> Result<Value, ProviderError> {
        if !valid_identifier(attempt_id, 128)
            || !valid_text(idempotency_key, MAX_IDEMPOTENCY_KEY_BYTES)
        {
            return Err(ProviderError::Invalid);
        }
        let attempt = self.load_oauth_attempt(actor, attempt_id).await?;
        if attempt.status != "active" {
            return Err(ProviderError::Conflict);
        }
        let ticket_bytes = self.store.keys().digest(
            b"oauth-authorize-ticket-value-v1",
            &[
                actor.actor_key(),
                attempt_id.as_bytes(),
                idempotency_key.as_bytes(),
            ],
        );
        let ticket = URL_SAFE_NO_PAD.encode(ticket_bytes);
        let ticket_digest = self
            .store
            .keys()
            .digest(b"oauth-authorize-ticket-digest-v1", &[ticket.as_bytes()]);
        let now = unix_millis()?;
        let expires_at_ms = now
            .checked_add(OAUTH_TICKET_LIFETIME_MS)
            .ok_or(ProviderError::Internal)?
            .min(attempt.expires_at_ms);
        let write = OAuthTicketWrite {
            actor_key: *actor.actor_key(),
            attempt_id: attempt_id.to_owned(),
            ticket_digest,
            expires_at_ms,
            created_at_ms: now,
        };
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.mint_oauth_ticket(write))
            .await
            .map_err(|_| ProviderError::Internal)?
            .map_err(map_store_error)?;
        Ok(json!({
            "schema": "zode.oauth-authorize-ticket.v1",
            "attempt_id": attempt_id,
            "ticket": ticket,
        }))
    }

    pub(crate) async fn redeem_oauth_ticket(
        &self,
        actor: &ActorContext,
        attempt_id: &str,
        ticket: &str,
    ) -> Result<String, ProviderError> {
        if !valid_identifier(attempt_id, 128)
            || !valid_capability(ticket, MAX_OAUTH_CAPABILITY_BYTES)
        {
            return Err(ProviderError::Invalid);
        }
        let attempt = self.load_oauth_attempt(actor, attempt_id).await?;
        let adapter = self
            .auth_adapters
            .get(&attempt.provider)
            .ok_or(ProviderError::Conflict)?;
        let keys = self.store.keys();
        let ticket_digest = keys.digest(b"oauth-authorize-ticket-digest-v1", &[ticket.as_bytes()]);
        let state_bytes = keys.digest(
            b"oauth-provider-state-value-v1",
            &[actor.actor_key(), attempt_id.as_bytes(), ticket.as_bytes()],
        );
        let state = URL_SAFE_NO_PAD.encode(state_bytes);
        let state_digest = keys.digest(b"oauth-provider-state-digest-v1", &[state.as_bytes()]);
        let verifier_left = keys.digest(
            b"oauth-pkce-verifier-left-v1",
            &[actor.actor_key(), attempt_id.as_bytes(), ticket.as_bytes()],
        );
        let verifier_right = keys.digest(
            b"oauth-pkce-verifier-right-v1",
            &[actor.actor_key(), attempt_id.as_bytes(), ticket.as_bytes()],
        );
        let mut verifier_bytes = [0_u8; 64];
        verifier_bytes[..32].copy_from_slice(&verifier_left);
        verifier_bytes[32..].copy_from_slice(&verifier_right);
        let mut verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);
        verifier_bytes.zeroize();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let pkce_secret_ref = hex(&keys.digest(
            b"oauth-pkce-secret-reference-v1",
            &[attempt_id.as_bytes(), &state_digest],
        ));
        let _secret_guard = self.secret_store_lock.lock().await;
        let store = Arc::clone(&self.store);
        let reference = pkce_secret_ref.clone();
        let verifier_secret = Secret(verifier.as_bytes().to_vec());
        tokio::task::spawn_blocking(move || {
            store.stage_provider_secret(&reference, &verifier_secret.0)
        })
        .await
        .map_err(|_| ProviderError::Internal)?
        .map_err(map_store_error)?;
        self.reconcile_signal.notify_one();
        let redeemed_at_ms = unix_millis()?;
        let event_json = serde_json::to_string(&json!({
            "schema": "zode.oauth-attempt-event.v1",
            "type": "provider_redirected",
            "attempt_id": attempt_id,
            "status": "active",
        }))
        .map_err(|_| ProviderError::Internal)?;
        let redemption = OAuthTicketRedemption {
            actor_key: *actor.actor_key(),
            attempt_id: attempt_id.to_owned(),
            ticket_digest,
            state_digest,
            pkce_secret_ref,
            redeemed_at_ms,
        };
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.redeem_oauth_ticket(redemption, &event_json))
            .await
            .map_err(|_| ProviderError::Internal)?
            .map_err(map_store_error)?;
        drop(_secret_guard);
        self.control_signal.notify_waiters();

        let mut authorization_url =
            Url::parse(adapter.authorization_endpoint()).map_err(|_| ProviderError::Internal)?;
        let redirect_uri = self.oauth_redirect_uri();
        {
            let mut query = authorization_url.query_pairs_mut();
            query.append_pair("response_type", "code");
            query.append_pair("client_id", adapter.client_id());
            query.append_pair("redirect_uri", &redirect_uri);
            query.append_pair("state", &state);
            query.append_pair("code_challenge", &challenge);
            query.append_pair("code_challenge_method", "S256");
            if !adapter.scopes().is_empty() {
                query.append_pair("scope", &adapter.scopes().join(" "));
            }
        }
        verifier.zeroize();
        Ok(authorization_url.to_string())
    }

    pub(crate) async fn cancel_oauth_attempt(
        &self,
        actor: &ActorContext,
        idempotency_key: &str,
        attempt_id: &str,
    ) -> Result<Value, ProviderError> {
        if !valid_identifier(attempt_id, 128)
            || !valid_text(idempotency_key, MAX_IDEMPOTENCY_KEY_BYTES)
        {
            return Err(ProviderError::Invalid);
        }
        let attempt = self.load_oauth_attempt(actor, attempt_id).await?;
        if attempt.status != "active" {
            return oauth_attempt_value(&attempt);
        }
        let finished_at_ms = unix_millis()?;
        let event_json = terminal_oauth_event(attempt_id, "cancelled", "cancelled")?;
        let store = Arc::clone(&self.store);
        let actor_key = *actor.actor_key();
        let attempt_id_owned = attempt_id.to_owned();
        let finished = tokio::task::spawn_blocking(move || {
            store.finish_oauth_attempt(
                &actor_key,
                &attempt_id_owned,
                "cancelled",
                "cancelled",
                finished_at_ms,
                &event_json,
            )
        })
        .await
        .map_err(|_| ProviderError::Internal)?
        .map_err(map_store_error)?;
        self.reconcile_signal.notify_one();
        self.control_signal.notify_waiters();
        oauth_attempt_value(&finished)
    }

    pub(crate) async fn oauth_callback(
        &self,
        actor: &ActorContext,
        state: &str,
        code: Option<&str>,
        error: Option<&str>,
    ) -> Result<String, ProviderError> {
        if !valid_capability(state, MAX_OAUTH_CAPABILITY_BYTES)
            || code.is_some_and(|value| !valid_capability(value, MAX_OAUTH_CODE_BYTES))
            || error.is_some_and(|value| !valid_identifier(value, 256))
            || (code.is_some() == error.is_some())
        {
            return Err(ProviderError::Invalid);
        }
        let state_digest = self
            .store
            .keys()
            .digest(b"oauth-provider-state-digest-v1", &[state.as_bytes()]);
        let store = Arc::clone(&self.store);
        let actor_key = *actor.actor_key();
        let attempt = tokio::task::spawn_blocking(move || {
            store.find_oauth_attempt_by_state(&actor_key, &state_digest)
        })
        .await
        .map_err(|_| ProviderError::Internal)?
        .map_err(map_store_error)?
        .ok_or(ProviderError::NotFound)?;
        if attempt.status != "active" {
            return Ok(oauth_return_location(&attempt));
        }
        if let Some(provider_error) = error {
            let (status, safe_code) = if provider_error == "access_denied" {
                ("cancelled", "access_denied")
            } else {
                ("failed", "provider_authorization_failed")
            };
            let finished = self
                .finish_oauth_attempt(actor, &attempt, status, safe_code)
                .await?;
            return Ok(oauth_return_location(&finished));
        }
        let code = code.ok_or(ProviderError::Invalid)?;
        let adapter = self
            .auth_adapters
            .get(&attempt.provider)
            .cloned()
            .ok_or(ProviderError::Conflict)?;
        let verifier_ref = attempt
            .pkce_secret_ref
            .as_deref()
            .ok_or(ProviderError::Conflict)?;
        let store = Arc::clone(&self.store);
        let verifier_ref_owned = verifier_ref.to_owned();
        let verifier =
            tokio::task::spawn_blocking(move || store.load_provider_secret(&verifier_ref_owned))
                .await
                .map_err(|_| ProviderError::Internal)?
                .map_err(map_store_error)?
                .ok_or(ProviderError::Internal)?;
        let verifier = Secret(verifier);
        let token = match self
            .exchange_authorization_code(&adapter, code, &verifier.0)
            .await
        {
            Ok(token) => token,
            Err(_) => {
                let failed = self
                    .finish_oauth_attempt(actor, &attempt, "failed", "oauth_exchange_failed")
                    .await?;
                return Ok(oauth_return_location(&failed));
            }
        };
        let expires_at_ms = oauth_expiry(unix_millis()?, token.expires_in)?;
        let credential = StoredOAuthCredential {
            schema: "zode.oauth-credential.v1".to_owned(),
            access_token: token.access_token.clone(),
            refresh_token: token.refresh_token.clone(),
            token_type: token.token_type.clone(),
            expires_at_ms,
        };
        let encoded = serde_json::to_vec(&credential).map_err(|_| ProviderError::Internal)?;
        let encoded = Secret(encoded);
        let credential_secret_ref = hex(&self.store.keys().digest(
            b"oauth-credential-secret-reference-v1",
            &[attempt.attempt_id.as_bytes(), attempt.profile_id.as_bytes()],
        ));
        let _secret_guard = self.secret_store_lock.lock().await;
        let store = Arc::clone(&self.store);
        let credential_reference = credential_secret_ref.clone();
        tokio::task::spawn_blocking(move || {
            store.stage_provider_secret(&credential_reference, &encoded.0)
        })
        .await
        .map_err(|_| ProviderError::Internal)?
        .map_err(map_store_error)?;
        self.reconcile_signal.notify_one();
        let event_json = terminal_oauth_event(&attempt.attempt_id, "succeeded", "succeeded")?;
        let success = OAuthAttemptSuccess {
            actor_key: *actor.actor_key(),
            attempt_id: attempt.attempt_id.clone(),
            credential_secret_ref,
            expires_at_ms,
            completed_at_ms: unix_millis()?,
        };
        let store = Arc::clone(&self.store);
        let (_profile, _replicas, _old_secret_ref) =
            tokio::task::spawn_blocking(move || store.complete_oauth_attempt(success, &event_json))
                .await
                .map_err(|_| ProviderError::Internal)?
                .map_err(map_store_error)?;
        drop(_secret_guard);
        self.reconcile_signal.notify_one();
        self.control_signal.notify_waiters();
        let completed = OAuthAttemptRecord {
            status: "succeeded".to_owned(),
            updated_at_ms: unix_millis()?,
            ..attempt
        };
        Ok(oauth_return_location(&completed))
    }

    pub(crate) async fn oauth_attempt_events(
        &self,
        actor: &ActorContext,
        attempt_id: &str,
        after: u64,
    ) -> Result<Vec<ProviderControlEvent>, ProviderError> {
        self.load_oauth_attempt(actor, attempt_id).await?;
        let store = Arc::clone(&self.store);
        let attempt_id = attempt_id.to_owned();
        tokio::task::spawn_blocking(move || {
            store.list_provider_control_events("oauth_attempt", &attempt_id, after)
        })
        .await
        .map_err(|_| ProviderError::Internal)?
        .map_err(map_store_error)
    }

    pub(crate) async fn start_auth_refresh(
        &self,
        actor: &ActorContext,
        idempotency_key: &str,
        profile_id: &str,
    ) -> Result<Value, ProviderError> {
        if !valid_identifier(profile_id, 128)
            || !valid_text(idempotency_key, MAX_IDEMPOTENCY_KEY_BYTES)
        {
            return Err(ProviderError::Invalid);
        }
        let store = Arc::clone(&self.store);
        let profile_id_owned = profile_id.to_owned();
        let profile =
            tokio::task::spawn_blocking(move || store.get_auth_profile(&profile_id_owned))
                .await
                .map_err(|_| ProviderError::Internal)?
                .map_err(map_store_error)?
                .ok_or(ProviderError::NotFound)?;
        if profile.kind != "oauth" || profile.deleted_at_ms.is_some() {
            return Err(ProviderError::Conflict);
        }
        let adapter = self
            .auth_adapters
            .get(&profile.provider)
            .ok_or(ProviderError::Conflict)?;
        let keys = self.store.keys();
        let command_key = keys.digest(
            b"auth-refresh-command-v1",
            &[profile_id.as_bytes(), idempotency_key.as_bytes()],
        );
        let request_fingerprint = keys.digest(b"auth-refresh-request-v1", &[profile_id.as_bytes()]);
        let operation_id = random_resource_id("auth-refresh")?;
        let target_secret_ref = hex(&keys.digest(
            b"auth-refresh-target-secret-reference-v1",
            &[operation_id.as_bytes(), profile_id.as_bytes()],
        ));
        let created_at_ms = unix_millis()?;
        let event_json = refresh_event(
            &operation_id,
            profile_id,
            "prepared",
            None,
            profile.revision,
            profile.revision.saturating_add(1),
        )?;
        let write = AuthRefreshWrite {
            operation_id,
            actor_key: *actor.actor_key(),
            profile_id: profile_id.to_owned(),
            command_key,
            request_fingerprint,
            target_secret_ref,
            recovery: adapter.refresh_recovery().as_str().to_owned(),
            created_at_ms,
        };
        let store = Arc::clone(&self.store);
        let operation =
            tokio::task::spawn_blocking(move || store.begin_auth_refresh(write, &event_json))
                .await
                .map_err(|_| ProviderError::Internal)?
                .map_err(map_store_error)?;
        if matches!(operation.status.as_str(), "prepared" | "dispatching") {
            self.reconcile_signal.notify_one();
        }
        self.control_signal.notify_waiters();
        refresh_operation_value(&operation)
    }

    pub(crate) async fn get_auth_refresh(
        &self,
        actor: &ActorContext,
        operation_id: &str,
    ) -> Result<Value, ProviderError> {
        let operation = self.load_auth_refresh(actor, operation_id).await?;
        refresh_operation_value(&operation)
    }

    pub(crate) async fn auth_refresh_events(
        &self,
        actor: &ActorContext,
        operation_id: &str,
        after: u64,
    ) -> Result<Vec<ProviderControlEvent>, ProviderError> {
        self.load_auth_refresh(actor, operation_id).await?;
        let store = Arc::clone(&self.store);
        let operation_id = operation_id.to_owned();
        tokio::task::spawn_blocking(move || {
            store.list_provider_control_events("auth_refresh", &operation_id, after)
        })
        .await
        .map_err(|_| ProviderError::Internal)?
        .map_err(map_store_error)
    }

    async fn load_auth_refresh(
        &self,
        actor: &ActorContext,
        operation_id: &str,
    ) -> Result<AuthRefreshRecord, ProviderError> {
        if !valid_identifier(operation_id, 128) {
            return Err(ProviderError::Invalid);
        }
        let store = Arc::clone(&self.store);
        let actor_key = *actor.actor_key();
        let operation_id = operation_id.to_owned();
        tokio::task::spawn_blocking(move || store.get_auth_refresh(&actor_key, &operation_id))
            .await
            .map_err(|_| ProviderError::Internal)?
            .map_err(map_store_error)?
            .ok_or(ProviderError::NotFound)
    }

    async fn dispatch_auth_refresh(
        &self,
        mut operation: AuthRefreshRecord,
    ) -> Result<AuthRefreshRecord, ProviderError> {
        if !matches!(operation.status.as_str(), "prepared" | "dispatching") {
            return Ok(operation);
        }
        if operation.status == "prepared" {
            let dispatched_at_ms = unix_millis()?;
            let event_json = refresh_event(
                &operation.operation_id,
                &operation.profile_id,
                "dispatching",
                None,
                operation.source_revision,
                operation.reserved_revision,
            )?;
            let store = Arc::clone(&self.store);
            let operation_id = operation.operation_id.clone();
            operation = tokio::task::spawn_blocking(move || {
                store.mark_auth_refresh_dispatching(&operation_id, dispatched_at_ms, &event_json)
            })
            .await
            .map_err(|_| ProviderError::Internal)?
            .map_err(map_store_error)?;
            self.control_signal.notify_waiters();
        }
        let adapter = self
            .auth_adapters
            .get(&operation.provider)
            .cloned()
            .ok_or(ProviderError::Conflict)?;
        let result = self.exchange_refresh(&adapter, &operation).await;
        match result {
            Ok(token) => self.complete_auth_refresh(operation, token).await,
            Err(RefreshDispatchError::Unknown)
                if operation.recovery != "same_operation_id_idempotent" =>
            {
                self.finish_refresh_unknown(&operation).await
            }
            Err(RefreshDispatchError::Unknown) => Ok(operation),
            Err(RefreshDispatchError::Rejected) => {
                self.finish_refresh_failed(&operation, "provider_refresh_rejected")
                    .await
            }
            Err(RefreshDispatchError::Internal) => Err(ProviderError::Internal),
        }
    }

    async fn exchange_refresh(
        &self,
        adapter: &ProviderAuthAdapterConfig,
        operation: &AuthRefreshRecord,
    ) -> Result<OAuthTokenResponse, RefreshDispatchError> {
        let store = Arc::clone(&self.store);
        let source_secret_ref = operation.source_secret_ref.clone();
        let source =
            tokio::task::spawn_blocking(move || store.load_provider_secret(&source_secret_ref))
                .await
                .map_err(|_| RefreshDispatchError::Internal)?
                .map_err(|_| RefreshDispatchError::Internal)?
                .ok_or(RefreshDispatchError::Internal)?;
        let source = Secret(source);
        let mut credential: StoredOAuthCredential =
            serde_json::from_slice(&source.0).map_err(|_| RefreshDispatchError::Internal)?;
        if credential.schema != "zode.oauth-credential.v1"
            || !credential.token_type.eq_ignore_ascii_case("bearer")
        {
            return Err(RefreshDispatchError::Internal);
        }
        let refresh_token = credential
            .refresh_token
            .as_deref()
            .ok_or(RefreshDispatchError::Rejected)?;
        let mut fields = vec![
            ("grant_type", "refresh_token".to_owned()),
            ("refresh_token", refresh_token.to_owned()),
            ("client_id", adapter.client_id().to_owned()),
            ("operation_id", operation.operation_id.clone()),
        ];
        let mut client_secret = read_client_secret(adapter.client_secret_file())
            .map_err(|_| RefreshDispatchError::Internal)?;
        if let Some(secret) = &client_secret {
            fields.push(("client_secret", secret.clone()));
        }
        let response = self
            .provider_client
            .post(adapter.token_endpoint())
            .header("x-zode-refresh-operation-id", &operation.operation_id)
            .form(&fields)
            .send()
            .await;
        fields.iter_mut().for_each(|(_, value)| value.zeroize());
        client_secret.zeroize();
        let response = response.map_err(|_| RefreshDispatchError::Unknown)?;
        if !response.status().is_success() {
            return Err(RefreshDispatchError::Rejected);
        }
        let body = read_bounded_provider_response(response)
            .await
            .map_err(|error| match error {
                ProviderError::Internal => RefreshDispatchError::Unknown,
                _ => RefreshDispatchError::Rejected,
            })?;
        let mut token: OAuthTokenResponse =
            serde_json::from_slice(&body.0).map_err(|_| RefreshDispatchError::Rejected)?;
        if token.access_token.is_empty()
            || token.access_token.len() > MAX_API_KEY_BYTES
            || token.access_token.contains('\0')
            || token.refresh_token.as_ref().is_some_and(|value| {
                value.is_empty() || value.len() > MAX_API_KEY_BYTES || value.contains('\0')
            })
            || !token.token_type.eq_ignore_ascii_case("bearer")
        {
            return Err(RefreshDispatchError::Rejected);
        }
        if token.refresh_token.is_none() {
            token.refresh_token = credential.refresh_token.take();
        }
        Ok(token)
    }

    async fn complete_auth_refresh(
        &self,
        operation: AuthRefreshRecord,
        token: OAuthTokenResponse,
    ) -> Result<AuthRefreshRecord, ProviderError> {
        let completed_at_ms = unix_millis()?;
        let expires_at_ms = oauth_expiry(completed_at_ms, token.expires_in)?;
        let credential = StoredOAuthCredential {
            schema: "zode.oauth-credential.v1".to_owned(),
            access_token: token.access_token.clone(),
            refresh_token: token.refresh_token.clone(),
            token_type: token.token_type.clone(),
            expires_at_ms,
        };
        let encoded = Secret(serde_json::to_vec(&credential).map_err(|_| ProviderError::Internal)?);
        let store = Arc::clone(&self.store);
        let target_secret_ref = operation.target_secret_ref.clone();
        let target_for_stage = target_secret_ref.clone();
        tokio::task::spawn_blocking(move || {
            store.stage_provider_secret(&target_for_stage, &encoded.0)
        })
        .await
        .map_err(|_| ProviderError::Internal)?
        .map_err(map_store_error)?;
        let event_json = refresh_event(
            &operation.operation_id,
            &operation.profile_id,
            "succeeded",
            None,
            operation.source_revision,
            operation.reserved_revision,
        )?;
        let success = AuthRefreshSuccess {
            operation_id: operation.operation_id.clone(),
            target_secret_ref,
            expires_at_ms,
            completed_at_ms,
        };
        let store = Arc::clone(&self.store);
        let (completed, _profile, _source_secret_ref) =
            tokio::task::spawn_blocking(move || store.complete_auth_refresh(success, &event_json))
                .await
                .map_err(|_| ProviderError::Internal)?
                .map_err(map_store_error)?;
        self.reconcile_signal.notify_one();
        self.control_signal.notify_waiters();
        Ok(completed)
    }

    async fn finish_refresh_unknown(
        &self,
        operation: &AuthRefreshRecord,
    ) -> Result<AuthRefreshRecord, ProviderError> {
        self.finish_auth_refresh(operation, "refresh_unknown", "reauth_required")
            .await
    }

    async fn finish_refresh_failed(
        &self,
        operation: &AuthRefreshRecord,
        safe_code: &str,
    ) -> Result<AuthRefreshRecord, ProviderError> {
        self.finish_auth_refresh(operation, "failed", safe_code)
            .await
    }

    async fn finish_auth_refresh(
        &self,
        operation: &AuthRefreshRecord,
        status: &str,
        safe_code: &str,
    ) -> Result<AuthRefreshRecord, ProviderError> {
        let finished_at_ms = unix_millis()?;
        let event_json = refresh_event(
            &operation.operation_id,
            &operation.profile_id,
            status,
            Some(safe_code),
            operation.source_revision,
            operation.reserved_revision,
        )?;
        let store = Arc::clone(&self.store);
        let operation_id = operation.operation_id.clone();
        let status = status.to_owned();
        let safe_code = safe_code.to_owned();
        let completed = tokio::task::spawn_blocking(move || {
            store.finish_auth_refresh(
                &operation_id,
                &status,
                &safe_code,
                finished_at_ms,
                &event_json,
            )
        })
        .await
        .map_err(|_| ProviderError::Internal)?
        .map_err(map_store_error)?;
        self.control_signal.notify_waiters();
        Ok(completed)
    }

    pub(crate) fn control_signal(&self) -> Arc<Notify> {
        Arc::clone(&self.control_signal)
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
        if let Some(profile_id) = request.replace_auth_profile_id.take() {
            if !valid_identifier(&profile_id, 128)
                || request.label.is_some()
                || request.sharing.is_some()
                || request.make_default
            {
                return Err(ProviderError::Invalid);
            }
            return self
                .rotate_api_key_profile(
                    actor,
                    idempotency_key,
                    provider,
                    profile_id,
                    request.api_key,
                )
                .await;
        }
        let label = request.label.take().ok_or(ProviderError::Invalid)?;
        if !valid_text(&label, MAX_PROFILE_LABEL_BYTES) {
            return Err(ProviderError::Invalid);
        }
        let mut sharing = request.sharing.take().ok_or(ProviderError::Invalid)?;
        normalize_sharing(&mut sharing)?;
        let sharing_json = serde_json::to_string(&json!({
            "mode": sharing.mode,
            "endpoint_ids": sharing.endpoint_ids,
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
                label.as_bytes(),
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
            label,
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
        if operation.phase == ProfileCreatePhase::Pending {
            let store = Arc::clone(&self.store);
            let reference = operation.secret_ref.clone();
            let secret = Secret(request.api_key.into_bytes());
            tokio::task::spawn_blocking(move || store.stage_provider_secret(&reference, &secret.0))
                .await
                .map_err(|_| ProviderError::Internal)?
                .map_err(map_store_error)?;
        }
        let store = Arc::clone(&self.store);
        let operation_for_commit = operation.clone();
        let authority_id = self.store.authority_id().to_owned();
        let response_json = tokio::task::spawn_blocking(move || {
            store.commit_profile_create(&operation_for_commit, |profile, replicas| {
                let response = profile_response_value(profile, replicas, &authority_id)
                    .map_err(|_| StoreError::Integrity)?;
                serde_json::to_string(&response).map_err(|_| StoreError::Integrity)
            })
        })
        .await
        .map_err(|_| ProviderError::Internal)?
        .map_err(map_store_error)?;
        if operation.phase != ProfileCreatePhase::Complete {
            self.reconcile_signal.notify_one();
        }
        serde_json::from_str(&response_json).map_err(|_| ProviderError::Internal)
    }

    async fn rotate_api_key_profile(
        &self,
        actor: &ActorContext,
        idempotency_key: &str,
        provider: &str,
        profile_id: String,
        api_key: String,
    ) -> Result<Value, ProviderError> {
        let store = Arc::clone(&self.store);
        let profile_for_read = profile_id.clone();
        let existing =
            tokio::task::spawn_blocking(move || store.get_auth_profile(&profile_for_read))
                .await
                .map_err(|_| ProviderError::Internal)?
                .map_err(map_store_error)?
                .ok_or(ProviderError::NotFound)?;
        if existing.provider != provider
            || existing.kind != "api_key"
            || existing.deleted_at_ms.is_some()
        {
            return Err(ProviderError::Conflict);
        }

        let keys = self.store.keys();
        let command_key = keys.digest(
            b"auth-profile-rotation-command-v1",
            &[provider.as_bytes(), idempotency_key.as_bytes()],
        );
        let request_fingerprint = keys.digest(
            b"auth-profile-rotation-request-v1",
            &[
                provider.as_bytes(),
                profile_id.as_bytes(),
                api_key.as_bytes(),
            ],
        );
        let secret_ref = hex(&keys.digest(
            b"auth-profile-rotation-secret-reference-v1",
            &[
                provider.as_bytes(),
                profile_id.as_bytes(),
                &command_key,
                &request_fingerprint,
            ],
        ));
        let _secret_guard = self.secret_store_lock.lock().await;
        let store = Arc::clone(&self.store);
        let reference = secret_ref.clone();
        let secret = Secret(api_key.into_bytes());
        tokio::task::spawn_blocking(move || store.stage_provider_secret(&reference, &secret.0))
            .await
            .map_err(|_| ProviderError::Internal)?
            .map_err(map_store_error)?;
        self.reconcile_signal.notify_one();

        let write = ProfileRotationWrite {
            actor_key: *actor.actor_key(),
            provider: provider.to_owned(),
            profile_id,
            command_key,
            request_fingerprint,
            secret_ref,
            created_at_ms: unix_millis()?,
        };
        let store = Arc::clone(&self.store);
        let authority_id = self.store.authority_id().to_owned();
        let rotation = tokio::task::spawn_blocking(move || {
            store.rotate_api_key_profile(write, |profile, replicas| {
                let response = profile_response_value(profile, replicas, &authority_id)
                    .map_err(|_| StoreError::Integrity)?;
                serde_json::to_string(&response).map_err(|_| StoreError::Integrity)
            })
        })
        .await
        .map_err(|_| ProviderError::Internal)?;
        let (response_json, _old_secret_ref) = match rotation {
            Ok(outcome) => outcome,
            Err(error) => {
                drop(_secret_guard);
                self.reconcile_signal.notify_one();
                return Err(map_store_error(error));
            }
        };
        drop(_secret_guard);
        self.reconcile_signal.notify_one();
        serde_json::from_str(&response_json).map_err(|_| ProviderError::Internal)
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

    pub(crate) async fn update_profile_sharing(
        &self,
        actor: &ActorContext,
        idempotency_key: &str,
        profile_id: &str,
        mut request: SharingRequest,
    ) -> Result<Value, ProviderError> {
        if !valid_identifier(profile_id, 128)
            || !valid_text(idempotency_key, MAX_IDEMPOTENCY_KEY_BYTES)
        {
            return Err(ProviderError::Invalid);
        }
        normalize_sharing(&mut request)?;
        let SharingRequest { mode, endpoint_ids } = request;
        let request_json = serde_json::to_string(&json!({
            "mode": &mode,
            "endpoint_ids": &endpoint_ids,
        }))
        .map_err(|_| ProviderError::Invalid)?;
        let keys = self.store.keys();
        let command_key = keys.digest(
            b"auth-profile-sharing-command-v1",
            &[profile_id.as_bytes(), idempotency_key.as_bytes()],
        );
        let request_fingerprint = keys.digest(
            b"auth-profile-sharing-request-v1",
            &[profile_id.as_bytes(), request_json.as_bytes()],
        );
        let write = ProfileSharingWrite {
            actor_key: *actor.actor_key(),
            profile_id: profile_id.to_owned(),
            command_key,
            request_fingerprint,
            mode,
            endpoint_ids,
            created_at_ms: unix_millis()?,
        };
        let store = Arc::clone(&self.store);
        let authority_id = self.store.authority_id().to_owned();
        let (response_json, changed) = tokio::task::spawn_blocking(move || {
            store.update_profile_sharing(write, |profile, replicas| {
                let response = profile_response_value(profile, replicas, &authority_id)
                    .map_err(|_| StoreError::Integrity)?;
                serde_json::to_string(&response).map_err(|_| StoreError::Integrity)
            })
        })
        .await
        .map_err(|_| ProviderError::Internal)?
        .map_err(map_store_error)?;
        if changed {
            self.reconcile_signal.notify_one();
        }
        serde_json::from_str(&response_json).map_err(|_| ProviderError::Internal)
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
        let execution_secret = match profile.kind.as_str() {
            "api_key" => Secret(secret.0.clone()),
            "oauth" => {
                let credential: StoredOAuthCredential =
                    serde_json::from_slice(&secret.0).map_err(|_| ProviderError::Internal)?;
                if credential.schema != "zode.oauth-credential.v1"
                    || !credential.token_type.eq_ignore_ascii_case("bearer")
                {
                    return Err(ProviderError::Internal);
                }
                Secret(credential.access_token.as_bytes().to_vec())
            }
            _ => return Err(ProviderError::Internal),
        };
        let secret_text =
            std::str::from_utf8(&execution_secret.0).map_err(|_| ProviderError::Internal)?;
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
                        "kind": profile.kind,
                        "revision": profile.revision,
                        "credential_schema": "openai-compatible.api-key.v1",
                        "expires_at_ms": profile.expires_at_ms,
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
        profile_response_value(profile, &replicas, self.store.authority_id())
    }

    async fn load_oauth_attempt(
        &self,
        actor: &ActorContext,
        attempt_id: &str,
    ) -> Result<OAuthAttemptRecord, ProviderError> {
        if !valid_identifier(attempt_id, 128) {
            return Err(ProviderError::Invalid);
        }
        let store = Arc::clone(&self.store);
        let actor_key = *actor.actor_key();
        let attempt_id_owned = attempt_id.to_owned();
        let attempt = tokio::task::spawn_blocking(move || {
            store.get_oauth_attempt(&actor_key, &attempt_id_owned)
        })
        .await
        .map_err(|_| ProviderError::Internal)?
        .map_err(map_store_error)?
        .ok_or(ProviderError::NotFound)?;
        if attempt.status == "active" && attempt.expires_at_ms <= unix_millis()? {
            return self
                .finish_oauth_attempt(actor, &attempt, "failed", "auth_attempt_expired")
                .await;
        }
        Ok(attempt)
    }

    async fn finish_oauth_attempt(
        &self,
        actor: &ActorContext,
        attempt: &OAuthAttemptRecord,
        status: &str,
        safe_code: &str,
    ) -> Result<OAuthAttemptRecord, ProviderError> {
        let finished_at_ms = unix_millis()?;
        let event_json = terminal_oauth_event(&attempt.attempt_id, status, safe_code)?;
        let store = Arc::clone(&self.store);
        let actor_key = *actor.actor_key();
        let attempt_id = attempt.attempt_id.clone();
        let status = status.to_owned();
        let safe_code = safe_code.to_owned();
        let finished = tokio::task::spawn_blocking(move || {
            store.finish_oauth_attempt(
                &actor_key,
                &attempt_id,
                &status,
                &safe_code,
                finished_at_ms,
                &event_json,
            )
        })
        .await
        .map_err(|_| ProviderError::Internal)?
        .map_err(map_store_error)?;
        self.reconcile_signal.notify_one();
        self.control_signal.notify_waiters();
        Ok(finished)
    }

    async fn exchange_authorization_code(
        &self,
        adapter: &ProviderAuthAdapterConfig,
        code: &str,
        verifier: &[u8],
    ) -> Result<OAuthTokenResponse, ProviderError> {
        let verifier = std::str::from_utf8(verifier).map_err(|_| ProviderError::Internal)?;
        let redirect_uri = self.oauth_redirect_uri();
        let mut fields = vec![
            ("grant_type", "authorization_code".to_owned()),
            ("code", code.to_owned()),
            ("redirect_uri", redirect_uri),
            ("client_id", adapter.client_id().to_owned()),
            ("code_verifier", verifier.to_owned()),
        ];
        let mut client_secret = read_client_secret(adapter.client_secret_file())?;
        if let Some(secret) = &client_secret {
            fields.push(("client_secret", secret.clone()));
        }
        let response = self
            .provider_client
            .post(adapter.token_endpoint())
            .form(&fields)
            .send()
            .await
            .map_err(|_| ProviderError::Internal)?;
        fields.iter_mut().for_each(|(_, value)| value.zeroize());
        client_secret.zeroize();
        if !response.status().is_success() {
            return Err(ProviderError::Conflict);
        }
        let body = read_bounded_provider_response(response).await?;
        let token: OAuthTokenResponse =
            serde_json::from_slice(&body.0).map_err(|_| ProviderError::Conflict)?;
        if token.access_token.is_empty()
            || token.access_token.len() > MAX_API_KEY_BYTES
            || token.access_token.contains('\0')
            || token.refresh_token.as_ref().is_some_and(|value| {
                value.is_empty() || value.len() > MAX_API_KEY_BYTES || value.contains('\0')
            })
            || !token.token_type.eq_ignore_ascii_case("bearer")
        {
            return Err(ProviderError::Conflict);
        }
        Ok(token)
    }

    fn oauth_redirect_uri(&self) -> String {
        format!(
            "{}/v1/oauth/callback",
            self.management_origin.trim_end_matches('/')
        )
    }
}

fn profile_response_value(
    profile: &AuthProfileRecord,
    replicas: &[AuthReplicaRecord],
    authority_id: &str,
) -> Result<Value, ProviderError> {
    let endpoint_ids: Value =
        serde_json::from_str(&profile.endpoint_ids_json).map_err(|_| ProviderError::Internal)?;
    let status = if replicas
        .iter()
        .any(|replica| replica.status == "unreachable")
    {
        "unreachable"
    } else if replicas.iter().any(|replica| replica.status == "stale") {
        "stale"
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
        "expires_at_ms": profile.expires_at_ms,
        "refresh_state": if profile.refresh_fenced { "reauth_required" } else { "ready" },
        "allowed_actions": if profile.kind == "oauth" {
            if profile.refresh_fenced { json!(["relogin"]) } else { json!(["refresh", "relogin"]) }
        } else {
            json!([])
        },
        "is_default": profile.is_default,
        "sharing": {
            "mode": profile.sharing_mode,
            "endpoint_ids": endpoint_ids,
        },
        "distribution": replica_list_value(replicas, authority_id),
    }))
}

fn oauth_attempt_value(attempt: &OAuthAttemptRecord) -> Result<Value, ProviderError> {
    let sharing: Value =
        serde_json::from_str(&attempt.sharing_json).map_err(|_| ProviderError::Internal)?;
    Ok(json!({
        "schema": "zode.oauth-attempt.v1",
        "attempt_id": attempt.attempt_id,
        "provider": attempt.provider,
        "auth_profile_id": attempt.profile_id,
        "profile_id": attempt.profile_id,
        "replace_auth_profile_id": attempt.replace_profile_id,
        "label": attempt.label,
        "status": attempt.status,
        "safe_code": attempt.safe_code,
        "sharing": sharing,
        "make_default": attempt.make_default,
        "created_at_ms": attempt.created_at_ms,
        "updated_at_ms": attempt.updated_at_ms,
        "expires_at_ms": attempt.expires_at_ms,
        "allowed_actions": if attempt.status == "active" {
            json!(["authorize", "cancel"])
        } else {
            json!([])
        },
    }))
}

fn refresh_operation_value(operation: &AuthRefreshRecord) -> Result<Value, ProviderError> {
    Ok(json!({
        "schema": "zode.auth-refresh-operation.v1",
        "operation_id": operation.operation_id,
        "auth_profile_id": operation.profile_id,
        "provider": operation.provider,
        "status": operation.status,
        "safe_code": operation.safe_code,
        "source_revision": operation.source_revision,
        "reserved_revision": operation.reserved_revision,
        "recovery": operation.recovery,
        "created_at_ms": operation.created_at_ms,
        "updated_at_ms": operation.updated_at_ms,
        "allowed_actions": if operation.status == "refresh_unknown" {
            json!(["relogin"])
        } else {
            json!([])
        },
    }))
}

fn refresh_event(
    operation_id: &str,
    profile_id: &str,
    status: &str,
    safe_code: Option<&str>,
    source_revision: u64,
    reserved_revision: u64,
) -> Result<String, ProviderError> {
    serde_json::to_string(&json!({
        "schema": "zode.auth-refresh-event.v1",
        "type": "refresh_state_changed",
        "operation_id": operation_id,
        "auth_profile_id": profile_id,
        "status": status,
        "safe_code": safe_code,
        "source_revision": source_revision,
        "reserved_revision": reserved_revision,
    }))
    .map_err(|_| ProviderError::Internal)
}

fn oauth_return_location(attempt: &OAuthAttemptRecord) -> String {
    let mut url = Url::parse("http://zode.invalid/providers")
        .expect("static OAuth return route must be a valid URL");
    url.query_pairs_mut()
        .append_pair("oauth_attempt", &attempt.attempt_id);
    format!("{}?{}", url.path(), url.query().unwrap_or_default())
}

fn terminal_oauth_event(
    attempt_id: &str,
    status: &str,
    safe_code: &str,
) -> Result<String, ProviderError> {
    serde_json::to_string(&json!({
        "schema": "zode.oauth-attempt-event.v1",
        "type": "attempt_terminal",
        "attempt_id": attempt_id,
        "status": status,
        "safe_code": safe_code,
    }))
    .map_err(|_| ProviderError::Internal)
}

fn valid_capability(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn random_resource_id(prefix: &str) -> Result<String, ProviderError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| ProviderError::Internal)?;
    Ok(format!("{prefix}-{}", hex(&bytes)))
}

fn oauth_expiry(now_ms: i64, expires_in: Option<u64>) -> Result<Option<i64>, ProviderError> {
    let Some(expires_in) = expires_in else {
        return Ok(None);
    };
    if expires_in == 0 || expires_in > 365 * 24 * 60 * 60 {
        return Err(ProviderError::Conflict);
    }
    let expires_in_ms = i64::try_from(expires_in)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1000))
        .ok_or(ProviderError::Internal)?;
    now_ms
        .checked_add(expires_in_ms)
        .map(Some)
        .ok_or(ProviderError::Internal)
}

fn read_client_secret(path: Option<&std::path::Path>) -> Result<Option<String>, ProviderError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let metadata = fs::symlink_metadata(path).map_err(|_| ProviderError::Internal)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_API_KEY_BYTES as u64 {
        return Err(ProviderError::Internal);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.nlink() != 1 || metadata.permissions().mode() & 0o077 != 0 {
            return Err(ProviderError::Internal);
        }
    }
    let mut bytes = fs::read(path).map_err(|_| ProviderError::Internal)?;
    if bytes.is_empty() || bytes.len() > MAX_API_KEY_BYTES || bytes.contains(&0) {
        bytes.zeroize();
        return Err(ProviderError::Internal);
    }
    let value = match String::from_utf8(bytes) {
        Ok(value) => value,
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            return Err(ProviderError::Internal);
        }
    };
    Ok(Some(value))
}

async fn read_bounded_provider_response(
    response: ProviderResponse,
) -> Result<Secret, ProviderError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_OAUTH_RESPONSE_BYTES as u64)
    {
        return Err(ProviderError::PayloadTooLarge);
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ProviderError::Internal)?;
        if bytes.len().saturating_add(chunk.len()) > MAX_OAUTH_RESPONSE_BYTES {
            bytes.zeroize();
            return Err(ProviderError::PayloadTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(Secret(bytes))
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
        "all_current" if sharing.endpoint_ids.is_empty() => Ok(()),
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
        StoreError::ReceiptUnavailable => ProviderError::ReceiptUnavailable,
        StoreError::NotFound => ProviderError::NotFound,
        StoreError::ReauthRequired => ProviderError::ReauthRequired,
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
