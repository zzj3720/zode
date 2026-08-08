use std::{collections::HashMap, sync::Arc, time::Duration};

use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use futures_util::StreamExt;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::{
    sync::{Mutex, RwLock},
    time::Instant,
};

use crate::{config::AccessConfig, store::KeyMaterial};

const ACCESS_HEADER: &str = "cf-access-jwt-assertion";
const MAX_ASSERTION_BYTES: usize = 16 * 1024;
const MAX_KID_BYTES: usize = 256;
const MAX_ACTOR_BYTES: usize = 1024;
const MAX_JWKS_BYTES: usize = 1024 * 1024;
const MAX_JWKS_KEYS: usize = 32;
const KEY_CACHE_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Clone)]
pub(crate) struct ActorContext {
    actor_key: [u8; 32],
    endpoint_subject: String,
}

impl ActorContext {
    pub(crate) fn actor_key(&self) -> &[u8; 32] {
        &self.actor_key
    }

    pub(crate) fn endpoint_subject(&self) -> &str {
        &self.endpoint_subject
    }
}

pub(crate) struct AccessVerifier {
    issuer: String,
    audiences: Vec<String>,
    jwks_url: String,
    client: reqwest::Client,
    keys: RwLock<HashMap<String, CachedKey>>,
    refresh: Mutex<()>,
    subject_keys: Arc<KeyMaterial>,
}

#[derive(Clone)]
struct CachedKey {
    modulus: String,
    exponent: String,
    expires_at: Instant,
}

#[derive(Deserialize)]
struct JwksDocument {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    kid: String,
    #[serde(rename = "use")]
    usage: Option<String>,
    alg: Option<String>,
    n: String,
    e: String,
}

impl AccessVerifier {
    pub(crate) fn new(config: &AccessConfig, subject_keys: Arc<KeyMaterial>) -> Result<Self, ()> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(4))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ())?;
        Ok(Self {
            issuer: config.issuer().to_owned(),
            audiences: config.audiences().to_vec(),
            jwks_url: config.jwks_url().to_owned(),
            client,
            keys: RwLock::new(HashMap::new()),
            refresh: Mutex::new(()),
            subject_keys,
        })
    }

    async fn authorize(&self, headers: &HeaderMap) -> Result<ActorContext, ()> {
        let mut assertions = headers.get_all(ACCESS_HEADER).iter();
        let assertion = assertions.next().ok_or(())?;
        if assertions.next().is_some()
            || assertion.as_bytes().is_empty()
            || assertion.as_bytes().len() > MAX_ASSERTION_BYTES
        {
            return Err(());
        }
        let assertion = std::str::from_utf8(assertion.as_bytes()).map_err(|_| ())?;
        let header = decode_header(assertion).map_err(|_| ())?;
        if header.alg != Algorithm::RS256 {
            return Err(());
        }
        let kid = header.kid.ok_or(())?;
        if !valid_text(&kid, MAX_KID_BYTES) {
            return Err(());
        }
        let key = self.key_for(&kid).await?;
        let decoding_key =
            DecodingKey::from_rsa_components(&key.modulus, &key.exponent).map_err(|_| ())?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&self.audiences);
        validation.validate_nbf = true;
        validation.leeway = 60;
        validation.required_spec_claims = ["aud", "exp", "iss"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let claims = decode::<Value>(assertion, &decoding_key, &validation)
            .map_err(|_| ())?
            .claims;
        self.actor_from_claims(&claims)
    }

    fn actor_from_claims(&self, claims: &Value) -> Result<ActorContext, ()> {
        let claims = claims.as_object().ok_or(())?;
        if claims.get("iss").and_then(Value::as_str) != Some(self.issuer.as_str())
            || claims.get("type").and_then(Value::as_str) != Some("app")
            || !accepted_audience(claims.get("aud"), &self.audiences)
            || !integer_claim(claims.get("exp"))
            || claims
                .get("nbf")
                .is_some_and(|value| !integer_claim(Some(value)))
        {
            return Err(());
        }
        let subject = claims.get("sub").and_then(Value::as_str).ok_or(())?;
        let common_name = match claims.get("common_name") {
            Some(Value::String(value)) => Some(value.as_str()),
            None => None,
            Some(_) => return Err(()),
        };
        let (kind, actor) = match (subject.is_empty(), common_name) {
            (false, None) if valid_text(subject, MAX_ACTOR_BYTES) => ("human", subject),
            (true, Some(name)) if valid_text(name, MAX_ACTOR_BYTES) => ("service", name),
            _ => return Err(()),
        };
        let actor_key = self.subject_keys.actor_key(kind, actor);
        Ok(ActorContext {
            endpoint_subject: self.subject_keys.endpoint_subject(&actor_key),
            actor_key,
        })
    }

    async fn key_for(&self, kid: &str) -> Result<CachedKey, ()> {
        let now = Instant::now();
        if let Some(key) = self.fresh_key(kid, now).await {
            return Ok(key);
        }
        let _refresh = self.refresh.lock().await;
        let now = Instant::now();
        if let Some(key) = self.fresh_key(kid, now).await {
            return Ok(key);
        }
        let refreshed = self.fetch_keys().await?;
        let expires_at = now + KEY_CACHE_TTL;
        let mut cache = self.keys.write().await;
        cache.retain(|_, key| key.expires_at > now);
        if cache.len().saturating_add(refreshed.len()) > MAX_JWKS_KEYS {
            return Err(());
        }
        for (key_id, (modulus, exponent)) in refreshed {
            cache.insert(
                key_id,
                CachedKey {
                    modulus,
                    exponent,
                    expires_at,
                },
            );
        }
        cache.get(kid).cloned().ok_or(())
    }

    async fn fresh_key(&self, kid: &str, now: Instant) -> Option<CachedKey> {
        self.keys
            .read()
            .await
            .get(kid)
            .filter(|key| key.expires_at > now)
            .cloned()
    }

    async fn fetch_keys(&self) -> Result<HashMap<String, (String, String)>, ()> {
        let response = self
            .client
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|_| ())?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > MAX_JWKS_BYTES as u64)
        {
            return Err(());
        }
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| ())?;
            if bytes.len().saturating_add(chunk.len()) > MAX_JWKS_BYTES {
                return Err(());
            }
            bytes.extend_from_slice(&chunk);
        }
        let document: JwksDocument = serde_json::from_slice(&bytes).map_err(|_| ())?;
        if document.keys.is_empty() || document.keys.len() > MAX_JWKS_KEYS {
            return Err(());
        }
        let mut keys = HashMap::with_capacity(document.keys.len());
        for key in document.keys {
            if key.kty != "RSA"
                || key.usage.as_deref().is_some_and(|usage| usage != "sig")
                || key
                    .alg
                    .as_deref()
                    .is_some_and(|algorithm| algorithm != "RS256")
                || !valid_text(&key.kid, MAX_KID_BYTES)
                || key.n.is_empty()
                || key.e.is_empty()
                || keys.insert(key.kid, (key.n, key.e)).is_some()
            {
                return Err(());
            }
        }
        Ok(keys)
    }
}

pub(crate) async fn require_access(
    State(verifier): State<Arc<AccessVerifier>>,
    mut request: Request,
    next: Next,
) -> Response {
    match verifier.authorize(request.headers()).await {
        Ok(actor) => {
            request.extensions_mut().insert(actor);
            next.run(request).await
        }
        Err(()) => unauthorized(),
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "error": {
                "code": "authentication_required",
                "message": "management authentication failed",
                "retryable": false
            }
        })),
    )
        .into_response()
}

fn accepted_audience(value: Option<&Value>, accepted: &[String]) -> bool {
    match value {
        Some(Value::String(audience)) => accepted.iter().any(|value| value == audience),
        Some(Value::Array(audiences)) if !audiences.is_empty() => {
            let strings = audiences
                .iter()
                .map(Value::as_str)
                .collect::<Option<Vec<_>>>();
            strings.is_some_and(|audiences| {
                audiences
                    .iter()
                    .any(|audience| accepted.iter().any(|value| value == audience))
            })
        }
        _ => false,
    }
}

fn integer_claim(value: Option<&Value>) -> bool {
    value.is_some_and(|value| value.is_i64() || value.is_u64())
}

fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
