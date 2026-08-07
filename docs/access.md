# Cloudflare Access ingress contract

Status: authoritative v0 ingress-authentication and actor-isolation contract.
`docs/server-api.md` owns application resources after ingress is accepted.

## 1. Decision

Zode does not implement a user system in v0. There are no Zode user,
workspace, membership, role, grant, password, login-session, login-cookie,
invite, or account-management resources and no login/logout API or UI.

Cloudflare Access is the sole admission authority for the management origin.
Its self-hosted application policy decides which humans and service tokens may
reach the web UI, management HTTP API, and SSE streams. Every actor admitted by
that Access application enters one shared Zode management trust domain and may
use and manage every configured Endpoint, provider descriptor, auth profile,
default, and distribution policy. Fine-grained application RBAC is explicitly
out of scope; adding it later requires a new reviewed design and red E2Es.

Provider profiles are therefore deployment-shared resources, not personal
resources. Agent sessions remain isolated: Server derives a stable opaque
Endpoint subject from the validated Access actor, and Endpoint enforces that
subject on create, list, read, command, and SSE.

## 2. Network topology

V0 has two distinct public origins:

- the **management origin** serves the UI and `/v1` management/session proxy
  routes and is covered completely by one Cloudflare Access self-hosted
  application;
- the **callback origin** serves only the Endpoint-scoped external-tool
  callback route. It is not covered by interactive Access because third-party
  tools cannot present an Access browser session. It accepts only the separate
  Endpoint-issued callback bearer described in `docs/server-api.md`.

The provider OAuth callback is browser navigation and remains on the Access-
protected management origin. The public callback origin must not serve UI,
management, OAuth, health, or session routes. Server validates the configured
HTTP authority/Host before routing and does not select a surface from
`Forwarded` or `X-Forwarded-Host`; the same path on the wrong origin is not
accepted. Do not create a broad Access Bypass policy on the management
application to make tool callbacks work.

Both origins should reach Server through Cloudflare Tunnel or an equivalent
origin firewall arrangement that prevents direct public access. This network
restriction is defense in depth, not a substitute for Server-side JWT or
callback-bearer validation. Endpoint control routes remain separately
authenticated and are not made public merely because Server uses Access.

## 3. Access assertion verification

For every request on the management origin, Server reads only
`Cf-Access-Jwt-Assertion` as its origin assertion. It does not authenticate from
the browser's `CF_Authorization` cookie, caller-supplied email headers, or a
Zode bearer token. Cloudflare owns its cookies and login redirects.

Production configuration contains:

- exact, distinct management and callback HTTP origins. They contain no path,
  query, fragment, or credentials; production uses HTTPS and loopback HTTP is
  allowed only for deterministic local tests;
- the exact Access team issuer, such as
  `https://<team>.cloudflareaccess.com`;
- one or more accepted Access application AUD tags;
- a JWKS URL defaulting to
  `<issuer>/cdn-cgi/access/certs` and never discovered from token claims;
- a restart-stable subject-derivation key reference and key version.

Server derives the routing authority only from the validated request-target
authority/`Host` matched against those two configured origins. It never trusts
`Forwarded`, `X-Forwarded-Host`, the presence or absence of an Access header, or
the requested path to choose between management and callback surfaces. Equal or
ambiguous configured origins fail readiness.

On first initialization, Server records only the derivation key's non-secret
version/fingerprint beside `server_authority_id`. A later startup with a
different key or version fails readiness before serving management traffic or
contacting an Endpoint. Key replacement is not ordinary rotation; it requires
the explicit ownership migration described below.

The verifier rejects a missing or ambiguous assertion and validates all of:

- JOSE algorithm `RS256`, a non-empty `kid`, and the signature against the
  configured JWKS;
- exact `iss`, membership in the configured `aud` set, and token `type=app`;
- required `exp` and, when present, `nbf`, with one bounded configured
  clock-skew allowance;
- exactly one supported actor shape defined below.

Keys are cached for a bounded duration. An unknown `kid` triggers one
single-flight JWKS refresh; concurrent requests share that refresh. A fetch or
validation failure when a refresh is required fails closed. A matching cached
key may be used only until its configured hard expiry; stale keys are never an
unbounded availability fallback. The implementation must never follow an
issuer/JWKS URL from an unverified token, fall back to unsigned claims, accept
another algorithm, or keep an unbounded stale-key cache. Key rotation must not
require Server restart.

An SSE proxy validates the assertion when opening and closes no later than the
validated token's `exp`. The browser reconnects through Access, causing current
Access policy and a fresh assertion to be checked. Access policy revocation is
not modeled or persisted inside Zode. Therefore the configured Access
application/policy session duration is the upper bound for an already-open
connection's revocation latency; deployments that need a shorter bound must
shorten that Access duration. Immediate mid-connection revocation is not a Zode
v0 guarantee.

## 4. Access actor and Endpoint subject

A validated application token becomes exactly one Access actor:

- **human**: non-empty `sub`; `common_name` is not its identity;
- **service**: empty `sub` and non-empty `common_name`, whose value is the
  Access service-token client ID.

Malformed or ambiguous combinations are rejected. Email, display name, group,
country, and arbitrary custom claims are never identity or authorization
inputs. Zode does not call Access's identity endpoint or persist an Access user
record.

Server derives a bounded pseudonymous `access_actor_key` with a versioned HMAC
over the exact issuer, actor kind, and actor identifier. Server-owned mutation
receipts and OAuth attempts may persist only that pseudonymous key, never the
raw `sub`, service-token client ID, email, JWT, or Access cookie. Separate HMAC
domain labels derive the Endpoint subject under `server_authority_id`, so an
operation receipt cannot be reused as a session credential.

AUD is deliberately excluded from subject derivation: recreating the Access
application requires updating accepted AUD configuration but must not silently
orphan existing Endpoint sessions. Changing the Access organization/issuer,
deleting and re-adding a human identity, recreating a service token, rotating
the derivation key, or changing `server_authority_id` can change the subject and
therefore requires an explicit ownership-migration design before use.

## 5. Request authorization behavior

After Access verification, Server applies only resource validity and product
semantic checks; it has no local per-actor management grants. Concrete IDs are
resolved inside the one Server authority and absent IDs return the normal safe
not-found response. All Access actors can see the same Endpoint and provider
management resources, but an Endpoint returns only sessions owned by the
derived subject.

Human browser mutations require JSON plus the configured same-origin
`Origin`/Fetch-Metadata policy. Service-token clients use Cloudflare's standard
service-token headers at the Access edge and are identified at Server only from
the verified application assertion. Zode never receives or stores the service
token secret. The management API does not enable credentialed cross-origin
CORS; non-browser automation uses an Access service token rather than borrowing
a human browser session.

The browser OAuth callback is the only cross-site management-origin exception:
it is a bounded GET protected by validated one-time OAuth state and the same
Access actor. OAuth authorize-ticket redemption still requires same-origin
Fetch-Metadata, and external-tool callbacks use the separate callback origin.

OAuth attempts bind to the initiating `access_actor_key`; their callback and
event stream require the same actor even though the resulting provider profile
becomes shared management state. Missing or invalid Access assertions receive
one safe authentication error without disclosing signature, claim, key-cache,
or actor details.

## 6. External callback ingress

The callback origin accepts only:

```http
POST /v1/endpoints/{endpoint_id}/callbacks/{callback_id}
```

It requires the distinct Endpoint-issued callback bearer in its documented
secret header, bounds and rate-limits the request, and forwards it to the
selected Endpoint. It does not accept Access assertions as a replacement for
that bearer, set cookies, enable credentialed CORS, or expose any management
route. Callback IDs are opaque routing capabilities; only Endpoint stores their
session/tool mapping. Server remains stateless and returns retryable
unavailability while Endpoint is offline.

## 7. E2E contract

Access behavior is tested only through real processes and public network
boundaries. The E2E fixture is a network Access edge/JWKS service that signs
real RS256 application JWTs and forwards the production assertion header to a
real Server. The Server uses its ordinary configured verifier; no hidden login,
header bypass, database insertion, or `cfg(test)` auth path is allowed.

Required red-before-fix scenarios include:

- an accepted human assertion can use the complete management happy path;
- two human `sub` values share management resources but cannot list, read,
  stream, mutate, or collide idempotency receipts for each other's Endpoint
  sessions;
- a service-token assertion uses `common_name`, remains distinct from human
  subjects, and can call the same public API;
- missing, duplicate, forged, expired, not-yet-valid, wrong-issuer,
  wrong-audience, wrong-type, unsupported-algorithm, and malformed actor tokens
  all fail closed without reaching Endpoint;
- an unknown `kid` fetches the rotated JWKS once and succeeds, while an
  unavailable or invalid JWKS after hard cache expiry never degrades to stale-
  key or claim-only acceptance;
- `CF_Authorization`, email, and custom identity headers without a valid origin
  assertion grant no access and no raw identity/JWT reaches logs or databases;
- a long-lived SSE connection closes at assertion expiry and reconnects through
  the edge without missing or duplicating durable Endpoint events;
- restart with the same subject key preserves actor/session access, while an
  unapproved key change fails Server readiness before Endpoint contact;
- replacing the accepted Access application AUD while retaining issuer,
  `server_authority_id`, derivation key, and human `sub` preserves the same
  Endpoint subject and existing sessions;
- the browser enters through the Access fixture with no Zode login screen,
  token input, login cookie, or user/grant settings;
- provider OAuth callback remains Access-protected, while an external tool
  callback succeeds on the callback origin without Access and every management
  route on that origin is absent.

## 8. Deployment validation

Before a production deployment is accepted, run a staging smoke through the
real Cloudflare edge in addition to the deterministic fixture suite:

- an allowed human reaches UI, HTTP, and SSE while a denied identity never
  reaches Server;
- a scoped Access service token reaches the API and deleting that token blocks
  its next request;
- the Access self-hosted application covers the entire management origin with
  no broad Bypass policy, and its configured session duration matches the
  accepted revocation bound;
- the callback origin is outside interactive Access, exposes only the callback
  route, and rejects missing/wrong callback bearers;
- Server origin is not directly Internet-reachable outside Tunnel/firewall
  controls, and Access authentication logs show the expected allow/deny/service
  decisions without application secrets.

This smoke uses test-owned Access applications, policies, identities, service
tokens, and callbacks. It is not run against production accounts or credentials.

## 9. Protocol basis

The integration follows Cloudflare's published application-token contract:

- <https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/application-token/>
- <https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/>
- <https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/>
- <https://developers.cloudflare.com/cloudflare-one/access-controls/policies/>
- <https://developers.cloudflare.com/cloudflare-one/access-controls/policies/app-paths/>
- <https://developers.cloudflare.com/cloudflare-one/access-controls/access-settings/session-management/>
