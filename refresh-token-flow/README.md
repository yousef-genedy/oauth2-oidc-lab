# OAuth 2.0 + OIDC Refresh Token Flow (Go + Keycloak)

Learning-focused Go module that demonstrates:

- Authorization Code Flow with PKCE
- Access token expiration behavior
- Refresh token usage for silent continuity
- Refresh token rotation detection
- Token lifecycle visibility with verbose logs

This module intentionally avoids high-level OAuth abstraction libraries so protocol details stay visible.

## What this example teaches

1. **Access tokens are short-lived by design**
   - Short lifespan limits blast radius if an access token is leaked.
   - In this lab, Keycloak access tokens are configured to expire quickly (60 seconds).

2. **Refresh tokens keep the user session alive**
   - Instead of forcing re-login, the app exchanges a refresh token for a new access token.
   - This enables **silent session continuity**.

3. **Refresh tokens are sensitive credentials**
   - Whoever holds a valid refresh token can mint new access tokens.
   - Keep refresh tokens server-side and never expose them unnecessarily.

4. **Rotation improves security**
   - With Keycloak `Revoke Refresh Token = ON`, refresh tokens are rotated.
   - Old refresh tokens become invalid after use, reducing replay risk.

5. **PKCE is still essential**
   - PKCE protects the authorization code exchange for public clients with no client secret.
   - It remains critical even when refresh tokens are used later in the session lifecycle.

## Project structure

```text
refresh-token-flow/
  main.go
  .env.example
  internal/
    config/
      config.go
    routes/
      routes.go
    handlers/
      handlers.go
      refresh.go
    pkce/
      pkce.go
    oauth/
      client.go
    tokenutil/
      tokenutil.go
    jwtutil/
      jwtutil.go
    session/
      store.go
    models/
      types.go
```

## Internal architecture (wiring and request execution)

This section explains how `main.go` wires dependencies and how each request travels through routes, handlers, storage, and Keycloak calls.

### Class / file interaction diagram

```mermaid
classDiagram
direction LR

class main_go {
  +main()
}

class config_Config {
  +ServerAddr
  +AuthorizationEndpoint
  +TokenEndpoint
  +UserInfoEndpoint
  +Load()
}

class session_Store {
  +SavePendingAuthorization()
  +ConsumePendingAuthorization()
  +SaveTokenSet()
  +CurrentTokenSet()
}

class oauth_Client {
  +ExchangeAuthorizationCode()
  +ExchangeRefreshToken()
  +CallUserInfo()
}

class handlers_Handler {
  -cfg *config.Config
  -store *session.Store
  -oauthClient *oauth.Client
  +Home()
  +Login()
  +Callback()
  +Profile()
  +TokenStatus()
  -refreshAccessToken()
}

class routes_go {
  +Register(mux, handler)
}

class pkce_pkg {
  +GenerateCodeVerifier()
  +GenerateCodeChallenge()
  +GenerateRandomURLSafe()
}

class jwtutil_pkg {
  +DecodeJWT()
}

class tokenutil_pkg {
  +NewTokenSet()
  +IsExpired()
  +SecondsRemaining()
}

main_go --> config_Config : Load()
main_go --> session_Store : NewStore()
main_go --> oauth_Client : NewClient()
main_go --> handlers_Handler : New(cfg,store,client)
main_go --> routes_go : Register()

handlers_Handler --> session_Store
handlers_Handler --> oauth_Client
handlers_Handler --> pkce_pkg
handlers_Handler --> jwtutil_pkg
handlers_Handler --> tokenutil_pkg
```

### Per-request execution diagram

```mermaid
sequenceDiagram
autonumber
participant B as Browser
participant R as routes.Register
participant H as handlers.Handler
participant S as session.Store
participant O as oauth.Client
participant K as Keycloak

Note over B,K: GET /login
B->>R: /login
R->>H: Login()
H->>H: pkce.GenerateRandomURLSafe(state, nonce)
H->>H: pkce.GenerateCodeVerifier/challenge
H->>S: SavePendingAuthorization()
H-->>B: 302 redirect to Keycloak /auth

Note over B,K: GET /callback
B->>R: /callback?code&state
R->>H: Callback()
H->>S: ConsumePendingAuthorization(state)
H->>O: ExchangeAuthorizationCode(code, verifier)
O->>K: POST /token (authorization_code)
K-->>O: access/id/refresh tokens
O-->>H: token response
H->>S: SaveTokenSet()
H->>H: jwtutil.DecodeJWT(access + id)
H-->>B: JSON with decoded tokens + lifecycle info

Note over B,K: GET /profile
B->>R: /profile
R->>H: Profile()
H->>S: CurrentTokenSet()
H->>O: CallUserInfo(access_token)
O->>K: GET /userinfo
alt access token valid
  K-->>O: 200 profile
  O-->>H: profile
  H-->>B: profile JSON
else expired/unauthorized
  K-->>O: 401
  O-->>H: unauthorized
  H->>H: refreshAccessToken()
  H->>O: ExchangeRefreshToken(refresh_token)
  O->>K: POST /token (refresh_token)
  K-->>O: new access + rotated refresh
  O-->>H: refreshed tokens
  H->>S: SaveTokenSet()
  H->>O: CallUserInfo(new access token)
  O->>K: GET /userinfo
  K-->>O: 200 profile
  O-->>H: profile
  H-->>B: profile JSON (silent continuity)
end

Note over B,K: GET /token-status
B->>R: /token-status
R->>H: TokenStatus()
H->>S: CurrentTokenSet()
H->>H: tokenutil.SecondsRemaining / IsExpired
H-->>B: expiry + remaining + expired
```

### Wiring summary

`main.go` creates shared singletons (`cfg`, `store`, `oauthClient`) once, injects them into one `handlers.Handler`, and route handlers use that same instance across requests. That is why in-memory token and pending-auth state are preserved through the flow.

## Keycloak configuration (required)

- Base URL: `http://127.0.0.1:8080`
- Realm: `oauth-poc`
- Client ID: `oauth-refresh-client`
- Client type: **Public** (no client secret)
- PKCE: **Enabled** (`S256`)
- Valid redirect URI: `http://localhost:3000/callback`
- Access Token Lifespan: **60 seconds**
- Revoke Refresh Token: **ON**

OIDC endpoints used by the app (derived from base + realm):

- Authorization: `/realms/oauth-poc/protocol/openid-connect/auth`
- Token: `/realms/oauth-poc/protocol/openid-connect/token`
- UserInfo: `/realms/oauth-poc/protocol/openid-connect/userinfo`
- JWKS: `/realms/oauth-poc/protocol/openid-connect/certs`

## Setup

1. Start Keycloak locally:

```bash
docker run -p 127.0.0.1:8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.6.1 start-dev
```

2. Configure realm/client/user in Keycloak as listed above.

3. Configure local app:

```bash
cd refresh-token-flow
cp .env.example .env
```

4. Run:

```bash
go mod tidy
go run .
```

5. Start flow:

```text
http://localhost:3000/login
```

## Endpoints in this module

- `GET /login`
  - Generates `state`, `nonce`, `code_verifier`, `code_challenge`
  - Logs full authorization URL
  - Redirects to Keycloak

- `GET /callback`
  - Validates `state`
  - Exchanges authorization code for tokens
  - Stores token set in memory
  - Prints:
    - raw token response
    - decoded access token (header + claims + exp)
    - decoded ID token (header + claims + exp)
    - refresh token info

- `GET /profile`
  - Calls UserInfo with current access token
  - If access token is rejected (expired), triggers refresh flow automatically
  - Retries UserInfo with the new access token

- `GET /token-status`
  - Returns token expiration timestamp
  - Returns seconds remaining
  - Returns expired/non-expired status

## Flow diagram: login + code exchange (PKCE)

```mermaid
sequenceDiagram
    actor User
    participant App as Go App
    participant KC as Keycloak

    User->>App: GET /login
    App->>App: Generate state, nonce, code_verifier, code_challenge
    App->>KC: Redirect to /auth (code_challenge + state + nonce)
    KC-->>User: Login page
    User->>KC: Authenticate
    KC-->>App: Redirect /callback?code=...&state=...
    App->>App: Validate state, load code_verifier
    App->>KC: POST /token (grant_type=authorization_code)
    KC-->>App: access_token + id_token + refresh_token
    App->>App: Decode JWT header/claims + expiration timestamps
```

## Flow diagram: refresh flow + silent continuity

```mermaid
sequenceDiagram
    actor User
    participant App as Go App
    participant KC as Keycloak
    participant UI as UserInfo Endpoint

    User->>App: GET /profile
    App->>UI: GET /userinfo (Bearer old access token)
    UI-->>App: 401 Unauthorized (token expired)
    App->>KC: POST /token (grant_type=refresh_token)
    KC-->>App: new access token + rotated refresh token
    App->>App: Replace stored tokens + log rotation
    App->>UI: Retry GET /userinfo (Bearer new access token)
    UI-->>App: 200 Profile JSON
    App-->>User: Profile response without re-login
```

## Token lifecycle timeline

```mermaid
sequenceDiagram
    participant App
    participant Keycloak

    App->>Keycloak: auth code exchange
    Keycloak-->>App: AT1 (60s), RT1
    Note over App: Store AT1 exp timestamp
    Note over App: /token-status shows countdown
    App->>Keycloak: refresh with RT1 after AT1 expiry
    Keycloak-->>App: AT2, RT2 (rotation)
    Note over App: RT1 becomes invalid when rotation is active
    App->>Keycloak: refresh with RT2 on next expiry
    Keycloak-->>App: AT3, RT3
```

## Refresh token lifecycle explained

1. Initial login returns:
   - `access_token` (short-lived)
   - `refresh_token` (used for new access tokens)
2. Access token expires quickly.
3. App calls token endpoint with `grant_type=refresh_token`.
4. Keycloak issues a new access token and (with rotation enabled) a new refresh token.
5. App replaces old tokens in memory.

If the app accidentally reuses an old rotated refresh token, Keycloak rejects it, demonstrating replay protection in practice.

## Sample HTTP interactions

### 1) Check token status before login

```bash
curl -s http://localhost:3000/token-status
```

Example response:

```json
{
  "has_tokens": false,
  "message": "no tokens in memory yet. Complete /login then /callback first."
}
```

### 2) Trigger login

```bash
curl -i http://localhost:3000/login
```

You will receive a `302` redirect to Keycloak `/auth?...`.

### 3) Callback response (after browser login)

`/callback` returns decoded token details and stores token lifecycle state in memory.

Example response shape:

```json
{
  "message": "Authorization Code + PKCE completed. Tokens stored in memory for lifecycle demo.",
  "nonce_check": "nonce validated",
  "access_token_expires_at": "2026-05-07T12:00:00Z",
  "decoded_access_token": {
    "header": {"alg": "RS256", "typ": "JWT"},
    "claims": {"sub": "...", "exp": 1746619200},
    "exp_unix": 1746619200,
    "expires_at": "2026-05-07T12:00:00Z"
  }
}
```

### 4) Call profile (auto-refresh if expired)

```bash
curl -s http://localhost:3000/profile
```

If the access token is expired, response indicates refresh behavior:

```json
{
  "message": "userinfo succeeded after refresh (silent session continuity)",
  "refresh": {
    "triggered": true,
    "rotation_occurred": true,
    "new_access_expires_at": "2026-05-07T12:02:00Z"
  }
}
```

## Troubleshooting

- `state validation failed`:
  - Ensure the callback belongs to the same in-memory app instance and flow.
- `nonce validation failed`:
  - Ensure `nonce` is included in authorization request and ID token is from the same request.
- refresh failures:
  - Confirm client is public, refresh tokens enabled, and old rotated token is not reused.

## Security scope for this PoC

This module is intentionally local and educational:

- In-memory token storage only
- JWT decode visibility (not full cryptographic signature verification)
- Verbose protocol logs

Do not deploy this exact shape as-is to production without hardening.
