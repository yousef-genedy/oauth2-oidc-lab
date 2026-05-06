# Keycloak OAuth2 + OIDC PKCE PoC (Node.js + TypeScript)

Minimal proof of concept that manually performs OAuth 2.0 Authorization Code Flow with PKCE and OpenID Connect against a local Keycloak server.

## What this demonstrates

- Building the `/auth` redirect URL manually
- PKCE generation (`code_verifier`, `code_challenge` with SHA-256 + base64url)
- State handling and validation in memory
- Manual token exchange (`authorization_code` grant)
- Logging raw `access_token` and `id_token`
- Decoding JWTs and highlighting `iss`, `sub`, `aud`, `exp`
- Calling OIDC UserInfo endpoint with the access token

## Project structure

```text
src/
  server.ts
  routes/
    auth.ts
    profile.ts
  utils/
    pkce.ts
    jwt.ts
  config.ts
```

## Prerequisites

- Node.js 18+
- Local Keycloak running at `http://127.0.0.1:8080`
- Realm: `oauth-poc`
- Public client: `oauth-poc-client`
- Redirect URI configured in Keycloak: `http://localhost:3000/callback`

## Setup

1. Copy env file and adjust values if needed.
2. Install dependencies.
3. Start the server.

```bash
cp .env .env
npm install
npm run dev
```

Then open:

- `http://localhost:3000/login` to start OAuth/OIDC flow

## Routes

- `GET /login`
  - Generates `code_verifier`, `code_challenge`, and `state`
  - Stores PKCE + state in memory
  - Redirects to Keycloak authorization endpoint
- `GET /callback`
  - Validates returned `state`
  - Exchanges `code` for tokens with Keycloak
  - Logs request body, response headers/body, decoded JWTs, and UserInfo
- `GET /profile` (optional)
  - Accepts `Authorization: Bearer <token>`
  - Decodes token payload and returns it

## Notes

- JWTs are decoded for visibility only. Full cryptographic signature validation is intentionally not abstracted away in this PoC.
- PKCE/state are stored in memory, so this is for local learning and debugging only.

