# Keycloak Basic OAuth2 + OIDC Authorization Code Flow

Minimal Node.js + TypeScript project that manually implements OAuth 2.0 Authorization Code Flow and OpenID Connect
against a local Keycloak server.

This project avoids high-level OAuth libraries so each step stays visible and easy to follow.

## What this demonstrates

- Building the authorization URL manually
- Generating and validating `state` (CSRF protection)
- Exchanging the authorization `code` for tokens manually
- Logging token request/response details
- Decoding `access_token` and `id_token` payloads with `jsonwebtoken.decode`
- Calling OIDC `userinfo` with a bearer access token

## Project structure

```text
auth-code-flow/
  src/
    server.ts
    config.ts
    routes/
      auth.ts
      profile.ts
    utils/
      jwt.ts
  .env.example
  package.json
  tsconfig.json
  README.md
```

## Prerequisites

- Node.js 18+
- Keycloak running at `http://127.0.0.1:8080`
- Realm: `oauth-poc`
- Confidential client: `oauth-basic-client`
- Redirect URI configured in Keycloak: `http://localhost:3000/callback`

## Environment variables

Copy `.env.example` to `.env` and set your client secret:

```bash
cp .env.example .env
```

## Run

```bash
npm install
npm run dev
```

Open `http://localhost:3000/login` to start the flow.

## Flow walkthrough (high level)

1. `GET /login` generates a random `state` and stores it in memory.
2. The server builds the authorization URL and redirects the browser to Keycloak.
3. After login/consent, Keycloak redirects back to `GET /callback` with `code` + `state`.
4. The server validates `state` and exchanges the `code` for tokens at the token endpoint.
5. The server decodes the JWTs (no signature verification) and calls the UserInfo endpoint.

## Routes

- `GET /login`
  - Generates random `state`
  - Stores it in memory
  - Redirects to Keycloak authorization endpoint with `response_type=code`
- `GET /callback`
  - Reads `code` + `state`
  - Validates `state`
  - Exchanges code for tokens
  - Logs and returns tokens, decoded JWT payloads, and UserInfo response
- `GET /profile` (optional)
  - Accepts `Authorization: Bearer <token>`
  - Decodes and returns payload (decode only)

## Logging checklist (visible in terminal)

- Authorization URL
- Callback query params
- Token request body
- Token response body
- Raw tokens (`access_token`, `id_token`, `refresh_token`)
- Decoded access/id token payloads (`iss`, `sub`, `aud`, `exp`, `email`, etc.)
- UserInfo response
