# OAuth 2.0 + OpenID Connect (OIDC) Learning Lab

Hands-on, step-by-step implementations to understand OAuth 2.0 and OpenID Connect by building the flows manually in Node.js + TypeScript.

## Project goals

- Build a deep understanding of OAuth 2.0 and OIDC
- Observe raw HTTP requests, redirects, and tokens
- Learn incrementally with small, focused examples

Implementations are intentionally simple and log-heavy to keep the protocol visible.

## Repository structure

Each directory is a step in the learning journey.

- `auth-code-flow` — basic OAuth 2.0 Authorization Code Flow (no PKCE)

Future directories will build on earlier steps (PKCE, refresh tokens, validation, extensions).

## Prerequisites

- Node.js 18+
- Docker

## Keycloak setup (Docker)

Start Keycloak locally:

```bash
docker run -p 127.0.0.1:8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.6.1 start-dev
```

Open the admin console at `http://127.0.0.1:8080`.

Default credentials:

- Username: `admin`
- Password: `admin`

Create a realm, a client, and a test user for the examples (keep it simple and local).

For more details, see the Keycloak docs: https://www.keycloak.org/

## Project setup

```bash
git clone <your-repo-url>
cd oauth2-oidc-lab
cd auth-code-flow
npm install
cp .env.example .env
npm run dev
```

## How to use

1. Open `http://localhost:3000`.
2. Visit `http://localhost:3000/login` to start the flow.
3. Log in via Keycloak and complete the redirect.
4. Watch the terminal logs to inspect:
   - Authorization URL
   - Token request/response
   - Decoded JWT payloads

## Learning notes

- Flows are implemented manually (no high-level OAuth libraries).
- Verbose logging is intentional for learning.
- Security hardening and best practices are introduced in later steps.

## Future improvements

- PKCE
- Refresh tokens
- Token validation with JWKS
- Advanced OAuth extensions
