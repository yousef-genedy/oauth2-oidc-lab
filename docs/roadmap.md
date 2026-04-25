# Roadmap for OAuth 2.0 & OpenID Connect

## Phase 0 — Prerequisites

### Topics

- Authentication vs Authorization
- Sessions vs Tokens
- Cookies vs Bearer Tokens
- Basic cryptography concepts (hashing, signing, public/private keys)
- JSON Web Tokens (JWT), JWS, JWE
- What is a “principal” and identity

### Why this matters

OAuth is **not authentication**, and confusion here breaks everything later.

### Resources

- Auth0 Blog (very clear):
    - _“Authentication vs Authorization”_
- Okta Dev YouTube:
    - “OAuth 2.0 Explained Simply”
- IETF RFC 7519 (JWT)

---

## Phase 1 — Why OAuth 2.0 Exists

### Topics

- Problems OAuth solves:
    - Password sharing (e.g., “Login with Google”)
    - Delegated access
- Roles in OAuth:
    - Resource Owner
    - Client
    - Authorization Server
    - Resource Server
- High-level flow

### Add this (missing but critical)

- **Bearer token concept**
- **Scopes**

### Resources

- IETF RFC 6749 (core OAuth spec)
- Auth0:
    - “OAuth 2.0 and OpenID Connect: The Professional Guide”
- Okta YouTube channel

---

## Phase 2 — OpenID Connect (OIDC)

### Topics

- Why OAuth ≠ Authentication
- What OIDC adds:
    - ID Token
    - UserInfo endpoint
- Difference:
    - Access Token vs ID Token
- Claims and scopes (`openid`, `profile`, etc.)

### Add

- **Discovery endpoint (`.well-known/openid-configuration`)**
- **JWKS (JSON Web Key Set)**

### Resources

- OpenID Foundation official docs
- OIDC Core Spec (skim, don’t memorize)

---

## Phase 3 — Architecture & System Design

### Topics

- Authorization Server vs Resource Server separation
- API Gateway integration
- Microservices + OAuth
- Token validation (introspection vs JWT validation)
- Session vs token-based systems

### Add

- **SSO (Single Sign-On)**
- **Federation (Google login, etc.)**

---

## Phase 4 — OAuth Flows (CRITICAL CORE)

### Topics (organized from important → deprecated)

- Authorization Code Flow (MOST IMPORTANT)
- Authorization Code + PKCE (modern standard)
- Client Credentials Flow
- Device Authorization Flow
- Refresh Tokens

### Avoid / understand why deprecated

- Implicit Flow
- Resource Owner Password Credentials

### Your topics integrated here:

- Grants & grant types
- Client types:
    - Public vs Confidential
- Client credentials
- Resource Owner

---

## Phase 5 — PKCE (Deep Dive)

### Topics

- Why PKCE exists (code interception attack)
- Code verifier / code challenge
- Why PKCE is mandatory now

### Resource

- RFC 7636 (PKCE)

---

## Phase 6 — Token Lifecycle

### Topics

- Access Token vs Refresh Token
- Token expiration strategies
- Rotation (refresh token rotation)
- Revocation endpoint

### Add

- **Token introspection (RFC 7662)**

---

## Phase 7 — Security Best Practices (VERY IMPORTANT)

### Topics

- OAuth 2.0 Security Best Current Practice
- Threat model:
    - Token leakage
    - CSRF
    - Redirect URI attacks
- SameSite cookies
- State parameter

### Resource

- OAuth 2.0 Security BCP (RFC 9207 + drafts)

---

## Phase 8 — Advanced Extensions (Your Topics Here)

### Topics

- PAR (Pushed Authorization Requests)
- RAR (Rich Authorization Requests)
- Token Exchange (RFC 8693)
- DPoP (Proof of Possession tokens)
- mTLS (Mutual TLS)
- ABCA (Attestation-Based Client Auth)
- FAPI (Financial-grade API — I think you meant FPA?)

---

## Phase 9 — Real-World Patterns

### Topics

- First-party vs third-party apps (FPA)
- SPA vs Mobile vs Backend flows
- BFF (Backend for Frontend pattern)
- API-to-API communication

---

## Phase 10 — Hands-On Practice

### What to build

- Implement Authorization Code + PKCE
- Build:
    - Authorization server (or use Keycloak)
    - Resource server (Spring Boot API)
- Add:
    - JWT validation
    - Refresh tokens
    - Scopes

### Tools

- Keycloak
- Postman
- Spring Security OAuth2
