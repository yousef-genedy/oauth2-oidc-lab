# Spring Boot OAuth2 / OIDC — Authorization Code Flow with Keycloak

A complete reference for the implementation, every design decision, all bugs found and fixed, and the full auth + logout flow.

---

## Project structure

```
src/main/
├── java/org/example/
│   ├── config/
│   │   ├── SecurityConfig.java          ← filter chain, logout, JWT converter
│   │   └── AuthFlowTraceFilter.java     ← structured JSON request/response logger
│   └── controller/
│       └── DashboardController.java     ← /dashboard (OidcUser) + /api/me (Jwt)
└── resources/
    ├── templates/
    │   └── dashboard.html               ← Thymeleaf view with logout modal
    └── application.yaml                 ← OAuth2 client + Keycloak config
```
---

## Keycloak setup

### Realm
Create a realm named `demo` at `http://localhost:8080`.

### Client
| Field | Value |
|---|---|
| Client ID | `spring-boot-app` |
| Client authentication | ON (confidential client — enables client secret) |
| Valid redirect URIs | `http://localhost:8081/login/oauth2/code/keycloak` |
| Valid post logout redirect URIs | `http://localhost:8081/login` |
| Web origins | `http://localhost:8081` |

### Client secret
Copy from **Clients → spring-boot-app → Credentials tab** and paste into `application.yaml`.

### User
Create a test user with First name, Last name, and Email set. Assign a password under **Credentials**.

---

## Full authentication flow

```
Browser                    Spring Boot :8081              Keycloak :8080
   │                               │                            │
   │  GET /dashboard               │                            │
   │──────────────────────────────>│                            │
   │                               │ AnonymousUser — no session │
   │                               │ AuthorizationFilter denies │
   │                               │ ExceptionTranslationFilter │
   │  302 → /oauth2/authorization/keycloak                      │
   │<──────────────────────────────│                            │
   │                               │                            │
   │  GET /oauth2/authorization/keycloak                        │
   │──────────────────────────────>│                            │
   │                               │ Generates state (CSRF)     │
   │                               │ Generates nonce (replay)   │
   │                               │ Saves both in session      │
   │  302 → Keycloak /auth?response_type=code&state=…&nonce=…   │
   │<──────────────────────────────│                            │
   │                               │                            │
   │  GET /auth?…                  │                            │
   │──────────────────────────────────────────────────────────>│
   │  (Keycloak login page)        │                            │
   │<──────────────────────────────────────────────────────────│
   │                               │                            │
   │  POST credentials             │                            │
   │──────────────────────────────────────────────────────────>│
   │                               │                            │
   │  302 → /login/oauth2/code/keycloak?code=…&state=…          │
   │<──────────────────────────────────────────────────────────│
   │                               │                            │
   │  GET /login/oauth2/code/keycloak?code=…&state=…            │
   │──────────────────────────────>│                            │
   │                               │ Validates state == session │
   │                               │                            │
   │                               │  POST /token               │
   │                               │  code + client_secret      │
   │                               │ ─────────────────────────>│
   │                               │  access_token + id_token   │
   │                               │ <─────────────────────────│
   │                               │                            │
   │                               │ Validates id_token JWT     │
   │                               │ Verifies nonce claim       │
   │                               │ Builds OidcUser            │
   │                               │ Stores in session          │
   │  302 → /dashboard             │                            │
   │<──────────────────────────────│                            │
   │                               │                            │
   │  GET /dashboard (JSESSIONID)  │                            │
   │──────────────────────────────>│                            │
   │  200 OK — dashboard.html      │                            │
   │<──────────────────────────────│                            │
```

---

## Full logout flow

```
Browser                    Spring Boot :8081              Keycloak :8080
   │                               │                            │
   │  POST /logout + CSRF token    │                            │
   │──────────────────────────────>│                            │
   │                               │ 1. Invalidate HTTP session │
   │                               │ 2. Clear SecurityContext   │
   │                               │ 3. Delete JSESSIONID cookie│
   │                               │                            │
   │                               │ OidcClientInitiated        │
   │                               │ LogoutSuccessHandler builds│
   │                               │ end_session URL            │
   │  302 → Keycloak /logout?id_token_hint=…&post_logout_redirect_uri=…
   │<──────────────────────────────│                            │
   │                               │                            │
   │  GET /logout?…                │                            │
   │──────────────────────────────────────────────────────────>│
   │                               │  Keycloak ends SSO session │
   │                               │  Clears Keycloak cookie    │
   │  302 → http://localhost:8081/login                         │
   │<──────────────────────────────────────────────────────────│
   │                               │                            │
   │  GET /login                   │                            │
   │──────────────────────────────>│                            │
   │  Login page                   │                            │
   │<──────────────────────────────│                            │
```

### Why OIDC RP-initiated logout matters

| Without it | With it |
|---|---|
| Spring clears local session only | Spring clears session AND tells Keycloak |
| User is still logged in at Keycloak | Keycloak SSO session is ended |
| Next visit to /dashboard silently re-authenticates | Next visit shows the Keycloak login form |
| Other apps sharing the SSO session are not notified | All RP sessions in the realm are aware |

### Why POST /logout and not GET

Spring Security's `LogoutFilter` only accepts POST by default. A GET link could be triggered by a `<img src="/logout">` tag on a malicious page, logging the user out without their intent. The CSRF token embedded by Thymeleaf in the form prevents this.

---

## Security parameters explained

### `state` (CSRF protection)
1. Spring generates a random Base64 string and saves it in the HTTP session
2. It is appended to the Keycloak authorization URL as `?state=…`
3. Keycloak echoes it back unmodified in the callback URL
4. Spring compares: `returned_state == session_state` — if they differ, the request is rejected

**Attack prevented:** An attacker cannot forge the callback URL because they cannot know the random `state` stored in the victim's session.

### `nonce` (replay attack protection)
1. Spring generates a random Base64 string and saves it in the HTTP session
2. It is sent to Keycloak as `?nonce=…` in the authorization URL
3. Keycloak embeds it inside the signed `id_token` JWT as a claim
4. Spring verifies: `token.nonce == session.nonce` — if they differ, the token is rejected

**Attack prevented:** A stolen `id_token` cannot be replayed in a different login session because the nonce in the token won't match the nonce in the new session.

| | state | nonce |
|---|---|---|
| Travels in | URL query param (outside token) | Signed JWT claim (inside token) |
| Verified by | Comparing URL param vs session | Comparing JWT claim vs session |
| Protects against | CSRF on the callback | Replay of stolen tokens |
| Tamper-proof | No — but unguessable (random) | Yes — changing it breaks JWT signature |

---

## Two authentication mechanisms

Your app supports two caller types simultaneously on the same filter chain:

### Browser → `/dashboard` (OIDC session)
- Authentication: OAuth2 Authorization Code + OIDC
- Principal type: `OidcUser`
- Session: HTTP session (`JSESSIONID` cookie), loaded once at login
- Logout: POST /logout → Keycloak end_session

### API client → `/api/me` (JWT Bearer)
- Authentication: JWT Bearer token in `Authorization` header
- Principal type: `Jwt`
- Session: none — token validated on every request
- Logout: not applicable — token expires naturally (or use token revocation)

```java
// Browser principal — rich typed accessors
@GetMapping("/dashboard")
public String dashboard(@AuthenticationPrincipal OidcUser user) {
    user.getFullName();   // "Ayat Mohamed"
    user.getEmail();      // "yoka91011@gmail.com"
    user.getClaims();     // all id_token claims as a Map
}

// API principal — raw claim access
@GetMapping("/api/me")
@ResponseBody
public Map<String, Object> me(@AuthenticationPrincipal Jwt jwt) {
    jwt.getClaimAsString("preferred_username");
    jwt.getClaim("realm_access");   // roles map
}
```

Injecting the wrong type gives `null` — no exception at injection time, `NullPointerException` at first method call.

---

## Token claims reference

These claims are present in your Keycloak id_token (from the debug log):

| Claim | Value example | Meaning |
|---|---|---|
| `sub` | `94033522-c41e-…` | Stable unique user ID — use this as your database foreign key |
| `preferred_username` | `ayat` | Login username — used as `user-name-attribute` |
| `name` | `Ayat Mohamed` | Full display name |
| `given_name` | `Ayat` | First name |
| `family_name` | `Mohamed` | Last name |
| `email` | `yoka91011@…` | Email address |
| `email_verified` | `true` | Whether Keycloak has verified the email |
| `iss` | `http://localhost:8080/realms/demo` | Token issuer — Spring validates this |
| `aud` | `spring-boot-app` | Intended audience — Spring validates this matches client-id |
| `iat` | `2026-05-02T10:27:23Z` | Issued at |
| `exp` | `2026-05-02T10:32:23Z` | Expires at (5 minutes by default) |
| `session_state` | `bef48df8-…` | Keycloak session ID |
| `realm_access` | `{"roles":["default-roles-demo"]}` | Keycloak roles — mapped by `jwtAuthConverter` |
| `nonce` | `zc-LR7PGXpmn7n…` | Replay protection — verified by Spring, not for application use |
| `at_hash` | `74QNUNki…` | Access token hash — binds id_token to access_token |

-
---

## Log output — what to expect

With the structured `AuthFlowTraceFilter`, every request produces one JSON event in `logs/debug.log`. A complete login + dashboard + logout cycle produces exactly 6 events:

```
AUTH-FLOW-EVENT { "event": "INITIAL_ACCESS_DENIED",    "uri": "/dashboard", ... }
AUTH-FLOW-EVENT { "event": "REDIRECT_TO_KEYCLOAK",     "uri": "/oauth2/authorization/keycloak",
                  "response": { "securityParams": { "state": "…", "nonce": "…" } } }
AUTH-FLOW-EVENT { "event": "KEYCLOAK_CALLBACK_RECEIVED","uri": "/login/oauth2/code/keycloak",
                  "request": { "oauthParams": { "code": "…", "state": "…" } } }
AUTH-FLOW-EVENT { "event": "AUTHENTICATION_SUCCESS",    "uri": "/login/oauth2/code/keycloak",
                  "extractedUser": { "username": "ayat", "email": "…", "roles": [...] } }
AUTH-FLOW-EVENT { "event": "DASHBOARD_ACCESS",          "uri": "/dashboard", "response": { "status": 200 } }
AUTH-FLOW-EVENT { "event": "LOGOUT",                    "uri": "/logout",
                  "response": { "location": "http://localhost:8080/…/logout?id_token_hint=…" } }
```

---

## Quick checklist before running

- [ ] Keycloak running on `localhost:8080`, realm `demo` exists
- [ ] Client `spring-boot-app` created, client authentication ON
- [ ] Valid redirect URI: `http://localhost:8081/login/oauth2/code/keycloak`
- [ ] Valid post logout redirect URI: `http://localhost:8081/login`
- [ ] Client secret copied into `application.yaml`
- [ ] Test user created with email, first name, last name, password
- [ ] `spring-boot-starter-thymeleaf` in `pom.xml`
- [ ] `dashboard.html` in `src/main/resources/templates/`
