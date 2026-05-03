package org.example.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Structured JSON auth-flow logger.
 *
 * Produces one clean JSON block per request, logged as:
 *   AUTH-FLOW-EVENT { ... }
 *
 * Covers every redirect, security param, and extracted user data.
 * Only auth-flow paths are logged; all other requests pass through silently.
 *
 * Sample output (condensed):
 *
 *   AUTH-FLOW-EVENT {
 *     "timestamp":   "2026-05-02T10:27:17.329Z",
 *     "event":       "REDIRECT_TO_KEYCLOAK",
 *     "method":      "GET",
 *     "uri":         "/oauth2/authorization/keycloak",
 *     "sessionId":   "none",
 *     "request":     { "cookies": [] },
 *     "response":    {
 *       "status":   302,
 *       "location": "http://localhost:8080/realms/demo/...auth",
 *       "securityParams": {
 *         "state": "QdXFX8-k… | CSRF protection — Spring saves this...",
 *         "nonce": "zc-LR7PG… | Replay protection — Keycloak embeds..."
 *       }
 *     }
 *   }
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class AuthFlowTraceFilter extends OncePerRequestFilter {

    private static final Logger       log  = LoggerFactory.getLogger(AuthFlowTraceFilter.class);
    private static final int          MAX_BODY_BYTES = 800;
    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    // ── event type labels ────────────────────────────────────────────────────
    private static final String EVT_INITIAL_ACCESS = "INITIAL_ACCESS_DENIED";
    private static final String EVT_OAUTH2_START   = "REDIRECT_TO_KEYCLOAK";
    private static final String EVT_CALLBACK       = "KEYCLOAK_CALLBACK_RECEIVED";
    private static final String EVT_AUTH_SUCCESS   = "AUTHENTICATION_SUCCESS";
    private static final String EVT_DASHBOARD      = "DASHBOARD_ACCESS";
    private static final String EVT_API_ACCESS     = "API_ACCESS";
    private static final String EVT_LOGIN_PAGE     = "LOGIN_PAGE";
    private static final String EVT_ERROR          = "AUTH_ERROR";

    // ── filter entry point ───────────────────────────────────────────────────

    @Override
    protected void doFilterInternal(HttpServletRequest  request,
                                    HttpServletResponse response,
                                    FilterChain         chain)
            throws ServletException, IOException {

        String uri = request.getRequestURI();
        if (!isTracedPath(uri)) {
            chain.doFilter(request, response);
            return;
        }

        ContentCachingRequestWrapper  req = new ContentCachingRequestWrapper(request);
        ContentCachingResponseWrapper res = new ContentCachingResponseWrapper(response);

        String sessionBefore = sessionId(req.getSession(false));

        try {
            chain.doFilter(req, res);
        } finally {
            try {
                String sessionAfter = sessionId(req.getSession(false));
                String session = "none".equals(sessionAfter) ? sessionBefore : sessionAfter;
                writeEvent(req, res, uri, session);
            } catch (Exception ex) {
                log.warn("[AUTH-FILTER] Failed to serialize log event: {}", ex.getMessage());
            }
            res.copyBodyToResponse();
        }
    }

    // ── event builder ────────────────────────────────────────────────────────

    private void writeEvent(ContentCachingRequestWrapper  req,
                            ContentCachingResponseWrapper res,
                            String uri,
                            String session) throws Exception {

        int    status   = res.getStatus();
        String location = res.getHeader("Location");

        Map<String, Object> event = new LinkedHashMap<>();
        event.put("timestamp", Instant.now().toString());
        event.put("event",     resolveEventType(uri, status, location));
        event.put("method",    req.getMethod());
        event.put("uri",       uri);
        event.put("sessionId", session);

        // ── request section ──────────────────────────────────────────────────
        Map<String, Object> reqSection = new LinkedHashMap<>();

        if (req.getQueryString() != null) {
            reqSection.put("queryString", req.getQueryString());
        }

        // Callback: explain the OAuth2 params coming back from Keycloak
        if (uri.startsWith("/login/oauth2/code/")) {
            Map<String, String> oauthParams = new LinkedHashMap<>();
            String code  = req.getParameter("code");
            String state = req.getParameter("state");
            if (code  != null) oauthParams.put("code",
                    abbrev(code, 16) + "… (one-time authorization code — exchanged server-to-server for tokens, ~60s TTL)");
            if (state != null) oauthParams.put("state",
                    abbrev(state, 20) + "… (echoed by Keycloak — Spring verifies this equals the value saved in session → CSRF protection)");
            if (!oauthParams.isEmpty()) reqSection.put("oauthParams", oauthParams);
        }

        // First dashboard hit: note it's anonymous
        if (uri.startsWith("/dashboard") && session.equals("none")) {
            reqSection.put("note", "Anonymous request — no session. Spring will deny and redirect to login.");
        }

        reqSection.put("cookies", extractCookies(req));
        event.put("request", reqSection);

        // ── response section ─────────────────────────────────────────────────
        Map<String, Object> resSection = new LinkedHashMap<>();
        resSection.put("status", status);

        if (location != null) {
            // Strip long query string from location for readability — full params go in securityParams
            resSection.put("location", stripQuery(location));

            Map<String, String> secParams = extractSecurityParams(location);
            if (!secParams.isEmpty()) {
                resSection.put("securityParams", secParams);
            }
        }

        if (status == 302 && location != null && location.contains("/dashboard")) {
            resSection.put("note",
                    "Authentication complete — OidcUser built from id_token, stored in HTTP session as SPRING_SECURITY_CONTEXT");
        }

        // Error bodies
        if (status >= 400) {
            String body = bodySnippet(res.getContentAsByteArray(), res.getCharacterEncoding());
            if (!body.isBlank()) resSection.put("errorBody", body);
        }

        event.put("response", resSection);

        // ── extracted user data (if session holds an authenticated user) ──────
        HttpSession s = req.getSession(false);
        if (s != null) {
            Object ctx = s.getAttribute("SPRING_SECURITY_CONTEXT");
            if (ctx != null) {
                Map<String, Object> userData = parseUserFromContext(ctx.toString());
                if (!userData.isEmpty()) {
                    event.put("extractedUser", userData);
                }
            }
        }

        log.info("AUTH-FLOW-EVENT {}", JSON.writeValueAsString(event));
    }

    // ── security parameter extraction ────────────────────────────────────────

    /**
     * Parses any redirect Location URL and annotates every OAuth2/OIDC security
     * parameter with a plain-English explanation of what it does.
     */
    private Map<String, String> extractSecurityParams(String url) {
        Map<String, String> params = new LinkedHashMap<>();
        int q = url.indexOf('?');
        if (q < 0) return params;

        for (String pair : url.substring(q + 1).split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length < 2) continue;
            String key = kv[0];
            String val = decode(kv[1]);

            switch (key) {
                case "state" -> params.put("state",
                        abbrev(val, 20) + "… | CSRF protection — Spring saves this in the HTTP session; "
                                + "when Keycloak echoes it back, Spring verifies they match before exchanging the code");
                case "nonce" -> params.put("nonce",
                        abbrev(val, 20) + "… | Replay attack protection — Keycloak embeds this in the signed id_token; "
                                + "Spring verifies it matches the session value so stolen tokens can't be reused");
                case "scope" -> params.put("scope",
                        val + " | 'openid' enables OIDC id_token; 'email'+'profile' add user claims to the token");
                case "response_type" -> params.put("response_type",
                        val + " | Authorization Code flow — only a short-lived code passes through the browser; "
                                + "actual tokens are fetched server-to-server");
                case "redirect_uri" -> params.put("redirect_uri",
                        val + " | must exactly match a URI registered in the Keycloak client settings");
                case "client_id" -> params.put("client_id", val);
                case "code" -> params.put("code",
                        abbrev(val, 16) + "… | authorization code returned by Keycloak — "
                                + "Spring exchanges this for access_token + id_token via POST /token (browser never sees the tokens)");
            }
        }
        return params;
    }

    // ── user data extraction from SecurityContext toString ────────────────────

    /**
     * Parses the SecurityContext.toString() representation to extract user fields.
     * This runs after a successful authentication — the context is already in the session.
     */
    private Map<String, Object> parseUserFromContext(String ctx) {
        Map<String, Object> user = new LinkedHashMap<>();

        extract(ctx, "preferred_username=", user, "username");
        extract(ctx, "name=",               user, "fullName");
        extract(ctx, "given_name=",         user, "givenName");
        extract(ctx, "family_name=",        user, "familyName");
        extract(ctx, "email=",              user, "email");
        extract(ctx, "email_verified=",     user, "emailVerified");
        extract(ctx, "sub=",                user, "subject");
        extract(ctx, "session_state=",      user, "sessionState");
        extract(ctx, "iss=",                user, "issuer");
        extract(ctx, "exp=",                user, "expiresAt");
        extract(ctx, "iat=",                user, "issuedAt");

        // Granted authorities (OIDC_USER, SCOPE_openid, etc.)
        int a1 = ctx.indexOf("Granted Authorities=[");
        if (a1 >= 0) {
            int a2 = ctx.indexOf("]", a1 + 21);
            if (a2 > a1) {
                String raw = ctx.substring(a1 + 21, a2)
                        .replace("[", "").replace("]", "");
                user.put("authorities", Arrays.asList(raw.split(", ")));
            }
        }

        return user;
    }

    private void extract(String src, String key, Map<String, Object> target, String label) {
        int i = src.indexOf(key);
        if (i < 0) return;
        int start = i + key.length();
        int end   = src.indexOf(",", start);
        if (end < 0) end = src.indexOf("}", start);
        if (end < 0) end = Math.min(start + 80, src.length());
        String val = src.substring(start, end).trim()
                .replaceAll("[{}\\[\\]]", "").trim();
        if (!val.isBlank()) target.put(label, val);
    }

    // ── event type resolver ───────────────────────────────────────────────────

    private String resolveEventType(String uri, int status, String location) {
        if (uri.equals("/login"))                     return EVT_LOGIN_PAGE;
        if (uri.startsWith("/oauth2/authorization/")) return EVT_OAUTH2_START;
        if (uri.startsWith("/login/oauth2/code/")) {
            if (status == 302 && location != null && location.contains("/dashboard"))
                return EVT_AUTH_SUCCESS;
            if (status >= 400) return EVT_ERROR;
            return EVT_CALLBACK;
        }
        if (uri.startsWith("/dashboard"))             return status == 200 ? EVT_DASHBOARD : EVT_INITIAL_ACCESS;
        if (uri.startsWith("/api/"))                  return EVT_API_ACCESS;
        return "AUTH_FLOW_REQUEST";
    }

    // ── utilities ─────────────────────────────────────────────────────────────

    private boolean isTracedPath(String uri) {
        return uri.startsWith("/oauth2/authorization/")
                || uri.startsWith("/login/oauth2/code/")
                || uri.equals("/login")
                || uri.startsWith("/dashboard")
                || uri.startsWith("/api/");
    }

    private String sessionId(HttpSession s) {
        return Optional.ofNullable(s)
                .map(HttpSession::getId)
                .map(id -> id.length() > 12 ? id.substring(0, 12) + "…" : id)
                .orElse("none");
    }

    private List<String> extractCookies(HttpServletRequest req) {
        if (req.getCookies() == null) return List.of();
        return Arrays.stream(req.getCookies())
                .map(c -> c.getName().equals("JSESSIONID")
                        ? "JSESSIONID=<present>" : c.getName() + "=" + c.getValue())
                .collect(Collectors.toList());
    }

    private String stripQuery(String url) {
        int q = url.indexOf('?');
        return q > 0 ? url.substring(0, q) : url;
    }

    private String abbrev(String v, int max) {
        if (v == null) return "";
        return v.length() <= max ? v : v.substring(0, max);
    }

    private String decode(String v) {
        try { return java.net.URLDecoder.decode(v, "UTF-8"); }
        catch (Exception e) { return v; }
    }

    private String bodySnippet(byte[] bytes, String enc) {
        if (bytes == null || bytes.length == 0) return "";
        int len = Math.min(bytes.length, MAX_BODY_BYTES);
        try {
            return new String(bytes, 0, len, enc == null ? "UTF-8" : enc)
                    .replaceAll("\\s+", " ").trim();
        } catch (Exception e) {
            return new String(bytes, 0, len, java.nio.charset.StandardCharsets.UTF_8)
                    .replaceAll("\\s+", " ").trim();
        }
    }
}