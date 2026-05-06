import { Router } from "express";
import { config } from "../config";
import { decodeJwt, pickStandardClaims } from "../utils/jwt";
import { generateCodeChallenge, generateCodeVerifier, generateState } from "../utils/pkce";

type PkceStoreEntry = {
  codeVerifier: string;
  createdAt: number;
};

const router = Router();
const pkceStore = new Map<string, PkceStoreEntry>();

function safeJsonParse(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function logStep(title: string, details?: unknown): void {
  console.log(`\n========== ${title} ==========`);
  if (details !== undefined) {
    console.log(typeof details === "string" ? details : JSON.stringify(details, null, 2));
  }
}

function cleanupPkceStore(): void {
  const now = Date.now();
  const ttlMs = 10 * 60 * 1000;

  for (const [state, entry] of pkceStore.entries()) {
    if (now - entry.createdAt > ttlMs) {
      pkceStore.delete(state);
    }
  }
}

router.get("/login", (_req, res) => {
  cleanupPkceStore();

  // PKCE values are generated per auth request and bound to the state.
  const codeVerifier = generateCodeVerifier(64);
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const state = generateState();

  pkceStore.set(state, {
    codeVerifier,
    createdAt: Date.now()
  });

  const params = new URLSearchParams({
    response_type: "code",
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: config.scope,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256"
  });

  const authorizationUrl = `${config.authorizationEndpoint}?${params.toString()}`;

  logStep("1) /login - Generated PKCE and authorization URL", {
    state,
    code_verifier: codeVerifier,
    code_challenge: codeChallenge,
    authorization_url: authorizationUrl
  });

  res.redirect(authorizationUrl);
});

router.get("/callback", async (req, res) => {
  const { code, state, error, error_description: errorDescription } = req.query;

  logStep("2) /callback - Query parameters", req.query);

  if (error) {
    return res.status(400).json({
      message: "Authorization server returned an error",
      error,
      error_description: errorDescription
    });
  }

  if (typeof code !== "string" || typeof state !== "string") {
    return res.status(400).json({ message: "Missing or invalid code/state" });
  }

  const pkceEntry = pkceStore.get(state);
  if (!pkceEntry) {
    return res.status(400).json({ message: "Invalid state. Possible CSRF or expired flow." });
  }

  // One-time use state to prevent replay.
  pkceStore.delete(state);

  const tokenParams = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: config.redirectUri,
    client_id: config.clientId,
    code_verifier: pkceEntry.codeVerifier
  });

  const tokenRequestHeaders = {
    "content-type": "application/x-www-form-urlencoded"
  };

  logStep("3) Token request - POST details", {
    url: config.tokenEndpoint,
    headers: tokenRequestHeaders,
    body: Object.fromEntries(tokenParams.entries())
  });

  const tokenResponse = await fetch(config.tokenEndpoint, {
    method: "POST",
    headers: tokenRequestHeaders,
    body: tokenParams
  });

  const tokenResponseText = await tokenResponse.text();
  const tokenResponseBody = safeJsonParse(tokenResponseText);

  logStep("4) Token response", {
    status: tokenResponse.status,
    statusText: tokenResponse.statusText,
    headers: Object.fromEntries(tokenResponse.headers.entries()),
    body: tokenResponseBody
  });

  if (!tokenResponse.ok || typeof tokenResponseBody !== "object" || tokenResponseBody === null) {
    return res.status(502).json({
      message: "Token exchange failed",
      token_response: tokenResponseBody
    });
  }

  const tokenJson = tokenResponseBody as Record<string, unknown>;
  const accessToken = typeof tokenJson.access_token === "string" ? tokenJson.access_token : "";
  const idToken = typeof tokenJson.id_token === "string" ? tokenJson.id_token : "";

  logStep("5) Raw tokens", {
    access_token: accessToken,
    id_token: idToken
  });

  const decodedAccessToken = accessToken ? decodeJwt(accessToken) : null;
  const decodedIdToken = idToken ? decodeJwt(idToken) : null;

  logStep("6) Decoded access token payload", decodedAccessToken);
  logStep("7) Access token standard claims", pickStandardClaims(decodedAccessToken));

  logStep("8) Decoded ID token payload", decodedIdToken);
  logStep("9) ID token standard claims", pickStandardClaims(decodedIdToken));

  const userInfoHeaders = {
    Authorization: `Bearer ${accessToken}`
  };

  logStep("10) UserInfo request", {
    url: config.userInfoEndpoint,
    headers: userInfoHeaders
  });

  const userInfoResponse = await fetch(config.userInfoEndpoint, {
    method: "GET",
    headers: userInfoHeaders
  });

  const userInfoText = await userInfoResponse.text();
  const userInfoBody = safeJsonParse(userInfoText);

  logStep("11) UserInfo response", {
    status: userInfoResponse.status,
    statusText: userInfoResponse.statusText,
    headers: Object.fromEntries(userInfoResponse.headers.entries()),
    body: userInfoBody
  });

  return res.json({
    message: "Authorization Code + PKCE flow completed",
    tokens: {
      access_token: accessToken,
      id_token: idToken,
      token_type: tokenJson.token_type,
      expires_in: tokenJson.expires_in,
      scope: tokenJson.scope
    },
    decoded: {
      access_token: decodedAccessToken,
      id_token: decodedIdToken
    },
    userinfo: userInfoBody
  });
});

export default router;

