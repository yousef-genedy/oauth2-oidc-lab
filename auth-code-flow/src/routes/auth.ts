import axios, { AxiosError } from "axios";
import crypto from "crypto";
import { Router } from "express";
import { config } from "../config";
import { decodeToken } from "../utils/jwt";

export const authRouter = Router();

// In-memory state store for CSRF protection in this local PoC.
const pendingStates = new Set<string>();

function logStep(title: string, payload?: unknown): void {
  console.log(`\n========== ${title} ==========`);
  if (payload !== undefined) {
    console.dir(payload, { depth: null, colors: true });
  }
}

authRouter.get("/login", (_req, res) => {
  // OAuth 2.0 state prevents CSRF by binding callback to this browser session.
  const state = crypto.randomBytes(16).toString("hex");
  pendingStates.add(state);

  const authorizationUrl = new URL(config.authorizationEndpoint);
  authorizationUrl.searchParams.set("response_type", "code");
  authorizationUrl.searchParams.set("client_id", config.clientId);
  authorizationUrl.searchParams.set("redirect_uri", config.redirectUri);
  authorizationUrl.searchParams.set("scope", "openid profile email");
  authorizationUrl.searchParams.set("state", state);

  logStep("LOGIN - Authorization URL", {
    state,
    authorizationUrl: authorizationUrl.toString()
  });

  res.redirect(authorizationUrl.toString());
});

authRouter.get("/callback", async (req, res) => {
  const { code, state, error, error_description: errorDescription } = req.query;

  logStep("CALLBACK - Query Parameters", req.query);

  if (error) {
    return res.status(400).json({
      message: "Authorization server returned an error",
      error,
      errorDescription
    });
  }

  if (typeof code !== "string" || typeof state !== "string") {
    return res.status(400).json({
      message: "Missing or invalid callback parameters",
      expected: ["code", "state"]
    });
  }

  if (!pendingStates.has(state)) {
    return res.status(400).json({
      message: "State validation failed",
      details: "Unknown or already consumed state"
    });
  }

  // Consume state once used to avoid replay.
  pendingStates.delete(state);

  const tokenRequestParams = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: config.redirectUri,
    client_id: config.clientId,
    client_secret: config.clientSecret
  });

  logStep("TOKEN REQUEST - Body", {
    tokenEndpoint: config.tokenEndpoint,
    bodyObject: Object.fromEntries(tokenRequestParams.entries()),
    bodyEncoded: tokenRequestParams.toString()
  });

  try {
    const tokenResponse = await axios.post(config.tokenEndpoint, tokenRequestParams, {
      headers: {
        "content-type": "application/x-www-form-urlencoded"
      },
      timeout: 10_000
    });

    logStep("TOKEN RESPONSE - Body", tokenResponse.data);

    const { access_token: accessToken, id_token: idToken, refresh_token: refreshToken } = tokenResponse.data;

    logStep("RAW TOKENS", {
      access_token: accessToken,
      id_token: idToken,
      refresh_token: refreshToken
    });

    const decodedAccessToken = typeof accessToken === "string" ? decodeToken(accessToken) : null;
    const decodedIdToken = typeof idToken === "string" ? decodeToken(idToken) : null;

    logStep("DECODED ACCESS TOKEN", decodedAccessToken);
    logStep("DECODED ID TOKEN", decodedIdToken);

    const userinfoResponse = await axios.get(config.userinfoEndpoint, {
      headers: {
        authorization: `Bearer ${accessToken}`
      },
      timeout: 10_000
    });

    logStep("USERINFO RESPONSE", userinfoResponse.data);

    return res.json({
      message: "Authorization Code flow completed successfully",
      callbackParams: { code, state },
      tokens: {
        access_token: accessToken,
        id_token: idToken,
        refresh_token: refreshToken
      },
      decoded: {
        access_token: decodedAccessToken,
        id_token: decodedIdToken
      },
      userinfo: userinfoResponse.data
    });
  } catch (error) {
    const axiosError = error as AxiosError;

    logStep("TOKEN OR USERINFO ERROR", {
      message: axiosError.message,
      status: axiosError.response?.status,
      responseBody: axiosError.response?.data
    });

    return res.status(500).json({
      message: "Failed during token exchange or userinfo retrieval",
      error: axiosError.message,
      status: axiosError.response?.status,
      responseBody: axiosError.response?.data
    });
  }
});
