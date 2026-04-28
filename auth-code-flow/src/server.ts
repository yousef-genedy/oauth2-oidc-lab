import express from "express";
import { config } from "./config";
import { authRouter } from "./routes/auth";
import { profileRouter } from "./routes/profile";

const app = express();

app.get("/", (_req, res) => {
  res.type("text/plain").send(
    [
      "Keycloak OAuth2/OIDC Basic Authorization Code Flow (No PKCE)",
      "",
      "Routes:",
      "- GET /login     Start flow and redirect to Keycloak",
      "- GET /callback  Handle Keycloak authorization response",
      "- GET /profile   Decode a bearer token payload"
    ].join("\n")
  );
});

app.use(authRouter);
app.use(profileRouter);

app.listen(config.port, () => {
  console.log(`\nServer running at http://localhost:${config.port}`);
  console.log("Start the flow at GET /login");
});

