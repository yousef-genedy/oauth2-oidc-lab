import express from "express";
import authRoutes from "./routes/auth";
import profileRoutes from "./routes/profile";
import { config } from "./config";

const app = express();

app.use(express.json());

app.use((req, _res, next) => {
  console.log(`\n--> ${req.method} ${req.originalUrl}`);
  next();
});

app.get("/", (_req, res) => {
  res.send(`
    <h1>OAuth 2.0 + OIDC PKCE Demo</h1>
    <p>This app manually executes Authorization Code + PKCE against Keycloak.</p>
    <ul>
      <li><a href="/login">Start login flow (/login)</a></li>
      <li>Optional: GET /profile with Authorization: Bearer &lt;token&gt;</li>
    </ul>
  `);
});

app.use(authRoutes);
app.use(profileRoutes);

app.listen(config.port, () => {
  console.log("\n============================================");
  console.log(`Server running at http://localhost:${config.port}`);
  console.log(`Client ID: ${config.clientId}`);
  console.log(`Redirect URI: ${config.redirectUri}`);
  console.log(`Authorization endpoint: ${config.authorizationEndpoint}`);
  console.log(`Token endpoint: ${config.tokenEndpoint}`);
  console.log(`UserInfo endpoint: ${config.userInfoEndpoint}`);
  console.log(`JWKS URI (for manual validation experiments): ${config.jwksUri}`);
  console.log("============================================\n");
});

