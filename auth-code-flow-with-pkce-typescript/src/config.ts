import dotenv from "dotenv";

dotenv.config();

function getRequiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

export const config = {
  port: Number(process.env.PORT ?? 3000),
  clientId: getRequiredEnv("CLIENT_ID"),
  redirectUri: getRequiredEnv("REDIRECT_URI"),
  authorizationEndpoint: getRequiredEnv("AUTHORIZATION_ENDPOINT"),
  tokenEndpoint: getRequiredEnv("TOKEN_ENDPOINT"),
  userInfoEndpoint: getRequiredEnv("USERINFO_ENDPOINT"),
  jwksUri: getRequiredEnv("JWKS_URI"),
  scope: "openid profile email"
};

