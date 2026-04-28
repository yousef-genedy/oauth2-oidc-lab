import dotenv from "dotenv";

dotenv.config();

function getEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

export const config = {
  port: Number(process.env.PORT ?? 3000),
  clientId: getEnv("CLIENT_ID"),
  clientSecret: getEnv("CLIENT_SECRET"),
  redirectUri: getEnv("REDIRECT_URI"),
  authorizationEndpoint: getEnv("AUTHORIZATION_ENDPOINT"),
  tokenEndpoint: getEnv("TOKEN_ENDPOINT"),
  userinfoEndpoint: getEnv("USERINFO_ENDPOINT")
};

