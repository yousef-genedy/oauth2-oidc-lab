import jwt, { JwtPayload } from "jsonwebtoken";

export function decodeJwt(token: string): JwtPayload | null {
  const decoded = jwt.decode(token);
  if (!decoded || typeof decoded === "string") {
    return null;
  }
  return decoded;
}

export function pickStandardClaims(payload: JwtPayload | null): Record<string, unknown> {
  if (!payload) {
    return {};
  }

  return {
    iss: payload.iss,
    sub: payload.sub,
    aud: payload.aud,
    exp: payload.exp
  };
}

