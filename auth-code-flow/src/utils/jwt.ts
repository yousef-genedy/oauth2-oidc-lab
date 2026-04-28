import jwt from "jsonwebtoken";

export type DecodedPayload = jwt.JwtPayload | string | null;

export function decodeToken(token: string): DecodedPayload {
  return jwt.decode(token);
}

