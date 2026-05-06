import { createHash, randomBytes } from "crypto";

function base64Url(buffer: Buffer): string {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function generateCodeVerifier(length = 64): string {
  if (length < 43 || length > 128) {
    throw new Error("code_verifier length must be between 43 and 128 characters");
  }

  // Keep generating random bytes until we have enough base64url characters.
  let verifier = "";
  while (verifier.length < length) {
    verifier += base64Url(randomBytes(length));
  }

  return verifier.slice(0, length);
}

export function generateCodeChallenge(codeVerifier: string): string {
  const digest = createHash("sha256").update(codeVerifier).digest();
  return base64Url(digest);
}

export function generateState(): string {
  return base64Url(randomBytes(32));
}

