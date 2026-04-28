import { Router } from "express";
import { decodeToken } from "../utils/jwt";

export const profileRouter = Router();

profileRouter.get("/profile", (req, res) => {
  const authHeader = req.header("authorization");
  const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : undefined;

  if (!token) {
    return res.status(401).json({
      error: "Missing bearer token",
      usage: "Send Authorization: Bearer <access_token>"
    });
  }

  const decoded = decodeToken(token);

  console.log("\n[PROFILE] Decoded bearer token payload:");
  console.dir(decoded, { depth: null, colors: true });

  return res.json({
    message: "Decoded bearer token payload (decode only; no signature validation)",
    decoded
  });
});

