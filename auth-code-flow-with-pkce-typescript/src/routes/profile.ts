import { Router } from "express";
import { decodeJwt } from "../utils/jwt";

const router = Router();

router.get("/profile", (req, res) => {
  const authHeader = req.header("authorization");

  console.log("\n========== /profile request ==========");
  console.log(JSON.stringify({ authorization: authHeader }, null, 2));

  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Missing Bearer token" });
  }

  const token = authHeader.slice("Bearer ".length);
  const payload = decodeJwt(token);

  if (!payload) {
    return res.status(400).json({ message: "Token could not be decoded" });
  }

  console.log("Decoded /profile token payload:");
  console.log(JSON.stringify(payload, null, 2));

  return res.json({ payload });
});

export default router;

