import { createVerify, X509Certificate } from "node:crypto";
import { sign } from "../_lib.js";

const CERTS_URL = process.env.FIREBASE_CERTS_URL
  || "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
const ISSUER_PREFIX = "https://securetoken.google.com/";
let certCache = { at: 0, map: null };

async function getGoogleCerts() {
  const now = Date.now();
  if (certCache.map && now - certCache.at < 3600_000) return certCache.map;
  const r = await fetch(CERTS_URL);
  if (!r.ok) throw new Error("gagal fetch sertifikat Google: " + r.status);
  certCache = { at: now, map: await r.json() };
  return certCache.map;
}

const b64urlToBuf = (s) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");

export async function verifyFirebaseIdToken(idToken) {
  const projectId = process.env.FIREBASE_PROJECT_ID;
  const secret = process.env.SESSION_SECRET;
  if (!projectId || !secret) throw new Error("FIREBASE_PROJECT_ID/SESSION_SECRET belum di-set");
  const parts = String(idToken || "").split(".");
  if (parts.length !== 3) throw new Error("token tidak valid");
  const [h, p, s] = parts;
  const header = JSON.parse(b64urlToBuf(h).toString("utf8"));
  const payload = JSON.parse(b64urlToBuf(p).toString("utf8"));
  const certs = await getGoogleCerts();
  const pem = certs[header.kid];
  if (!pem) throw new Error("kid sertifikat tidak dikenal");
  const verifier = createVerify("RSA-SHA256");
  verifier.update(h + "." + p);
  const ok = verifier.verify(new X509Certificate(pem).publicKey, b64urlToBuf(s));
  if (!ok) throw new Error("signature tidak valid");
  const now = Math.floor(Date.now() / 1000);
  if (payload.aud !== projectId) throw new Error("audience tidak cocok");
  if (payload.iss !== ISSUER_PREFIX + projectId) throw new Error("issuer tidak cocok");
  if (!payload.exp || now >= payload.exp) throw new Error("token expired");
  if (!payload.sub) throw new Error("sub kosong");
  return payload;
}

export default async function handler(req, res) {
  if (req.method !== "POST") { res.setHeader("Allow", "POST"); return res.status(405).end(); }
  // Vercel sudah parse JSON body jadi OBJECT — jangan JSON.parse lagi (bug lama bikin idToken hilang)
  let body = req.body;
  if (typeof body === "string") {
    try { body = JSON.parse(body || "{}"); } catch { return res.status(400).json({ error: "body tidak valid" }); }
  }
  if (!body || typeof body !== "object") body = {};
  try {
    const p = await verifyFirebaseIdToken(body.idToken);
    const session = sign({
      sub: p.sub,
      email: p.email || "",
      name: p.name || p.email || "User",
      picture: p.picture || "",
      exp: Date.now() + 7 * 24 * 3600 * 1000,
    }, process.env.SESSION_SECRET);
    res.setHeader("Set-Cookie", `aihub_session=${session}; Path=/; Max-Age=${7 * 24 * 3600}; HttpOnly; Secure; SameSite=Lax`);
    return res.status(200).json({ email: p.email || "", name: p.name || "", picture: p.picture || "" });
  } catch (e) {
    return res.status(401).json({ error: "login ditolak: " + e.message });
  }
}
