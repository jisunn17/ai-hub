import crypto from "crypto";

// ===== Session helper: HMAC-SHA256 signed token (stateless, tanpa DB) =====
// Format: base64url(payloadJSON) . base64url(hmac)
export function sign(payload, secret) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(body).digest("base64url");
  return body + "." + sig;
}

export function verify(token, secret) {
  if (!token || typeof token !== "string" || token.indexOf(".") < 0) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const body = parts[0], sig = parts[1];
  const expect = crypto.createHmac("sha256", secret).update(body).digest("base64url");
  const a = Buffer.from(sig), b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    if (!p.exp || Date.now() > p.exp) return null;
    return p;
  } catch { return null; }
}

export function parseCookies(req) {
  const h = (req.headers && req.headers.cookie) || "";
  const out = {};
  for (const part of h.split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

// Return payload session atau null (belum login / kedaluwarsa)
export function sessionOf(req, secret) {
  const c = parseCookies(req);
  return verify(c.aihub_session, secret);
}
