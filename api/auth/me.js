import { sessionOf } from "../_lib.js";

export default function handler(req, res) {
  const secret = process.env.SESSION_SECRET;
  if (!secret) {
    res.statusCode = 500;
    return res.end(JSON.stringify({ error: "SESSION_SECRET belum di-set" }));
  }
  const s = sessionOf(req, secret);
  res.setHeader("Content-Type", "application/json");
  if (!s) {
    res.statusCode = 401;
    return res.end(JSON.stringify({ error: "belum login" }));
  }
  res.end(JSON.stringify({ email: s.email, name: s.name, picture: s.picture }));
}
