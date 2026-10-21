// Config Firebase Web App dengan 3-layer protection (strict referer check)
const rateLimit = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 menit
const MAX_REQUESTS = 50; // Max 50 req/menit per IP

export default async function handler(req, res) {
  if (req.method !== "GET") { res.setHeader("Allow", "GET"); return res.status(405).end(); }

  // 1. STRICT Referer/Origin check - WAJIB dari domain sendiri
  const referer = req.headers.referer || req.headers.origin || '';
  const allowedOrigins = [
    'https://ai-hub-two-eta.vercel.app',
    'http://localhost:8400',
    'http://127.0.0.1:8400',
  ];
  const isAllowed = allowedOrigins.some(origin => referer.startsWith(origin));
  
  // Block kalau nggak ada referer ATAU referer bukan dari domain kita
  if (!isAllowed) {
    return res.status(403).json({ error: 'Forbidden: Invalid or missing origin' });
  }

  // 2. Rate limiting per IP (50 req/menit)
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const requests = rateLimit.get(ip) || [];
  const recentRequests = requests.filter(time => now - time < RATE_LIMIT_WINDOW);
  
  if (recentRequests.length >= MAX_REQUESTS) {
    return res.status(429).json({ error: 'Too many requests - max 50 per minute' });
  }
  
  recentRequests.push(now);
  rateLimit.set(ip, recentRequests);

  // Cleanup old entries
  if (Math.random() < 0.01) {
    for (const [k, v] of rateLimit.entries()) {
      const recent = v.filter(time => now - time < RATE_LIMIT_WINDOW * 5);
      if (recent.length === 0) rateLimit.delete(k);
      else rateLimit.set(k, recent);
    }
  }

  // 3. Return Firebase config
  const cfg = {
    apiKey: process.env.FIREBASE_API_KEY || "",
    authDomain: process.env.FIREBASE_AUTH_DOMAIN || "",
    projectId: process.env.FIREBASE_PROJECT_ID || "",
    appId: process.env.FIREBASE_APP_ID || "",
  };
  if (!cfg.apiKey || !cfg.projectId) {
    return res.status(200).json({ configured: false });
  }

  // 4. Security headers
  res.setHeader('Cache-Control', 'private, no-cache, no-store, must-revalidate');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  return res.status(200).json({ configured: true, ...cfg });
}
