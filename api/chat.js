export const config = { supportsResponseStreaming: true };

const PROVIDERS = {
  openai:     { kind: "openai",     base: "https://api.openai.com/v1" },
  deepseek:   { kind: "openai",     base: "https://api.deepseek.com/v1" },
  "deepseek-web": { kind: "openai", base: process.env.DSW_BASE_URL || "" },  // 9Router DeepSeek Web (lokal saja)
  openrouter: { kind: "openai",     base: "https://openrouter.ai/api/v1" },
  tokenharbor:{ kind: "openai",     base: "https://tokenharbor.ai/v1" },
  anthropic:  { kind: "anthropic",  base: "https://api.anthropic.com/v1" },
  gemini:     { kind: "gemini",     base: "https://generativelanguage.googleapis.com/v1beta" },
  lokal:      { kind: "openai",     base: "http://127.0.0.1:20128/v1" },
  custom:     { kind: "openai",     base: null },
};

const sse = (res, obj) => res.write(`data: ${JSON.stringify(obj)}\n\n`);

const fail = async (resp, res) => {
  const raw = await resp.text().catch(() => "");
  let msg = raw;
  try { msg = JSON.parse(raw).error?.message || raw; } catch {}
  msg = String(msg).replace(/(sk|thk|key|api)[-_][A-Za-z0-9._-]{8,}/gi, "[redacted]").slice(0, 400);
  sse(res, { error: `[${resp.status}] ${msg}` });
  sse(res, { done: true });
  res.end();
};

import { sessionOf } from "./_lib.js";
import { dswChat } from "./_dsw.js";

export default async function handler(req, res) {
  if (req.method !== "POST") { res.statusCode = 405; return res.end(JSON.stringify({ error: "method" })); }

  // --- AUTH: wajib login Google (session cookie HMAC) ---
  const sessSecret = process.env.SESSION_SECRET;
  if (!sessSecret || !sessionOf(req, sessSecret)) {
    res.statusCode = 401;
    return res.end(JSON.stringify({ error: "belum login — masuk dengan Google dulu" }));
  }

  // --- hardening: origin same-host + rate limit per-IP + payload caps ---
  const origin = req.headers.origin;
  if (origin) {
    try {
      if (new URL(origin).host !== req.headers.host) { res.statusCode = 403; return res.end(JSON.stringify({ error: "origin ditolak" })); }
    } catch { res.statusCode = 403; return res.end(JSON.stringify({ error: "origin ditolak" })); }
  }
  const ip = String(req.headers["x-forwarded-for"] || (req.socket && req.socket.remoteAddress) || "unknown").split(",")[0].trim();
  const nowTs = Date.now();
  const RL = globalThis.__aihub_rl || (globalThis.__aihub_rl = new Map());
  const hits = (RL.get(ip) || []).filter(function(t){ return nowTs - t < 60000; });
  if (hits.length >= 30) { res.statusCode = 429; return res.end(JSON.stringify({ error: "rate limit — coba lagi sebentar lagi" })); }
  hits.push(nowTs); RL.set(ip, hits);

  let b = {};
  try { b = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {}); } catch { res.statusCode = 400; return res.end(JSON.stringify({ error: "body tidak valid" })); }
  const provider = b.provider || "openai";
  let prov = PROVIDERS[provider];
  if (!prov) { res.statusCode = 400; return res.end(JSON.stringify({ error: "provider?" })); }
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._\/:@-]{0,99}$/.test(String(b.model || ""))) { res.statusCode = 400; return res.end(JSON.stringify({ error: "model tidak valid" })); }
  const rawMsgs = b.messages || [];
  if (!Array.isArray(rawMsgs) || rawMsgs.length > 200) { res.statusCode = 400; return res.end(JSON.stringify({ error: "messages tidak valid" })); }
  let psize = 0;
  for (const m of rawMsgs) psize += (m && m.content ? String(m.content).length : 0) + (m && m.images ? m.images.length * 1500000 : 0);
  if (psize > 8000000) { res.statusCode = 413; return res.end(JSON.stringify({ error: "payload terlalu besar" })); }

  let key = (b.api_key || "").trim();
  if (!key && provider === "lokal") key = process.env.LOKAL_API_KEY || "";
  if (!key && provider === "tokenharbor") key = process.env.TOKENHARBOR_API_KEY || "";
  // Fallback: DeepSeek tanpa key pribadi → model DeepSeek gratis di TokenHarbor (server-side key)
  let effProvider = provider;
  let effModel = b.model;
  if (!key && provider === "deepseek") {
    key = process.env.TOKENHARBOR_API_KEY || "";
    effProvider = "tokenharbor";
    effModel = (String(b.model).includes("reasoner")) ? "deepseek-v4.1-flash:free" : "deepseek-v4-flash:free";
    prov = PROVIDERS[effProvider];
  }
  // DeepSeek Web native: pakai cookie userToken langsung ke chat.deepseek.com (server-side)
  const dswToken = key || process.env.DEEPSEEK_USER_TOKEN || "";
  if (provider === "deepseek-web" && !dswToken) {
    res.statusCode = 400;
    return res.end(JSON.stringify({ error: "DeepSeek Web: DEEPSEEK_USER_TOKEN belum di-set di server" }));
  }
  if (!key && ["openai", "anthropic", "gemini", "openrouter", "custom"].includes(provider)) {
    res.statusCode = 400;
    return res.end(JSON.stringify({ error: "API key " + provider + " belum diisi — buka Settings (⚙) → API Keys, atau pakai provider TokenHarbor (gratis)" }));
  }
  const base = (b.base_url || "").trim() || prov.base;
  if (!base && provider !== "deepseek-web") { res.statusCode = 400; return res.end(JSON.stringify({ error: "base_url kosong" })); }

  const sys = (b.system || "").trim();
  const msgs = (b.messages || []).filter(m => m && (m.content || (m.images && m.images.length)));
  const maxTokens = Number(b.max_tokens) || 0;
  const temperature = typeof b.temperature === "number" ? b.temperature : 0.7;
  const model = effModel || "";

  const b64 = (u) => { const i = u.indexOf(","); return i >= 0 ? u.slice(i + 1) : u; };

  res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");

  try {
    // === DeepSeek Web native (Vercel-friendly: langsung ke chat.deepseek.com) ===
    if (provider === "deepseek-web") {
      const deltas = [];
      const out = await dswChat({
        userToken: dswToken,
        model,
        messages: msgs,
        systemPrompt: sys || "",
        temperature: temperature || undefined,
        maxTokens: maxTokens || undefined,
        searchEnabled: !!b.search_enabled,
        onDelta: (d) => { deltas.push(d); sse(res, { delta: d }); },
      });
      sse(res, { done: true, usage: { prompt: out.usage?.prompt_tokens || 0, completion: out.usage?.completion_tokens || 0 } });
      res.end();
      return;
    }

    let url, init;
    if (prov.kind === "anthropic") {
      url = base.replace(/\/$/, "") + "/messages";
      const amsgs = msgs.map(m => {
        if (m.images && m.images.length) {
          const blocks = [{ type: "text", text: m.content || "(lihat gambar)" }];
          for (const u of m.images) blocks.push({ type: "image", source: { type: "base64", media_type: "image/jpeg", data: b64(u) } });
          return { role: m.role, content: blocks };
        }
        return { role: m.role, content: m.content };
      });
      const body = { model, max_tokens: maxTokens || 4096, stream: true, temperature, messages: amsgs };
      if (sys) body.system = sys;
      init = { method: "POST", headers: { "Content-Type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01" }, body: JSON.stringify(body) };
    } else if (prov.kind === "gemini") {
      url = `${base.replace(/\/$/, "")}/models/${model}:streamGenerateContent?alt=sse&key=${encodeURIComponent(key)}`;
      const contents = msgs.map(m => {
        const parts = [{ text: m.content || "(lihat gambar)" }];
        for (const u of (m.images || [])) parts.push({ inline_data: { mime_type: "image/jpeg", data: b64(u) } });
        return { role: m.role === "user" ? "user" : "model", parts };
      });
      const genCfg = { temperature };
      if (maxTokens) genCfg.maxOutputTokens = maxTokens;
      const body = { contents, generationConfig: genCfg };
      if (sys) body.systemInstruction = { parts: [{ text: sys }] };
      init = { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
    } else {
      url = base.replace(/\/$/, "") + "/chat/completions";
      const omsgs = msgs.map(m => {
        if (m.images && m.images.length) {
          const content = [{ type: "text", text: m.content || "(lihat gambar)" }];
          for (const u of m.images) content.push({ type: "image_url", image_url: { url: u } });
          return { role: m.role, content };
        }
        return { role: m.role, content: m.content };
      });
      const full = sys ? [{ role: "system", content: sys }, ...omsgs] : omsgs;
      const headers = { "Content-Type": "application/json" };
      if (key) headers["Authorization"] = `Bearer ${key}`;
      const payload = { model, messages: full, stream: true, temperature };
      if (maxTokens) payload.max_tokens = maxTokens;
      init = { method: "POST", headers, body: JSON.stringify(payload) };
    }

    const resp = await fetch(url, init);
    if (!resp.ok || !resp.body) return fail(resp, res);

    const reader = resp.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      const lines = buf.split("\n");
      buf = lines.pop() || "";
      for (const line of lines) {
        const t = line.trim();
        if (!t.startsWith("data:")) continue;
        const payload = t.slice(5).trim();
        if (payload === "[DONE]") continue;
        try {
          const j = JSON.parse(payload);
          if (prov.kind === "anthropic") {
            if (j.type === "message_start") {
              const u = j.message?.usage;
              if (u) sse(res, { usage: { prompt: u.input_tokens || 0, completion: u.output_tokens || 0 } });
            } else if (j.type === "content_block_delta" && j.delta?.text) {
              sse(res, { delta: j.delta.text });
            } else if (j.type === "message_delta" && j.usage?.output_tokens) {
              sse(res, { usage: { completion: j.usage.output_tokens } });
            }
          } else if (prov.kind === "gemini") {
            if (j.usageMetadata) sse(res, { usage: { prompt: j.usageMetadata.promptTokenCount || 0, completion: j.usageMetadata.candidatesTokenCount || 0 } });
            const parts = j.candidates?.[0]?.content?.parts || [];
            for (const p of parts) if (p.text) sse(res, { delta: p.text });
          } else {
            if (j.usage) sse(res, { usage: { prompt: j.usage.prompt_tokens || 0, completion: j.usage.completion_tokens || 0 } });
            const txt = j.choices?.[0]?.delta?.content || "";
            if (txt) sse(res, { delta: txt });
          }
        } catch {}
      }
    }
    sse(res, { done: true });
    res.end();
  } catch (e) {
    sse(res, { error: `server error: ${e.message}` });
    sse(res, { done: true });
    res.end();
  }
}
