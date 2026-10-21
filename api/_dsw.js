// DeepSeek Web (chat.deepseek.com) native client — port dari 9Router chunk 5330.js
// Alur: userToken -> accessToken (/users/current) -> chat_session/create -> PoW challenge
//       -> solve DeepSeekHashV1 -> chat/completion -> parse SSE -> delete session

const ORIGIN = "https://chat.deepseek.com";
const API = ORIGIN + "/api";
const COMPLETION = API + "/v0/chat/completion";

const BASE_HEADERS = {
  Accept: "*/*",
  "Accept-Language": "en-US,en;q=0.9",
  Origin: ORIGIN,
  Referer: ORIGIN + "/",
  "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
  "X-Client-Bundle-Id": "com.deepseek.chat",
  "X-Client-Locale": "en-US",
  "X-Client-Platform": "web",
  "X-Client-Version": "2.0.0",
};

// cache accessToken per userToken (TTL 3600s, max 50 entries)
const tokenCache = new Map();
function cachePut(k, v) { if (tokenCache.size >= 50) { const first = tokenCache.keys().next().value; if (first) tokenCache.delete(first); } tokenCache.set(k, v); }

function fakeCookies() {
  const now = Date.now();
  const uuid = () => "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => { const r = (Math.random() * 16) | 0; return (c === "x" ? r : (r & 3) | 8).toString(16); });
  return `intercom-HWWAFSESTIME=${now}; HWWAFSESID=${Array.from({ length: 18 }, () => Math.floor(Math.random() * 16).toString(16)).join("")}; Hm_lvt_${uuid()}=${Math.floor(now / 1000)}; _frid=${uuid()}`;
}

function isThinkingModel(model) { const m = String(model || "").toLowerCase(); return m.includes("think") || m.includes("r1") || m.includes("reason"); }
function isExpertModel(model) { const m = String(model || "").toLowerCase(); return m.includes("pro") || m.includes("expert"); }

// ---- SHA-3 (Keccak-f[1600]) custom ala 9Router, untuk PoW DeepSeekHashV1 ----
const KECCAK_RC = [1n, 32898n, 0x800000000000808an, 0x8000000080008000n, 32907n, 2147483649n, 0x8000000080008081n, 0x8000000000008009n, 138n, 136n, 2147516425n, 2147483658n, 2147516555n, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n, 32778n, 0x800000008000000an, 0x8000000080008081n, 0x8000000000008080n, 2147483649n, 0x8000000080008008n];
const HEX64 = /^[a-f0-9]{64}$/i;
const RC_LO = Uint32Array.from(KECCAK_RC, (a) => Number(4294967295n & a));
const RC_HI = Uint32Array.from(KECCAK_RC, (a) => Number((a >> 32n) & 4294967295n));
const ROT_IDX = Uint8Array.from({ length: 25 }, (a, b) => { const c = Math.floor(b / 5); return 2 * (c + ((b % 5) * 2 + 3 * c) % 5 * 5); });
const ROT_OFF = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
const RHO_IDX = Uint8Array.from({ length: 25 }, (a, b) => { const c = b % 5; return 2 * (b - c + ((c + 1) % 5)); });
const CHI_IDX = Uint8Array.from({ length: 25 }, (a, b) => { const c = b % 5; return 2 * (b - c + ((c + 2) % 5)); });

function keccakRound(A, B, C, D, numRounds) {
  const start = KECCAK_RC.length - numRounds;
  for (let r = start; r < KECCAK_RC.length; r++) {
    for (let x = 0; x < 5; x++) { const d2 = 2 * x; C[d2] = A[d2] ^ A[d2 + 10] ^ A[d2 + 20] ^ A[d2 + 30] ^ A[d2 + 40]; C[d2 + 1] = A[d2 + 1] ^ A[d2 + 11] ^ A[d2 + 21] ^ A[d2 + 31] ^ A[d2 + 41]; }
    for (let x = 0; x < 5; x++) { const b = ((x + 4) % 5) * 2, e = ((x + 1) % 5) * 2, f1 = (C[e] << 1) | (C[e + 1] >>> 31), f2 = (C[e + 1] << 1) | (C[e] >>> 31); D[2 * x] = C[b] ^ f1; D[2 * x + 1] = C[b + 1] ^ f2; }
    for (let x = 0; x < 5; x++) { const c2 = 2 * x, e = D[c2], f = D[c2 + 1]; A[c2] ^= e; A[c2 + 1] ^= f; A[c2 + 10] ^= e; A[c2 + 11] ^= f; A[c2 + 20] ^= e; A[c2 + 21] ^= f; A[c2 + 30] ^= e; A[c2 + 31] ^= f; A[c2 + 40] ^= e; A[c2 + 41] ^= f; }
    B[0] = A[0]; B[1] = A[1];
    for (let c = 1; c < 25; c++) { const d2 = 2 * c, ri = ROT_IDX[c], sh = ROT_OFF[c], h = A[d2], i2 = A[d2 + 1]; if (sh < 32) { B[ri] = (h << sh) | (i2 >>> (32 - sh)); B[ri + 1] = (i2 << sh) | (h >>> (32 - sh)); } else { const s2 = sh - 32; B[ri] = (i2 << s2) | (h >>> (32 - s2)); B[ri + 1] = (h << s2) | (i2 >>> (32 - s2)); } }
    for (let c = 0; c < 25; c++) { const d2 = 2 * c, e = RHO_IDX[c], f = CHI_IDX[c]; A[d2] = B[d2] ^ (~B[e] & B[f]); A[d2 + 1] = B[d2 + 1] ^ (~B[e + 1] & B[f + 1]); }
    A[0] ^= RC_LO[r]; A[1] ^= RC_HI[r];
  }
}

function solveDeepSeekPow(challengeObj) {
  const { algorithm, challenge, salt, difficulty, expire_at, signature, target_path } = challengeObj;
  if (algorithm !== "DeepSeekHashV1") throw new Error("Unsupported PoW algorithm: " + algorithm);
  const prefix = `${salt}_${expire_at}_`;
  if (!HEX64.test(challenge)) throw new Error("PoW challenge harus 64-char hex");
  const diff = Number(difficulty);
  if (!Number.isSafeInteger(diff) || diff < 1 || diff > 250000) throw new Error("PoW difficulty tidak valid");

  // hash state dari prefix (padding SHA-256 standar atas prefix saja)
  const bytes = new TextEncoder().encode(prefix);
  const w = new Uint32Array(50), tmp = new Uint32Array(50), C = new Uint32Array(10), D = new Uint32Array(10);
  let off = 0;
  for (; off + 136 <= bytes.length;) { const base = off; for (let i = 0; i < 136; i++) { const wi = i >>> 2; w[wi] ^= bytes[base + i] << ((3 & i) * 8); } keccakRound(w, tmp, C, D, 23); off += 136; }
  const tailLen = bytes.length - off;
  const tail = new Uint32Array(Math.ceil(tailLen / 4));
  for (let i = 0; i < tailLen; i++) tail[i >>> 2] ^= bytes[off + i] << ((3 & i) * 8);
  // parse target dari hex challenge (little-endian per-byte seperti kode asli 9Router)
  const tgt = new Uint32Array(8);
  for (let i = 0; i < 32; i++) { const d = Number.parseInt(challenge.toLowerCase().slice(2 * i, 2 * i + 2), 16); tgt[i >>> 2] |= d << ((3 & i) * 8); }
  const A = new Uint32Array(50);
  mining: for (let nonce = 0; nonce < diff; nonce++) {
    A.set(w);
    for (let i = 0; i < tail.length; i++) A[i] ^= tail[i];
    let pos = tailLen;
    const s = String(nonce);
    for (let i = 0; i < s.length; i++) { A[pos >>> 2] ^= s.charCodeAt(i) << ((3 & pos) * 8); if ((pos += 1) === 136) { keccakRound(A, tmp, C, D, 23); pos = 0; } }
    A[pos >>> 2] ^= 6 << ((3 & pos) * 8);
    A[33] ^= -0x80000000;
    keccakRound(A, tmp, C, D, 23);
    for (let i = 0; i < 8; i++) if (A[i] !== tgt[i]) continue mining;
    const solution = { algorithm, challenge, salt, answer: nonce, signature, target_path };
    return Buffer.from(JSON.stringify(solution)).toString("base64");
  }
  throw new Error("PoW solver failed (difficulty " + diff + ")");
}

// ---- API calls ----
export async function dswGetAccessToken(userToken, signal) {
  const hit = tokenCache.get(userToken);
  if (hit && hit.expiresAt > Math.floor(Date.now() / 1000)) return hit.token;
  const r = await fetch(API + "/v0/users/current", { headers: { ...BASE_HEADERS, Authorization: "Bearer " + userToken }, signal });
  if (r.status === 401 || r.status === 403) throw new Error("DeepSeek token expired/invalid — update DEEPSEEK_USER_TOKEN");
  if (!r.ok) throw new Error("users/current HTTP " + r.status);
  const j = await r.json();
  if (j?.code && j.code !== 0) throw new Error("DeepSeek menolak token: " + (j.msg || j?.data?.biz_msg || j.code));
  const biz = j?.data?.biz_data || j?.biz_data;
  if (!biz?.token) throw new Error("Gagal ambil access token: " + (j.msg || j?.data?.biz_msg || "?"));
  cachePut(userToken, { token: biz.token, expiresAt: Math.floor(Date.now() / 1000) + 3600 });
  return biz.token;
}

export async function dswCreateSession(accessToken, signal) {
  const r = await fetch(API + "/v0/chat_session/create", { method: "POST", headers: { ...BASE_HEADERS, "Content-Type": "application/json", Authorization: "Bearer " + accessToken, Cookie: fakeCookies() }, body: "{}", signal });
  if (!r.ok) throw new Error("chat_session/create HTTP " + r.status);
  const j = await r.json();
  const biz = j?.data?.biz_data || j?.biz_data;
  const id = biz?.chat_session?.id;
  if (!id) throw new Error("No session id: code=" + j?.code);
  return id;
}

export async function dswDeleteSession(accessToken, sessionId) {
  try { await fetch(API + "/v0/chat_session/delete", { method: "POST", headers: { ...BASE_HEADERS, "Content-Type": "application/json", Authorization: "Bearer " + accessToken }, body: JSON.stringify({ chat_session_id: sessionId }) }); } catch {}
}

export async function dswCreatePowChallenge(accessToken, signal) {
  const r = await fetch(API + "/v0/chat/create_pow_challenge", { method: "POST", headers: { ...BASE_HEADERS, "Content-Type": "application/json", Authorization: "Bearer " + accessToken }, body: JSON.stringify({ target_path: "/api/v0/chat/completion" }), signal });
  if (!r.ok) throw new Error("create_pow_challenge HTTP " + r.status);
  const j = await r.json();
  const biz = j?.data?.biz_data || j?.biz_data;
  // response asli: {biz_data:{challenge:{algorithm,challenge,salt,...}}}
  const ch = biz?.challenge?.algorithm ? biz.challenge : biz?.challenge?.challenge;
  if (!ch || !ch.challenge) throw new Error("No PoW challenge: code=" + j?.code + " " + (j?.msg || ""));
  return ch;
}

// Konversi OpenAI messages -> transcript string (alai O di 9Router)
export function dswBuildPrompt(messages, systemPrompt) {
  const sysParts = [], turns = [];
  let lastUser = "";
  for (const m of messages || []) {
    let text = "";
    if (Array.isArray(m.content)) text = m.content.filter((c) => c?.type === "text").map((c) => String(c.text || "")).join("\n");
    else text = String(m.content || "");
    text = text.trim();
    if (m.role === "system" || m.role === "developer") { if (text) sysParts.push(text); }
    else if (m.role === "user" || m.role === "assistant") { if (text) { turns.push({ role: m.role, text }); if (m.role === "user") lastUser = text; } }
  }
  if (systemPrompt && systemPrompt.trim()) sysParts.unshift(systemPrompt.trim());
  const parts = [];
  if (sysParts.length) parts.push(sysParts.join("\n\n"));
  if (turns.length > 1) {
    parts.push(turns.slice(-40).map((t) => (t.role === "assistant" ? "Assistant: " + t.text : "User: " + t.text)).join("\n\n"));
  } else if (lastUser) parts.push(lastUser);
  return parts.join("\n\n").replace(/!\[.*?\]\(.*?\)/g, "");
}

// Parse SSE DeepSeek Web -> stream delta ke onDelta (content saja; thinking di-skip)
export async function dswStreamCompletion(resp, model, onDelta) {
  const reader = resp.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  let content = "", reasoning = "";
  let mode = ""; // "thinking" | "content"
  const thinking = isThinkingModel(model);
  const push = (piece) => {
    let txt = String(piece || "").replace(/FINISHED/g, "").replace(/^(SEARCH|WEB_SEARCH|SEARCHING)\s*/i, "");
    if (!txt) return;
    if (mode === "thinking") reasoning += txt;
    else { content += txt; onDelta(txt); }
  };
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    const lines = buf.split("\n");
    buf = lines.pop() || "";
    for (const raw of lines) {
      if (!raw.startsWith("data:")) continue;
      const payloadStr = raw.replace(/^data:\s*/, "").trim();
      if (!payloadStr) continue;
      let ev;
      try { ev = JSON.parse(payloadStr); } catch { continue; }
      const path = ev?.p, val = ev?.v;
      // payload utama: {v:{response:{thinking_enabled, fragments:[...]}}}
      if (val && typeof val === "object" && val.response) {
        if (val.response.thinking_enabled === true) mode = "thinking";
        else if (val.response.thinking_enabled === false) mode = "content";
        if (Array.isArray(val.response.fragments)) for (const fr of val.response.fragments) {
          const t = String(fr?.type || "").toUpperCase();
          if (t === "THINK") mode = "thinking"; else if (t === "ANSWER" || t === "RESPONSE") mode = "content";
          push(fr?.content);
        }
      }
      if (path === "response/fragments") {
        const items = Array.isArray(val) ? val : (val && typeof val === "object" ? [val] : []);
        for (const fr of items) {
          const t = String(fr?.type || "").toUpperCase();
          if (t === "THINK") mode = "thinking"; else if (t === "ANSWER" || t === "RESPONSE") mode = "content";
          push(fr?.content);
        }
      }
      if (typeof val === "string") push(val);
      if (Array.isArray(val) && path === "response") { for (const it of val) if (Array.isArray(it?.v)) { const joined = it.v.map((x) => x?.content || "").join(""); if (joined) push(joined); } }
    }
  }
  return { content, reasoning };
}

// Chat utama: streaming via onDelta
export async function dswChat({ userToken, model, messages, systemPrompt, signal, onDelta }) {
  const accessToken = await dswGetAccessToken(userToken, signal);
  const sessionId = await dswCreateSession(accessToken, signal);
  try {
    const challenge = await dswCreatePowChallenge(accessToken, signal);
    const powSolution = solveDeepSeekPow(challenge);
    const modelLower = String(model || "").toLowerCase();
    const payload = {
      chat_session_id: sessionId,
      parent_message_id: null,
      model_type: isExpertModel(modelLower) ? "expert" : "default",
      prompt: dswBuildPrompt(messages, systemPrompt),
      ref_file_ids: [],
      thinking_enabled: thinkingEnabledFor(modelLower),
      search_enabled: modelLower.includes("search"),
      preempt: false,
    };
    const headers = {
      ...BASE_HEADERS,
      "Content-Type": "application/json",
      Authorization: "Bearer " + accessToken,
      "X-Ds-Pow-Response": powSolution,
      "X-Client-Timezone-Offset": String(-60 * new Date().getTimezoneOffset()),
      Cookie: fakeCookies(),
    };
    const resp = await fetch(COMPLETION, { method: "POST", headers, body: JSON.stringify(payload), signal });
    if (!resp.ok) {
      let msg = "DeepSeek API error (" + resp.status + ")";
      if (resp.status === 401 || resp.status === 403) msg = "DeepSeek token expired — update DEEPSEEK_USER_TOKEN";
      else if (resp.status === 429) msg = "DeepSeek rate limited — tunggu sebentar";
      try { const j = await resp.json(); if (j?.code && j.code !== 0) msg = "DeepSeek error " + j.code + ": " + (j.msg || ""); } catch {}
      tokenCache.delete(userToken);
      throw new Error(msg);
    }
    if ((resp.headers.get("content-type") || "").includes("application/json")) {
      const j = await resp.json();
      if (j?.code && j.code !== 0) throw new Error("DeepSeek error " + j.code + ": " + (j.msg || j?.data?.biz_msg || ""));
      return { content: JSON.stringify(j), reasoning: "" };
    }
    return await dswStreamCompletion(resp, model, onDelta || (() => {}));
  } finally {
    await dswDeleteSession(accessToken, sessionId);
  }
}

function thinkingEnabledFor(modelLower) {
  return modelLower.includes("r1") || modelLower.includes("think") || modelLower.includes("reason");
}
