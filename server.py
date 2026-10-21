#!/usr/bin/env python3
"""AI Hub — multi-provider chat backend (OpenAI / DeepSeek / Claude / Gemini / OpenRouter / lokal)."""
import json
import os
import re
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE = Path(__file__).parent
STATIC = BASE / "static"

# ---- provider definitions ----
PROVIDERS = {
    "openai":     {"kind": "openai",     "base": "https://api.openai.com/v1"},
    "deepseek":   {"kind": "openai",     "base": "https://api.deepseek.com/v1"},
    "deepseek-web": {"kind": "openai",   "base": "http://127.0.0.1:20128/v1"},  # 9Router DeepSeek Web (cookies)
    "openrouter": {"kind": "openai",     "base": "https://openrouter.ai/api/v1"},
    "tokenharbor":{"kind": "openai",     "base": "https://tokenharbor.ai/v1"},
    "anthropic":  {"kind": "anthropic",  "base": "https://api.anthropic.com/v1"},
    "gemini":     {"kind": "gemini",     "base": "https://generativelanguage.googleapis.com/v1beta"},
    "lokal":      {"kind": "openai",     "base": "http://127.0.0.1:20128/v1"},  # 9Router lokal
    "custom":     {"kind": "openai",     "base": None},  # base_url dari client
}

# config.json opsional: override base_url / default provider
CFG = {}
cfg_file = BASE / "config.json"
if cfg_file.exists():
    try:
        CFG = json.loads(cfg_file.read_text())
        for pid, over in (CFG.get("providers") or {}).items():
            if pid in PROVIDERS and "base" in over:
                PROVIDERS[pid]["base"] = over["base"]
    except Exception:
        pass

MODELS = {
    "openai":     ["gpt-4o", "gpt-4o-mini", "gpt-4.1", "gpt-4.1-mini", "o4-mini", "o3"],
    "deepseek":   ["deepseek-chat", "deepseek-reasoner"],
    "deepseek-web": ["dsw/deepseek-chat", "dsw/deepseek-reasoner", "dsw/deepseek-v4.1-flash"],
    "anthropic":  ["claude-sonnet-4-5", "claude-haiku-4-5", "claude-opus-4-1"],
    "gemini":     ["gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.0-flash"],
    "openrouter": [
        "deepseek/deepseek-chat-v3-0324:free",
        "meta-llama/llama-3.3-70b-instruct:free",
        "google/gemini-2.0-flash-exp:free",
        "qwen/qwen3-235b-a22b:free",
    ],
    "lokal":      ["dsw/deepseek-chat", "thk/deepseek-v4.1-flash:free",
                   "tokenharbor/qwen3.8-flash:free", "oc/jev-1.13-free"],
    "tokenharbor":["mimo-v2.5:free", "mimo-v2.6-flash:free", "deepseek-v4-flash:free", "deepseek-v4.1-flash:free", "qwen3.8-flash:free"],
    "custom":     [],
}

app = FastAPI(title="AI Hub")


# ===== AUTH: Google OAuth + HMAC session (mirror api/_lib.js) =====
def _load_env():
    ef = BASE / ".env"
    if ef.exists():
        for line in ef.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

_load_env()

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
SESSION_SECRET = os.environ.get("SESSION_SECRET", "")
APP_URL = os.environ.get("APP_URL", "http://127.0.0.1:8400")

import base64 as _b64
import hashlib as _hl
import hmac as _hmac
import time as _time
from urllib.parse import urlencode


def _b64e(b: bytes) -> str:
    return _b64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return _b64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign_session(payload: dict, secret: str) -> str:
    body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64e(_hmac.new(secret.encode(), body.encode(), _hl.sha256).digest())
    return body + "." + sig


def verify_session(token: str, secret: str):
    if not token or "." not in token:
        return None
    body, sig = token.split(".", 1)
    expect = _b64e(_hmac.new(secret.encode(), body.encode(), _hl.sha256).digest())
    if not _hmac.compare_digest(sig, expect):
        return None
    try:
        p = json.loads(_b64d(body))
        if not p.get("exp") or _time.time() * 1000 > p["exp"]:
            return None
        return p
    except Exception:
        return None


def _session_cookie_secure() -> bool:
    return (APP_URL or "").startswith("https")


@app.get("/api/auth/firebase-config")
async def auth_firebase_config():
    """Config Firebase Web App — PUBLIK by design (apiKey bukan secret)."""
    cfg = {
        "apiKey": os.environ.get("FIREBASE_API_KEY", ""),
        "authDomain": os.environ.get("FIREBASE_AUTH_DOMAIN", ""),
        "projectId": os.environ.get("FIREBASE_PROJECT_ID", ""),
        "appId": os.environ.get("FIREBASE_APP_ID", ""),
    }
    if not cfg["apiKey"] or not cfg["projectId"]:
        return {"configured": False}
    return {"configured": True, **cfg}


@app.post("/api/auth/session")
async def auth_session(request: Request):
    """Verify Firebase ID token (RS256 via sertifikat Google) → set session cookie."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    try:
        import jwt as pyjwt
        pid = os.environ.get("FIREBASE_PROJECT_ID", "")
        if not pid or not SESSION_SECRET:
            raise Exception("FIREBASE_PROJECT_ID/SESSION_SECRET belum di-set")
        id_token = body.get("idToken", "")
        kid = json.loads(_b64d(id_token.split(".")[0] + "=" * (-len(id_token.split(".")[0]) % 4))).get("kid")
        async with httpx.AsyncClient() as cl:
            rr = await cl.get("https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com")
            certs = rr.json()
        pem = certs.get(kid or "")
        if not pem:
            raise Exception("kid sertifikat tidak dikenal")
        p = pyjwt.decode(id_token, key=pem, algorithms=["RS256"],
                         audience=pid, issuer=f"https://securetoken.google.com/{pid}")
        payload = {"sub": p["sub"], "email": p.get("email", ""),
                   "name": p.get("name") or p.get("email", "User"),
                   "picture": p.get("picture", ""),
                   "exp": int(_time.time() * 1000) + 7 * 24 * 3600 * 1000}
        token = sign_session(payload, SESSION_SECRET)
        resp = JSONResponse({"email": payload["email"], "name": payload["name"], "picture": payload["picture"]})
        resp.set_cookie("aihub_session", token, max_age=7 * 24 * 3600, httponly=True,
                        samesite="lax", secure=_session_cookie_secure())
        return resp
    except Exception as e:
        return JSONResponse({"error": "login ditolak: " + str(e)}, status_code=401)


@app.get("/api/auth/logout")
async def auth_logout():
    resp = RedirectResponse("/")
    resp.delete_cookie("aihub_session")
    return resp


@app.get("/api/auth/me")
async def auth_me(request: Request):
    if not SESSION_SECRET:
        return JSONResponse({"error": "SESSION_SECRET belum di-set"}, status_code=500)
    p = verify_session(request.cookies.get("aihub_session", ""), SESSION_SECRET)
    if not p:
        return JSONResponse({"error": "belum login"}, status_code=401)
    return {"email": p.get("email", ""), "name": p.get("name", ""), "picture": p.get("picture", "")}


class ChatReq(BaseModel):
    provider: str = "openai"
    model: str
    messages: list          # [{role, content, images?}] tanpa system
    system: str = ""
    temperature: float = 0.7
    api_key: str = ""
    base_url: str = ""      # untuk provider custom / override
    max_tokens: int = 0


def sse(data: dict) -> str:
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"


async def stream_openai(base: str, key: str, body: dict):
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    url = base.rstrip("/") + "/chat/completions"
    async with httpx.AsyncClient(timeout=httpx.Timeout(15, read=180)) as client:
        async with client.stream("POST", url, headers=headers, json=body) as resp:
            if resp.status_code != 200:
                raw = (await resp.aread()).decode(errors="replace")[:500]
                try:
                    msg = json.loads(raw).get("error", {}).get("message", raw)
                except Exception:
                    msg = raw
                yield sse({"error": f"[{resp.status_code}] {msg}"})
                return
            async for line in resp.aiter_lines():
                line = line.strip()
                if not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if payload == "[DONE]":
                    yield sse({"done": True})
                    return
                try:
                    j = json.loads(payload)
                    if j.get("usage"):
                        u = j["usage"]
                        yield sse({"usage": {"prompt": u.get("prompt_tokens", 0), "completion": u.get("completion_tokens", 0)}})
                    delta = j["choices"][0].get("delta", {}) if j.get("choices") else {}
                    txt = delta.get("content") or ""
                    if txt:
                        yield sse({"delta": txt})
                except Exception:
                    continue
    yield sse({"done": True})


async def stream_anthropic(base: str, key: str, body: dict):
    headers = {
        "Content-Type": "application/json",
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
    }
    url = base.rstrip("/") + "/messages"
    async with httpx.AsyncClient(timeout=httpx.Timeout(15, read=180)) as client:
        async with client.stream("POST", url, headers=headers, json=body) as resp:
            if resp.status_code != 200:
                raw = (await resp.aread()).decode(errors="replace")[:500]
                try:
                    msg = json.loads(raw).get("error", {}).get("message", raw)
                except Exception:
                    msg = raw
                yield sse({"error": f"[{resp.status_code}] {msg}"})
                return
            async for line in resp.aiter_lines():
                line = line.strip()
                if not line.startswith("data:"):
                    continue
                try:
                    j = json.loads(line[5:].strip())
                    if j.get("type") == "message_start":
                        u = j.get("message", {}).get("usage", {})
                        if u:
                            yield sse({"usage": {"prompt": u.get("input_tokens", 0), "completion": u.get("output_tokens", 0)}})
                    elif j.get("type") == "content_block_delta":
                        txt = j.get("delta", {}).get("text", "")
                        if txt:
                            yield sse({"delta": txt})
                    elif j.get("type") == "message_delta":
                        u = j.get("usage", {})
                        if u and u.get("output_tokens"):
                            yield sse({"usage": {"completion": u.get("output_tokens", 0)}})
                    elif j.get("type") == "message_stop":
                        yield sse({"done": True})
                        return
                except Exception:
                    continue
    yield sse({"done": True})


async def stream_gemini(base: str, key: str, model: str, body: dict):
    url = f"{base.rstrip('/')}/models/{model}:streamGenerateContent?alt=sse&key={key}"
    async with httpx.AsyncClient(timeout=httpx.Timeout(15, read=180)) as client:
        async with client.stream("POST", url, json=body) as resp:
            if resp.status_code != 200:
                raw = (await resp.aread()).decode(errors="replace")[:500]
                try:
                    msg = json.loads(raw).get("error", {}).get("message", raw)
                except Exception:
                    msg = raw
                yield sse({"error": f"[{resp.status_code}] {msg}"})
                return
            async for line in resp.aiter_lines():
                line = line.strip()
                if not line.startswith("data:"):
                    continue
                try:
                    j = json.loads(line[5:].strip())
                    um = j.get("usageMetadata")
                    if um:
                        yield sse({"usage": {"prompt": um.get("promptTokenCount", 0), "completion": um.get("candidatesTokenCount", 0)}})
                    parts = j.get("candidates", [{}])[0].get("content", {}).get("parts", [])
                    for p in parts:
                        if p.get("text"):
                            yield sse({"delta": p["text"]})
                except Exception:
                    continue
    yield sse({"done": True})


@app.get("/api/health")
def health():
    return {"ok": True, "providers": list(PROVIDERS.keys()),
            "default": CFG.get("default_provider", "lokal")}


@app.get("/api/models")
def models():
    return {"providers": PROVIDERS.keys().__iter__().__length_hint__() and
            {k: MODELS.get(k, []) for k in PROVIDERS},
            "meta": {k: {"label": k.capitalize(), "kind": v["kind"]}
                     for k, v in PROVIDERS.items()}}


@app.post("/api/chat")
async def chat(req: ChatReq, request: Request):
    if not SESSION_SECRET or not verify_session(request.cookies.get("aihub_session", ""), SESSION_SECRET):
        return JSONResponse({"error": "belum login — masuk dengan Google dulu"}, status_code=401)
    prov = PROVIDERS.get(req.provider)
    if not prov:
        async def gen():
            yield sse({"error": f"provider tidak dikenal: {req.provider}"})
            yield sse({"done": True})
        return StreamingResponse(gen(), media_type="text/event-stream")

    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._/:@-]{0,99}$", req.model or ""):
        async def gen_m():
            yield sse({"error": "model tidak valid"})
            yield sse({"done": True})
        return StreamingResponse(gen_m(), media_type="text/event-stream")
    if len(req.messages) > 200:
        async def gen_n():
            yield sse({"error": "messages terlalu banyak"})
            yield sse({"done": True})
        return StreamingResponse(gen_n(), media_type="text/event-stream")
    _sz = sum(len(str(m.get("content") or "")) + len(m.get("images") or []) * 1500000 for m in req.messages)
    if _sz > 8_000_000:
        async def gen_s():
            yield sse({"error": "payload terlalu besar"})
            yield sse({"done": True})
        return StreamingResponse(gen_s(), media_type="text/event-stream")

    key = req.api_key.strip()
    eff_provider = req.provider
    eff_model = req.model
    # DeepSeek Web via 9Router: key disuntik server-side
    if not key and req.provider == "deepseek-web":
        key = (os.environ.get("DEEPSEEK_WEB_KEY") or os.environ.get("AIHUB_DEEPSEEK_WEB_KEY")
               or os.environ.get("AIHUB_LOKAL_KEY", ""))
    # DeepSeek tanpa key pribadi -> model DeepSeek gratis di TokenHarbor (server-side key)
    if not key and req.provider == "deepseek":
        thk = os.environ.get("HERMES_CUSTOM_TOKENHARBOR_AI_API_KEY") or os.environ.get("TOKENHARBOR_API_KEY", "")
        if thk:
            key = thk
            eff_provider = "tokenharbor"
            eff_model = "deepseek-v4.1-flash:free" if "reasoner" in req.model else "deepseek-v4-flash:free"
            prov = PROVIDERS["tokenharbor"]
    # fallback key dari env / config untuk provider lokal
    if not key and req.provider == "lokal":
        key = os.environ.get("AIHUB_LOKAL_KEY") or (CFG.get("providers", {}).get("lokal", {}) or {}).get("api_key", "hermes-agent")
    if not key and req.provider == "tokenharbor":
        key = os.environ.get("HERMES_CUSTOM_TOKENHARBOR_AI_API_KEY") or os.environ.get("TOKENHARBOR_API_KEY", "")
    if not key and req.provider in ("openai", "deepseek", "anthropic", "gemini", "openrouter"):
        envmap = {"openai": "OPENAI_API_KEY", "deepseek": "DEEPSEEK_API_KEY",
                  "anthropic": "ANTHROPIC_API_KEY", "gemini": "GEMINI_API_KEY",
                  "openrouter": "OPENROUTER_API_KEY"}
        key = os.environ.get(envmap[req.provider], "")

    base = req.base_url.strip() or prov["base"]
    if not base:
        async def gen():
            yield sse({"error": "base_url kosong untuk provider custom"})
            yield sse({"done": True})
        return StreamingResponse(gen(), media_type="text/event-stream")

    sysmsg = req.system.strip()
    msgs = []
    for m in req.messages:
        if not m.get("content") and not m.get("images"):
            continue
        item = {"role": m["role"], "content": m.get("content") or ""}
        if m.get("images"):
            item["images"] = m["images"]
        msgs.append(item)

    if prov["kind"] == "anthropic":
        amsgs = []
        for m in msgs:
            if m.get("images"):
                blocks = [{"type": "text", "text": m["content"] or "(lihat gambar)"}]
                for u in m["images"]:
                    b64 = u.split(",", 1)[1] if "," in u else u
                    blocks.append({"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": b64}})
                amsgs.append({"role": m["role"], "content": blocks})
            else:
                amsgs.append({"role": m["role"], "content": m["content"]})
        body = {"model": eff_model, "max_tokens": req.max_tokens or 4096, "stream": True,
                "temperature": req.temperature, "messages": amsgs}
        if sysmsg:
            body["system"] = sysmsg
        agen = stream_anthropic(base, key, body)
    elif prov["kind"] == "gemini":
        contents = []
        for m in msgs:
            parts = [{"text": m["content"] or "(lihat gambar)"}]
            for u in (m.get("images") or []):
                b64 = u.split(",", 1)[1] if "," in u else u
                parts.append({"inline_data": {"mime_type": "image/jpeg", "data": b64}})
            contents.append({"role": "user" if m["role"] == "user" else "model", "parts": parts})
        body = {"contents": contents,
                "generationConfig": {"temperature": req.temperature}}
        if req.max_tokens:
            body["generationConfig"]["maxOutputTokens"] = req.max_tokens
        if sysmsg:
            body["systemInstruction"] = {"parts": [{"text": sysmsg}]}
        agen = stream_gemini(base, key, eff_model, body)
    else:  # openai-compatible
        omsgs = []
        for m in msgs:
            if m.get("images"):
                content = [{"type": "text", "text": m["content"] or "(lihat gambar)"}]
                for u in m["images"]:
                    content.append({"type": "image_url", "image_url": {"url": u}})
                omsgs.append({"role": m["role"], "content": content})
            else:
                omsgs.append({"role": m["role"], "content": m["content"]})
        full = ([{"role": "system", "content": sysmsg}] if sysmsg else []) + omsgs
        body = {"model": eff_model, "messages": full, "stream": True,
                "temperature": req.temperature}
        if req.max_tokens:
            body["max_tokens"] = req.max_tokens
        agen = stream_openai(base, key, body)

    async def guard():
        try:
            async for chunk in agen:
                yield chunk
        except httpx.ConnectError as e:
            yield sse({"error": f"koneksi gagal ke {base}: {e}"})
            yield sse({"done": True})
        except Exception as e:
            err = re.sub(r"(sk|thk|key|api)[-_][A-Za-z0-9._-]{8,}", "[redacted]", str(e))[:400]
            yield sse({"error": f"upstream error: {err}"})
            yield sse({"done": True})

    return StreamingResponse(guard(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8400, log_level="warning")
