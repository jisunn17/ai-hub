# AI Hub 🔥

Chat AI multi-provider dalam satu antarmuka — GPT, DeepSeek, Claude, Gemini, TokenHarbor. Streaming cepat, responsif di HP & desktop, dengan vault API key ter-encrypt (AES-256-GCM) dan login Google OAuth.

## Fitur

- **Multi-provider**: TokenHarbor (default, gratis), OpenAI, DeepSeek, Anthropic, Gemini, OpenRouter, custom/lokal
- **Streaming**: SSE real-time dengan syntax highlighting + markdown rendering
- **Image vision**: Lampirkan gambar, AI bisa analisa (GPT-4o/Gemini/Claude)
- **Vault API key**: AES-256-GCM + PBKDF2 250k iterasi — key tidak pernah disimpan plaintext
- **Login Google**: OAuth 2.0, session HMAC-SHA256 (7 hari), HttpOnly + Secure cookies
- **Template prompt**: Slash `/` command, kelola di Settings
- **Share link**: Encode chat ke URL, mode view-only
- **Chat management**: Search, rename, pin, edit & resend, auto-title (AI)
- **TTS**: Baca jawaban AI dengan suara browser (id-ID)
- **Security hardening**: CSP, HSTS, X-Frame-Options, rate limit 30/menit, origin check, DOMPurify XSS protection

## Setup

### Prerequisites

- Node.js 18+ (untuk Vercel) atau Python 3.10+ (untuk lokal)
- Akun Google Cloud Console (untuk OAuth)
- Akun Vercel (untuk deploy)

### 1. Google OAuth Setup

1. Buka [console.cloud.google.com](https://console.cloud.google.com)
2. Buat project baru atau pilih yang sudah ada
3. **APIs & Services** → **Credentials** → **Create Credentials** → **OAuth client ID**
4. **Application type**: Web application
5. **Authorized redirect URIs** — tambahkan:
   ```
   https://DOMAIN-LO.vercel.app/api/auth/callback
   http://127.0.0.1:8400/api/auth/callback
   ```
6. **Publish** consent screen (atau tambahkan email di Test users)
7. Copy **Client ID** & **Client Secret**

### 2. Vercel Deploy

```bash
# Login Vercel
vercel login

# Set environment variables
vercel env add GOOGLE_CLIENT_ID production
vercel env add GOOGLE_CLIENT_SECRET production
vercel env add SESSION_SECRET production  # openssl rand -hex 32
vercel env add APP_URL production  # https://DOMAIN-LO.vercel.app
vercel env add TOKENHARBOR_API_KEY production  # opsional, untuk provider TokenHarbor

# Deploy
vercel deploy --prod
```

### 3. Local Development

```bash
# Clone & install
cd ai-hub
pip install fastapi uvicorn httpx

# Setup .env
cp .env.example .env
# Edit .env — isi GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, SESSION_SECRET

# Run
python3 server.py
# Buka http://127.0.0.1:8400
```

## Struktur File

```
ai-hub/
├── index.html          ← Frontend (UI + vault + auth)
├── server.py           ← Backend FastAPI (lokal, port 8400)
├── vercel.json         ← Deploy config + security headers
├── config.json         ← Config provider lokal (opsional)
├── mascot.webp         ← Mascot transparan 768px
├── .env.example        ← Template environment variables
├── api/                ← Vercel serverless functions
│   ├── _lib.js         ← Helper (HMAC session, cookies)
│   ├── auth/
│   │   ├── login.js    ← Redirect ke Google OAuth
│   │   ├── callback.js ← Tukar kode → session token
│   │   ├── logout.js   ← Bersihkan session
│   │   └── me.js       ← Profil user (JSON)
│   ├── chat.js         ← Proxy streaming + rate limit + auth gate
│   ├── models.js       ← Daftar model/provider
│   └── health.js       ← Health check
└── static/             ← Versi lokal (di-serve FastAPI)
    ├── index.html
    └── mascot.webp
```

## Environment Variables

| Variable | Wajib | Deskripsi |
|----------|-------|-----------|
| `GOOGLE_CLIENT_ID` | ✅ | Client ID dari Google Cloud Console |
| `GOOGLE_CLIENT_SECRET` | ✅ | Client Secret dari Google Cloud Console |
| `SESSION_SECRET` | ✅ | Random string 64+ karakter (`openssl rand -hex 32`) |
| `APP_URL` | ✅ | URL publik (Vercel: `https://domain.vercel.app`, lokal: `http://127.0.0.1:8400`) |
| `TOKENHARBOR_API_KEY` | Opsional | API key TokenHarbor (untuk provider gratis) |

## Security Notes

- **Vault API key**: Key disimpan ter-encrypt (AES-256-GCM) di browser. Tanpa passphrase, storage tidak bisa dibaca.
- **Session**: HMAC-SHA256 signed + expiry 7 hari + timing-safe comparison. Cookie HttpOnly + Secure + SameSite=Lax.
- **Rate limit**: 30 request/menit per IP di `/api/chat`
- **XSS**: DOMPurify strict profile + CSP + esc() hardened
- **Origin check**: Cross-site request ditolak (403)

## Troubleshooting

**"GOOGLE_CLIENT_ID belum di-set"**
- Pastikan env var sudah di-set di Vercel dashboard → Settings → Environment Variables
- Redeploy setelah set env var

**"state tidak valid"**
- Coba login dari awal (buka `/api/auth/login` lagi)
- Pastikan redirect URI di Google Cloud Console persis sama

**"Rate limit"**
- Tunggu 60 detik (window rate limit)
- Kurangi frequency request

**Vault tidak bisa unlock**
- Pastikan passphrase benar (case-sensitive)
- Kalau lupa, key hilang (by design — tidak ada recovery)
- Hapus `aihub_vault` di localStorage untuk reset (key hilang)

## Tech Stack

- **Frontend**: Vanilla JS + Tailwind CSS + marked.js + highlight.js + DOMPurify
- **Backend**: Vercel Serverless (Node.js) + FastAPI (Python, lokal)
- **Auth**: Google OAuth 2.0 + HMAC-SHA256 session
- **Crypto**: Web Crypto API (PBKDF2 + AES-256-GCM)

---

Built with ❤️ by AI Hub. Report security issues via Telegram.
