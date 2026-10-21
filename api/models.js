const MODELS = {
  openai:     ["gpt-4o", "gpt-4o-mini", "gpt-4.1", "gpt-4.1-mini", "o4-mini", "o3"],
  deepseek:   ["deepseek-chat", "deepseek-reasoner"],
  "deepseek-web": ["dsw/deepseek-chat", "dsw/deepseek-reasoner", "dsw/deepseek-v4.1-flash"],
  openrouter: ["deepseek/deepseek-chat-v3-0324:free", "meta-llama/llama-3.3-70b-instruct:free", "google/gemini-2.0-flash-exp:free", "qwen/qwen3-235b-a22b:free"],
  tokenharbor: ["mimo-v2.5:free", "mimo-v2.6-flash:free", "deepseek-v4-flash:free", "deepseek-v4.1-flash:free", "qwen3.8-flash:free"],
  anthropic:  ["claude-sonnet-4-5", "claude-haiku-4-5", "claude-opus-4-1"],
  gemini:     ["gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.0-flash"],
  lokal:      ["dsw-fallback"],
  custom:     [],
};
export default function handler(req, res) {
  res.setHeader("Content-Type", "application/json");
  const providers = Object.keys(MODELS);
  const meta = Object.fromEntries(providers.map(p => [p, { label: p.charAt(0).toUpperCase() + p.slice(1) }]));
  res.end(JSON.stringify({ providers: MODELS, meta, runtime: "vercel" }));
}
