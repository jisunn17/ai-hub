export default function handler(req, res) {
  res.setHeader("Set-Cookie", [
    "aihub_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
    "aihub_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
  ]);
  res.statusCode = 302;
  res.setHeader("Location", "/");
  res.end();
}
