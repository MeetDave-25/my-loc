import "dotenv/config";
import express from "express";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { readFileSync, existsSync } from "node:fs";
import { createServer as createHttp } from "node:http";
import { createServer as createHttps } from "node:https";
import * as store from "./db.js";
import { sendVerificationEmail } from "./mailer.js";

const baseUrl = req =>
  (process.env.PUBLIC_URL || `${req.protocol}://${req.get("host")}`).replace(/\/$/, "");

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is not set. Copy .env.example to .env and fill it in.");
  process.exit(1);
}

const app = express();
app.set("trust proxy", 1); // behind a TLS-terminating proxy in production
app.use(express.json({ limit: "16kb" }));

// --- security headers (no external dep) ---
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy",
    "default-src 'self'; " +
    "script-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; " +
    "style-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; " +
    "img-src 'self' data: https:; " +          // OSM tiles + leaflet marker icons
    "connect-src 'self'"
  );
  if (req.secure) res.setHeader("Strict-Transport-Security", "max-age=15552000; includeSubDomains");
  next();
});

app.use(express.static(join(dirname(fileURLToPath(import.meta.url)), "public")));

const PORT = process.env.PORT || 3000;

// --- tiny in-memory rate limiter (per IP+bucket). Swap for Redis in a cluster. ---
function rateLimit({ windowMs, max, bucket }) {
  const hits = new Map();
  setInterval(() => hits.clear(), windowMs).unref();
  return (req, res, next) => {
    const key = `${bucket}:${req.ip}`;
    const n = (hits.get(key) || 0) + 1;
    hits.set(key, n);
    if (n > max) return res.status(429).json({ error: "too many requests, slow down" });
    next();
  };
}
const authLimiter = rateLimit({ windowMs: 60_000, max: 10, bucket: "auth" });

// --- auth middleware ---
async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    const user = await store.userForToken(token);
    if (!user) return res.status(401).json({ error: "unauthorized" });
    req.user = user;
    req.token = token;
    next();
  } catch (e) { next(e); }
}
const publicUser = u => ({ id: u.id, email: u.email, displayName: u.displayName, emailVerified: u.emailVerified });

// health check for the hosting platform
app.get("/api/health", (_req, res) => res.json({ ok: true }));
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// --- accounts ---
app.post("/api/register", authLimiter, wrap(async (req, res) => {
  const { email, password, displayName } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "email and password required" });
  if (String(password).length < 8) return res.status(400).json({ error: "password must be at least 8 chars" });
  try {
    const user = await store.createUser(email, password, displayName);
    const vtoken = await store.createEmailToken(user.id);
    await sendVerificationEmail(user.email, `${baseUrl(req)}/api/verify?token=${vtoken}`);
    res.json({ token: await store.issueToken(user.id), user: publicUser(user) });
  } catch (e) { res.status(409).json({ error: e.message }); }
}));

// Verify email from the link in the message → land back on the app.
app.get("/api/verify", wrap(async (req, res) => {
  const okv = await store.verifyEmailToken(req.query.token || "");
  res.redirect(okv ? "/?verified=1" : "/?verified=0");
}));

// Resend the verification email to the logged-in user.
app.post("/api/verify/resend", auth, authLimiter, wrap(async (req, res) => {
  if (req.user.emailVerified) return res.json({ ok: true, already: true });
  const vtoken = await store.createEmailToken(req.user.id);
  await sendVerificationEmail(req.user.email, `${baseUrl(req)}/api/verify?token=${vtoken}`);
  res.json({ ok: true });
}));

app.post("/api/login", authLimiter, wrap(async (req, res) => {
  const { email, password } = req.body || {};
  const user = await store.findUserByEmail(email || "");
  if (!user || !store.verifyPassword(password || "", user.password))
    return res.status(401).json({ error: "invalid credentials" });
  res.json({ token: await store.issueToken(user.id), user: publicUser(user) });
}));

app.post("/api/logout", auth, wrap(async (req, res) => { await store.revokeToken(req.token); res.json({ ok: true }); }));
app.get("/api/me", auth, (req, res) => res.json({ user: publicUser(req.user) }));

// Change password (verifies current), then sign out all sessions and issue a fresh one.
app.post("/api/account/password", auth, authLimiter, wrap(async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!store.verifyPassword(currentPassword || "", req.user.password))
    return res.status(401).json({ error: "current password is wrong" });
  if (String(newPassword || "").length < 8)
    return res.status(400).json({ error: "new password must be at least 8 chars" });
  await store.updatePassword(req.user.id, newPassword);
  await store.revokeAllTokens(req.user.id);
  res.json({ token: await store.issueToken(req.user.id) });
}));

// TRANSPARENCY: who can see me right now, and through which group.
app.get("/api/visibility", auth, wrap(async (req, res) => {
  res.json({ viewers: await store.whoCanSeeMe(req.user.id) });
}));

// Erase my account and ALL my data (privacy right). Irreversible.
app.delete("/api/account", auth, wrap(async (req, res) => {
  await store.deleteUser(req.user.id);
  res.json({ ok: true });
}));

// --- groups (the sharing/consent boundary) ---
app.get("/api/groups", auth, wrap(async (req, res) => {
  res.json({ groups: await store.groupsForUser(req.user.id) });
}));

app.post("/api/groups", auth, wrap(async (req, res) => {
  const name = (req.body?.name || "").trim();
  if (!name) return res.status(400).json({ error: "name required" });
  res.json({ group: await store.createGroup(name, req.user.id) });
}));

app.post("/api/groups/join", auth, wrap(async (req, res) => {
  const group = await store.findGroupByCode(req.body?.joinCode || "");
  if (!group) return res.status(404).json({ error: "no group with that code" });
  await store.joinGroup(group.id, req.user.id); // joins with sharing OFF
  res.json({ group: { ...group, sharing: false } });
}));

app.post("/api/groups/:id/leave", auth, wrap(async (req, res) => {
  await store.leaveGroup(req.params.id, req.user.id);
  res.json({ ok: true });
}));

// Live consent switch: whether YOU are visible to a group.
app.post("/api/groups/:id/sharing", auth, wrap(async (req, res) => {
  if (!(await store.isMember(req.params.id, req.user.id)))
    return res.status(403).json({ error: "not a member" });
  // Turning sharing ON requires a verified email. Turning it OFF is always allowed.
  if (req.body?.sharing && !req.user.emailVerified)
    return res.status(403).json({ error: "verify your email before sharing your location" });
  const m = await store.setSharing(req.params.id, req.user.id, req.body?.sharing);
  res.json({ sharing: m.sharing });
}));

app.get("/api/groups/:id/members", auth, wrap(async (req, res) => {
  if (!(await store.isMember(req.params.id, req.user.id)))
    return res.status(403).json({ error: "not a member" });
  res.json({ members: await store.membersSharingIn(req.params.id) });
}));

// --- location: you can only ever write your OWN position ---
app.post("/api/location", auth, wrap(async (req, res) => {
  const { lat, lng, accuracy } = req.body || {};
  if (typeof lat !== "number" || typeof lng !== "number")
    return res.status(400).json({ error: "lat and lng (numbers) required" });
  if (lat < -90 || lat > 90 || lng < -180 || lng > 180)
    return res.status(400).json({ error: "coordinates out of range" });
  res.json({ location: await store.setLocation(req.user.id, lat, lng, accuracy) });
}));

app.delete("/api/location", auth, wrap(async (req, res) => {
  await store.clearLocation(req.user.id);
  res.json({ ok: true });
}));

// central error handler
app.use((err, req, res, _next) => {
  const status = err.status || err.statusCode || 500;
  if (status >= 500) console.error(err);
  res.status(status).json({ error: status === 413 ? "request too large" : status >= 500 ? "server error" : err.message });
});

// Serve HTTPS locally when certs exist (from `npm run gen-cert`); otherwise HTTP.
// In production, keep this HTTP and let a proxy/load balancer terminate TLS.
const KEY = process.env.SSL_KEY || "certs/key.pem";
const CERT = process.env.SSL_CERT || "certs/cert.pem";
function startServer() {
  if (existsSync(KEY) && existsSync(CERT)) {
    createHttps({ key: readFileSync(KEY), cert: readFileSync(CERT) }, app)
      .listen(PORT, () => console.log(`Whereabouts running on https://localhost:${PORT}`));
  } else {
    createHttp(app).listen(PORT, () => console.log(`Whereabouts running on http://localhost:${PORT}`));
  }
}

store.initSchema()
  .then(() => {
    setInterval(() => store.purgeExpiredTokens().catch(() => {}), 3600_000).unref();
    startServer();
  })
  .catch(e => { console.error("Failed to init database:", e.message); process.exit(1); });
