# Whereabouts — consent-based location sharing

A "Find My"-style app where people **opt in** to share their location. It is built so that
misuse as covert tracking is structurally hard, not just discouraged.

## Consent guarantees (built into the design)

1. **You can only ever write your own location.** The `POST /api/location` endpoint uses your
   auth token to decide whose position is being set — there is no way to submit a position "for"
   someone else.
2. **The browser/OS asks permission.** Location comes from the standard `navigator.geolocation`
   API, which triggers the operating system's own permission prompt. No prompt, no data.
3. **Sharing is per-group and opt-in.** When you join a group you start with sharing **OFF**.
   You are invisible until you flip it on, and flipping it off removes you immediately.
4. **No phone-number or stranger lookup.** There is no endpoint that takes a phone number, email,
   or name and returns a location. You only see people who joined a shared group *and* turned
   sharing on.
5. **One-tap wipe.** "Wipe my last position" deletes your stored coordinates everywhere.

## Run it

```bash
npm install
cp .env.example .env      # then put your Postgres URL in DATABASE_URL
npm run gen-cert          # optional: self-signed cert for local HTTPS (see below)
npm start                 # http://localhost:3000  (or https:// if certs exist)
```

The schema is created automatically on first boot via `initSchema()`. Storage is
**PostgreSQL** (tested against Neon).

Register two accounts (two browsers / a private window), create a group in one, copy the join
code into the other, verify each email, then turn sharing ON to appear on the map.

### HTTPS locally

Browser geolocation needs a "secure context." `localhost` counts over plain HTTP, but any
other device (your phone on the LAN) needs HTTPS. Run `npm run gen-cert` to write
`certs/key.pem` + `certs/cert.pem`; the server then serves HTTPS automatically. Your browser
will warn once about the self-signed cert — accept it for local testing only. **In production,
delete these and terminate TLS at your proxy/load balancer instead.**

### Email verification

On signup the app emails a verification link; **sharing your location stays disabled until the
email is verified** (anti-abuse: no anonymous throwaway accounts). Without SMTP configured, the
link is printed to the server console so you can still test locally. To send real mail, set
`SMTP_HOST`/`SMTP_PORT`/`SMTP_USER`/`SMTP_PASS`/`MAIL_FROM` in `.env`.

## Run with Docker

```bash
docker compose up --build       # reads secrets from .env, serves on :3000
```

`docker-compose.yml` runs only the app and points it at your existing Postgres (Neon) via
`DATABASE_URL`. The image runs as the non-root `node` user.

## Deploy

Any Node host works. On **Render / Railway / Fly.io**:

1. Push this repo to GitHub.
2. Create a Web Service from it (build `npm ci`, start `npm start`), or use the Dockerfile.
3. Set env vars: `DATABASE_URL`, `PUBLIC_URL` (your https URL, for correct email links),
   and the `SMTP_*` vars. Leave `SSL_*` unset — the platform terminates TLS for you.

## Files

- `server.js`  — Express API; auth rate limiting, security headers, HTTP/HTTPS listener.
- `db.js`      — PostgreSQL store: schema, scrypt hashing, parameterized queries, token expiry.
- `mailer.js`  — SMTP sender (logs the link when SMTP is unset).
- `gen-cert.js`— writes a self-signed dev cert.
- `public/index.html` — the whole client: auth, verify banner, groups, consent toggle, map.
- `Dockerfile`, `docker-compose.yml`, `.env.example` — deployment.

## Production features included

- **PostgreSQL** storage, parameterized queries (no SQL injection), scrypt password hashing.
- **Email verification** gate — location sharing is blocked until the email is confirmed.
- **Token expiry** (30 days) + hourly cleanup.
- **"Who can see me right now"** panel — every person always sees their exact audience, by group.
- **Change password** (verifies current, signs out all sessions) and **delete account & all data**.
- **Location freshness** — the map shows how long ago each fix was reported.
- **HTTPS** support (local dev cert + production proxy notes).
- **Security**: per-IP auth rate limiting, CSP + `nosniff` + `X-Frame-Options`, HSTS over TLS,
  16 KB body cap, runs as non-root in Docker.

Verified by **33 automated end-to-end checks** against a live Postgres database.

## Still recommended before a big public launch

An **access/audit log** of security events, httpOnly secure **cookies** instead of bearer tokens
in `localStorage`, and a background job to **age out stale locations**.

## What this deliberately does NOT do

It cannot locate someone from a phone number, and it cannot show you anyone who has not personally
installed it, joined your group, and turned sharing on. That is the point.
