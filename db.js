// Postgres-backed store. Same responsibilities as the old JSON store, but async.
// Enforces the same consent rules: you can only write your own location,
// and you are invisible in a group until you explicitly turn sharing on.
import pg from "pg";
import { randomUUID, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

const { Pool } = pg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // Neon requires TLS
  max: 10,
  idleTimeoutMillis: 30_000,
});

export async function initSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id             UUID PRIMARY KEY,
      email          TEXT UNIQUE NOT NULL,
      display_name   TEXT NOT NULL,
      password       TEXT NOT NULL,
      email_verified BOOLEAN NOT NULL DEFAULT false,
      created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false;

    CREATE TABLE IF NOT EXISTS email_verifications (
      token       TEXT PRIMARY KEY,
      user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS tokens (
      token       TEXT PRIMARY KEY,
      user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS groups (
      id          UUID PRIMARY KEY,
      name        TEXT NOT NULL,
      owner_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      join_code   TEXT UNIQUE NOT NULL,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS memberships (
      group_id   UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
      user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      sharing    BOOLEAN NOT NULL DEFAULT false,
      joined_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (group_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS locations (
      user_id    UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      lat        DOUBLE PRECISION NOT NULL,
      lng        DOUBLE PRECISION NOT NULL,
      accuracy   DOUBLE PRECISION,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}

// --- password hashing (scrypt) ---
export function hashPassword(pw) {
  const salt = randomBytes(16).toString("hex");
  return `${salt}:${scryptSync(pw, salt, 64).toString("hex")}`;
}
export function verifyPassword(pw, stored) {
  const [salt, hash] = String(stored).split(":");
  const test = scryptSync(pw, salt, 64);
  const known = Buffer.from(hash, "hex");
  return test.length === known.length && timingSafeEqual(test, known);
}

const rowUser = r => r && { id: r.id, email: r.email, displayName: r.display_name, password: r.password, emailVerified: r.email_verified };
const rowLoc  = r => r && { lat: r.lat, lng: r.lng, accuracy: r.accuracy, updatedAt: r.updated_at };

// --- users ---
export async function createUser(email, pw, displayName) {
  email = email.toLowerCase().trim();
  const id = randomUUID();
  const name = displayName || email.split("@")[0];
  try {
    const { rows } = await pool.query(
      `INSERT INTO users (id, email, display_name, password) VALUES ($1,$2,$3,$4) RETURNING *`,
      [id, email, name, hashPassword(pw)]
    );
    return rowUser(rows[0]);
  } catch (e) {
    if (e.code === "23505") throw new Error("email already registered");
    throw e;
  }
}
export async function findUserByEmail(email) {
  const { rows } = await pool.query(`SELECT * FROM users WHERE email=$1`, [email.toLowerCase().trim()]);
  return rowUser(rows[0]);
}
export async function getUser(id) {
  const { rows } = await pool.query(`SELECT * FROM users WHERE id=$1`, [id]);
  return rowUser(rows[0]);
}
export async function updatePassword(id, newPw) {
  await pool.query(`UPDATE users SET password=$2 WHERE id=$1`, [id, hashPassword(newPw)]);
}
// Full account + data erasure. Cascades delete tokens, memberships, location, owned groups.
export async function deleteUser(id) {
  await pool.query(`DELETE FROM users WHERE id=$1`, [id]);
}
// --- email verification ---
export const EMAIL_TOKEN_TTL_HOURS = 24;

export async function createEmailToken(userId) {
  const token = randomBytes(32).toString("hex");
  await pool.query(`INSERT INTO email_verifications (token, user_id) VALUES ($1,$2)`, [token, userId]);
  return token;
}
// Consume a verification token: mark the user verified and delete the token. Returns true on success.
export async function verifyEmailToken(token) {
  const { rows } = await pool.query(
    `DELETE FROM email_verifications
      WHERE token=$1 AND created_at > now() - ($2 || ' hours')::interval
      RETURNING user_id`,
    [token, String(EMAIL_TOKEN_TTL_HOURS)]
  );
  if (!rows[0]) return false;
  await pool.query(`UPDATE users SET email_verified=true WHERE id=$1`, [rows[0].user_id]);
  return true;
}

// TRANSPARENCY: exactly who can see me right now, and via which group.
// = people in groups where I have sharing ON (my sharing is what exposes me).
export async function whoCanSeeMe(userId) {
  const { rows } = await pool.query(
    `SELECT DISTINCT g.name AS group_name, u.display_name AS viewer
       FROM memberships mine
       JOIN groups g       ON g.id = mine.group_id
       JOIN memberships om ON om.group_id = mine.group_id AND om.user_id <> mine.user_id
       JOIN users u        ON u.id = om.user_id
      WHERE mine.user_id = $1 AND mine.sharing = true
      ORDER BY g.name, u.display_name`,
    [userId]
  );
  return rows.map(r => ({ group: r.group_name, viewer: r.viewer }));
}

// --- tokens (expire after TOKEN_TTL_DAYS of no use) ---
export const TOKEN_TTL_DAYS = 30;

export async function issueToken(userId) {
  const token = randomBytes(32).toString("hex");
  await pool.query(`INSERT INTO tokens (token, user_id) VALUES ($1,$2)`, [token, userId]);
  return token;
}
export async function userForToken(token) {
  if (!token) return null;
  const { rows } = await pool.query(
    `SELECT u.* FROM tokens t JOIN users u ON u.id=t.user_id
      WHERE t.token=$1 AND t.created_at > now() - ($2 || ' days')::interval`,
    [token, String(TOKEN_TTL_DAYS)]
  );
  return rowUser(rows[0]);
}
export async function revokeToken(token) {
  await pool.query(`DELETE FROM tokens WHERE token=$1`, [token]);
}
// Log out everywhere (used on password change / "sign out all devices").
export async function revokeAllTokens(userId) {
  await pool.query(`DELETE FROM tokens WHERE user_id=$1`, [userId]);
}
// Housekeeping: drop expired tokens. Called on an interval by the server.
export async function purgeExpiredTokens() {
  const { rowCount } = await pool.query(
    `DELETE FROM tokens WHERE created_at < now() - ($1 || ' days')::interval`,
    [String(TOKEN_TTL_DAYS)]
  );
  return rowCount;
}

// --- groups & memberships (the consent boundary) ---
export async function createGroup(name, ownerId) {
  const id = randomUUID();
  const joinCode = randomBytes(4).toString("hex").toUpperCase();
  const { rows } = await pool.query(
    `INSERT INTO groups (id, name, owner_id, join_code) VALUES ($1,$2,$3,$4) RETURNING *`,
    [id, name, ownerId, joinCode]
  );
  // owner is a member and sharing-on by default (it's their own group)
  await pool.query(
    `INSERT INTO memberships (group_id, user_id, sharing) VALUES ($1,$2,true)`, [id, ownerId]
  );
  const g = rows[0];
  return { id: g.id, name: g.name, ownerId: g.owner_id, joinCode: g.join_code };
}
export async function findGroupByCode(code) {
  const { rows } = await pool.query(`SELECT * FROM groups WHERE join_code=$1`, [code.toUpperCase().trim()]);
  const g = rows[0];
  return g ? { id: g.id, name: g.name, ownerId: g.owner_id, joinCode: g.join_code } : null;
}
export async function joinGroup(groupId, userId) {
  // ON CONFLICT DO NOTHING keeps an existing member's sharing setting untouched.
  // New members default to sharing=false — explicit opt-in required to be visible.
  await pool.query(
    `INSERT INTO memberships (group_id, user_id, sharing) VALUES ($1,$2,false)
     ON CONFLICT (group_id, user_id) DO NOTHING`, [groupId, userId]
  );
}
export async function leaveGroup(groupId, userId) {
  await pool.query(`DELETE FROM memberships WHERE group_id=$1 AND user_id=$2`, [groupId, userId]);
}
export async function setSharing(groupId, userId, sharing) {
  const { rowCount } = await pool.query(
    `UPDATE memberships SET sharing=$3 WHERE group_id=$1 AND user_id=$2`, [groupId, userId, !!sharing]
  );
  if (!rowCount) throw new Error("not a member");
  return { sharing: !!sharing };
}
export async function groupsForUser(userId) {
  const { rows } = await pool.query(
    `SELECT g.id, g.name, g.join_code, m.sharing
       FROM memberships m JOIN groups g ON g.id=m.group_id
      WHERE m.user_id=$1 ORDER BY g.created_at`, [userId]
  );
  return rows.map(r => ({ id: r.id, name: r.name, joinCode: r.join_code, sharing: r.sharing }));
}
export async function isMember(groupId, userId) {
  const { rowCount } = await pool.query(
    `SELECT 1 FROM memberships WHERE group_id=$1 AND user_id=$2`, [groupId, userId]
  );
  return rowCount > 0;
}
export async function membersSharingIn(groupId) {
  // Only members who turned sharing ON, joined to their latest location (if any).
  const { rows } = await pool.query(
    `SELECT u.id, u.display_name, l.lat, l.lng, l.accuracy, l.updated_at
       FROM memberships m
       JOIN users u ON u.id=m.user_id
       LEFT JOIN locations l ON l.user_id=u.id
      WHERE m.group_id=$1 AND m.sharing=true`, [groupId]
  );
  return rows.map(r => ({
    id: r.id,
    displayName: r.display_name,
    location: r.lat == null ? null : { lat: r.lat, lng: r.lng, accuracy: r.accuracy, updatedAt: r.updated_at },
  }));
}

// --- locations (you can only ever write your OWN) ---
export async function setLocation(userId, lat, lng, accuracy) {
  const { rows } = await pool.query(
    `INSERT INTO locations (user_id, lat, lng, accuracy, updated_at)
     VALUES ($1,$2,$3,$4, now())
     ON CONFLICT (user_id) DO UPDATE SET lat=$2, lng=$3, accuracy=$4, updated_at=now()
     RETURNING *`, [userId, lat, lng, accuracy ?? null]
  );
  return rowLoc(rows[0]);
}
export async function clearLocation(userId) {
  await pool.query(`DELETE FROM locations WHERE user_id=$1`, [userId]);
}
