const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const DATA_DIR = path.join(__dirname, "data");
const DB_PATH = path.join(DATA_DIR, "db.json");

function createStorage({ databaseUrl }) {
  if (databaseUrl) return new PostgresStorage(databaseUrl);
  return new JsonStorage(DB_PATH);
}

function defaultSettings() {
  return {
    llm: { provider: "gemini", model: "gemini-3.1-flash-lite-preview", apiKeyEnc: null },
    stt: { provider: "groq", model: "whisper-large-v3-turbo", apiKeyEnc: null },
    email: {
      provider: "smtp",
      host: "",
      port: 587,
      secure: false,
      fromEmail: "",
      fromName: "talksyql",
      username: "",
      passwordEnc: null
    },
    updatedAt: null
  };
}

function defaultDb() {
  return {
    settings: defaultSettings(),
    users: [],
    histories: [],
    sessions: [],
    adminSessions: [],
    authCodes: [],
    rateLimits: []
  };
}

function normalizeDb(db) {
  const defaults = defaultDb();
  return {
    ...defaults,
    ...db,
    settings: normalizeSettings(db.settings || {})
  };
}

function normalizeSettings(settings) {
  const defaults = defaultSettings();
  const stt = { ...defaults.stt, ...(settings.stt || {}) };
  if (stt.provider !== "groq") {
    stt.provider = "groq";
    stt.model = defaults.stt.model;
    stt.apiKeyEnc = null;
  }
  return {
    ...defaults,
    ...settings,
    llm: { ...defaults.llm, ...(settings.llm || {}) },
    stt,
    email: { ...defaults.email, ...(settings.email || {}) }
  };
}

class JsonStorage {
  constructor(dbPath) {
    this.dbPath = dbPath;
  }

  async init() {
    this.ensureDb();
  }

  ensureDb() {
    if (!fs.existsSync(path.dirname(this.dbPath))) fs.mkdirSync(path.dirname(this.dbPath), { recursive: true });
    if (!fs.existsSync(this.dbPath)) this.write(defaultDb());
  }

  read() {
    this.ensureDb();
    return normalizeDb(JSON.parse(fs.readFileSync(this.dbPath, "utf8")));
  }

  write(db) {
    if (!fs.existsSync(path.dirname(this.dbPath))) fs.mkdirSync(path.dirname(this.dbPath), { recursive: true });
    fs.writeFileSync(this.dbPath, JSON.stringify(db, null, 2));
  }

  async getSettings() {
    return this.read().settings;
  }

  async healthCheck() {
    this.read();
  }

  async updateSettings(settings) {
    const db = this.read();
    db.settings = normalizeSettings(settings);
    this.write(db);
    return db.settings;
  }

  async replaceAuthCodeForEmail(email, authCode, now) {
    const db = this.read();
    db.authCodes = db.authCodes.filter((item) => item.email !== email && item.expiresAt > now);
    db.authCodes.push(authCode);
    this.write(db);
  }

  async listActiveAuthCodes(email, now) {
    return this.read().authCodes.filter((item) => item.email === email && item.expiresAt > now);
  }

  async removeAuthCode(id) {
    const db = this.read();
    db.authCodes = db.authCodes.filter((item) => item.id !== id);
    this.write(db);
  }

  async getRateLimit(key, now) {
    const item = this.read().rateLimits.find((rateLimit) => rateLimit.key === key);
    if (!item) return { key, count: 0, windowStart: now, lockedUntil: 0 };
    return normalizeRateLimit(item, now);
  }

  async saveRateLimit(rateLimit) {
    const db = this.read();
    db.rateLimits = db.rateLimits.filter((item) => item.key !== rateLimit.key);
    db.rateLimits.push(rateLimit);
    this.write(db);
  }

  async clearRateLimit(key) {
    const db = this.read();
    db.rateLimits = db.rateLimits.filter((item) => item.key !== key);
    this.write(db);
  }

  async consumeAuthCodeAndCreateSession({ email, authCodeId, tokenHash, expiresAt }) {
    const db = this.read();
    const user = findOrCreateUser(db, email);
    user.lastLoginAt = new Date().toISOString();
    db.authCodes = db.authCodes.filter((item) => item.id !== authCodeId);
    db.sessions.push({
      id: crypto.randomUUID(),
      tokenHash,
      userId: user.id,
      role: "user",
      createdAt: new Date().toISOString(),
      expiresAt
    });
    this.write(db);
    return user;
  }

  async deleteSessionByTokenHash(tokenHash) {
    const db = this.read();
    db.sessions = db.sessions.filter((session) => session.tokenHash !== tokenHash);
    this.write(db);
  }

  async getUserBySessionTokenHash(tokenHash, now) {
    const db = this.read();
    const session = db.sessions.find((item) => item.tokenHash === tokenHash && item.expiresAt > now);
    if (!session) return { user: null, session: null };
    const user = db.users.find((item) => item.id === session.userId);
    return { user: user || null, session };
  }

  async createHistory(history) {
    const db = this.read();
    db.histories.unshift(history);
    this.write(db);
  }

  async listUserHistory(userId) {
    return this.read().histories.filter((item) => item.userId === userId).slice(0, 100);
  }

  async deleteUserHistory(userId, id) {
    const db = this.read();
    db.histories = db.histories.filter((item) => !(item.id === id && item.userId === userId));
    this.write(db);
  }

  async createAdminSession({ tokenHash, expiresAt }) {
    const db = this.read();
    db.adminSessions.push({
      id: crypto.randomUUID(),
      tokenHash,
      createdAt: new Date().toISOString(),
      expiresAt
    });
    this.write(db);
  }

  async deleteAdminSessionByTokenHash(tokenHash) {
    const db = this.read();
    db.adminSessions = db.adminSessions.filter((session) => session.tokenHash !== tokenHash);
    this.write(db);
  }

  async getAdminSessionByTokenHash(tokenHash, now) {
    return this.read().adminSessions.find((item) => item.tokenHash === tokenHash && item.expiresAt > now) || null;
  }

  async listAdminUsers() {
    const db = this.read();
    return db.users.map((user) => ({
      ...publicUserRecord(user),
      historyCount: db.histories.filter((item) => item.userId === user.id).length
    }));
  }

  async deleteAdminUser(id) {
    const db = this.read();
    db.users = db.users.filter((user) => user.id !== id);
    db.histories = db.histories.filter((item) => item.userId !== id);
    db.sessions = db.sessions.filter((item) => item.userId !== id);
    this.write(db);
  }

  async listAdminHistories() {
    const db = this.read();
    return db.histories.slice(0, 250).map((item) => ({
      ...item,
      userEmail: db.users.find((user) => user.id === item.userId)?.email || "deleted"
    }));
  }

  async deleteAdminHistory(id) {
    const db = this.read();
    db.histories = db.histories.filter((item) => item.id !== id);
    this.write(db);
  }
}

class PostgresStorage {
  constructor(databaseUrl) {
    const { Pool } = require("pg");
    this.pool = new Pool({
      connectionString: databaseUrl,
      ssl: shouldUseSsl(databaseUrl) ? { rejectUnauthorized: false } : false
    });
  }

  async init() {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS settings (
        id integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
        data jsonb NOT NULL,
        updated_at timestamptz
      );

      CREATE TABLE IF NOT EXISTS users (
        id uuid PRIMARY KEY,
        email text UNIQUE NOT NULL,
        created_at timestamptz NOT NULL,
        last_login_at timestamptz
      );

      CREATE TABLE IF NOT EXISTS histories (
        id uuid PRIMARY KEY,
        user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        database_style text NOT NULL,
        transcript text NOT NULL,
        extra_instructions text NOT NULL DEFAULT '',
        sql text NOT NULL,
        created_at timestamptz NOT NULL
      );

      CREATE TABLE IF NOT EXISTS sessions (
        id uuid PRIMARY KEY,
        token_hash text UNIQUE NOT NULL,
        user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role text NOT NULL DEFAULT 'user',
        created_at timestamptz NOT NULL,
        expires_at bigint NOT NULL
      );

      CREATE TABLE IF NOT EXISTS admin_sessions (
        id uuid PRIMARY KEY,
        token_hash text UNIQUE NOT NULL,
        created_at timestamptz NOT NULL,
        expires_at bigint NOT NULL
      );

      CREATE TABLE IF NOT EXISTS auth_codes (
        id uuid PRIMARY KEY,
        email text NOT NULL,
        code_hash text NOT NULL,
        created_at timestamptz NOT NULL,
        expires_at bigint NOT NULL
      );

      CREATE TABLE IF NOT EXISTS rate_limits (
        key text PRIMARY KEY,
        count integer NOT NULL,
        window_start bigint NOT NULL,
        locked_until bigint NOT NULL DEFAULT 0
      );

      CREATE INDEX IF NOT EXISTS histories_user_created_idx ON histories(user_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS auth_codes_email_expires_idx ON auth_codes(email, expires_at);
      CREATE INDEX IF NOT EXISTS sessions_token_idx ON sessions(token_hash);
      CREATE INDEX IF NOT EXISTS admin_sessions_token_idx ON admin_sessions(token_hash);
    `);
    await this.pool.query(
      `INSERT INTO settings (id, data, updated_at)
       VALUES (1, $1::jsonb, NULL)
       ON CONFLICT (id) DO NOTHING`,
      [JSON.stringify(defaultSettings())]
    );
  }

  async getSettings() {
    const result = await this.pool.query("SELECT data FROM settings WHERE id = 1");
    return normalizeSettings(result.rows[0]?.data || {});
  }

  async healthCheck() {
    await this.pool.query("SELECT 1");
  }

  async updateSettings(settings) {
    const normalized = normalizeSettings(settings);
    await this.pool.query(
      `INSERT INTO settings (id, data, updated_at)
       VALUES (1, $1::jsonb, now())
       ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`,
      [JSON.stringify(normalized)]
    );
    return normalized;
  }

  async replaceAuthCodeForEmail(email, authCode, now) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("DELETE FROM auth_codes WHERE email = $1 OR expires_at <= $2", [email, now]);
      await client.query(
        `INSERT INTO auth_codes (id, email, code_hash, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5)`,
        [authCode.id, authCode.email, authCode.codeHash, authCode.createdAt, authCode.expiresAt]
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async listActiveAuthCodes(email, now) {
    const result = await this.pool.query(
      "SELECT id, email, code_hash, created_at, expires_at FROM auth_codes WHERE email = $1 AND expires_at > $2",
      [email, now]
    );
    return result.rows.map(mapAuthCode);
  }

  async removeAuthCode(id) {
    await this.pool.query("DELETE FROM auth_codes WHERE id = $1", [id]);
  }

  async getRateLimit(key, now) {
    const result = await this.pool.query("SELECT key, count, window_start, locked_until FROM rate_limits WHERE key = $1", [key]);
    if (!result.rows.length) return { key, count: 0, windowStart: now, lockedUntil: 0 };
    return normalizeRateLimit(result.rows[0], now);
  }

  async saveRateLimit(rateLimit) {
    await this.pool.query(
      `INSERT INTO rate_limits (key, count, window_start, locked_until)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (key) DO UPDATE SET
         count = EXCLUDED.count,
         window_start = EXCLUDED.window_start,
         locked_until = EXCLUDED.locked_until`,
      [rateLimit.key, rateLimit.count, rateLimit.windowStart, rateLimit.lockedUntil]
    );
  }

  async clearRateLimit(key) {
    await this.pool.query("DELETE FROM rate_limits WHERE key = $1", [key]);
  }

  async consumeAuthCodeAndCreateSession({ email, authCodeId, tokenHash, expiresAt }) {
    const client = await this.pool.connect();
    const now = new Date();
    try {
      await client.query("BEGIN");
      await client.query("DELETE FROM auth_codes WHERE id = $1", [authCodeId]);
      const userResult = await client.query(
        `INSERT INTO users (id, email, created_at, last_login_at)
         VALUES ($1, $2, $3, $3)
         ON CONFLICT (email) DO UPDATE SET last_login_at = EXCLUDED.last_login_at
         RETURNING id, email, created_at, last_login_at`,
        [crypto.randomUUID(), email, now.toISOString()]
      );
      const user = mapUser(userResult.rows[0]);
      await client.query(
        `INSERT INTO sessions (id, token_hash, user_id, role, created_at, expires_at)
         VALUES ($1, $2, $3, 'user', $4, $5)`,
        [crypto.randomUUID(), tokenHash, user.id, now.toISOString(), expiresAt]
      );
      await client.query("COMMIT");
      return user;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async deleteSessionByTokenHash(tokenHash) {
    await this.pool.query("DELETE FROM sessions WHERE token_hash = $1", [tokenHash]);
  }

  async getUserBySessionTokenHash(tokenHash, now) {
    const result = await this.pool.query(
      `SELECT s.id AS session_id, s.token_hash, s.user_id, s.role, s.created_at AS session_created_at, s.expires_at,
              u.id, u.email, u.created_at, u.last_login_at
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = $1 AND s.expires_at > $2`,
      [tokenHash, now]
    );
    if (!result.rows.length) return { user: null, session: null };
    const row = result.rows[0];
    return {
      user: mapUser(row),
      session: {
        id: row.session_id,
        tokenHash: row.token_hash,
        userId: row.user_id,
        role: row.role,
        createdAt: toIso(row.session_created_at),
        expiresAt: Number(row.expires_at)
      }
    };
  }

  async createHistory(history) {
    await this.pool.query(
      `INSERT INTO histories (id, user_id, database_style, transcript, extra_instructions, sql, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        history.id,
        history.userId,
        history.databaseStyle,
        history.transcript,
        history.extraInstructions,
        history.sql,
        history.createdAt
      ]
    );
  }

  async listUserHistory(userId) {
    const result = await this.pool.query(
      `SELECT * FROM histories WHERE user_id = $1 ORDER BY created_at DESC LIMIT 100`,
      [userId]
    );
    return result.rows.map(mapHistory);
  }

  async deleteUserHistory(userId, id) {
    await this.pool.query("DELETE FROM histories WHERE id = $1 AND user_id = $2", [id, userId]);
  }

  async createAdminSession({ tokenHash, expiresAt }) {
    await this.pool.query(
      `INSERT INTO admin_sessions (id, token_hash, created_at, expires_at) VALUES ($1, $2, $3, $4)`,
      [crypto.randomUUID(), tokenHash, new Date().toISOString(), expiresAt]
    );
  }

  async deleteAdminSessionByTokenHash(tokenHash) {
    await this.pool.query("DELETE FROM admin_sessions WHERE token_hash = $1", [tokenHash]);
  }

  async getAdminSessionByTokenHash(tokenHash, now) {
    const result = await this.pool.query(
      "SELECT id, token_hash, created_at, expires_at FROM admin_sessions WHERE token_hash = $1 AND expires_at > $2",
      [tokenHash, now]
    );
    if (!result.rows.length) return null;
    const row = result.rows[0];
    return {
      id: row.id,
      tokenHash: row.token_hash,
      createdAt: toIso(row.created_at),
      expiresAt: Number(row.expires_at)
    };
  }

  async listAdminUsers() {
    const result = await this.pool.query(
      `SELECT u.id, u.email, u.created_at, u.last_login_at, COUNT(h.id)::int AS history_count
       FROM users u
       LEFT JOIN histories h ON h.user_id = u.id
       GROUP BY u.id
       ORDER BY u.created_at DESC`
    );
    return result.rows.map((row) => ({ ...mapUser(row), historyCount: row.history_count }));
  }

  async deleteAdminUser(id) {
    await this.pool.query("DELETE FROM users WHERE id = $1", [id]);
  }

  async listAdminHistories() {
    const result = await this.pool.query(
      `SELECT h.*, COALESCE(u.email, 'deleted') AS user_email
       FROM histories h
       LEFT JOIN users u ON u.id = h.user_id
       ORDER BY h.created_at DESC
       LIMIT 250`
    );
    return result.rows.map((row) => ({ ...mapHistory(row), userEmail: row.user_email }));
  }

  async deleteAdminHistory(id) {
    await this.pool.query("DELETE FROM histories WHERE id = $1", [id]);
  }
}

function findOrCreateUser(db, email) {
  let user = db.users.find((item) => item.email === email);
  if (!user) {
    user = {
      id: crypto.randomUUID(),
      email,
      createdAt: new Date().toISOString(),
      lastLoginAt: null
    };
    db.users.push(user);
  }
  return user;
}

function publicUserRecord(user) {
  return {
    id: user.id,
    email: user.email,
    createdAt: user.createdAt,
    lastLoginAt: user.lastLoginAt
  };
}

function mapUser(row) {
  return {
    id: row.id,
    email: row.email,
    createdAt: toIso(row.created_at),
    lastLoginAt: row.last_login_at ? toIso(row.last_login_at) : null
  };
}

function mapHistory(row) {
  return {
    id: row.id,
    userId: row.user_id,
    databaseStyle: row.database_style,
    transcript: row.transcript,
    extraInstructions: row.extra_instructions || "",
    sql: row.sql,
    createdAt: toIso(row.created_at)
  };
}

function mapAuthCode(row) {
  return {
    id: row.id,
    email: row.email,
    codeHash: row.code_hash,
    createdAt: toIso(row.created_at),
    expiresAt: Number(row.expires_at)
  };
}

function normalizeRateLimit(item, now) {
  return {
    key: item.key,
    count: Number(item.count || 0),
    windowStart: Number(item.windowStart ?? item.window_start ?? now),
    lockedUntil: Number(item.lockedUntil ?? item.locked_until ?? 0)
  };
}

function toIso(value) {
  if (!value) return null;
  if (value instanceof Date) return value.toISOString();
  return new Date(value).toISOString();
}

function shouldUseSsl(databaseUrl) {
  const value = String(databaseUrl || "");
  if (/sslmode=(disable|prefer)/i.test(value)) return false;
  if (/sslmode=require/i.test(value)) return true;
  try {
    const url = new URL(value);
    return !["localhost", "127.0.0.1", "::1", "host.docker.internal"].includes(url.hostname);
  } catch {
    return value.includes("render.com");
  }
}

module.exports = {
  createStorage,
  defaultSettings,
  normalizeSettings
};
