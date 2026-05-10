const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const net = require("net");
const tls = require("tls");
const { URL } = require("url");
const { createStorage } = require("./storage");

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, "public");
const PORT = Number(process.env.PORT || 4173);
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const SECRET = process.env.TALKSYQL_SECRET || (IS_PRODUCTION ? "" : "talksyql-dev-secret-change-me");
const ADMIN_EMAIL = normalizeEmail(process.env.TALKSYQL_ADMIN_EMAIL || "admin@talksyql.local");
const ADMIN_PASSWORD = process.env.TALKSYQL_ADMIN_PASSWORD || "change-me-now";
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 14;
const CODE_TTL_MS = 1000 * 60 * 10;
const MAX_JSON_BYTES = 32 * 1024 * 1024;
const OTP_REQUEST_LIMIT = { limit: 3, windowMs: 15 * 60 * 1000, lockoutMs: 15 * 60 * 1000 };
const OTP_VERIFY_LIMIT = { limit: 5, windowMs: 10 * 60 * 1000, lockoutMs: 10 * 60 * 1000, lockOnLimitReached: true };
const ADMIN_LOGIN_LIMIT = { limit: 5, windowMs: 15 * 60 * 1000, lockoutMs: 15 * 60 * 1000, lockOnLimitReached: true };
const FREE_AI_LIMIT = { limit: 3, windowMs: 60 * 1000, lockoutMs: 5 * 60 * 1000 };

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon"
};

validateStartupConfig();
const storage = createStorage({ databaseUrl: process.env.DATABASE_URL });

const server = http.createServer(async (req, res) => {
  try {
    applySecurityHeaders(res);
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

    if (url.pathname.startsWith("/api/")) {
      await routeApi(req, res, url);
      return;
    }

    await serveStatic(req, res, url);
  } catch (error) {
    if (error.status) {
      sendJson(res, error.status, { error: error.message });
      return;
    }
    console.error(error);
    sendJson(res, 500, { error: "Unexpected server error." });
  }
});

startServer().catch((error) => {
  console.error(error);
  process.exit(1);
});

async function startServer() {
  await storage.init();
  server.listen(PORT, "0.0.0.0", () => {
    console.log(`talksyql running at http://localhost:${PORT}`);
    if (!IS_PRODUCTION && (!process.env.TALKSYQL_ADMIN_EMAIL || !process.env.TALKSYQL_ADMIN_PASSWORD)) {
      console.log("Local admin: admin@talksyql.local / change-me-now");
    }
  });
}

async function routeApi(req, res, url) {
  const route = `${req.method} ${url.pathname}`;

  if (route === "GET /api/health") {
    await storage.healthCheck();
    sendJson(res, 200, { ok: true, name: "talksyql" });
    return;
  }

  if (route === "GET /api/me") {
    const { user } = await getUserFromRequest(req);
    sendJson(res, 200, { user: user ? publicUser(user) : null });
    return;
  }

  if (route === "GET /api/provider-status") {
    const settings = await storage.getSettings();
    sendJson(res, 200, { settings: publicSettings(settings) });
    return;
  }

  if (route === "POST /api/auth/request") {
    const body = await readJson(req);
    const email = normalizeEmail(body.email);
    if (!isValidEmail(email)) {
      sendJson(res, 400, { error: "Enter a valid email address." });
      return;
    }
    const settings = await storage.getSettings();
    const code = createCode();
    const codeHash = hashValue(code);
    const now = Date.now();
    if (!isEmailConfigured(settings.email)) {
      sendJson(res, 409, { error: "Email delivery is not configured. Admin can add SMTP settings." });
      return;
    }
    const requestLimit = await consumeRateLimit(`otp-request:${email}:${clientIp(req)}`, OTP_REQUEST_LIMIT);
    if (!requestLimit.allowed) {
      sendRateLimit(res, requestLimit, "Too many login-code requests. Please wait before requesting another OTP.");
      return;
    }

    const authCode = {
      id: crypto.randomUUID(),
      email,
      codeHash,
      expiresAt: now + CODE_TTL_MS,
      createdAt: new Date(now).toISOString()
    };
    await storage.replaceAuthCodeForEmail(email, authCode, now);

    try {
      await sendOtpEmail(settings.email, email, code);
    } catch (error) {
      await storage.removeAuthCode(authCode.id);
      throwStatus(502, `Email delivery failed: ${error.message}`);
    }

    sendJson(res, 200, {
      ok: true,
      email,
      message: "Login code sent."
    });
    return;
  }

  if (route === "POST /api/auth/verify") {
    const body = await readJson(req);
    const email = normalizeEmail(body.email);
    const code = String(body.code || "").replace(/\D/g, "");
    const now = Date.now();
    const verifyLimitKey = `otp-verify:${email}:${clientIp(req)}`;
    const verifyLock = await getRateLimitLock(verifyLimitKey);
    if (verifyLock.locked) {
      sendRateLimit(res, verifyLock, "Too many incorrect OTP attempts. Please wait before trying again.");
      return;
    }
    const authCodes = await storage.listActiveAuthCodes(email, now);
    const authCode = authCodes.find(
      (item) => item.email === email && item.expiresAt > now && timingSafeEqual(item.codeHash, hashValue(code))
    );

    if (!authCode) {
      const failedAttempt = await consumeRateLimit(verifyLimitKey, OTP_VERIFY_LIMIT);
      if (!failedAttempt.allowed) {
        sendRateLimit(res, failedAttempt, "Too many incorrect OTP attempts. Please wait before trying again.");
        return;
      }
      sendJson(res, 401, { error: "Invalid or expired login code." });
      return;
    }
    await clearRateLimit(verifyLimitKey);

    const token = crypto.randomBytes(32).toString("hex");
    const user = await storage.consumeAuthCodeAndCreateSession({
      email,
      authCodeId: authCode.id,
      tokenHash: hashValue(token),
      expiresAt: now + SESSION_TTL_MS
    });

    setCookie(res, "talksyql_session", token, { maxAge: SESSION_TTL_MS / 1000 });
    sendJson(res, 200, { ok: true, user: publicUser(user) });
    return;
  }

  if (route === "POST /api/auth/logout") {
    const token = getCookie(req, "talksyql_session");
    if (token) {
      await storage.deleteSessionByTokenHash(hashValue(token));
    }
    clearCookie(res, "talksyql_session");
    sendJson(res, 200, { ok: true });
    return;
  }

  if (route === "POST /api/transcribe") {
    const { user } = await getUserFromRequest(req);
    const limit = await consumeRateLimit(`transcribe:${actorKey(req, user)}`, FREE_AI_LIMIT);
    if (!limit.allowed) {
      sendRateLimit(res, limit, "Free transcribe limit reached: 3 requests per minute. Please wait 5 minutes. Future upgrades may include BYOK and premium tiers.");
      return;
    }
    const body = await readJson(req);
    const text = await transcribeAudio(body);
    sendJson(res, 200, { text });
    return;
  }

  if (route === "POST /api/generate-sql") {
    const body = await readJson(req);
    const { user } = await getUserFromRequest(req);
    const limit = await consumeRateLimit(`generate-sql:${actorKey(req, user)}`, FREE_AI_LIMIT);
    if (!limit.allowed) {
      sendRateLimit(res, limit, "Free SQL generation limit reached: 3 requests per minute. Please wait 5 minutes. Future upgrades may include BYOK and premium tiers.");
      return;
    }
    const result = await generateSql(body);

    if (user) {
      await storage.createHistory({
        id: crypto.randomUUID(),
        userId: user.id,
        databaseStyle: result.databaseStyle,
        transcript: result.transcript,
        extraInstructions: result.extraInstructions,
        sql: result.sql,
        createdAt: new Date().toISOString()
      });
    }

    sendJson(res, 200, { ...result, stored: Boolean(user) });
    return;
  }

  if (route === "GET /api/history") {
    const auth = await requireUser(req, res);
    if (!auth) return;
    const items = await storage.listUserHistory(auth.user.id);
    sendJson(res, 200, { items });
    return;
  }

  if (route === "DELETE /api/history") {
    const auth = await requireUser(req, res);
    if (!auth) return;
    const id = url.searchParams.get("id");
    await storage.deleteUserHistory(auth.user.id, id);
    sendJson(res, 200, { ok: true });
    return;
  }

  if (route === "POST /api/admin/login") {
    const body = await readJson(req);
    const email = normalizeEmail(body.email);
    const password = String(body.password || "");
    const adminLimitKey = `admin-login:${email || "unknown"}:${clientIp(req)}`;
    const adminLock = await getRateLimitLock(adminLimitKey);
    if (adminLock.locked) {
      sendRateLimit(res, adminLock, "Too many incorrect admin login attempts. Please wait before trying again.");
      return;
    }
    if (email !== ADMIN_EMAIL || !timingSafeEqual(hashValue(password), hashValue(ADMIN_PASSWORD))) {
      const failedAttempt = await consumeRateLimit(adminLimitKey, ADMIN_LOGIN_LIMIT);
      if (!failedAttempt.allowed) {
        sendRateLimit(res, failedAttempt, "Too many incorrect admin login attempts. Please wait before trying again.");
        return;
      }
      sendJson(res, 401, { error: "Invalid admin credentials." });
      return;
    }
    await clearRateLimit(adminLimitKey);

    const token = crypto.randomBytes(32).toString("hex");
    await storage.createAdminSession({
      tokenHash: hashValue(token),
      expiresAt: Date.now() + SESSION_TTL_MS
    });

    setCookie(res, "talksyql_admin", token, { maxAge: SESSION_TTL_MS / 1000 });
    sendJson(res, 200, { ok: true, admin: { email: ADMIN_EMAIL } });
    return;
  }

  if (route === "POST /api/admin/logout") {
    const token = getCookie(req, "talksyql_admin");
    if (token) {
      await storage.deleteAdminSessionByTokenHash(hashValue(token));
    }
    clearCookie(res, "talksyql_admin");
    sendJson(res, 200, { ok: true });
    return;
  }

  if (route === "GET /api/admin/me") {
    if (!(await getAdminFromRequest(req))) {
      sendJson(res, 200, { admin: null });
      return;
    }
    sendJson(res, 200, { admin: { email: ADMIN_EMAIL } });
    return;
  }

  if (route === "GET /api/admin/settings") {
    if (!(await requireAdmin(req, res))) return;
    const settings = await storage.getSettings();
    sendJson(res, 200, { settings: publicSettings(settings) });
    return;
  }

  if (route === "PUT /api/admin/settings") {
    if (!(await requireAdmin(req, res))) return;
    const body = await readJson(req);
    const settings = await storage.getSettings();

    settings.llm.provider = "gemini";
    settings.llm.model = safeModelName(body.llmModel || settings.llm.model || "gemini-3.1-flash-lite-preview");
    if (typeof body.llmApiKey === "string" && body.llmApiKey.trim()) {
      settings.llm.apiKeyEnc = encrypt(body.llmApiKey.trim());
    }

    settings.stt.provider = "groq";
    settings.stt.model = safeModelName(body.sttModel || settings.stt.model || "whisper-large-v3-turbo");
    if (typeof body.sttApiKey === "string" && body.sttApiKey.trim()) {
      settings.stt.apiKeyEnc = encrypt(body.sttApiKey.trim());
    }

    settings.email.host = String(body.smtpHost || settings.email.host || "").trim();
    settings.email.port = normalizePort(body.smtpPort || settings.email.port || 587);
    settings.email.secure = normalizeBoolean(body.smtpSecure);
    settings.email.fromEmail = normalizeEmail(body.smtpFromEmail || settings.email.fromEmail || "");
    settings.email.fromName = String(body.smtpFromName || settings.email.fromName || "talksyql").trim().slice(0, 80);
    settings.email.username = String(body.smtpUsername || settings.email.username || "").trim();
    if (typeof body.smtpPassword === "string" && body.smtpPassword.trim()) {
      settings.email.passwordEnc = encrypt(body.smtpPassword.trim());
    }

    settings.updatedAt = new Date().toISOString();
    const updatedSettings = await storage.updateSettings(settings);
    sendJson(res, 200, { ok: true, settings: publicSettings(updatedSettings) });
    return;
  }

  if (route === "GET /api/admin/users") {
    if (!(await requireAdmin(req, res))) return;
    const users = await storage.listAdminUsers();
    sendJson(res, 200, { users });
    return;
  }

  if (route === "DELETE /api/admin/users") {
    if (!(await requireAdmin(req, res))) return;
    const id = url.searchParams.get("id");
    await storage.deleteAdminUser(id);
    sendJson(res, 200, { ok: true });
    return;
  }

  if (route === "GET /api/admin/histories") {
    if (!(await requireAdmin(req, res))) return;
    const items = await storage.listAdminHistories();
    sendJson(res, 200, { items });
    return;
  }

  if (route === "DELETE /api/admin/histories") {
    if (!(await requireAdmin(req, res))) return;
    const id = url.searchParams.get("id");
    await storage.deleteAdminHistory(id);
    sendJson(res, 200, { ok: true });
    return;
  }

  sendJson(res, 404, { error: "Route not found." });
}

async function transcribeAudio(body) {
  const audioBase64 = String(body.audioBase64 || "").replace(/^data:[^;]+;base64,/, "");
  const mimeType = String(body.mimeType || "audio/webm").slice(0, 80);
  const fileName = String(body.fileName || "talksyql-audio.webm").replace(/[^\w.-]/g, "_");
  if (!audioBase64) {
    throwStatus(400, "Record or upload audio first.");
  }

  const settings = await storage.getSettings();
  const apiKey = decrypt(settings.stt.apiKeyEnc);
  if (!apiKey) {
    throwStatus(409, "Groq API key is not configured. Admin can add it in Provider Settings.");
  }

  const bytes = Buffer.from(audioBase64, "base64");
  if (bytes.length > 25 * 1024 * 1024) {
    throwStatus(413, "Audio file is too large for Groq free-tier transcription. Keep uploads under 25 MB.");
  }

  const form = new FormData();
  form.append("model", settings.stt.model || "whisper-large-v3-turbo");
  form.append("response_format", "json");
  form.append("temperature", "0");
  form.append("file", new Blob([bytes], { type: mimeType }), fileName);

  const response = await fetch("https://api.groq.com/openai/v1/audio/transcriptions", {
    method: "POST",
    headers: { Authorization: `Bearer ${apiKey}` },
    body: form
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throwStatus(response.status, payload.error?.message || payload.message || "Groq transcription failed.");
  }

  const text = String(payload.text || "").trim();
  if (!text) {
    throwStatus(502, "Groq returned an empty transcript.");
  }
  return text;
}

async function generateSql(body) {
  const transcript = normalizeMultiline(body.transcript);
  const extraInstructions = normalizeMultiline(body.extraInstructions || "");
  const databaseStyle = normalizeDatabaseStyle(body.databaseStyle);

  if (!transcript) {
    throwStatus(400, "Provide a transcript or typed request before generating SQL.");
  }

  const settings = await storage.getSettings();
  const apiKey = decrypt(settings.llm.apiKeyEnc);
  if (!apiKey) {
    throwStatus(409, "Gemini API key is not configured. Admin can add it in Provider Settings.");
  }

  const model = settings.llm.model || "gemini-3.1-flash-lite-preview";
  const prompt = buildSqlPrompt({ transcript, extraInstructions, databaseStyle });
  const response = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": apiKey
      },
      body: JSON.stringify({
        systemInstruction: {
          parts: [
            {
              text: "You are talksyql, an expert SQL query generator. Return only executable SQL for the requested database dialect unless comments are necessary to prevent dangerous ambiguity."
            }
          ]
        },
        contents: [{ role: "user", parts: [{ text: prompt }] }],
        generationConfig: {
          temperature: 0.1,
          topP: 0.9
        }
      })
    }
  );

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throwStatus(response.status, payload.error?.message || "Gemini SQL generation failed.");
  }

  const sql = extractGeminiText(payload);
  if (!sql) {
    throwStatus(502, "Gemini returned an empty SQL response.");
  }

  return { transcript, extraInstructions, databaseStyle, sql: cleanSql(sql) };
}

async function sendOtpEmail(emailSettings, recipientEmail, code) {
  const password = decrypt(emailSettings.passwordEnc);
  const fromEmail = normalizeEmail(emailSettings.fromEmail);
  const username = String(emailSettings.username || "").trim();
  if (!isEmailConfigured(emailSettings)) {
    throw new Error("SMTP settings are incomplete.");
  }

  const subject = "Your talksyql login code";
  const text = [
    `Your talksyql login code is ${code}.`,
    "",
    "This code expires in 10 minutes.",
    "If you did not request this code, you can ignore this email."
  ].join("\n");

  const html = [
    "<!doctype html>",
    '<html><body style="margin:0;padding:24px;background:#080a12;color:#f5f8ff;font-family:Arial,sans-serif">',
    '<div style="max-width:520px;margin:0 auto;border:1px solid #283047;border-radius:8px;padding:24px;background:#101426">',
    '<p style="color:#64ff9f;text-transform:uppercase;letter-spacing:2px;font-size:12px;font-weight:700;margin:0 0 12px">talksyql</p>',
    '<h1 style="font-size:24px;margin:0 0 16px">Your login code</h1>',
    `<p style="font-size:34px;letter-spacing:8px;font-weight:800;margin:0 0 16px">${escapeHtml(code)}</p>`,
    '<p style="color:#a9b3c7;line-height:1.5;margin:0">This code expires in 10 minutes. If you did not request it, you can ignore this email.</p>',
    "</div></body></html>"
  ].join("");

  await sendSmtpMail({
    host: emailSettings.host,
    port: emailSettings.port,
    secure: Boolean(emailSettings.secure),
    username,
    password,
    fromEmail,
    fromName: emailSettings.fromName || "talksyql",
    toEmail: recipientEmail,
    subject,
    text,
    html
  });
}

async function sendSmtpMail(options) {
  const session = new SmtpSession(options);
  await session.connect();
  try {
    await session.greet();
    if (!options.secure && session.capabilities.has("STARTTLS")) {
      await session.command("STARTTLS", 220);
      await session.upgradeToTls();
      await session.greet();
    }
    if (options.username || options.password) {
      await session.authLogin(options.username, options.password);
    }
    await session.command(`MAIL FROM:<${options.fromEmail}>`, 250);
    await session.command(`RCPT TO:<${options.toEmail}>`, [250, 251]);
    await session.command("DATA", 354);
    await session.writeData(buildEmailMessage(options));
    await session.read([250]);
    await session.command("QUIT", 221).catch(() => {});
  } finally {
    session.close();
  }
}

class SmtpSession {
  constructor(options) {
    this.options = options;
    this.socket = null;
    this.buffer = "";
    this.waiters = [];
    this.capabilities = new Set();
  }

  connect() {
    return new Promise((resolve, reject) => {
      const onConnect = () => this.read([220]).then(resolve, reject);
      const socketOptions = {
        host: this.options.host,
        port: this.options.port,
        servername: this.options.host,
        timeout: 15000
      };
      this.socket = this.options.secure ? tls.connect(socketOptions, onConnect) : net.connect(socketOptions, onConnect);
      this.socket.setEncoding("utf8");
      this.socket.on("data", (chunk) => this.onData(chunk));
      this.socket.on("error", reject);
      this.socket.on("timeout", () => {
        reject(new Error("SMTP connection timed out."));
        this.close();
      });
    });
  }

  async greet() {
    const response = await this.command(`EHLO ${smtpDomain()}`, 250);
    this.capabilities = parseCapabilities(response.lines);
  }

  upgradeToTls() {
    return new Promise((resolve, reject) => {
      const oldSocket = this.socket;
      oldSocket.removeAllListeners("data");
      oldSocket.removeAllListeners("error");
      this.buffer = "";
      this.socket = tls.connect({
        socket: oldSocket,
        servername: this.options.host
      }, resolve);
      this.socket.setEncoding("utf8");
      this.socket.on("data", (chunk) => this.onData(chunk));
      this.socket.on("error", reject);
    });
  }

  async authLogin(username, password) {
    await this.command("AUTH LOGIN", 334);
    await this.command(Buffer.from(username).toString("base64"), 334);
    await this.command(Buffer.from(password).toString("base64"), 235);
  }

  command(command, expectedCodes) {
    this.socket.write(`${command}\r\n`);
    return this.read(expectedCodes);
  }

  writeData(message) {
    const normalized = message.replace(/\r?\n/g, "\r\n").replace(/^\./gm, "..");
    this.socket.write(`${normalized}\r\n.\r\n`);
  }

  read(expectedCodes) {
    const allowed = Array.isArray(expectedCodes) ? expectedCodes : [expectedCodes];
    return new Promise((resolve, reject) => {
      this.waiters.push({ allowed, resolve, reject });
      this.flush();
    });
  }

  onData(chunk) {
    this.buffer += chunk;
    this.flush();
  }

  flush() {
    if (!this.waiters.length) return;
    const parsed = parseSmtpResponse(this.buffer);
    if (!parsed) return;
    this.buffer = this.buffer.slice(parsed.length);
    const waiter = this.waiters.shift();
    if (waiter.allowed.includes(parsed.code)) {
      waiter.resolve(parsed);
      return;
    }
    waiter.reject(new Error(parsed.lines.join(" ")));
  }

  close() {
    if (this.socket) this.socket.destroy();
  }
}

function parseSmtpResponse(buffer) {
  const lines = buffer.split(/\r?\n/);
  let consumed = 0;
  const responseLines = [];
  for (const line of lines) {
    if (!line) break;
    consumed += line.length + (buffer.slice(consumed + line.length, consumed + line.length + 2) === "\r\n" ? 2 : 1);
    const match = /^(\d{3})([\s-])(.*)$/.exec(line);
    if (!match) continue;
    responseLines.push(match[3]);
    if (match[2] === " ") {
      return { code: Number(match[1]), lines: responseLines, length: consumed };
    }
  }
  return null;
}

function parseCapabilities(lines) {
  const caps = new Set();
  for (const line of lines) {
    const key = String(line).trim().split(/\s+/)[0]?.toUpperCase();
    if (key) caps.add(key);
  }
  return caps;
}

function buildEmailMessage(options) {
  const boundary = `talksyql-${crypto.randomBytes(12).toString("hex")}`;
  const headers = [
    `From: ${formatAddress(options.fromName, options.fromEmail)}`,
    `To: ${formatAddress("", options.toEmail)}`,
    `Subject: ${encodeHeader(options.subject)}`,
    "MIME-Version: 1.0",
    `Message-ID: <${crypto.randomUUID()}@talksyql.local>`,
    `Date: ${new Date().toUTCString()}`,
    `Content-Type: multipart/alternative; boundary="${boundary}"`
  ];

  return [
    ...headers,
    "",
    `--${boundary}`,
    'Content-Type: text/plain; charset="UTF-8"',
    "Content-Transfer-Encoding: 7bit",
    "",
    options.text,
    `--${boundary}`,
    'Content-Type: text/html; charset="UTF-8"',
    "Content-Transfer-Encoding: 7bit",
    "",
    options.html,
    `--${boundary}--`,
    ""
  ].join("\r\n");
}

function formatAddress(name, email) {
  const safeName = String(name || "").replace(/["\r\n]/g, "").trim();
  return safeName ? `"${safeName}" <${email}>` : `<${email}>`;
}

function encodeHeader(value) {
  return String(value || "").replace(/[\r\n]/g, " ");
}

function smtpDomain() {
  return "talksyql.local";
}

function buildSqlPrompt({ transcript, extraInstructions, databaseStyle }) {
  return [
    `Database dialect: ${databaseStyle}.`,
    "Create the best optimal SQL query for the user's request.",
    "Preserve intent from punctuation and wording.",
    "Use idiomatic syntax for the selected database.",
    "If table or column names are ambiguous, use readable placeholder identifiers and include a short SQL comment at the top naming the assumptions.",
    "Do not wrap the answer in Markdown fences.",
    "",
    "User request:",
    transcript,
    extraInstructions ? `\nAdditional instructions:\n${extraInstructions}` : ""
  ].join("\n");
}

function extractGeminiText(payload) {
  return String(
    payload.candidates?.[0]?.content?.parts
      ?.map((part) => part.text || "")
      .join("") || ""
  ).trim();
}

function cleanSql(sql) {
  return sql
    .replace(/^```sql\s*/i, "")
    .replace(/^```\s*/i, "")
    .replace(/```$/i, "")
    .trim();
}

async function serveStatic(req, res, url) {
  let requestedPath = decodeURIComponent(url.pathname);
  if (requestedPath === "/") requestedPath = "/index.html";
  const safePath = path.normalize(requestedPath).replace(/^(\.\.[/\\])+/, "");
  const filePath = path.join(PUBLIC_DIR, safePath);
  if (!filePath.startsWith(PUBLIC_DIR)) {
    sendText(res, 403, "Forbidden");
    return;
  }

  fs.readFile(filePath, (error, content) => {
    if (error) {
      fs.readFile(path.join(PUBLIC_DIR, "index.html"), (fallbackError, fallback) => {
        if (fallbackError) {
          sendText(res, 404, "Not found");
          return;
        }
        res.writeHead(200, { "Content-Type": MIME_TYPES[".html"] });
        res.end(fallback);
      });
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { "Content-Type": MIME_TYPES[ext] || "application/octet-stream" });
    res.end(content);
  });
}

async function getUserFromRequest(req) {
  const token = getCookie(req, "talksyql_session");
  if (!token) return { user: null, session: null };
  return storage.getUserBySessionTokenHash(hashValue(token), Date.now());
}

async function getAdminFromRequest(req) {
  const token = getCookie(req, "talksyql_admin");
  if (!token) return null;
  return storage.getAdminSessionByTokenHash(hashValue(token), Date.now());
}

async function requireUser(req, res) {
  const auth = await getUserFromRequest(req);
  if (!auth.user) {
    sendJson(res, 401, { error: "Login required." });
    return null;
  }
  return auth;
}

async function requireAdmin(req, res) {
  const admin = await getAdminFromRequest(req);
  if (!admin) {
    sendJson(res, 401, { error: "Admin login required." });
    return null;
  }
  return admin;
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    createdAt: user.createdAt,
    lastLoginAt: user.lastLoginAt
  };
}

function publicSettings(settings) {
  return {
    llm: {
      provider: "gemini",
      model: settings.llm.model,
      hasApiKey: Boolean(settings.llm.apiKeyEnc)
    },
    stt: {
      provider: "groq",
      model: settings.stt.model,
      hasApiKey: Boolean(settings.stt.apiKeyEnc)
    },
    email: {
      provider: "smtp",
      host: settings.email.host,
      port: settings.email.port,
      secure: Boolean(settings.email.secure),
      fromEmail: settings.email.fromEmail,
      fromName: settings.email.fromName,
      username: settings.email.username,
      hasPassword: Boolean(settings.email.passwordEnc),
      configured: isEmailConfigured(settings.email)
    },
    updatedAt: settings.updatedAt
  };
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk;
      if (Buffer.byteLength(raw) > MAX_JSON_BYTES) {
        reject(statusError(413, "Request body is too large."));
        req.destroy();
      }
    });
    req.on("end", () => {
      if (!raw) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(statusError(400, "Invalid JSON body."));
      }
    });
    req.on("error", reject);
  });
}

function sendJson(res, status, payload) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(payload));
}

function sendRateLimit(res, limit, message) {
  const retryAfterSeconds = Math.max(1, Math.ceil(limit.retryAfterMs / 1000));
  res.writeHead(429, {
    "Content-Type": "application/json; charset=utf-8",
    "Retry-After": String(retryAfterSeconds)
  });
  res.end(JSON.stringify({
    error: `${message} Try again in ${formatDuration(limit.retryAfterMs)}.`,
    retryAfterSeconds
  }));
}

function sendText(res, status, text) {
  res.writeHead(status, { "Content-Type": "text/plain; charset=utf-8" });
  res.end(text);
}

function statusError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function throwStatus(status, message) {
  throw statusError(status, message);
}

async function consumeRateLimit(rawKey, policy) {
  const now = Date.now();
  const key = rateLimitKey(rawKey);
  const current = await storage.getRateLimit(key, now);
  if (current.lockedUntil > now) {
    return { allowed: false, retryAfterMs: current.lockedUntil - now };
  }

  const windowExpired = now - current.windowStart >= policy.windowMs;
  const next = {
    key,
    count: windowExpired ? 1 : current.count + 1,
    windowStart: windowExpired ? now : current.windowStart,
    lockedUntil: 0
  };
  const shouldLock = policy.lockOnLimitReached ? next.count >= policy.limit : next.count > policy.limit;
  if (shouldLock) {
    next.lockedUntil = now + policy.lockoutMs;
    await storage.saveRateLimit(next);
    return { allowed: false, retryAfterMs: policy.lockoutMs };
  }

  await storage.saveRateLimit(next);
  const windowRetry = Math.max(1000, policy.windowMs - (now - next.windowStart));
  return { allowed: true, retryAfterMs: windowRetry };
}

async function getRateLimitLock(rawKey) {
  const now = Date.now();
  const current = await storage.getRateLimit(rateLimitKey(rawKey), now);
  return current.lockedUntil > now
    ? { locked: true, allowed: false, retryAfterMs: current.lockedUntil - now }
    : { locked: false, allowed: true, retryAfterMs: 0 };
}

async function clearRateLimit(rawKey) {
  await storage.clearRateLimit(rateLimitKey(rawKey));
}

function rateLimitKey(rawKey) {
  return `rl:${hashValue(rawKey)}`;
}

function actorKey(req, user) {
  return user ? `user:${user.id}` : `ip:${clientIp(req)}`;
}

function clientIp(req) {
  const forwarded = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return forwarded || req.socket.remoteAddress || "unknown";
}

function formatDuration(ms) {
  const seconds = Math.ceil(ms / 1000);
  if (seconds < 60) return `${seconds} second${seconds === 1 ? "" : "s"}`;
  const minutes = Math.ceil(seconds / 60);
  return `${minutes} minute${minutes === 1 ? "" : "s"}`;
}

function validateStartupConfig() {
  if (!IS_PRODUCTION) return;
  const missing = [];
  if (!process.env.DATABASE_URL) missing.push("DATABASE_URL");
  if (!process.env.TALKSYQL_SECRET) missing.push("TALKSYQL_SECRET");
  if (!process.env.TALKSYQL_ADMIN_EMAIL) missing.push("TALKSYQL_ADMIN_EMAIL");
  if (!process.env.TALKSYQL_ADMIN_PASSWORD) missing.push("TALKSYQL_ADMIN_PASSWORD");
  if (missing.length) {
    throw new Error(`Missing required production environment variables: ${missing.join(", ")}`);
  }
}

process.on("uncaughtException", (error) => {
  console.error(error);
});

process.on("unhandledRejection", (error) => {
  console.error(error);
});

function applySecurityHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(self)");
}

function setCookie(res, name, value, options = {}) {
  const maxAge = options.maxAge ? `; Max-Age=${Math.floor(options.maxAge)}` : "";
  res.setHeader("Set-Cookie", `${name}=${encodeURIComponent(value)}; HttpOnly; SameSite=Lax; Path=/${maxAge}`);
}

function clearCookie(res, name) {
  res.setHeader("Set-Cookie", `${name}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`);
}

function getCookie(req, name) {
  const cookie = req.headers.cookie || "";
  const found = cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`));
  return found ? decodeURIComponent(found.slice(name.length + 1)) : "";
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function createCode() {
  return String(crypto.randomInt(100000, 1000000));
}

function hashValue(value) {
  return crypto.createHmac("sha256", SECRET).update(String(value)).digest("hex");
}

function timingSafeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function encryptionKey() {
  return crypto.createHash("sha256").update(SECRET).digest();
}

function encrypt(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(String(value), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("base64")}.${tag.toString("base64")}.${encrypted.toString("base64")}`;
}

function decrypt(value) {
  if (!value) return "";
  try {
    const [ivRaw, tagRaw, encryptedRaw] = String(value).split(".");
    const decipher = crypto.createDecipheriv("aes-256-gcm", encryptionKey(), Buffer.from(ivRaw, "base64"));
    decipher.setAuthTag(Buffer.from(tagRaw, "base64"));
    return Buffer.concat([
      decipher.update(Buffer.from(encryptedRaw, "base64")),
      decipher.final()
    ]).toString("utf8");
  } catch {
    return "";
  }
}

function normalizeMultiline(value) {
  return String(value || "")
    .replace(/\r\n/g, "\n")
    .replace(/\n{4,}/g, "\n\n\n")
    .trim()
    .slice(0, 12000);
}

function safeModelName(value) {
  return String(value || "")
    .trim()
    .replace(/[^A-Za-z0-9_.:-]/g, "")
    .slice(0, 80);
}

function normalizePort(value) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return 587;
  return port;
}

function normalizeBoolean(value) {
  return value === true || value === "true" || value === "on" || value === "1";
}

function isEmailConfigured(emailSettings) {
  return Boolean(
    emailSettings &&
      String(emailSettings.host || "").trim() &&
      normalizePort(emailSettings.port) &&
      isValidEmail(emailSettings.fromEmail) &&
      String(emailSettings.username || "").trim() &&
      emailSettings.passwordEnc
  );
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function normalizeDatabaseStyle(value) {
  const allowed = new Set([
    "PostgreSQL",
    "MySQL",
    "SQL Server",
    "SQLite",
    "Oracle",
    "BigQuery",
    "Snowflake",
    "Redshift",
    "MariaDB",
    "DuckDB"
  ]);
  return allowed.has(value) ? value : "PostgreSQL";
}
