require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const path = require("node:path");
const fs = require("node:fs");

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const production = process.env.NODE_ENV === "production";
const secret = process.env.SESSION_SECRET || "";
if (production && secret.length < 32) {
  throw new Error("SESSION_SECRET must be at least 32 characters in production.");
}
if (!production && secret.length < 32) {
  console.warn("WARNING: Set a long SESSION_SECRET in .env before deployment.");
}

const dataDir = process.env.DATA_DIR || path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, "app.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, email TEXT NOT NULL, message TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

const normalizeEmail = (v) => String(v || "").trim().toLowerCase();
const validEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) && v.length <= 254;
const safeUser = (u) => ({ id: u.id, name: u.name, email: u.email, role: u.role, created_at: u.created_at });

async function createInitialAdmin() {
  const email = normalizeEmail(process.env.ADMIN_EMAIL);
  const password = process.env.ADMIN_PASSWORD || "";
  if (!email || !validEmail(email) || password.length < 12) {
    console.log("Admin bootstrap skipped. Set ADMIN_EMAIL and ADMIN_PASSWORD (12+ chars) in .env.");
    return;
  }
  const exists = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (!exists) {
    const hash = await bcrypt.hash(password, 12);
    db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'admin')")
      .run("Администратор", email, hash);
    console.log("Initial administrator account created.");
  }
}

app.disable("x-powered-by");
if (production) app.set("trust proxy", 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'"],
      imgSrc: ["'self'", "data:"], connectSrc: ["'self'"], objectSrc: ["'none'"],
      baseUri: ["'self'"], formAction: ["'self'"], frameAncestors: ["'none'"],
      upgradeInsecureRequests: production ? [] : null
    }
  },
  hsts: production ? { maxAge: 31536000, includeSubDomains: true } : false,
  referrerPolicy: { policy: "strict-origin-when-cross-origin" }
}));
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));
app.use(session({
  name: "itspace.sid",
  store: new SQLiteStore({ db: "sessions.sqlite", dir: dataDir, concurrentDB: true }),
  secret: secret || crypto.randomBytes(32).toString("hex"),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true, secure: production, sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 4
  }
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 10,
  standardHeaders: "draft-8", legacyHeaders: false,
  message: { error: "Слишком много попыток. Попробуйте через 15 минут." }
});
const contactLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 5,
  standardHeaders: "draft-8", legacyHeaders: false
});

// Synchronizer CSRF token. Forms send it in X-CSRF-Token.
app.get("/api/csrf", (req, res) => {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  res.json({ csrfToken: req.session.csrfToken });
});
app.use("/api", (req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const supplied = req.get("X-CSRF-Token");
  const expected = req.session.csrfToken;
  if (!supplied || !expected || supplied.length !== expected.length ||
      !crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected))) {
    return res.status(403).json({ error: "Проверка безопасности не пройдена. Обновите страницу." });
  }
  next();
});

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Сначала войдите в аккаунт." });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ error: "Доступ только для администратора." });
  }
  next();
}

app.post("/api/register", authLimiter, async (req, res, next) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    if (name.length < 2 || name.length > 80 || !validEmail(email) ||
        password.length < 10 || password.length > 72 ||
        !/[A-Za-zА-Яа-я]/.test(password) || !/[0-9]/.test(password)) {
      return res.status(400).json({ error: "Имя: 2–80 символов; корректный email; пароль: 10–72 символа, буквы и цифры." });
    }
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)")
      .run(name, email, hash);
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.user = { id: Number(result.lastInsertRowid), name, email, role: "user" };
      req.session.csrfToken = crypto.randomBytes(32).toString("hex");
      res.status(201).json({ user: req.session.user, csrfToken: req.session.csrfToken });
    });
  } catch (err) {
    if (String(err.code).startsWith("SQLITE_CONSTRAINT")) {
      return res.status(409).json({ error: "Аккаунт с таким email уже существует." });
    }
    next(err);
  }
});

app.post("/api/login", authLimiter, async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
    const ok = user ? await bcrypt.compare(password, user.password_hash) : false;
    if (!ok) return res.status(401).json({ error: "Неверный email или пароль." });
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.user = safeUser(user);
      req.session.csrfToken = crypto.randomBytes(32).toString("hex");
      res.json({ user: req.session.user, csrfToken: req.session.csrfToken });
    });
  } catch (err) { next(err); }
});

app.get("/api/me", (req, res) => res.json({ user: req.session.user || null }));
app.post("/api/logout", requireAuth, (req, res, next) => {
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie("itspace.sid", { httpOnly: true, sameSite: "strict", secure: production });
    res.json({ ok: true });
  });
});

app.get("/api/admin/users", requireAuth, requireAdmin, (req, res) => {
  const users = db.prepare("SELECT id,name,email,role,created_at FROM users ORDER BY id DESC LIMIT 200").all();
  res.json({ users });
});

app.get("/api/admin/messages", requireAuth, requireAdmin, (req, res) => {
  const messages = db.prepare("SELECT id,name,email,message,created_at FROM messages ORDER BY id DESC LIMIT 200").all();
  res.json({ messages });
});

app.post("/api/contact", contactLimiter, (req, res) => {
  const { name, email, message } = req.body || {};
  const n = typeof name === "string" ? name.trim() : "";
  const e = normalizeEmail(email);
  const m = typeof message === "string" ? message.trim() : "";
  if (n.length < 2 || n.length > 80 || !validEmail(e) || m.length < 10 || m.length > 2000) {
    return res.status(400).json({ error: "Проверьте имя, email и сообщение." });
  }
  db.prepare("INSERT INTO messages(name,email,message) VALUES(?,?,?)").run(n, e, m);
  res.status(201).json({ ok: true, message: "Сообщение сохранено. Спасибо за обращение!" });
});

app.use(express.static(path.join(__dirname, "public"), { dotfiles: "deny", maxAge: production ? "1h" : 0 }));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.use((err, req, res, next) => {
  console.error("Request error:", err.message);
  res.status(500).json({ error: "Внутренняя ошибка сервера." });
});

createInitialAdmin().then(() => {
  app.listen(PORT, () => console.log(`IT Пространство: http://localhost:${PORT}`));
}).catch((err) => {
  console.error("Startup failed:", err.message);
  process.exit(1);
});