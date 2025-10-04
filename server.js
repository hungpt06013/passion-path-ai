// server.js (ESM)
import express from "express";
import { Pool } from "pg";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import OpenAI from "openai";

dotenv.config();

const app = express();

import cors from 'cors';

// ----------- CORS: minimal secure change -------------
// If ALLOWED_ORIGINS env is set (comma-separated), restrict to those origins.
// Otherwise fall back to permissive (dev convenience) but warn if in production.
const rawAllowed = (process.env.ALLOWED_ORIGINS || '').trim();
if (rawAllowed) {
  const allowedList = rawAllowed.split(',').map(s => s.trim()).filter(Boolean);
  app.use(cors({
    origin: function(origin, callback) {
      if (!origin) return callback(null, true); // allow server-to-server or curl (no origin)
      if (allowedList.indexOf(origin) !== -1) return callback(null, true);
      return callback(new Error('CORS not allowed from origin ' + origin));
    }
  }));
} else {
  if ((process.env.NODE_ENV || 'development') === 'production') {
    console.warn('⚠️ ALLOWED_ORIGINS not set in production. This is insecure. Set ALLOWED_ORIGINS to your domain(s).');
  }
  app.use(cors());
}

// Initialize OpenAI client (works even if API key missing; we check before real calls)
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// __dirname in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Public dir (can override by PUBLIC_DIR env)
const publicDir = path.resolve(process.env.PUBLIC_DIR || path.join(__dirname, "public"));

// Body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static if exists
if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir));
  console.log(`✅ Serving static files from: ${publicDir}`);
} else {
  console.warn(`⚠️ Static folder not found: ${publicDir} – static files WILL NOT be served`);
}

// Build pool config: prefer DATABASE_URL, otherwise use per-field env vars
let poolConfig = {};
if (process.env.DATABASE_URL) {
  poolConfig.connectionString = process.env.DATABASE_URL;
  if (process.env.PGSSLMODE === "require") {
    poolConfig.ssl = { rejectUnauthorized: false };
  }
} else {
  poolConfig = {
    user: process.env.DB_USER || process.env.PGUSER || "postgres",
    host: process.env.DB_HOST || process.env.PGHOST || "localhost",
    database: process.env.DB_NAME || process.env.PGDATABASE || "myapp",
    password: process.env.DB_PASSWORD || process.env.PGPASSWORD || "",
    port: parseInt(process.env.DB_PORT || process.env.PGPORT || "5432", 10),
  };
}

const pool = new Pool(poolConfig);

// Warn if JWT_SECRET missing
if (!process.env.JWT_SECRET) {
  console.warn("⚠️ Warning: JWT_SECRET not set. Using default dev secret. Don't use this in production.");
}

// Warn if OpenAI API key missing
if (!process.env.OPENAI_API_KEY) {
  console.warn("⚠️ Warning: OPENAI_API_KEY not set. AI features will not work.");
}

// Test connection (don't crash the app, just log)
(async function testDB() {
  try {
    const client = await pool.connect();
    try {
      await client.query("SET client_encoding = 'UTF8'");
    } catch (e) {
      console.warn("⚠️ Could not set client_encoding to UTF8:", e.message);
    }
    client.release();
    console.log(`✅ PostgreSQL connected (${poolConfig.database || poolConfig.connectionString || "unknown"})`);
  } catch (err) {
    console.error("❌ PostgreSQL connection failed:", err.message || err);
  }
})();

// bcrypt helpers
function hashPassword(password, saltRounds = 10) {
  return new Promise((resolve, reject) => {
    bcrypt.hash(password, saltRounds, (err, hash) => {
      if (err) return reject(err);
      resolve(hash);
    });
  });
}
function comparePassword(plain, hashed) {
  return new Promise((resolve, reject) => {
    bcrypt.compare(plain, hashed, (err, same) => {
      if (err) return reject(err);
      resolve(same);
    });
  });
}

// token
function makeToken(userId) {
  return jwt.sign({ userId }, process.env.JWT_SECRET || "dev_local_secret", { expiresIn: "2h" });
}

// 🔥🔥🔥 Config AI / tokens (kept original values) 🔥🔥🔥
const MAX_AI_DAYS = parseInt(process.env.MAX_AI_DAYS || "180", 10);
const MAX_AI_TOKENS = parseInt(process.env.MAX_AI_TOKENS || "400000", 10);
const TOKENS_PER_DAY = parseInt(process.env.TOKENS_PER_DAY || "1500", 10);
const PREFERRED_OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-5-nano";
const FALLBACK_OPENAI_MODEL = process.env.FALLBACK_OPENAI_MODEL || "gpt-4o";
const SAFETY_MARGIN_TOKENS = parseInt(process.env.SAFETY_MARGIN_TOKENS || "2048", 10);
const MIN_COMPLETION_TOKENS = 128;

// Temperatures: preferred model must use 1.0; fallback kept at 0.5
const PREFERRED_OPENAI_TEMPERATURE = parseFloat(process.env.PREFERRED_OPENAI_TEMPERATURE || "1");
const FALLBACK_OPENAI_TEMPERATURE = parseFloat(process.env.FALLBACK_OPENAI_TEMPERATURE || "0.5");

function buildOpenAIParams({ model, messages, maxCompletionTokens, temperature = 0.5 }) {
  const tokens = Math.max(MIN_COMPLETION_TOKENS, Math.floor(maxCompletionTokens || MIN_COMPLETION_TOKENS));
  return {
    model,
    messages,
    max_completion_tokens: tokens,
    temperature,
  };
}

// helper to call OpenAI with automatic model-not-found fallback and param adaptation
async function callOpenAIWithFallback({ messages, desiredCompletionTokens, temperature = 0.5 }) {
  const capped = Math.max(
    MIN_COMPLETION_TOKENS,
    Math.min(desiredCompletionTokens, MAX_AI_TOKENS - SAFETY_MARGIN_TOKENS)
  );

  try {
    const params = buildOpenAIParams({
      model: PREFERRED_OPENAI_MODEL,
      messages,
      maxCompletionTokens: capped,
      temperature,
    });
    // mask messages in logs
    const safeLog = { ...params, messages: undefined };
    console.log('📤 Sending params:', JSON.stringify(safeLog, null, 2));
    return await openai.chat.completions.create(params);
  } catch (err) {
    // ---- SAFER ERROR LOGGING: do not stringify full object ----
    console.error('❌ OpenAI error message:', err && err.message ? err.message : String(err));
    console.error('❌ OpenAI error code/status:', err && (err.code || err.status || (err.error && err.error.code)) );
    // ---- end safer logging ----

    const code = err && (err.code || (err.error && err.error.code));
    const status = err && err.status;
    console.warn("OpenAI call failed for preferred model:", code || status || err.message || err);

    if (code === "model_not_found" || status === 404 || String(err.message).toLowerCase().includes("model")) {
      console.warn(`⚠️ Preferred model "${PREFERRED_OPENAI_MODEL}" not available. Falling back to ${FALLBACK_OPENAI_MODEL}.`);
      const fallbackTokens = Math.min(capped, MAX_AI_TOKENS - SAFETY_MARGIN_TOKENS);
      // IMPORTANT: use fallback temperature (keep at 0.5 unless overridden by env)
      const fallbackParams = buildOpenAIParams({
        model: FALLBACK_OPENAI_MODEL,
        messages,
        maxCompletionTokens: fallbackTokens,
        temperature: FALLBACK_OPENAI_TEMPERATURE,
      });
      return await openai.chat.completions.create(fallbackParams);
    }

    throw err;
  }
}

// -----------------
// DB init (unchanged except admin seed requires SEED_ADMIN=true)
// -----------------
async function initDB() {
  try {
    // Tạo bảng users
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log("✅ Bảng users đã sẵn sàng");

    // Tạo bảng learning_roadmaps
    await pool.query(`
      CREATE TABLE IF NOT EXISTS learning_roadmaps (
        roadmap_id SERIAL PRIMARY KEY,
        roadmap_name VARCHAR(255) NOT NULL,
        category VARCHAR(100) NOT NULL,
        sub_category VARCHAR(100),
        start_level VARCHAR(20) CHECK (start_level IN ('Beginner', 'Intermediate', 'Advanced')),
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        duration_days INTEGER NOT NULL CHECK (duration_days > 0),
        duration_hours DECIMAL(6,2) NOT NULL CHECK (duration_hours > 0),
        status VARCHAR(20) DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'COMPLETED', 'PAUSED')),
        expected_outcome TEXT,
        progress_percentage DECIMAL(5,2) DEFAULT 0.00 CHECK (progress_percentage >= 0 AND progress_percentage <= 100),
        total_studied_hours DECIMAL(6,2) DEFAULT 0.00,
        overall_rating DECIMAL(2,1) CHECK (overall_rating >= 1 AND overall_rating <= 5),
        learning_effectiveness INTEGER CHECK (learning_effectiveness >= 1 AND learning_effectiveness <= 5),
        difficulty_suitability INTEGER CHECK (difficulty_suitability >= 1 AND difficulty_suitability <= 5),
        content_relevance INTEGER CHECK (content_relevance >= 1 AND content_relevance <= 5),
        engagement_level INTEGER CHECK (engagement_level >= 1 AND engagement_level <= 5),
        would_recommend BOOLEAN,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Tạo bảng learning_roadmap_details
    await pool.query(`
      CREATE TABLE IF NOT EXISTS learning_roadmap_details (
        detail_id SERIAL PRIMARY KEY,
        roadmap_id INTEGER NOT NULL REFERENCES learning_roadmaps(roadmap_id) ON DELETE CASCADE,
        day_number INTEGER NOT NULL,
        daily_goal VARCHAR(500) NOT NULL,
        learning_content TEXT NOT NULL,
        practice_exercises TEXT,
        learning_materials VARCHAR(500),
        study_duration_hours DECIMAL(4,2) NOT NULL CHECK (study_duration_hours > 0),
        completion_status VARCHAR(20) DEFAULT 'NOT_STARTED' CHECK (completion_status IN ('NOT_STARTED', 'IN_PROGRESS', 'COMPLETED', 'SKIPPED')),
        study_date DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP,
        UNIQUE(roadmap_id, day_number)
      );
    `);

    // Tạo index để tối ưu performance
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_roadmaps_user_id ON learning_roadmaps(user_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_roadmaps_status ON learning_roadmaps(status);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_roadmap_details_roadmap_id ON learning_roadmap_details(roadmap_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_roadmap_details_completion ON learning_roadmap_details(completion_status);`);

    console.log("✅ Tất cả bảng roadmap đã sẵn sàng");

    // optional admin seed from env -> NOW requires SEED_ADMIN === 'true' to run
    const adminUsername = (process.env.ADMIN_USERNAME || "").trim();
    const adminPassword = (process.env.ADMIN_PASSWORD || "").trim();
    const adminEmail = (process.env.ADMIN_EMAIL || "").trim() || `${adminUsername || "admin"}@local`;

    if (process.env.SEED_ADMIN === 'true' && adminUsername && adminPassword) {
      const exists = await pool.query("SELECT id FROM users WHERE username = $1 LIMIT 1", [adminUsername]);
      if (exists.rows.length === 0) {
        const hashed = await hashPassword(adminPassword, 10);
        await pool.query(
          "INSERT INTO users (name, username, email, password, role) VALUES ($1, $2, $3, $4, 'admin')",
          [adminUsername, adminUsername, adminEmail, hashed]
        );
        console.log(`🔑 Admin seeded: username='${adminUsername}' (seeded because SEED_ADMIN=true)`);
      } else {
        console.log("ℹ️ Admin username already exists; skipping seed.");
      }
    } else {
      if (adminUsername && adminPassword) {
        console.log("ℹ️ Admin credentials present in env but SEED_ADMIN !== 'true'. Skipping automatic admin seed (safer).");
      }
    }
  } catch (err) {
    console.error("❌ DB init error:", err.message || err);
  }
}
initDB();

// Middleware: requireAdmin
async function requireAdmin(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.replace(/^Bearer\s+/i, "").trim();
  if (!token) return res.status(401).json({ message: "Không có token" });

  // quick sanity check: JWT must have 2 dots
  if ((token.match(/\./g) || []).length !== 2) {
    return res.status(401).json({ message: "Token không hợp lệ" });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || "dev_local_secret");
    const result = await pool.query("SELECT id, username, role FROM users WHERE id = $1 LIMIT 1", [payload.userId]);
    if (result.rows.length === 0) return res.status(401).json({ message: "Người dùng không tồn tại" });

    const user = result.rows[0];

    // If role column exists and is 'admin'
    if (user.role && String(user.role).toLowerCase() === "admin") {
      req.user = user;
      return next();
    }

    // Fallback: ADMIN_USERNAME env
    const adminName = (process.env.ADMIN_USERNAME || "").trim();
    if (adminName && user.username === adminName) {
      req.user = user;
      return next();
    }

    return res.status(403).json({ message: "Yêu cầu quyền admin" });
  } catch (err) {
    if (err && err.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Token đã hết hạn, vui lòng đăng nhập lại" });
    }
    console.error("Auth error (requireAdmin):", err && err.message ? err.message : err);
    return res.status(401).json({ message: "Token không hợp lệ" });
  }
}

// Middleware xác thực user
async function requireAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.replace(/^Bearer\s+/i, "").trim();
  if (!token) return res.status(401).json({ message: "Không có token" });

  if ((token.match(/\./g) || []).length !== 2) {
    return res.status(401).json({ message: "Token không hợp lệ" });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || "dev_local_secret");
    const result = await pool.query("SELECT id, username, role FROM users WHERE id = $1 LIMIT 1", [payload.userId]);
    if (result.rows.length === 0) return res.status(401).json({ message: "Người dùng không tồn tại" });

    req.user = result.rows[0];
    next();
  } catch (err) {
    if (err && err.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Token đã hết hạn, vui lòng đăng nhập lại" });
    }
    console.error("Auth error:", err && err.message ? err.message : err);
    return res.status(401).json({ message: "Token không hợp lệ" });
  }
}

// --- API: Register ---
app.post("/api/register", async (req, res) => {
  const { name, username, email, password } = req.body;
  if (!name || !username || !email || !password) return res.status(400).json({ message: "Thiếu dữ liệu!" });

  try {
    // do NOT lowercase email/username – keep case-sensitive behavior
    const normalizedEmail = String(email).trim();
    const normalizedUsername = String(username).trim();

    // server-side password policy (must match client)
    const pw = String(password);
    const errors = {};
    if (pw.length < 8) errors.password = "Mật khẩu phải có ít nhất 8 ký tự.";
    if (!/[A-Z]/.test(pw)) errors.password = "Mật khẩu phải bao gồm ít nhất 1 chữ hoa.";
    if (!/[a-z]/.test(pw)) errors.password = "Mật khẩu phải bao gồm ít nhất 1 chữ thường.";
    if (!/[0-9]/.test(pw)) errors.password = "Mật khẩu phải bao gồm ít nhất 1 chữ số.";
    if (!/[^A-Za-z0-9]/.test(pw)) errors.password = "Mật khẩu phải bao gồm ít nhất 1 ký tự đặc biệt.";
    if (Object.keys(errors).length > 0) {
      return res.status(400).json({ message: "Dữ liệu mật khẩu không hợp lệ.", errors });
    }

    // Check existing by exact (case-sensitive) username or email
    const existing = await pool.query(
      "SELECT id FROM users WHERE username = $1 OR email = $2",
      [normalizedUsername, normalizedEmail]
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({ message: "Tên đăng nhập hoặc email đã tồn tại!" });
    }

    const hashed = await hashPassword(password, 10);
    const result = await pool.query(
      "INSERT INTO users (name, username, email, password) VALUES ($1, $2, $3, $4) RETURNING id, name, username, email",
      [name.trim(), normalizedUsername, normalizedEmail, hashed]
    );
    const user = result.rows[0];
    const token = makeToken(user.id);
    res.json({ message: "Đăng ký thành công!", token, user });
  } catch (err) {
    console.error("❌ SQL Error (register):", err.message || err);
    if (err.code === "23505") {
      return res.status(409).json({ message: "Tên đăng nhập hoặc email đã tồn tại!" });
    }
    res.status(500).json({ message: "Lỗi server khi đăng ký!" });
  }
});

// --- API: Login ---
app.post("/api/login", async (req, res) => {
  // safer logs: avoid printing raw body (may contain password); print only keys and content-type
  try {
    console.log('[/api/login] content-type:', req.headers['content-type']);
    console.log('[/api/login] body keys:', Object.keys(req.body || {}));

    // defensive normalization
    const body = (req.body && typeof req.body === 'object') ? req.body : {};
    let username = body.username ? String(body.username).trim() : "";
    let email = body.email ? String(body.email).trim() : "";
    let password = body.password ? String(body.password) : "";

    if (!password || (!username && !email)) {
      return res.status(400).json({ message: "Thiếu tên đăng nhập hoặc email, hoặc mật khẩu!" });
    }

    // simple email validation when email is present
    const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (email && !EMAIL_RE.test(email)) {
      return res.status(400).json({ message: "Email không đúng định dạng!" });
    }

    let result;
    let user;

    if (username && email) {
      // Both provided: fetch by username then ensure email matches (case-sensitive)
      result = await pool.query(
        "SELECT id, name, username, email, password FROM users WHERE username = $1 LIMIT 1",
        [username]
      );
      if (result.rows.length === 0) {
        return res.status(401).json({ message: "Sai tên đăng nhập hoặc mật khẩu!" });
      }
      user = result.rows[0];
      if (String(user.email) !== String(email)) {
        return res.status(401).json({ message: "Tên đăng nhập và email không khớp." });
      }
    } else if (username) {
      // Only username: exact match (case-sensitive)
      result = await pool.query(
        "SELECT id, name, username, email, password FROM users WHERE username = $1 LIMIT 1",
        [username]
      );
      if (result.rows.length === 0) {
        return res.status(401).json({ message: "Sai tên đăng nhập hoặc mật khẩu!" });
      }
      user = result.rows[0];
    } else {
      // Only email: exact match (case-sensitive)
      result = await pool.query(
        "SELECT id, name, username, email, password FROM users WHERE email = $1 LIMIT 1",
        [email]
      );
      if (result.rows.length === 0) {
        return res.status(401).json({ message: "Sai email hoặc mật khẩu!" });
      }
      user = result.rows[0];
    }

    const match = await comparePassword(password, user.password);
    if (!match) {
      return res.status(401).json({ message: "Sai tên đăng nhập hoặc mật khẩu!" });
    }

    const token = makeToken(user.id);
    return res.json({
      message: "Đăng nhập thành công!",
      token,
      user: { id: user.id, name: user.name, username: user.username, email: user.email },
    });
  } catch (err) {
    console.error("❌ SQL Error (login):", err && err.message ? err.message : err);
    return res.status(500).json({ message: "Lỗi server khi đăng nhập!" });
  }
});

// --- API: me (from token) ---
app.get("/api/me", async (req, res) => {
  const auth = req.headers.authorization || "";
  const token = auth.replace(/^Bearer\s+/i, "").trim();
  if (!token) return res.status(401).json({ message: "Không có token" });

  if ((token.match(/\./g) || []).length !== 2) {
    return res.status(401).json({ message: "Token không hợp lệ" });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || "dev_local_secret");
    const result = await pool.query("SELECT id, name, username, email, role, created_at FROM users WHERE id = $1", [payload.userId]);
    if (result.rows.length === 0) return res.status(404).json({ message: "Người dùng không tồn tại" });
    res.json({ user: result.rows[0] });
  } catch (err) {
    if (err && err.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Token đã hết hạn, vui lòng đăng nhập lại" });
    }
    console.error("Auth error:", err && err.message ? err.message : err);
    return res.status(401).json({ message: "Token không hợp lệ" });
  }
});

// --- API: Lấy danh sách users (admin only) ---
app.get("/api/users", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT id, name, email, created_at FROM users ORDER BY id DESC");
    return res.json(result.rows);
  } catch (err) {
    console.error("SQL Error (get users):", err && err.message ? err.message : err);
    return res.status(500).json({ message: "Lỗi server khi lấy danh sách users" });
  }
});

// --- API: Xóa user theo id (number) hoặc email (string) (admin only) ---
app.delete("/api/users/:id", requireAdmin, async (req, res) => {
  const raw = req.params.id;
  try {
    let result;
    if (/^\d+$/.test(raw)) {
      const id = parseInt(raw, 10);
      // Protect against deleting self accidentally
      if (req.user && req.user.id === id) {
        return res.status(400).json({ message: "Không thể tự xóa tài khoản admin đang đăng nhập" });
      }
      // Additional protection: do not allow deleting seeded ADMIN_USERNAME by id
      const adminName = (process.env.ADMIN_USERNAME || "").trim();
      if (adminName) {
        const maybeAdmin = await pool.query("SELECT id, username FROM users WHERE id = $1 LIMIT 1", [id]);
        if (maybeAdmin.rows.length && maybeAdmin.rows[0].username === adminName) {
          return res.status(400).json({ message: "Không thể xóa tài khoản admin mặc định" });
        }
      }
      result = await pool.query("DELETE FROM users WHERE id = $1 RETURNING id", [id]);
    } else {
      const email = decodeURIComponent(raw);
      // optional: prevent deleting admin by email if it's the seeded admin username's email
      const adminEmail = process.env.ADMIN_EMAIL || `${process.env.ADMIN_USERNAME || ""}@local`;
      if (adminEmail && email === adminEmail) {
        return res.status(400).json({ message: "Không thể xóa tài khoản admin mặc định" });
      }
      result = await pool.query("DELETE FROM users WHERE email = $1 RETURNING id", [email]);
    }

    if (!result || result.rowCount === 0) {
      return res.status(404).json({ message: "Người dùng không tồn tại" });
    }
    return res.json({ message: "Xóa thành công.", deletedId: result.rows[0].id });
  } catch (err) {
    console.error("SQL Error (delete user):", err && err.message ? err.message : err);
    return res.status(500).json({ message: "Lỗi server khi xóa user" });
  }
});

// === AI ROADMAP GENERATION API ===
app.post("/api/generate-roadmap-ai", requireAuth, async (req, res) => {
  try {
    if (!process.env.OPENAI_API_KEY) {
      return res.status(503).json({
        success: false,
        error: "Tính năng AI chưa được cấu hình. Vui lòng liên hệ quản trị viên."
      });
    }

    const {
      roadmap_name,
      category,
      sub_category,
      start_level,
      duration_days,
      duration_hours,
      expected_outcome
    } = req.body;

    // Validate required fields
    if (!roadmap_name || !category || !start_level || !duration_days || !duration_hours || !expected_outcome) {
      return res.status(400).json({
        success: false,
        error: "Thiếu thông tin bắt buộc để tạo lộ trình"
      });
    }

    // Validate duration limit using configurable MAX_AI_DAYS
    const maxDays = MAX_AI_DAYS;
    if (parseInt(duration_days) > maxDays) {
      return res.status(400).json({
        success: false,
        error: `AI chỉ có thể tạo lộ trình tối đa ${maxDays} ngày. Vui lòng giảm số ngày học hoặc tạo thủ công.`
      });
    }

    const actualDays = parseInt(duration_days);
    const totalHours = parseFloat(duration_hours);
    if (isNaN(totalHours) || totalHours <= 0) {
      return res.status(400).json({ success: false, error: "duration_hours không hợp lệ" });
    }

    // Calculate hours per day
    const hoursPerDay = Math.round((totalHours / actualDays) * 100) / 100;

    const systemPrompt = `Bạn là một chuyên gia thiết kế lộ trình học tập. Nhiệm vụ của bạn là tạo ra một lộ trình học chi tiết, thực tế và có thể thực hiện được.

QUAN TRỌNG:
- Trả lời CHÍNH XÁC bằng định dạng JSON array
- KHÔNG thêm bất kỳ text nào khác ngoài JSON
- KHÔNG sử dụng "..." hay "tiếp tục" - phải tạo đầy đủ tất cả ngày
- Mỗi ngày phải có đầy đủ tất cả các trường bắt buộc
- Nội dung phải phù hợp với trình độ và thời gian học
- Sử dụng tiếng Việt cho tất cả nội dung

Định dạng JSON trả về (BẮT BUỘC tạo đầy đủ ${actualDays} ngày):
[
  {
    "day_number": 1,
    "daily_goal": "Mục tiêu cụ thể của ngày",
    "learning_content": "Nội dung kiến thức chi tiết cần học",
    "practice_exercises": "Bài tập thực hành cụ thể",
    "learning_materials": "Công cụ, tài liệu cần thiết",
    "study_duration_hours": 2.5
  }
]`;

    const userPrompt = `Tạo lộ trình học "${roadmap_name}" với các thông số sau:

📚 THÔNG TIN LỘ TRÌNH:
- Tên lộ trình: ${roadmap_name}
- Danh mục: ${category}${sub_category ? ` / ${sub_category}` : ''}
- Trình độ hiện tại: ${start_level}
- Thời gian: ${actualDays} ngày
- Tổng số giờ: ${totalHours} giờ (trung bình ${hoursPerDay} giờ/ngày)
- Kết quả mong đợi: ${expected_outcome}

🎯 YÊU CẦU CHI TIẾT:
1. Tạo ĐÚNG ${actualDays} ngày học (từ 1 đến ${actualDays})
2. Mỗi ngày khoảng ${hoursPerDay} giờ học
3. Nội dung phù hợp với trình độ ${start_level}
4. Có sự liên kết và tiến triển giữa các ngày
5. Bài tập thực hành cụ thể, có thể làm được
6. Tài liệu học tập thực tế và dễ tìm

QUAN TRỌNG: Phải tạo đầy đủ ${actualDays} ngày, KHÔNG được viết "..." hay "tiếp tục"!`;

    // SAFE debug: do not print API key or its length
    console.log('🤖 Sending request to OpenAI...');
    console.log('🔑 OpenAI API key set?', Boolean(process.env.OPENAI_API_KEY));
    console.log('🎯 Attempting model:', PREFERRED_OPENAI_MODEL);

    // compute safe desired completion tokens based on days and caps
    const perDayEstimate = TOKENS_PER_DAY;
    const desired = actualDays * perDayEstimate;

    // call OpenAI with fallback helper
    const completion = await callOpenAIWithFallback({
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt }
      ],
      desiredCompletionTokens: desired,
      // IMPORTANT: preferred model temperature set to 1.0
      temperature: PREFERRED_OPENAI_TEMPERATURE,
    });

    const aiResponse = completion?.choices?.[0]?.message?.content?.trim();
    if (!aiResponse) {
      throw new Error("AI không trả về phản hồi");
    }

    // Parse JSON response from AI
    let roadmapData;
    try {
      // Remove possible markdown fences
      const jsonStr = aiResponse.replace(/```json\n?/g, '').replace(/```/g, '').trim();

      if (jsonStr.includes('...') || jsonStr.includes('tiếp tục') || jsonStr.includes('continue')) {
        throw new Error("AI response bị cắt ngắn hoặc không đầy đủ");
      }

      roadmapData = JSON.parse(jsonStr);
    } catch (parseError) {
      console.error('JSON Parse Error:', parseError);
      console.error('AI Response was:', aiResponse);
      // Fallback
      roadmapData = generateFallbackRoadmap(actualDays, hoursPerDay, roadmap_name, category, start_level);
    }

    // Validate structure
    if (!Array.isArray(roadmapData) || roadmapData.length === 0) {
      roadmapData = generateFallbackRoadmap(actualDays, hoursPerDay, roadmap_name, category, start_level);
    }

    // Adjust length if needed
    if (roadmapData.length !== actualDays) {
      if (roadmapData.length < actualDays) {
        for (let i = roadmapData.length; i < actualDays; i++) {
          roadmapData.push({
            day_number: i + 1,
            daily_goal: `Ôn tập và củng cố kiến thức ngày ${i + 1}`,
            learning_content: `Ôn lại và thực hành các kiến thức đã học trong ${category.toLowerCase()}`,
            practice_exercises: "Làm bài tập tổng hợp và thực hành",
            learning_materials: "Tài liệu học tập cơ bản",
            study_duration_hours: hoursPerDay
          });
        }
      } else {
        roadmapData = roadmapData.slice(0, actualDays);
      }
    }

    // Normalize each day to expected keys and types
    for (let i = 0; i < roadmapData.length; i++) {
      const day = roadmapData[i] || {};
      const daily_goal = day.daily_goal || day.goal || day.dailyGoal || '';
      const learning_content = day.learning_content || day.content || day.learningContent || '';
      const practice_exercises = day.practice_exercises || day.exercises || day.practiceExercises || '';
      const learning_materials = day.learning_materials || day.materials || day.learningMaterials || '';
      const study_duration_hours = parseFloat(day.study_duration_hours ?? day.hours ?? day.studyDurationHours) || hoursPerDay;

      const fixedDay = {
        day_number: parseInt(day.day_number) || (i + 1),
        daily_goal: daily_goal || `Mục tiêu ngày ${i + 1}`,
        learning_content: learning_content || `Nội dung học tập ngày ${i + 1}`,
        practice_exercises: practice_exercises || "Thực hành và ôn tập",
        learning_materials: learning_materials || "Tài liệu học tập",
        study_duration_hours: study_duration_hours,
      };

      roadmapData[i] = fixedDay;
    }

    // Sort by day_number
    roadmapData.sort((a, b) => a.day_number - b.day_number);

    console.log(`✅ Successfully generated ${roadmapData.length} days of roadmap`);

    res.json({
      success: true,
      message: "Tạo lộ trình bằng AI thành công",
      data: roadmapData
    });

  } catch (error) {
    console.error("❌ AI Generation Error:", error);

    let errorMessage = "Không thể tạo lộ trình bằng AI";
    if (error.code === 'insufficient_quota') {
      errorMessage = "Hạn mức API đã hết. Vui lòng liên hệ quản trị viên.";
    } else if (error.code === 'rate_limit_exceeded') {
      errorMessage = "Quá nhiều yêu cầu. Vui lòng thử lại sau ít phút.";
    } else if (error.code === 'invalid_api_key') {
      errorMessage = "Cấu hình API không hợp lệ. Vui lòng liên hệ quản trị viên.";
    } else if (error.message) {
      errorMessage = error.message;
    }

    res.status(500).json({
      success: false,
      error: errorMessage
    });
  }
});

function generateFallbackRoadmap(days, hoursPerDay, roadmapName, category, startLevel) {
  console.log(`🔧 Generating fallback roadmap for ${days} days...`);

  const roadmap = [];
  const categoryLower = category.toLowerCase();

  for (let i = 1; i <= days; i++) {
    let phase = '';
    let content = '';
    let exercises = '';

    if (i <= Math.ceil(days * 0.3)) {
      phase = 'Cơ bản';
      content = `Học các kiến thức cơ bản về ${categoryLower}. Tìm hiểu các khái niệm và nguyên lý nền tảng.`;
      exercises = `Làm các bài tập cơ bản về ${categoryLower}. Thực hành với các ví dụ đơn giản.`;
    } else if (i <= Math.ceil(days * 0.7)) {
      phase = 'Trung cấp';
      content = `Phát triển kỹ năng trung cấp trong ${categoryLower}. Áp dụng kiến thức vào các tình huống thực tế.`;
      exercises = `Thực hiện các dự án nhỏ và bài tập thực hành nâng cao trong ${categoryLower}.`;
    } else {
      phase = 'Nâng cao';
      content = `Hoàn thiện kỹ năng và làm dự án tổng hợp trong ${categoryLower}. Chuẩn bị cho việc ứng dụng thực tế.`;
      exercises = `Hoàn thành dự án cuối khóa và tổng hợp kiến thức đã học trong ${categoryLower}.`;
    }

    roadmap.push({
      day_number: i,
      daily_goal: `${phase}: Phát triển kỹ năng ${categoryLower} - Ngày ${i}`,
      learning_content: content,
      practice_exercises: exercises,
      learning_materials: `Tài liệu học tập ${categoryLower}, các công cụ cần thiết`,
      study_duration_hours: hoursPerDay
    });
  }

  return roadmap;
}

// GET: Lấy tất cả roadmaps của user
app.get("/api/roadmaps", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM learning_roadmaps 
       WHERE user_id = $1 
       ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error("Error fetching roadmaps:", err);
    res.status(500).json({ success: false, error: "Không thể lấy danh sách lộ trình" });
  }
});

// POST: Tạo roadmap mới
app.post("/api/roadmaps", requireAuth, async (req, res) => {
  try {
    const {
      roadmap_name,
      category,
      sub_category,
      start_level,
      duration_days,
      duration_hours,
      expected_outcome,
      days
    } = req.body;

    if (!roadmap_name || !category || !start_level || !duration_days || !duration_hours || !expected_outcome) {
      return res.status(400).json({ success: false, error: "Thiếu thông tin bắt buộc" });
    }

    const roadmapResult = await pool.query(
      `INSERT INTO learning_roadmaps 
       (roadmap_name, category, sub_category, start_level, user_id, duration_days, duration_hours, expected_outcome)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING roadmap_id`,
      [roadmap_name, category, sub_category || null, start_level, req.user.id, duration_days, duration_hours, expected_outcome]
    );

    const roadmapId = roadmapResult.rows[0].roadmap_id;

    if (days && Array.isArray(days)) {
      for (let i = 0; i < days.length; i++) {
        const day = days[i];
        await pool.query(
          `INSERT INTO learning_roadmap_details
           (roadmap_id, day_number, daily_goal, learning_content, practice_exercises, learning_materials, study_duration_hours)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [
            roadmapId,
            i + 1,
            day.goal || day.daily_goal || '',
            day.content || day.learning_content || '',
            day.exercises || day.practice_exercises || '',
            day.materials || day.learning_materials || '',
            parseFloat(day.hours || day.study_duration_hours || 2)
          ]
        );
      }
    }

    res.json({ success: true, roadmap_id: roadmapId, message: "Tạo lộ trình thành công" });
  } catch (err) {
    console.error("Error creating roadmap:", err);
    res.status(500).json({ success: false, error: "Không thể tạo lộ trình" });
  }
});

// GET: Lấy chi tiết roadmap
app.get("/api/roadmaps/:id/details", requireAuth, async (req, res) => {
  try {
    const roadmapId = parseInt(req.params.id);
    
    const roadmapCheck = await pool.query(
      "SELECT user_id FROM learning_roadmaps WHERE roadmap_id = $1",
      [roadmapId]
    );
    
    if (roadmapCheck.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Lộ trình không tồn tại" });
    }
    
    if (roadmapCheck.rows[0].user_id !== req.user.id) {
      return res.status(403).json({ success: false, error: "Không có quyền truy cập" });
    }

    const result = await pool.query(
      `SELECT * FROM learning_roadmap_details 
       WHERE roadmap_id = $1 
       ORDER BY day_number ASC`,
      [roadmapId]
    );

    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error("Error fetching roadmap details:", err);
    res.status(500).json({ success: false, error: "Không thể lấy chi tiết lộ trình" });
  }
});

// PUT: Cập nhật trạng thái chi tiết
app.put("/api/roadmaps/details/:id/status", requireAuth, async (req, res) => {
  try {
    const detailId = parseInt(req.params.id);
    const { completion_status } = req.body;

    if (!['NOT_STARTED', 'IN_PROGRESS', 'COMPLETED', 'SKIPPED'].includes(completion_status)) {
      return res.status(400).json({ success: false, error: "Trạng thái không hợp lệ" });
    }

    // NOTE: Cast $1 explicitly to the column type (VARCHAR) to avoid Postgres inferring inconsistent types
    const result = await pool.query(
      `UPDATE learning_roadmap_details 
       SET completion_status = $1::varchar, 
           completed_at = CASE WHEN $1::varchar = 'COMPLETED' THEN CURRENT_TIMESTAMP ELSE completed_at END,
           updated_at = CURRENT_TIMESTAMP
       WHERE detail_id = $2
       RETURNING *`,
      [completion_status, detailId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Không tìm thấy" });
    }

    const detail = result.rows[0];
    await pool.query(
      `UPDATE learning_roadmaps
       SET progress_percentage = (
         SELECT ROUND(COUNT(*) FILTER (WHERE completion_status = 'COMPLETED') * 100.0 / COUNT(*), 2)
         FROM learning_roadmap_details
         WHERE roadmap_id = $1
       ),
       updated_at = CURRENT_TIMESTAMP
       WHERE roadmap_id = $1`,
      [detail.roadmap_id]
    );

    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error("Error updating status:", err);
    res.status(500).json({ success: false, error: "Không thể cập nhật trạng thái" });
  }
});

// DELETE: Xóa roadmap
app.delete("/api/roadmaps/:id", requireAuth, async (req, res) => {
  try {
    const roadmapId = parseInt(req.params.id);
    
    const roadmapCheck = await pool.query(
      "SELECT user_id FROM learning_roadmaps WHERE roadmap_id = $1",
      [roadmapId]
    );
    
    if (roadmapCheck.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Lộ trình không tồn tại" });
    }
    
    if (roadmapCheck.rows[0].user_id !== req.user.id) {
      return res.status(403).json({ success: false, error: "Không có quyền xóa" });
    }

    await pool.query("DELETE FROM learning_roadmaps WHERE roadmap_id = $1", [roadmapId]);
    
    res.json({ success: true, message: "Đã xóa lộ trình" });
  } catch (err) {
    console.error("Error deleting roadmap:", err);
    res.status(500).json({ success: false, error: "Không thể xóa lộ trình" });
  }
});
// === ROADMAP APIs ===
// ... (các route khác giữ nguyên - không thay đổi, đã nằm ở trên)

app.get("/", (req, res) => {
  const tryFiles = ["main.html", "login.html", "index.html", "app.html", "register.html"];
  for (const f of tryFiles) {
    const p = path.join(publicDir, f);
    if (fs.existsSync(p)) return res.sendFile(p);
  }
  return res.status(200).send("Welcome. No frontend found in " + publicDir);
});

app.use((req, res, next) => {
  if (req.path.startsWith("/api/")) return next();
  const indexPath = path.join(publicDir, "index.html");
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  if (fs.existsSync(publicDir)) return res.status(404).send("Not found");
  return res.status(404).send("No frontend found in " + publicDir);
});

// Start server
const PORT = parseInt(process.env.PORT || "5000", 10);
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server chạy trên cổng ${PORT} (listening on 0.0.0.0).`);
  console.log(`ℹ️  Truy cập local: http://localhost:${PORT}/`);
});
