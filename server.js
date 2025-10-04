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
import cors from "cors";

// -------- CORS -----------
const rawAllowed = (process.env.ALLOWED_ORIGINS || "").trim();
if (rawAllowed) {
  const allowedList = rawAllowed.split(",").map((s) => s.trim()).filter(Boolean);
  app.use(
    cors({
      origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedList.indexOf(origin) !== -1) return callback(null, true);
        return callback(new Error("CORS not allowed from origin " + origin));
      },
    })
  );
} else {
  if ((process.env.NODE_ENV || "development") === "production") {
    console.warn("⚠️ ALLOWED_ORIGINS not set in production. This is insecure.");
  }
  app.use(cors());
}

// OpenAI client
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// __dirname ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// public dir
const publicDir = path.resolve(process.env.PUBLIC_DIR || path.join(__dirname, "public"));

// parsers
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// static serve
if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir));
  console.log(`✅ Serving static files from: ${publicDir}`);
} else {
  console.warn(`⚠️ Static folder not found: ${publicDir} – static files WILL NOT be served`);
}

// Postgres pool
let poolConfig = {};
if (process.env.DATABASE_URL) {
  poolConfig.connectionString = process.env.DATABASE_URL;
  if (process.env.PGSSLMODE === "require") poolConfig.ssl = { rejectUnauthorized: false };
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

if (!process.env.JWT_SECRET) {
  console.warn("⚠️ Warning: JWT_SECRET not set. Using default dev secret.");
}
if (!process.env.OPENAI_API_KEY) {
  console.warn("⚠️ Warning: OPENAI_API_KEY not set. AI features will not work.");
}

// quick DB test
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

// AI config
const MAX_AI_DAYS = parseInt(process.env.MAX_AI_DAYS || "180", 10);
const MAX_AI_TOKENS = parseInt(process.env.MAX_AI_TOKENS || "400000", 10);
const TOKENS_PER_DAY = parseInt(process.env.TOKENS_PER_DAY || "1500", 10);
const PREFERRED_OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-5-nano";
const FALLBACK_OPENAI_MODEL = process.env.FALLBACK_OPENAI_MODEL || "gpt-4o";
const SAFETY_MARGIN_TOKENS = parseInt(process.env.SAFETY_MARGIN_TOKENS || "2048", 10);
const MIN_COMPLETION_TOKENS = 128;
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

async function callOpenAIWithFallback({ messages, desiredCompletionTokens, temperature = 0.5 }) {
  const capped = Math.max(MIN_COMPLETION_TOKENS, Math.min(desiredCompletionTokens, MAX_AI_TOKENS - SAFETY_MARGIN_TOKENS));
  try {
    const params = buildOpenAIParams({ model: PREFERRED_OPENAI_MODEL, messages, maxCompletionTokens: capped, temperature });
    const safeLog = { ...params, messages: undefined };
    console.log("📤 Sending params:", JSON.stringify(safeLog, null, 2));
    return await openai.chat.completions.create(params);
  } catch (err) {
    console.error("❌ OpenAI error message:", err && err.message ? err.message : String(err));
    const code = err && (err.code || (err.error && err.error.code));
    const status = err && err.status;
    if (code === "model_not_found" || status === 404 || String(err.message).toLowerCase().includes("model")) {
      console.warn(`⚠️ Preferred model "${PREFERRED_OPENAI_MODEL}" not available. Falling back to ${FALLBACK_OPENAI_MODEL}.`);
      const fallbackTokens = Math.min(capped, MAX_AI_TOKENS - SAFETY_MARGIN_TOKENS);
      const fallbackParams = buildOpenAIParams({ model: FALLBACK_OPENAI_MODEL, messages, maxCompletionTokens: fallbackTokens, temperature: FALLBACK_OPENAI_TEMPERATURE });
      return await openai.chat.completions.create(fallbackParams);
    }
    throw err;
  }
}

// ---------------- DB init (same schema) ----------------
async function initDB() {
  try {
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
    await pool.query(`
      CREATE TABLE IF NOT EXISTS learning_roadmap_details (
        detail_id SERIAL PRIMARY KEY,
        roadmap_id INTEGER NOT NULL REFERENCES learning_roadmaps(roadmap_id) ON DELETE CASCADE,
        day_number INTEGER NOT NULL,
        daily_goal VARCHAR(500) NOT NULL,
        learning_content TEXT NOT NULL,
        practice_exercises TEXT,
        learning_materials VARCHAR(1000),
        study_duration_hours DECIMAL(4,2) NOT NULL CHECK (study_duration_hours > 0),
        completion_status VARCHAR(20) DEFAULT 'NOT_STARTED' CHECK (completion_status IN ('NOT_STARTED', 'IN_PROGRESS', 'COMPLETED', 'SKIPPED')),
        study_date DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP,
        UNIQUE(roadmap_id, day_number)
      );
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_roadmaps_user_id ON learning_roadmaps(user_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_roadmaps_status ON learning_roadmaps(status);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_roadmap_details_roadmap_id ON learning_roadmap_details(roadmap_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_roadmap_details_completion ON learning_roadmap_details(completion_status);`);
    console.log("✅ DB initialized");
  } catch (err) {
    console.error("❌ DB init error:", err && err.message ? err.message : err);
  }
}
initDB();

// ---------------- Auth middlewares (same) ----------------
async function requireAdmin(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.replace(/^Bearer\s+/i, "").trim();
  if (!token) return res.status(401).json({ message: "Không có token" });
  if ((token.match(/\./g) || []).length !== 2) return res.status(401).json({ message: "Token không hợp lệ" });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || "dev_local_secret");
    const result = await pool.query("SELECT id, username, role FROM users WHERE id = $1 LIMIT 1", [payload.userId]);
    if (result.rows.length === 0) return res.status(401).json({ message: "Người dùng không tồn tại" });
    const user = result.rows[0];
    if (user.role && String(user.role).toLowerCase() === "admin") { req.user = user; return next(); }
    const adminName = (process.env.ADMIN_USERNAME || "").trim();
    if (adminName && user.username === adminName) { req.user = user; return next(); }
    return res.status(403).json({ message: "Yêu cầu quyền admin" });
  } catch (err) {
    if (err && err.name === "TokenExpiredError") return res.status(401).json({ message: "Token đã hết hạn, vui lòng đăng nhập lại" });
    console.error("Auth error (requireAdmin):", err && err.message ? err.message : err);
    return res.status(401).json({ message: "Token không hợp lệ" });
  }
}

async function requireAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.replace(/^Bearer\s+/i, "").trim();
  if (!token) return res.status(401).json({ message: "Không có token" });
  if ((token.match(/\./g) || []).length !== 2) return res.status(401).json({ message: "Token không hợp lệ" });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || "dev_local_secret");
    const result = await pool.query("SELECT id, username, role FROM users WHERE id = $1 LIMIT 1", [payload.userId]);
    if (result.rows.length === 0) return res.status(401).json({ message: "Người dùng không tồn tại" });
    req.user = result.rows[0];
    next();
  } catch (err) {
    if (err && err.name === "TokenExpiredError") return res.status(401).json({ message: "Token đã hết hạn, vui lòng đăng nhập lại" });
    console.error("Auth error:", err && err.message ? err.message : err);
    return res.status(401).json({ message: "Token không hợp lệ" });
  }
}

// ---------------- Utilities: parsing, enrichment, dynamic links ----------------
function safeTruncate(s, n) { return s ? s.slice(0, n) : s; }

// CATEGORY_LINKS exist but used only as last-resort fallback
const CATEGORY_LINKS = {
  programming: ["https://developer.mozilla.org/", "https://www.freecodecamp.org/", "https://stackoverflow.com/"],
  english: ["https://www.bbc.co.uk/learningenglish", "https://www.cambridge.org/", "https://www.ef.com/wwen/english-resources/"],
  math: ["https://www.khanacademy.org/", "https://en.wikipedia.org/wiki/Mathematics"],
  default: ["https://en.wikipedia.org/", "https://www.google.com/search?q="]
};
function chooseLinksForCategory(rawCategory) {
  if (!rawCategory) return CATEGORY_LINKS.default;
  const k = rawCategory.toLowerCase();
  if (k.includes("program")) return CATEGORY_LINKS.programming;
  if (k.includes("english") || k.includes("tiếng anh")) return CATEGORY_LINKS.english;
  if (k.includes("math") || k.includes("toán")) return CATEGORY_LINKS.math;
  return CATEGORY_LINKS.default;
}

function makeExerciseVariants(topic) {
  return [
    `Bài trắc nghiệm ngắn (10 câu) kiểm tra khái niệm: ${topic}`,
    `Bài thực hành: xây dựng một ví dụ nhỏ ứng dụng ${topic}`,
    `Bài luyện phản xạ: mô tả/giải thích ${topic} trong 3 câu`,
    `Bài tổng hợp: kết hợp ${topic} với 1 khái niệm khác để giải bài tập`
  ];
}

// transform human-readable AI output to days (best-effort)
function transformTextToDays(text, actualDays, hoursPerDay, category) {
  if (!text) return null;
  const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const days = [];
  let current = { contentLines: [] };
  const dayRegex = /(^|\b)(day|ngày)\s*[:\-]?\s*(\d{1,3})/i;
  for (const l of lines) {
    const m = l.match(dayRegex);
    if (m) {
      if (current.contentLines.length > 0) days.push(current.contentLines.join(" "));
      current = { contentLines: [] };
      current.contentLines.push(l);
    } else if (/^🎯|^Goal:|^Mục tiêu/i.test(l)) {
      if (current.contentLines.length > 0) { days.push(current.contentLines.join(" ")); current = { contentLines: [] }; }
      current.contentLines.push(l);
    } else {
      current.contentLines.push(l);
    }
  }
  if (current.contentLines.length > 0) days.push(current.contentLines.join(" "));
  let segments = days.filter(Boolean);
  if (segments.length < actualDays) {
    const big = text.replace(/\s+/g, " ");
    const avg = Math.max(1, Math.floor(big.length / actualDays));
    segments = [];
    for (let i = 0; i < actualDays; i++) {
      const start = i * avg;
      const seg = big.slice(start, start + avg).trim();
      segments.push(seg || `Nội dung tổng quan cho ngày ${i+1}`);
    }
  } else if (segments.length > actualDays) segments = segments.slice(0, actualDays);

  const links = chooseLinksForCategory(category);
  const seen = new Set();
  const result = [];
  for (let i = 0; i < actualDays; i++) {
    const seg = segments[i] || `Nội dung học tập ngày ${i+1}`;
    const topic = seg.split(".")[0].slice(0, 80);
    const exercises = makeExerciseVariants(topic);
    const ex = [exercises[i % exercises.length], exercises[(i + 1) % exercises.length]];
    const materials = [links[0], `${links[1] || links[0]}#search?q=${encodeURIComponent(topic)}`];
    const daily = {
      day_number: i + 1,
      daily_goal: `Học: ${safeTruncate(topic, 120)}`,
      learning_content: seg + " — Chi tiết: đọc kỹ, làm ví dụ và ghi chú.",
      practice_exercises: ex.join(" | "),
      learning_materials: materials.join(" | "),
      study_duration_hours: parseFloat(hoursPerDay || 2)
    };
    const fp = `${daily.daily_goal}|${daily.learning_content}`.slice(0, 200);
    if (!seen.has(fp)) { seen.add(fp); result.push(daily); } else { daily.daily_goal += " (bổ sung)"; result.push(daily); }
  }
  while (result.length < actualDays) {
    const i = result.length;
    result.push({
      day_number: i + 1,
      daily_goal: `Ôn tập và củng cố - Ngày ${i+1}`,
      learning_content: `Ôn và thực hành các nội dung đã học trước đó.`,
      practice_exercises: `Bài tập ôn tập tổng hợp`,
      learning_materials: chooseLinksForCategory(category).join(" | "),
      study_duration_hours: parseFloat(hoursPerDay || 2)
    });
  }
  return result.slice(0, actualDays);
}

// --- Dynamic link discovery / validation ---
// MAX_LINK_ATTEMPTS default 15 (from user)
const MAX_LINK_ATTEMPTS = parseInt(process.env.MAX_LINK_ATTEMPTS || "15", 10);
const MIN_VALID_LINKS_PER_DAY = parseInt(process.env.MIN_VALID_LINKS_PER_DAY || "1", 10);

// global cache of validated links: Map<link, {lastValidated: timestamp, topics: Set<string>} >
// We will try to reuse links validated earlier
const validatedLinksCache = new Map();

async function validateUrl(url, keyword = "") {
  try {
    if (!url) return false;
    if (!/^https?:\/\//i.test(url)) url = "https://" + url;
    // try HEAD
    try {
      const head = await fetch(url, { method: "HEAD", redirect: "follow" });
      if (head && head.status >= 200 && head.status < 400) {
        if (!keyword) return true;
      }
    } catch (e) {
      // ignore and try GET
    }
    // GET and optional keyword check
    const getResp = await fetch(url, { method: "GET", redirect: "follow" });
    if (!getResp || getResp.status < 200 || getResp.status >= 400) return false;
    if (!keyword) return true;
    const text = await getResp.text();
    if (!text) return false;
    // check if page contains keyword token (simple)
    const token = keyword.split(/\s+/)[0].toLowerCase();
    return text.toLowerCase().includes(token);
  } catch (e) {
    return false;
  }
}

// Ask OpenAI for candidate links (AI may hallucinate; we'll validate)
async function getCandidateLinksFromAIForTopic(topic, category) {
  try {
    const sys = `Bạn là chuyên gia cung cấp nguồn học đáng tin cậy. Trả về CHỈ MỘT MẢNG JSON gồm các URL (chuỗi). Không thêm mô tả.`;
    const usr = `Hãy đề xuất tối đa 8 đường dẫn đáng tin cậy, phù hợp nhất để học về: "${topic}" (danh mục: ${category}). Trả về CHỈ MỘT MẢNG JSON như ["https://...","https://..."].`;
    const comp = await callOpenAIWithFallback({
      messages: [{ role: "system", content: sys }, { role: "user", content: usr }],
      desiredCompletionTokens: 22500,
      temperature: 1
    });
    const text = comp?.choices?.[0]?.message?.content?.trim();
    if (!text) return [];
    const fenceMatch = text.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
    const candidate = fenceMatch ? fenceMatch[1] : text;
    try {
      const arr = JSON.parse(candidate);
      if (Array.isArray(arr)) return arr.map((x) => String(x).trim()).filter(Boolean);
    } catch (e) {
      // fallback url regex
      const urls = Array.from(new Set((candidate.match(/https?:\/\/[^\s"'\)\]\s]+/g) || [])));
      return urls;
    }
  } catch (e) {
    console.warn("getCandidateLinksFromAIForTopic error:", e && e.message ? e.message : e);
    return [];
  }
  return [];
}

// For a given topic, try to return at least minLinks validated links by repeated AI queries and validation
async function getValidatedLinksForTopic(topic, category, minLinks = MIN_VALID_LINKS_PER_DAY) {
  const validated = new Set();
  const tried = new Set();

  // first attempt reuse of global cache (if any link was validated before)
  for (const [link, meta] of validatedLinksCache.entries()) {
    // quick re-check: if previously validated and topic related, test live
    try {
      const keyword = topic || "";
      const ok = await validateUrl(link, keyword);
      if (ok) {
        validated.add(link);
        // tag topic into cache meta
        meta.topics.add(topic);
        meta.lastValidated = Date.now();
        if (validated.size >= minLinks) return Array.from(validated);
      } else {
        // remove invalid from cache
        validatedLinksCache.delete(link);
      }
    } catch (e) {
      // ignore
    }
  }

  // iterative attempts with AI suggestions
  for (let attempt = 1; attempt <= MAX_LINK_ATTEMPTS; attempt++) {
    const candidates = await getCandidateLinksFromAIForTopic(topic, category);
    for (const u of candidates) {
      if (!u || tried.has(u)) continue;
      tried.add(u);
      try {
        const ok = await validateUrl(u, topic);
        if (ok) {
          validated.add(u);
          // cache it
          validatedLinksCache.set(u, { lastValidated: Date.now(), topics: new Set([topic]) });
          if (validated.size >= minLinks) return Array.from(validated);
        }
      } catch (e) {
        // ignore single url error
      }
    }
  }

  // if still not enough, fallback to category root links but try validate
  const picks = chooseLinksForCategory(category);
  for (const p of picks) {
    if (validated.size >= minLinks) break;
    if (tried.has(p)) continue;
    tried.add(p);
    try {
      if (await validateUrl(p, topic)) {
        validated.add(p);
        validatedLinksCache.set(p, { lastValidated: Date.now(), topics: new Set([topic]) });
      }
    } catch (e) {}
  }

  return Array.from(validated);
}

// simple fingerprint
function simpleFingerprint(s) {
  return (s || "").replace(/\s+/g, " ").slice(0, 120).toLowerCase();
}

// Generate fallback enriched roadmap (if AI fails)
function generateFallbackRoadmap(days, hoursPerDay, roadmapName, category, startLevel) {
  console.log(`🔧 Generating fallback roadmap (enriched) for ${days} days...`);
  const linksPool = chooseLinksForCategory(category);
  const roadmap = [];
  const topics = ["Nền tảng", "Thực hành", "Áp dụng", "Dự án nhỏ", "Ôn luyện"];
  for (let i = 1; i <= days; i++) {
    const phase = topics[(i - 1) % topics.length];
    const topic = `${phase} - phần ${((i - 1) % 5) + 1}`;
    const exercises = makeExerciseVariants(topic);
    const practice = [exercises[i % exercises.length], `Bài kiểm tra ngắn (10 câu) trên ${linksPool[0]}`];
    roadmap.push({
      day_number: i,
      daily_goal: `${phase}: Mục tiêu ngày ${i}`,
      learning_content: `Nội dung: ${topic}. Hướng dẫn: đọc tài liệu, xem ví dụ, thực hành theo bước.`,
      practice_exercises: practice.join(" | "),
      learning_materials: linksPool.join(" | "),
      study_duration_hours: parseFloat(hoursPerDay || 2),
    });
  }
  return roadmap;
}

// Strict validate & enrich function: ensures each day has enough detail and at least 1 validated link
async function validateAndEnrichRoadmap(rawDays, requiredDays, hoursPerDay, category) {
  const problems = [];
  if (!Array.isArray(rawDays)) return { ok: false, problems: ["not_array"], days: [] };

  // normalize to exact length
  let days = rawDays.slice(0, requiredDays);
  if (days.length < requiredDays) {
    // pad with fallback skeleton
    for (let i = days.length; i < requiredDays; i++) {
      days.push({
        day_number: i + 1,
        daily_goal: `Ôn tập và củng cố - Ngày ${i + 1}`,
        learning_content: `Ôn và thực hành các nội dung đã học.`,
        practice_exercises: `Bài tập ôn tập`,
        learning_materials: "",
        study_duration_hours: parseFloat(hoursPerDay || 2),
      });
    }
    problems.push("padded_missing_days");
  }

  // dedupe and enrich
  const seen = new Set();
  for (let i = 0; i < days.length; i++) {
    const dRaw = days[i] || {};
    const dd = {
      day_number: parseInt(dRaw.day_number) || (i + 1),
      daily_goal: (dRaw.daily_goal || dRaw.goal || "").toString().trim(),
      learning_content: (dRaw.learning_content || dRaw.content || "").toString().trim(),
      practice_exercises: (dRaw.practice_exercises || dRaw.exercises || "").toString().trim(),
      learning_materials: (dRaw.learning_materials || dRaw.materials || "").toString().trim(),
      study_duration_hours: parseFloat(dRaw.study_duration_hours || dRaw.hours) || hoursPerDay,
    };

    // ensure minimal lengths
    if (dd.daily_goal.length < 20) {
      dd.daily_goal = (dd.daily_goal || `Mục tiêu ngày ${i + 1}`) + ` — chi tiết ${i + 1}`;
      problems.push(`short_goal_day_${i + 1}`);
    }
    if (dd.learning_content.length < 120) {
      // attempt to expand with AI (small call)
      try {
        const sys = `Bạn là chuyên gia giáo dục. Trả về CHỈ MỘT MẢNG JSON gồm 3 bullet ngắn (chuỗi) miêu tả chi tiết cho nội dung học: không thêm text khác.`;
        const usr = `Mở rộng nội dung: "${dd.learning_content || dd.daily_goal}" thành 3 bullet ngắn (mỗi bullet <=140 ký tự). Trả về CHỈ MỘT MẢNG JSON.`;
        const comp = await callOpenAIWithFallback({
          messages: [{ role: "system", content: sys }, { role: "user", content: usr }],
          desiredCompletionTokens: 200,
          temperature: 1,
        });
        const text = comp?.choices?.[0]?.message?.content?.trim();
        if (text) {
          const fence = text.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
          const cand = fence ? fence[1] : text;
          try {
            const arr = JSON.parse(cand);
            if (Array.isArray(arr) && arr.length > 0) dd.learning_content = arr.join(" | ");
            else dd.learning_content = (dd.learning_content || "") + " (mở rộng AI)";
          } catch (e) {
            const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean).slice(0, 3);
            if (lines.length > 0) dd.learning_content = lines.join(" | ");
            else dd.learning_content = (dd.learning_content || "") + " (mở rộng fallback)";
          }
        } else dd.learning_content = (dd.learning_content || "") + " (mở rộng fallback)";
      } catch (e) {
        dd.learning_content = (dd.learning_content || "") + " (mở rộng error)";
      }
      problems.push(`expanded_content_day_${i + 1}`);
    }
    if (dd.practice_exercises.length < 30) {
      const topic = dd.daily_goal || dd.learning_content;
      dd.practice_exercises = makeExerciseVariants(topic).slice(0, 2).join(" | ");
      problems.push(`generated_practice_day_${i + 1}`);
    }

    // dedupe exact duplicates
    const fp = simpleFingerprint(dd.daily_goal + "|" + dd.learning_content);
    if (seen.has(fp)) {
      dd.daily_goal += " (mở rộng để tránh trùng lặp)";
    }
    seen.add(fp);

    days[i] = dd;
  }

  // Link discovery per day with reuse policy:
  // If any link exists in validatedLinksCache that is relevant, reuse it first (we already attempted revalidation in getValidatedLinksForTopic)
  for (let i = 0; i < days.length; i++) {
    const d = days[i];
    // If day has learning_materials with URLs, validate them
    let urlsInField = (d.learning_materials || "").match(/https?:\/\/[^\s"'\s|]+/g) || [];
    let validatedForThisDay = [];
    for (const u of urlsInField) {
      try {
        if (await validateUrl(u, d.daily_goal || d.learning_content)) {
          validatedForThisDay.push(u);
          validatedLinksCache.set(u, { lastValidated: Date.now(), topics: new Set([d.daily_goal || d.learning_content]) });
        }
      } catch (e) {}
    }

    // If not enough validated links, try to reuse any globally validated link (previous days)
    if (validatedForThisDay.length < MIN_VALID_LINKS_PER_DAY) {
      for (const [link, meta] of validatedLinksCache.entries()) {
        if (validatedForThisDay.length >= MIN_VALID_LINKS_PER_DAY) break;
        // check quickly if it already validated and still live
        try {
          if (await validateUrl(link, d.daily_goal || d.learning_content)) {
            validatedForThisDay.push(link);
            meta.lastValidated = Date.now();
            meta.topics.add(d.daily_goal || d.learning_content);
          } else {
            validatedLinksCache.delete(link);
          }
        } catch (e) {}
      }
    }

    // If still not enough, call getValidatedLinksForTopic to find new validated links (this will ask AI and validate)
    if (validatedForThisDay.length < MIN_VALID_LINKS_PER_DAY) {
      const found = await getValidatedLinksForTopic(d.daily_goal || d.learning_content || `${category} ${i+1}`, category, MIN_VALID_LINKS_PER_DAY);
      if (found && found.length > 0) {
        for (const f of found) {
          if (!validatedForThisDay.includes(f)) validatedForThisDay.push(f);
        }
      }
    }

    // As absolute last resort, attach category root links (if any)
    if (validatedForThisDay.length === 0) {
      const picks = chooseLinksForCategory(category);
      for (const p of picks) {
        try {
          if (await validateUrl(p, d.daily_goal || d.learning_content)) {
            validatedForThisDay.push(p);
            validatedLinksCache.set(p, { lastValidated: Date.now(), topics: new Set([d.daily_goal || d.learning_content]) });
            break;
          }
        } catch (e) {}
      }
    }

    d.learning_materials = (validatedForThisDay.length > 0) ? validatedForThisDay.join(" | ") : (d.learning_materials || "");
  }

  // Final checks: ensure each day has reasonable content; compute OK flag
  let failing = 0;
  for (let i = 0; i < days.length; i++) {
    const d = days[i];
    if ((d.daily_goal || "").length < 20) failing++;
    if ((d.learning_content || "").length < 80) failing++;
    if ((d.practice_exercises || "").length < 20) failing++;
    // if no validated link, count as problem
    if (!d.learning_materials || !d.learning_materials.match(/https?:\/\//)) failing++;
  }
  const ok = failing === 0 && days.length === requiredDays;
  return { ok, problems, days };
}

// --------- API endpoints (register/login/me same as existing) ----------

// Register
app.post("/api/register", async (req, res) => {
  const { name, username, email, password } = req.body;
  if (!name || !username || !email || !password) return res.status(400).json({ message: "Thiếu dữ liệu!" });
  try {
    const normalizedEmail = String(email).trim();
    const normalizedUsername = String(username).trim();
    const pw = String(password);
    const errors = {};
    if (pw.length < 8) errors.password = "Mật khẩu phải có ít nhất 8 ký tự.";
    if (!/[A-Z]/.test(pw)) errors.password = "Mật khẩu phải bao gồm ít nhất 1 chữ hoa.";
    if (!/[a-z]/.test(pw)) errors.password = "Mật khẩu phải bao gồm ít nhất 1 chữ thường.";
    if (!/[0-9]/.test(pw)) errors.password = "Mật khẩu phải bao gồm ít nhất 1 chữ số.";
    if (!/[^A-Za-z0-9]/.test(pw)) errors.password = "Mật khẩu phải bao gồm ít nhất 1 ký tự đặc biệt.";
    if (Object.keys(errors).length > 0) return res.status(400).json({ message: "Dữ liệu mật khẩu không hợp lệ.", errors });
    const existing = await pool.query("SELECT id FROM users WHERE username = $1 OR email = $2", [normalizedUsername, normalizedEmail]);
    if (existing.rows.length > 0) return res.status(409).json({ message: "Tên đăng nhập hoặc email đã tồn tại!" });
    const hashed = await hashPassword(password, 10);
    const result = await pool.query("INSERT INTO users (name, username, email, password) VALUES ($1,$2,$3,$4) RETURNING id, name, username, email", [name.trim(), normalizedUsername, normalizedEmail, hashed]);
    const user = result.rows[0];
    const token = makeToken(user.id);
    res.json({ message: "Đăng ký thành công!", token, user });
  } catch (err) {
    console.error("❌ SQL Error (register):", err && err.message ? err.message : err);
    if (err.code === "23505") return res.status(409).json({ message: "Tên đăng nhập hoặc email đã tồn tại!" });
    res.status(500).json({ message: "Lỗi server khi đăng ký!" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    console.log("[/api/login] content-type:", req.headers["content-type"]);
    console.log("[/api/login] body keys:", Object.keys(req.body || {}));
    const body = (req.body && typeof req.body === "object") ? req.body : {};
    let username = body.username ? String(body.username).trim() : "";
    let email = body.email ? String(body.email).trim() : "";
    let password = body.password ? String(body.password) : "";
    if (!password || (!username && !email)) return res.status(400).json({ message: "Thiếu tên đăng nhập hoặc email, hoặc mật khẩu!" });
    const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (email && !EMAIL_RE.test(email)) return res.status(400).json({ message: "Email không đúng định dạng!" });
    let result;
    let user;
    if (username && email) {
      result = await pool.query("SELECT id, name, username, email, password FROM users WHERE username = $1 LIMIT 1", [username]);
      if (result.rows.length === 0) return res.status(401).json({ message: "Sai tên đăng nhập hoặc mật khẩu!" });
      user = result.rows[0];
      if (String(user.email) !== String(email)) return res.status(401).json({ message: "Tên đăng nhập và email không khớp." });
    } else if (username) {
      result = await pool.query("SELECT id, name, username, email, password FROM users WHERE username = $1 LIMIT 1", [username]);
      if (result.rows.length === 0) return res.status(401).json({ message: "Sai tên đăng nhập hoặc mật khẩu!" });
      user = result.rows[0];
    } else {
      result = await pool.query("SELECT id, name, username, email, password FROM users WHERE email = $1 LIMIT 1", [email]);
      if (result.rows.length === 0) return res.status(401).json({ message: "Sai email hoặc mật khẩu!" });
      user = result.rows[0];
    }
    const match = await comparePassword(password, user.password);
    if (!match) return res.status(401).json({ message: "Sai tên đăng nhập hoặc mật khẩu!" });
    const token = makeToken(user.id);
    return res.json({ message: "Đăng nhập thành công!", token, user: { id: user.id, name: user.name, username: user.username, email: user.email } });
  } catch (err) {
    console.error("❌ SQL Error (login):", err && err.message ? err.message : err);
    return res.status(500).json({ message: "Lỗi server khi đăng nhập!" });
  }
});

// me
app.get("/api/me", async (req, res) => {
  const auth = req.headers.authorization || "";
  const token = auth.replace(/^Bearer\s+/i, "").trim();
  if (!token) return res.status(401).json({ message: "Không có token" });
  if ((token.match(/\./g) || []).length !== 2) return res.status(401).json({ message: "Token không hợp lệ" });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || "dev_local_secret");
    const result = await pool.query("SELECT id, name, username, email, role, created_at FROM users WHERE id = $1", [payload.userId]);
    if (result.rows.length === 0) return res.status(404).json({ message: "Người dùng không tồn tại" });
    res.json({ user: result.rows[0] });
  } catch (err) {
    if (err && err.name === "TokenExpiredError") return res.status(401).json({ message: "Token đã hết hạn, vui lòng đăng nhập lại" });
    console.error("Auth error:", err && err.message ? err.message : err);
    return res.status(401).json({ message: "Token không hợp lệ" });
  }
});

// === AI ROADMAP GENERATION API (main, strict validation & dynamic links) ===
app.post("/api/generate-roadmap-ai", requireAuth, async (req, res) => {
  try {
    if (!process.env.OPENAI_API_KEY) {
      return res.status(503).json({ success: false, error: "Tính năng AI chưa được cấu hình. Vui lòng liên hệ quản trị viên." });
    }

    const { roadmap_name, category, sub_category, start_level, duration_days, duration_hours, expected_outcome } = req.body;
    if (!roadmap_name || !category || !start_level || !duration_days || !duration_hours || !expected_outcome) {
      return res.status(400).json({ success: false, error: "Thiếu thông tin bắt buộc để tạo lộ trình" });
    }

    const maxDays = MAX_AI_DAYS;
    if (parseInt(duration_days) > maxDays) return res.status(400).json({ success: false, error: `AI chỉ có thể tạo lộ trình tối đa ${maxDays} ngày.` });

    const actualDays = parseInt(duration_days);
    const totalHours = parseFloat(duration_hours);
    if (isNaN(totalHours) || totalHours <= 0) return res.status(400).json({ success: false, error: "duration_hours không hợp lệ" });

    const hoursPerDay = Math.round((totalHours / actualDays) * 100) / 100;

    // strong system prompt
    const systemPrompt = `Bạn là chuyên gia giáo dục. PHẢI TRẢ VỀ CHỈ MỘT CHUỖI JSON duy nhất: { "roadmap": [ ... ] }.
Mảng 'roadmap' PHẢI có đúng ${actualDays} phần (day objects). Mỗi object phải có các trường: day_number (int), daily_goal (>=20 chars), learning_content (>=120 chars), practice_exercises (>=30 chars), learning_materials (string chứa >=1 URL), study_duration_hours (number). Ngôn ngữ: Tiếng Việt. KHÔNG thêm giải thích ngoài JSON.`;

    const userPrompt = `Dữ liệu: roadmap_name="${roadmap_name}", category="${category}${sub_category ? ` / ${sub_category}` : ""}", start_level="${start_level}", duration_days=${actualDays}, duration_hours=${totalHours}, hoursPerDay=${hoursPerDay}, expected_outcome="${expected_outcome}".
Yêu cầu: tạo JSON đúng schema, không trùng lặp, mỗi ngày có nội dung chi tiết, bài tập phong phú, và nếu có thể kèm link nguồn đúng (AI có thể gợi link nhưng server sẽ validate).`;

    const perDayEstimate = TOKENS_PER_DAY;
    const desired = Math.max(MIN_COMPLETION_TOKENS, actualDays * perDayEstimate);

    // try up to 2 AI attempts to get good main output; else fallback enriched generator
    let attempts = 0;
    const MAX_AI_ATTEMPTS = 2;
    let finalDays = null;
    let usedFallback = false;

    while (attempts < MAX_AI_ATTEMPTS && !finalDays) {
      attempts++;
      try {
        const completion = await callOpenAIWithFallback({
          messages: [{ role: "system", content: systemPrompt }, { role: "user", content: userPrompt }],
          desiredCompletionTokens: desired,
          temperature: Math.max(1, PREFERRED_OPENAI_TEMPERATURE - 0.4)
        });
        const aiResponse = completion?.choices?.[0]?.message?.content?.trim();
        if (!aiResponse) {
          console.warn("AI returned empty on attempt", attempts);
          continue;
        }

        // extract JSON robustly
        function extractJsonSubstring(text) {
          if (!text) return null;
          const fenceMatch = text.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
          if (fenceMatch && fenceMatch[1]) return fenceMatch[1].trim();
          const startIdx = text.search(/[\{\[]/);
          if (startIdx === -1) return null;
          let stack = [], inString = false, stringChar = null, escape = false;
          for (let i = startIdx; i < text.length; i++) {
            const ch = text[i];
            if (escape) { escape = false; continue; }
            if (ch === "\\") { escape = true; continue; }
            if (inString) {
              if (ch === stringChar) { inString = false; stringChar = null; }
              continue;
            } else {
              if (ch === '"' || ch === "'") { inString = true; stringChar = ch; continue; }
            }
            if (ch === "{" || ch === "[") stack.push(ch);
            else if (ch === "}" || ch === "]") {
              if (stack.length === 0) return null;
              const last = stack[stack.length - 1];
              if ((last === "{" && ch === "}") || (last === "[" && ch === "]")) {
                stack.pop();
                if (stack.length === 0) return text.slice(startIdx, i + 1).trim();
              } else return null;
            }
          }
          return null;
        }

        const candidate = extractJsonSubstring(aiResponse);
        let parsed = null;
        if (candidate) {
          try {
            parsed = JSON.parse(candidate);
          } catch (e) {
            const clean = candidate.replace(/[\u2018\u2019\u201C\u201D]/g, '"').replace(/,\s*([}\]])/g, "$1");
            try { parsed = JSON.parse(clean); } catch (e2) { parsed = null; }
          }
        }
        let candidateDays = null;
        if (parsed && Array.isArray(parsed.roadmap)) candidateDays = parsed.roadmap;
        else if (parsed && Array.isArray(parsed)) candidateDays = parsed;
        else {
          // try transform human readable
          const transformed = transformTextToDays(aiResponse, actualDays, hoursPerDay, category);
          if (transformed && transformed.length === actualDays) candidateDays = transformed;
        }

        if (!candidateDays) {
          console.warn("AI output not parseable as roadmap on attempt", attempts);
          continue;
        }

        // Validate & enrich (this includes dynamic link discovery & reuse)
        const validation = await validateAndEnrichRoadmap(candidateDays, actualDays, hoursPerDay, category);
        if (validation.ok) {
          finalDays = validation.days;
          break;
        } else {
          console.warn("Validation issues on attempt", attempts, "problems:", validation.problems.slice(0, 10));
          // try again if attempts remain
          continue;
        }
      } catch (e) {
        console.error("Error during AI attempt:", e && e.message ? e.message : e);
      }
    }

    if (!finalDays) {
      usedFallback = true;
      const generated = generateFallbackRoadmap(actualDays, hoursPerDay, roadmap_name, category, start_level);
      const validated = await validateAndEnrichRoadmap(generated, actualDays, hoursPerDay, category);
      finalDays = validated.days;
    }

    // Final normalize & ensure day_number order
    finalDays = finalDays.map((d, idx) => ({
      day_number: idx + 1,
      daily_goal: (d.daily_goal || "").replace(/\s+/g, " ").trim(),
      learning_content: (d.learning_content || "").replace(/\s+/g, " ").trim(),
      practice_exercises: (d.practice_exercises || "").replace(/\s+/g, " ").trim(),
      learning_materials: (d.learning_materials || "").trim(),
      study_duration_hours: parseFloat(d.study_duration_hours) || hoursPerDay
    }));

    console.log(`✅ Returning roadmap (usedFallback=${usedFallback}) with ${finalDays.length} days`);
    return res.json({ success: true, usedFallback, message: usedFallback ? "Tạo lộ trình bằng AI (fallback/enriched)" : "Tạo lộ trình bằng AI (validated main)", data: finalDays });
  } catch (error) {
    console.error("❌ AI Generation Error:", error && error.message ? error.message : error);
    const days = Math.max(1, parseInt(req.body.duration_days || 7));
    const hoursPerDay = parseFloat(req.body.duration_hours || 2) / days;
    const fallback = generateFallbackRoadmap(days, hoursPerDay, req.body.roadmap_name || "Roadmap", req.body.category || "general", req.body.start_level || "Beginner");
    return res.status(500).json({ success: false, error: error.message || "Lỗi khi tạo lộ trình", data: fallback });
  }
});

// --- Roadmap CRUD endpoints (reuse your existing implementations) ---

// GET all roadmaps for user
app.get("/api/roadmaps", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM learning_roadmaps WHERE user_id = $1 ORDER BY created_at DESC`, [req.user.id]);
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error("Error fetching roadmaps:", err && err.message ? err.message : err);
    res.status(500).json({ success: false, error: "Không thể lấy danh sách lộ trình" });
  }
});

// POST create roadmap (store days)
app.post("/api/roadmaps", requireAuth, async (req, res) => {
  try {
    const { roadmap_name, category, sub_category, start_level, duration_days, duration_hours, expected_outcome, days } = req.body;
    if (!roadmap_name || !category || !start_level || !duration_days || !duration_hours || !expected_outcome) {
      return res.status(400).json({ success: false, error: "Thiếu thông tin bắt buộc" });
    }
    const roadmapResult = await pool.query(
      `INSERT INTO learning_roadmaps (roadmap_name, category, sub_category, start_level, user_id, duration_days, duration_hours, expected_outcome)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING roadmap_id`,
      [roadmap_name, category, sub_category || null, start_level, req.user.id, duration_days, duration_hours, expected_outcome]
    );
    const roadmapId = roadmapResult.rows[0].roadmap_id;
    if (Array.isArray(days)) {
      for (let i = 0; i < days.length; i++) {
        const day = days[i];
        const dayNumber = parseInt(day.day_number) || (i + 1);
        await pool.query(
          `INSERT INTO learning_roadmap_details (roadmap_id, day_number, daily_goal, learning_content, practice_exercises, learning_materials, study_duration_hours)
           VALUES ($1,$2,$3,$4,$5,$6,$7)`,
          [
            roadmapId,
            dayNumber,
            day.daily_goal || day.goal || "",
            day.learning_content || day.content || "",
            day.practice_exercises || day.exercises || "",
            day.learning_materials || day.materials || "",
            parseFloat(day.study_duration_hours || day.hours || 2)
          ]
        );
      }
    }
    res.json({ success: true, roadmap_id: roadmapId, message: "Tạo lộ trình thành công" });
  } catch (err) {
    console.error("Error creating roadmap:", err && err.message ? err.message : err);
    res.status(500).json({ success: false, error: "Không thể tạo lộ trình" });
  }
});

// GET roadmap details
app.get("/api/roadmaps/:id/details", requireAuth, async (req, res) => {
  try {
    const roadmapId = parseInt(req.params.id);
    const roadmapCheck = await pool.query("SELECT user_id FROM learning_roadmaps WHERE roadmap_id = $1", [roadmapId]);
    if (roadmapCheck.rows.length === 0) return res.status(404).json({ success: false, error: "Lộ trình không tồn tại" });
    if (roadmapCheck.rows[0].user_id !== req.user.id) return res.status(403).json({ success: false, error: "Không có quyền truy cập" });
    const result = await pool.query(`SELECT * FROM learning_roadmap_details WHERE roadmap_id = $1 ORDER BY day_number ASC`, [roadmapId]);
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error("Error fetching roadmap details:", err && err.message ? err.message : err);
    res.status(500).json({ success: false, error: "Không thể lấy chi tiết lộ trình" });
  }
});

// PUT update detail status
app.put("/api/roadmaps/details/:id/status", requireAuth, async (req, res) => {
  try {
    const detailId = parseInt(req.params.id);
    const { completion_status } = req.body;
    if (!["NOT_STARTED", "IN_PROGRESS", "COMPLETED", "SKIPPED"].includes(completion_status)) return res.status(400).json({ success: false, error: "Trạng thái không hợp lệ" });
    const result = await pool.query(
      `UPDATE learning_roadmap_details SET completion_status = $1::varchar, completed_at = CASE WHEN $1::varchar = 'COMPLETED' THEN CURRENT_TIMESTAMP ELSE completed_at END, updated_at = CURRENT_TIMESTAMP WHERE detail_id = $2 RETURNING *`,
      [completion_status, detailId]
    );
    if (result.rows.length === 0) return res.status(404).json({ success: false, error: "Không tìm thấy" });
    const detail = result.rows[0];
    await pool.query(
      `UPDATE learning_roadmaps SET progress_percentage = (
         SELECT ROUND(COUNT(*) FILTER (WHERE completion_status = 'COMPLETED') * 100.0 / COUNT(*), 2)
         FROM learning_roadmap_details WHERE roadmap_id = $1
       ), updated_at = CURRENT_TIMESTAMP WHERE roadmap_id = $1`,
      [detail.roadmap_id]
    );
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error("Error updating status:", err && err.message ? err.message : err);
    res.status(500).json({ success: false, error: "Không thể cập nhật trạng thái" });
  }
});

// DELETE roadmap
app.delete("/api/roadmaps/:id", requireAuth, async (req, res) => {
  try {
    const roadmapId = parseInt(req.params.id);
    const roadmapCheck = await pool.query("SELECT user_id FROM learning_roadmaps WHERE roadmap_id = $1", [roadmapId]);
    if (roadmapCheck.rows.length === 0) return res.status(404).json({ success: false, error: "Lộ trình không tồn tại" });
    if (roadmapCheck.rows[0].user_id !== req.user.id) return res.status(403).json({ success: false, error: "Không có quyền xóa" });
    await pool.query("DELETE FROM learning_roadmaps WHERE roadmap_id = $1", [roadmapId]);
    res.json({ success: true, message: "Đã xóa lộ trình" });
  } catch (err) {
    console.error("Error deleting roadmap:", err && err.message ? err.message : err);
    res.status(500).json({ success: false, error: "Không thể xóa lộ trình" });
  }
});

// root / SPA fallback
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

// start server
const PORT = parseInt(process.env.PORT || "5000", 10);
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`ℹ️  Local: http://localhost:${PORT}/`);
});


