// server.js (ESM) - Optimized for AI Roadmap Generation
import express from "express";
import { Pool } from "pg";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import OpenAI from "openai";
import multer from "multer";
import XLSX from "xlsx";
import Joi from "joi";

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
const rawOpenAiKey = (process.env.OPENAI_API_KEY || "").trim();
const openAiKey = rawOpenAiKey.replace(/^['"]|['"]$/g, "");

// ✅ THÊM DEBUG
if (!openAiKey || openAiKey.length < 20) {
  console.error("❌❌❌ OPENAI_API_KEY NOT SET OR INVALID!");
  console.error("❌ Key length:", openAiKey.length);
} else {
  console.log("✅ OPENAI key valid, length:", openAiKey.length, "last6:", openAiKey.slice(-6));
}

const openai = new OpenAI({ apiKey: openAiKey });

// Safe debug: show length and last few chars (avoid printing full key)
console.log("Using OPENAI key length:", openAiKey.length, " last6:", openAiKey.slice(-6));
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
// Postgres pool - FORCE POOLER
let poolConfig = {};

if (process.env.DATABASE_URL) {
  console.log('🔗 Using DATABASE_URL from env');
  poolConfig = {
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 5, // Giới hạn connections cho serverless
    idleTimeoutMillis: 20000,
    connectionTimeoutMillis: 10000
  };
} else {
  console.error('❌ DATABASE_URL not found! Using fallback config');
  poolConfig = {
    user: process.env.DB_USER || "postgres",
    host: process.env.DB_HOST || "localhost",
    database: process.env.DB_NAME || "postgres",
    password: process.env.DB_PASSWORD || "",
    port: parseInt(process.env.DB_PORT || "5432", 10),
    ssl: { rejectUnauthorized: false }
  };
}

const pool = new Pool(poolConfig);

// Error handler
pool.on('error', (err) => {
  console.error('❌ Unexpected pool error:', err.message);
});
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ext !== '.xlsx' && ext !== '.xls') {
      return cb(new Error('Chỉ chấp nhận file Excel (.xlsx, .xls)'));
    }
    cb(null, true);
  }
});
if (!process.env.JWT_SECRET) {
  console.warn("⚠️ Warning: JWT_SECRET not set. Using default dev secret.");
}
if (!process.env.OPENAI_API_KEY) {
  console.warn("⚠️ Warning: OPENAI_API_KEY not set. AI features will not work.");
}

// quick DB test
(async function testDB() {
  try {
    console.log('🔍 Testing database connection...');
    console.log('📋 Pool config:', {
      host: poolConfig.host || 'from connectionString',
      database: poolConfig.database || 'from connectionString',
      port: poolConfig.port || 'from connectionString',
      ssl: poolConfig.ssl ? 'enabled' : 'disabled'
    });
    
    const client = await pool.connect();
    
    try {
      await client.query("SET client_encoding = 'UTF8'");
    } catch (e) {
      console.warn("⚠️ Could not set client_encoding to UTF8:", e.message);
    }
    
    const result = await client.query('SELECT NOW() as current_time');
    console.log(`✅ PostgreSQL connected at: ${result.rows[0].current_time}`);
    
    client.release();
  } catch (err) {
    console.error("❌ PostgreSQL connection failed:");
    console.error("   Message:", err.message);
    console.error("   Code:", err.code);
    console.error("   Host:", err.hostname || 'N/A');
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

// AI config - CRITICAL: Temperature MUST be 1
const MAX_AI_DAYS = parseInt(process.env.MAX_AI_DAYS || "180", 10);
const MAX_AI_TOKENS = parseInt(process.env.MAX_AI_TOKENS || "400000", 10);
const TOKENS_PER_DAY = parseInt(process.env.TOKENS_PER_DAY || "1500", 10);
const PREFERRED_OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-5-nano";
const FALLBACK_OPENAI_MODEL = process.env.FALLBACK_OPENAI_MODEL || "gpt-4o";
const SAFETY_MARGIN_TOKENS = parseInt(process.env.SAFETY_MARGIN_TOKENS || "2048", 10);
const MIN_COMPLETION_TOKENS = 128;
const AI_TEMPERATURE = 1; // MUST BE 1

function buildOpenAIParams({ model, messages, maxCompletionTokens }) {
  const tokens = Math.max(MIN_COMPLETION_TOKENS, Math.floor(maxCompletionTokens || MIN_COMPLETION_TOKENS));
  return {
    model,
    messages,
    max_completion_tokens: tokens,
    temperature: AI_TEMPERATURE, // Always 1
  };
}

// ...existing code...
async function callOpenAIWithFallback({ messages, desiredCompletionTokens }) {
  const capped = Math.max(MIN_COMPLETION_TOKENS, Math.min(desiredCompletionTokens, MAX_AI_TOKENS - SAFETY_MARGIN_TOKENS));
  try {
    const params = buildOpenAIParams({ model: PREFERRED_OPENAI_MODEL, messages, maxCompletionTokens: capped });
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
      const fallbackParams = buildOpenAIParams({ model: FALLBACK_OPENAI_MODEL, messages, maxCompletionTokens: fallbackTokens });
      return await openai.chat.completions.create(fallbackParams);
    }
    throw err;
  }
}

// ---------------- DB init ----------------
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
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ai_query_history (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        query_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        prompt_content TEXT NOT NULL,
        status VARCHAR(20) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'SUCCESS', 'FAIL', 'TIMEOUT')),
        roadmap_id INTEGER REFERENCES learning_roadmaps(roadmap_id) ON DELETE SET NULL,
        error_message TEXT,
        response_tokens INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    await pool.query(`ALTER TABLE ai_query_history ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_roadmaps_user_id ON learning_roadmaps(user_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_roadmaps_status ON learning_roadmaps(status);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_roadmap_details_roadmap_id ON learning_roadmap_details(roadmap_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_roadmap_details_completion ON learning_roadmap_details(completion_status);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_ai_history_user ON ai_query_history(user_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_ai_history_time ON ai_query_history(query_time DESC);`);
    // ============ THÊM CÁC TABLE CATEGORY ============
    await pool.query(`
      CREATE TABLE IF NOT EXISTS categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) UNIQUE NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS sub_categories (
        id SERIAL PRIMARY KEY,
        category_id INTEGER NOT NULL REFERENCES categories(id) ON DELETE CASCADE,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(category_id, name)
      );
    `);

    // Insert dữ liệu mẫu
    await pool.query(`
      INSERT INTO categories (name, description) VALUES
      ('Lập trình', 'Các ngôn ngữ và framework lập trình'),
      ('Marketing', 'Digital Marketing và truyền thông'),
      ('Thiết kế', 'UI/UX và đồ họa'),
      ('Ngoại ngữ', 'Học ngoại ngữ và giao tiếp'),
      ('Kinh doanh', 'Kỹ năng kinh doanh và quản lý'),
      ('Kỹ năng mềm', 'Kỹ năng giao tiếp và làm việc nhóm')
      ON CONFLICT (name) DO NOTHING;
    `);
    // ✅ BỔ SUNG: Đảm bảo cột study_date tồn tại
    await pool.query(`
      DO $$ 
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns 
          WHERE table_name = 'learning_roadmap_details' 
          AND column_name = 'study_date'
        ) THEN
          ALTER TABLE learning_roadmap_details 
          ADD COLUMN study_date DATE;
        END IF;
      END $$;
    `);
    // ✅ TẠO INDEX cho study_date để tăng tốc query
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_roadmap_details_study_date 
      ON learning_roadmap_details(study_date);
    `);
    console.log("✅ DB initialized");
  } catch (err) {
    console.error("❌ DB init error:", err && err.message ? err.message : err);
  }
}
initDB();

// ---------------- Auth middlewares ----------------
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

// ============== OPTIMIZED AI ROADMAP GENERATION ==============

// Link validation - GIỮ ĐƠN GIẢN, KHÔNG QUÁ STRICT
const linkCache = new Map();
const LINK_CACHE_TTL = 3600000; // 1 hour

async function validateUrlQuick(url, timeout = 8000) {
  try {
    if (!url || typeof url !== 'string') return false;
    if (!/^https?:\/\//i.test(url)) url = "https://" + url;
    
    const cached = linkCache.get(url);
    if (cached && (Date.now() - cached.timestamp) < LINK_CACHE_TTL) {
      return cached.valid;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    try {
      const response = await fetch(url, {
        method: "HEAD",
        redirect: "follow",
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      
      const isValid = response && response.status >= 200 && response.status < 500; // Chấp nhận cả 404 (một số site block HEAD)
      linkCache.set(url, { valid: isValid, timestamp: Date.now() });
      return isValid;
    } catch (e) {
      clearTimeout(timeoutId);
      // Nếu timeout hoặc lỗi network, CÓ THỂ link vẫn OK, chấp nhận nó
      linkCache.set(url, { valid: true, timestamp: Date.now() });
      return true;
    }
  } catch (e) {
    return true; // Default accept nếu không validate được
  }
}

// ✅ SIMPLIFIED: 1 PROMPT CHUNG CHO MỌI CATEGORY - KHÔNG VALIDATE
async function getSpecificExerciseLink(topic, category, dayNumber, learningContent) {
  const MAX_ATTEMPTS = 5;
  const DEBUG = true; // Bật log cho test
  const USE_PUPPETEER = true; // Nếu GET trả HTML rỗng/JS-heavy thì thử Puppeteer
  const ENFORCE_WHITELIST = false; // true => chỉ chấp nhận domains trong WHITELIST_DOMAINS
  const WHITELIST_DOMAINS = [
    'leetcode.com','codeforces.com','atcoder.jp','geeksforgeeks.org',
    'hackerrank.com','freecodecamp.org','edabit.com','uva.onlinejudge.org',
    'interviewbit.com','cses.fi'
  ];

  const KEYWORD_TOKENS = topic.toLowerCase().split(/\W+/).filter(Boolean).slice(0, 4);

  const fetchWithTimeout = async (url, opts = {}, timeout = 5000) => {
    if (typeof fetch === 'undefined') {
      // If Node <18 you must polyfill fetch in your project (node-fetch)
      throw new Error('fetch not available - polyfill required for fetchWithTimeout');
    }
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    try {
      const res = await fetch(url, { ...opts, signal: controller.signal });
      clearTimeout(id);
      return res;
    } catch (e) {
      clearTimeout(id);
      throw e;
    }
  };

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      const systemPrompt = `You are an expert at finding ONE SPECIFIC exercise URL for a given topic.
OUTPUT EXACT FORMAT (single line): <URL> --- keyword: <one_word_from_topic>
Rules:
- Return a URL that points directly to a single exercise/problem page (not a category, course, or listing).
- URL must have at least 2 non-empty path segments.
- Avoid pages that are generic landing/overview/course lists.
- Include exactly one short keyword after '--- keyword:' that is clearly related to the topic.`;

      const userPrompt = `Day ${dayNumber}. Topic: "${topic}". Category: "${category}".
Focus: "${learningContent.substring(0, 300)}".
Return a concrete exercise URL and one short keyword (format above).`;

      const completion = await callOpenAIWithFallback({
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt }
        ],
        model: "gpt-5-nano",
        temperature: 1,
        desiredCompletionTokens: 220
      });

      const text = completion?.choices?.[0]?.message?.content?.trim();
      if (!text) {
        if (DEBUG) console.log(`[Exercise][Attempt ${attempt}] no text from model`);
        continue;
      }

      const urlMatch = text.match(/https?:\/\/[^\s"'()<>\]]+/i);
      const kwMatch = text.match(/keyword:\s*([^\s]+)/i);
      if (!urlMatch) {
        if (DEBUG) console.log(`[Exercise][Attempt ${attempt}] no URL in model output:`, text);
        continue;
      }

      let url = urlMatch[0].replace(/[.,;:!?]+$/, '');
      // whitelist enforcement
      try {
        const hostname = new URL(url).hostname.replace(/^www\./, '').toLowerCase();
        if (ENFORCE_WHITELIST && !WHITELIST_DOMAINS.some(d => hostname.endsWith(d))) {
          if (DEBUG) console.log(`[Exercise][Attempt ${attempt}] domain not in whitelist:`, hostname);
          continue;
        }
      } catch (e) {
        if (DEBUG) console.log(`[Exercise][Attempt ${attempt}] invalid URL parse`, e.message);
        continue;
      }

      const quickOk = await validateUrlQuick(url, 4000).catch(e => { if (DEBUG) console.log('validateUrlQuick err', e.message); return false; });
      if (!quickOk) {
        if (DEBUG) console.log(`[Exercise][Attempt ${attempt}] validateUrlQuick failed for`, url);
        continue;
      }

      // path check
      const urlObj = new URL(url);
      const pathParts = urlObj.pathname.split('/').filter(p => p.length > 0);
      if (pathParts.length < 2) {
        if (DEBUG) console.log(`[Exercise][Attempt ${attempt}] path too short:`, url);
        continue;
      }

      const bannedWords = ['problems','exercises','challenges','kata','practice','lessons','courses','blog','articles','learn','tutorials','dashboard','tracks','overview','topics'];
      const lastSegment = pathParts[pathParts.length - 1].toLowerCase();
      if (bannedWords.includes(lastSegment)) {
        if (DEBUG) console.log(`[Exercise][Attempt ${attempt}] banned last segment:`, lastSegment);
        continue;
      }

      // fetch page and inspect title/meta/body for topic tokens
      let pageText = '';
      try {
        // HEAD quick check
        try {
          const head = await fetchWithTimeout(url, { method: 'HEAD', headers: { 'User-Agent': 'Mozilla/5.0' } }, 2500);
          const ct = (head.headers.get('content-type') || '').toLowerCase();
          if (!ct.includes('text/html') && !ct.includes('application/xhtml+xml')) {
            // still continue to GET once - some sites mis-report
          }
        } catch (e) {
          // ignore HEAD failure
        }
        const getRes = await fetchWithTimeout(url, { method: 'GET', headers: { 'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html' } }, 5000);
        if (!getRes.ok) {
          if (DEBUG) console.log(`[Exercise][Attempt ${attempt}] GET failed status`, getRes.status);
          continue;
        }
        pageText = await getRes.text();
      } catch (e) {
        if (DEBUG) console.log(`[Exercise][Attempt ${attempt}] fetch failed`, e.message);
        // try puppeteer below if allowed
        pageText = '';
      }

      // if pageText is empty or doesn't contain tokens, optionally try Puppeteer (for JS-heavy pages)
      const loweredFetch = (pageText || '').toLowerCase();
      const reportedKw = kwMatch ? kwMatch[1].toLowerCase() : '';
      let tokenMatch = KEYWORD_TOKENS.some(t => t && loweredFetch.includes(t));
      let reportedPresent = reportedKw && loweredFetch.includes(reportedKw);

      if ((!tokenMatch && !reportedPresent) && USE_PUPPETEER) {
        // attempt puppeteer render once
        try {
          if (DEBUG) console.log(`[Exercise][Attempt ${attempt}] trying puppeteer for`, url);
          let puppeteer;
          try { puppeteer = require('puppeteer'); } catch (e) { puppeteer = null; if (DEBUG) console.log('puppeteer not installed'); }
          if (puppeteer) {
            const browser = await puppeteer.launch({ args: ['--no-sandbox','--disable-setuid-sandbox'] });
            const page = await browser.newPage();
            await page.setUserAgent('Mozilla/5.0');
            await page.goto(url, { waitUntil: 'networkidle2', timeout: 8000 }).catch(()=>{});
            const content = await page.content();
            await browser.close();
            const lowered = content.toLowerCase();
            tokenMatch = KEYWORD_TOKENS.some(t => t && lowered.includes(t));
            reportedPresent = reportedKw && lowered.includes(reportedKw);
            pageText = content;
          }
        } catch (e) {
          if (DEBUG) console.log(`[Exercise][Attempt ${attempt}] puppeteer error`, e.message);
        }
      }

      if (!(tokenMatch || reportedPresent)) {
        if (DEBUG) console.log(`[Exercise][Attempt ${attempt}] keyword not found in page/title/meta`, { url, reportedKw, KEYWORD_TOKENS });
        continue;
      }

      if (DEBUG) console.log(`[Exercise][Accepted] attempt ${attempt} -> ${url}`);
      return url;
    } catch (err) {
      if (DEBUG) console.log(`[Exercise][Attempt ${attempt}] exception`, err && err.message);
      continue;
    }
  }

  return null;
}


async function getSpecificMaterialLink(topic, category, dayNumber, learningContent) {
  const MAX_ATTEMPTS = 5;
  const DEBUG = true;
  const USE_PUPPETEER = true;
  const ENFORCE_WHITELIST = false;
  const WHITELIST_DOMAINS = [
    'developer.mozilla.org','freecodecamp.org','geeksforgeeks.org','w3schools.com',
    'tutorialspoint.com','medium.com','dev.to','stackabuse.com'
  ];

  const KEYWORD_TOKENS = topic.toLowerCase().split(/\W+/).filter(Boolean).slice(0, 4);

  const fetchWithTimeout = async (url, opts = {}, timeout = 5000) => {
    if (typeof fetch === 'undefined') throw new Error('fetch not available - polyfill required');
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    try {
      const res = await fetch(url, { ...opts, signal: controller.signal });
      clearTimeout(id);
      return res;
    } catch (e) {
      clearTimeout(id);
      throw e;
    }
  };

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      const systemPrompt = `You are an expert at finding ONE SPECIFIC tutorial/article/document URL for a given topic.
OUTPUT EXACT FORMAT (single line): <URL> --- keyword: <one_word_from_topic>
Rules:
- Return a URL that points directly to a single article/tutorial/page (not a list or course landing).
- URL must have at least 2 non-empty path segments.`;

      const userPrompt = `Day ${dayNumber}. Topic: "${topic}". Category: "${category}".
Focus: "${learningContent.substring(0, 300)}".
Return one concrete material URL and one short keyword (format above).`;

      const completion = await callOpenAIWithFallback({
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt }
        ],
        model: "gpt-5-nano",
        temperature: 1,
        desiredCompletionTokens: 220
      });

      const text = completion?.choices?.[0]?.message?.content?.trim();
      if (!text) {
        if (DEBUG) console.log(`[Material][Attempt ${attempt}] no text`);
        continue;
      }

      const urlMatch = text.match(/https?:\/\/[^\s"'()<>\]]+/i);
      const kwMatch = text.match(/keyword:\s*([^\s]+)/i);
      if (!urlMatch) {
        if (DEBUG) console.log(`[Material][Attempt ${attempt}] no url in output`, text);
        continue;
      }

      let url = urlMatch[0].replace(/[.,;:!?]+$/, '');
      // whitelist enforcement
      try {
        const hostname = new URL(url).hostname.replace(/^www\./, '').toLowerCase();
        if (ENFORCE_WHITELIST && !WHITELIST_DOMAINS.some(d => hostname.endsWith(d))) {
          if (DEBUG) console.log(`[Material][Attempt ${attempt}] domain not in whitelist:`, hostname);
          continue;
        }
      } catch (e) {
        if (DEBUG) console.log(`[Material][Attempt ${attempt}] invalid url parse`, e.message);
        continue;
      }

      const quickOk = await validateUrlQuick(url, 4000).catch(e => { if (DEBUG) console.log('validateUrlQuick err', e.message); return false; });
      if (!quickOk) {
        if (DEBUG) console.log(`[Material][Attempt ${attempt}] validateUrlQuick failed`, url);
        continue;
      }

      const urlObj = new URL(url);
      const pathParts = urlObj.pathname.split('/').filter(p => p.length > 0);
      if (pathParts.length < 2) {
        if (DEBUG) console.log(`[Material][Attempt ${attempt}] path too short`);
        continue;
      }

      const bannedWords = ['blog','articles','learn','tutorials','overview','guide','dashboard','topics','courses'];
      const lastSegment = pathParts[pathParts.length - 1].toLowerCase();
      if (bannedWords.includes(lastSegment)) {
        if (DEBUG) console.log(`[Material][Attempt ${attempt}] banned last segment`, lastSegment);
        continue;
      }

      // fetch and inspect page
      let pageText = '';
      try {
        try {
          await fetchWithTimeout(url, { method: 'HEAD', headers: { 'User-Agent': 'Mozilla/5.0' } }, 2500);
        } catch (e) { /* ignore HEAD failure */ }
        const getRes = await fetchWithTimeout(url, { method: 'GET', headers: { 'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html' } }, 5000);
        if (!getRes.ok) {
          if (DEBUG) console.log(`[Material][Attempt ${attempt}] GET not ok`, getRes.status);
          continue;
        }
        pageText = await getRes.text();
      } catch (e) {
        if (DEBUG) console.log(`[Material][Attempt ${attempt}] fetch failed`, e.message);
        pageText = '';
      }

      const loweredFetch = (pageText || '').toLowerCase();
      const reportedKw = kwMatch ? kwMatch[1].toLowerCase() : '';
      let tokenMatch = KEYWORD_TOKENS.some(t => t && loweredFetch.includes(t));
      let reportedPresent = reportedKw && loweredFetch.includes(reportedKw);

      if ((!tokenMatch && !reportedPresent) && USE_PUPPETEER) {
        try {
          if (DEBUG) console.log(`[Material][Attempt ${attempt}] trying puppeteer for`, url);
          let puppeteer;
          try { puppeteer = require('puppeteer'); } catch (e) { puppeteer = null; if (DEBUG) console.log('puppeteer not installed'); }
          if (puppeteer) {
            const browser = await puppeteer.launch({ args: ['--no-sandbox','--disable-setuid-sandbox'] });
            const page = await browser.newPage();
            await page.setUserAgent('Mozilla/5.0');
            await page.goto(url, { waitUntil: 'networkidle2', timeout: 8000 }).catch(()=>{});
            const content = await page.content();
            await browser.close();
            const lowered = content.toLowerCase();
            tokenMatch = KEYWORD_TOKENS.some(t => t && lowered.includes(t));
            reportedPresent = reportedKw && lowered.includes(reportedKw);
            pageText = content;
          }
        } catch (e) {
          if (DEBUG) console.log(`[Material][Attempt ${attempt}] puppeteer error`, e.message);
        }
      }

      if (!(tokenMatch || reportedPresent)) {
        if (DEBUG) console.log(`[Material][Attempt ${attempt}] keyword not found in page/title/meta`, { url, reportedKw, KEYWORD_TOKENS });
        continue;
      }

      if (DEBUG) console.log(`[Material][Accepted] attempt ${attempt} -> ${url}`);
      return url;
    } catch (err) {
      if (DEBUG) console.log(`[Material][Attempt ${attempt}] exception`, err && err.message);
      continue;
    }
  }

  return null;
}


// Fallback links by category - ĐẦY ĐỦ CHO MỌI CATEGORY
const FALLBACK_LINKS = {
  programming: {
    exercises: [
      "https://www.hackerrank.com/challenges/solve-me-first/problem",
      "https://leetcode.com/problems/two-sum/",
      "https://www.geeksforgeeks.org/problems/array-insert-at-index",
      "https://codeforces.com/problemset/problem/4/A",
      "https://www.codechef.com/problems/START01"
    ],
    materials: [
      "https://www.geeksforgeeks.org/learn-data-structures-and-algorithms-dsa-tutorial/",
      "https://developer.mozilla.org/en-US/docs/Learn/JavaScript/First_steps",
      "https://www.w3schools.com/python/python_intro.asp",
      "https://www.tutorialspoint.com/cprogramming/index.htm"
    ]
  },
  english: {
    exercises: [
      "https://www.perfect-english-grammar.com/present-simple-exercise-1.html",
      "https://www.englishpage.com/verbpage/presentperfect.html",
      "https://learnenglish.britishcouncil.org/grammar/beginner-to-pre-intermediate/present-simple",
      "https://www.englishclub.com/grammar/verb-tenses_simple-present_quiz.htm"
    ],
    materials: [
      "https://www.bbc.co.uk/learningenglish/english/course/lower-intermediate/unit-1",
      "https://learnenglish.britishcouncil.org/grammar/english-grammar-reference",
      "https://www.englishclub.com/grammar/sentence/",
      "https://www.perfect-english-grammar.com/grammar-explanations.html"
    ]
  },
  math: {
    exercises: [
      "https://www.khanacademy.org/math/algebra/x2f8bb11595b61c86:linear-equations-functions",
      "https://www.mathsisfun.com/algebra/index-practice.html",
      "https://brilliant.org/practice/algebra-equations/",
      "https://www.ixl.com/math/algebra-1"
    ],
    materials: [
      "https://www.khanacademy.org/math/algebra/x2f8bb11595b61c86:foundation-algebra",
      "https://www.mathsisfun.com/algebra/index.html",
      "https://brilliant.org/wiki/algebra/",
      "https://mathworld.wolfram.com/Algebra.html"
    ]
  },
  marketing: {
    exercises: [
      "https://academy.hubspot.com/lessons/creating-buyer-personas",
      "https://learndigital.withgoogle.com/digitalgarage/course/digital-marketing",
      "https://www.coursera.org/learn/wharton-marketing/quiz/",
      "https://www.semrush.com/academy/courses/seo-fundamentals-with-greg-gifford/"
    ],
    materials: [
      "https://blog.hubspot.com/marketing/what-is-marketing",
      "https://neilpatel.com/blog/beginners-guide-to-digital-marketing/",
      "https://moz.com/learn/seo/what-is-seo",
      "https://contentmarketinginstitute.com/what-is-content-marketing/"
    ]
  },
  design: {
    exercises: [
      "https://www.dailyui.co/",
      "https://designercize.com/challenge/design-a-landing-page",
      "https://uxchallenge.co/",
      "https://sharpen.design/challenges"
    ],
    materials: [
      "https://www.nngroup.com/articles/ten-usability-heuristics/",
      "https://www.interaction-design.org/literature/article/what-is-user-experience-ux-design",
      "https://uxdesign.cc/ux-design-methods-deliverables-657f54ce3c7d",
      "https://www.smashingmagazine.com/2018/01/comprehensive-guide-ux-design/"
    ]
  },
  softskills: {
    exercises: [
      "https://www.mindtools.com/a0aqrse/how-good-are-your-communication-skills",
      "https://www.themuse.com/advice/self-assessment-examples",
      "https://www.indeed.com/career-advice/career-development/team-building-activities",
      "https://hbr.org/2022/03/what-self-awareness-really-is-and-how-to-cultivate-it"
    ],
    materials: [
      "https://www.mindtools.com/auc6xrk/communication-skills",
      "https://www.indeed.com/career-advice/career-development/interpersonal-skills",
      "https://www.themuse.com/advice/emotional-intelligence-skills",
      "https://hbr.org/2017/02/how-to-build-a-culture-of-learning"
    ]
  },
  business: {
    exercises: [
      "https://www.coursera.org/learn/wharton-introduction-financial-accounting/quiz/",
      "https://academy.hubspot.com/lessons/sales-fundamentals",
      "https://learndigital.withgoogle.com/digitalgarage/course/business-strategy",
      "https://www.linkedin.com/learning/business-analysis-foundations/quiz/"
    ],
    materials: [
      "https://hbr.org/topic/business-management",
      "https://www.investopedia.com/financial-term-dictionary-4769738",
      "https://www.mindtools.com/amtbj63/porters-five-forces",
      "https://blog.hubspot.com/sales/business-strategy"
    ]
  },
  default: {
    exercises: [
      "https://www.khanacademy.org/",
      "https://www.coursera.org/courses",
      "https://www.edx.org/learn",
      "https://www.udemy.com/"
    ],
    materials: [
      "https://en.wikipedia.org/wiki/Main_Page",
      "https://www.khanacademy.org/",
      "https://www.youtube.com/education",
      "https://www.coursera.org/"
    ]
  }
};

function getFallbackLinks(category) {
  const cat = (category || '').toLowerCase();
  
  // Lập trình
  if (cat.includes('lập trình') || cat.includes('program') || cat.includes('code')) {
    return FALLBACK_LINKS.programming;
  }
  
  // Tiếng Anh
  if (cat.includes('tiếng anh') || cat.includes('english') || cat.includes('ngoại ngữ')) {
    return FALLBACK_LINKS.english;
  }
  
  // Toán
  if (cat.includes('toán') || cat.includes('math')) {
    return FALLBACK_LINKS.math;
  }
  
  // Marketing
  if (cat.includes('marketing')) {
    return FALLBACK_LINKS.marketing;
  }
  
  // Thiết kế
  if (cat.includes('thiết kế') || cat.includes('design') || cat.includes('ui') || cat.includes('ux')) {
    return FALLBACK_LINKS.design;
  }
  
  // Kỹ năng mềm
  if (cat.includes('kỹ năng mềm') || cat.includes('soft skill')) {
    return FALLBACK_LINKS.softskills;
  }
  
  // Kinh doanh
  if (cat.includes('kinh doanh') || cat.includes('business') || cat.includes('quản lý')) {
    return FALLBACK_LINKS.business;
  }
  
  return FALLBACK_LINKS.default;
}
// Main AI roadmap generation endpoint
// server.js (CHỈ SỬA PHẦN /api/generate-roadmap-ai ENDPOINT)

async function getPromptTemplate() {
    try {
        const query = `
            SELECT prompt_template, json_format_response
            FROM admin_settings
            WHERE setting_key = 'prompt_template'
            LIMIT 1
        `;
        
        const result = await pool.query(query);
        
        const defaultPrompt = buildDefaultPromptTemplate();
        const defaultJsonFormat = JSON.stringify({
            analysis: "Phân tích chi tiết...",
            roadmap: []
        });

        if (result && result.rows && result.rows.length > 0) {
            const row = result.rows[0];
            return {
                prompt_template: row.prompt_template || defaultPrompt,
                json_format_response: row.json_format_response || defaultJsonFormat
            };
        }
        
        return {
            prompt_template: defaultPrompt,
            json_format_response: defaultJsonFormat
        };
    } catch (error) {
        console.error('Error getting prompt template:', error);
        return {
            prompt_template: buildDefaultPromptTemplate(),
            json_format_response: JSON.stringify({ analysis: "", roadmap: [] })
        };
    }
}

function buildDefaultPromptTemplate() {
    return `**THIẾT KẾ LỘ TRÌNH HỌC CÁ NHÂN HÓA: <CATEGORY> -- <SUB_CATEGORY>**
      **I/ Vai trò của AI**
      Bạn là một chuyên gia giáo dục <CATEGORY> -- <SUB_CATEGORY> có 15+ năm kinh nghiệm.

      **II/ Thông tin từ học viên:**
      - <MAIN_PURPOSE>
      - <SPECIFIC_GOAL>
      - <CURRENT_JOB>
      - <STUDY_TIME>
      - <CURRENT_LEVEL>
      - <SKILLS_TO_IMPROVE>
      - <DAILY_TIME>
      - <WEEKLY_FREQUENCY>
      - <TOTAL_DURATION>
      - <LEARNING_STYLE>
      - <LEARNING_METHOD>
      - <DIFFICULTIES>
      - <MOTIVATION>
      - <MATERIAL_TYPE>
      - <MATERIAL_LANGUAGE>
      - <ASSESSMENT_TYPE>
      - <RESULT_DISPLAY>
      - <ASSESSMENT_FREQUENCY>

      **III/ Yêu cầu**
      Tạo lộ trình với 2 phần:
      1. Phân tích hiện trạng
      2. Lộ trình chi tiết (7 cột: day, goal, content, exercises, materials, instructions, duration)

      Trả về JSON format:
      {
        "analysis": "Phân tích chi tiết...",
        "roadmap": [
          {
            "day": 1,
            "goal": "Mục tiêu ngày 1",
            "content": "Nội dung học tập",
            "exercises": "Bài tập thực hành",
            "materials": "https://...",
            "instructions": "Hướng dẫn chi tiết",
            "duration": "1 giờ"
          }
        ]
      }`;
}

app.post("/api/generate-roadmap-ai", requireAuth, async (req, res) => {
  let historyId = null;
  
  try {
    console.log('🚀 AI REQUEST RECEIVED');
    console.log('📦 Request body keys:', Object.keys(req.body));
    console.log('👤 User ID:', req.user.id);
    if (!process.env.OPENAI_API_KEY) {
      return res.status(503).json({ success: false, error: "Tính năng AI chưa được cấu hình. Vui lòng liên hệ quản trị viên." });
    }

    // ✅ LẤY TẤT CẢ DỮ LIỆU TỪ 20 CÂU HỎI (FIXED)
    const {
      roadmap_name,
      category,
      sub_category,
      start_level,
      duration_days,
      duration_hours,
      expected_outcome,
      customized_prompt,
      // Q1-Q5
      q1_roadmap_name,
      q2_category,
      q3_category_detail,
      q4_main_purpose,
      q4_main_purpose_other, // ✅ THÊM
      q5_specific_goal,
      q5_current_job, // ✅ THÊM MỚI
      // Q6-Q8
      q6_learning_duration,
      q7_current_level,
      q8_skills_text,
      // Q9-Q11
      q9_daily_time,
      q10_weekly_sessions,
      q11_program_days,
      // Q12-Q13
      q12_learning_styles,
      q12_learning_styles_other, // ✅ THÊM
      q13_learning_combinations,
      q13_learning_combinations_other, // ✅ THÊM
      // Q14-Q15
      q14_challenges,
      q14_challenges_other, // ✅ THÊM
      q15_motivation,
      q15_motivation_other, // ✅ THÊM
      // Q16-Q20
      q16_material_types,
      q16_material_types_other, // ✅ THÊM
      q17_material_language,
      q18_assessment_types,
      q19_result_display,
      q20_assessment_frequency,
      q20_assessment_frequency_other // ✅ THÊM
    } = req.body;

    // ✅ HÀM XỬ LÝ ARRAY + "OTHER" (FIXED)
    const processArrayWithOther = (arr, otherValue) => {
      if (!Array.isArray(arr)) return '';
      const filtered = arr.filter(v => v && v !== 'Khác' && v !== 'AI gợi ý');
      if (otherValue && otherValue.trim()) {
        filtered.push(otherValue.trim());
      }
      return filtered.length > 0 ? filtered.join(', ') : 'Chưa xác định';
    };

    // ✅ HÀM XỬ LÝ RADIO + "OTHER" (FIXED)
    const processRadioWithOther = (value, otherValue) => {
      if (!value) return 'Chưa xác định';
      if (value === 'Khác' && otherValue && otherValue.trim()) {
        return otherValue.trim();
      }
      return value;
    };

    // ✅ TÀI CHÍNH DỮ LIỆU - ƯU TIÊN DỮ LIỆU TỪ 20 CÂU HỎI (FIXED)
    const finalData = {
      // Basic Info
      roadmap_name: q1_roadmap_name || roadmap_name,
      category: q2_category || category,
      category_detail: q3_category_detail || sub_category,
      
      // Q4 - Main Purpose (FIXED: xử lý "Khác")
      main_purpose: processRadioWithOther(q4_main_purpose, q4_main_purpose_other),
      
      // Q5 - Specific Goal
      specific_goal: q5_specific_goal || expected_outcome,
      
      // Q6-Q8 - Current Level
      current_job: q5_current_job || 'Chưa xác định', // MỚI
      learning_duration: q6_learning_duration || 'Chưa xác định',
      current_level: q7_current_level || start_level,
      skills_text: q8_skills_text || 'Chưa xác định',
      
      // Q9-Q11 - Time Commitment
      daily_time: q9_daily_time || 'Chưa xác định',
      weekly_sessions: q10_weekly_sessions || 'Chưa xác định',
      program_days: q11_program_days || duration_days,
      
      // Q12-Q13 - Learning Style (FIXED: xử lý array + other)
      learning_styles: processArrayWithOther(q12_learning_styles, q12_learning_styles_other),
      learning_combinations: processArrayWithOther(q13_learning_combinations, q13_learning_combinations_other),
      
      // Q14-Q15 - Challenges & Motivation (FIXED: xử lý array + other)
      challenges: processArrayWithOther(q14_challenges, q14_challenges_other),
      motivation: processArrayWithOther(q15_motivation, q15_motivation_other),
      
      // Q16-Q20 - Materials & Assessment (FIXED: xử lý array + other)
      material_types: processArrayWithOther(q16_material_types, q16_material_types_other),
      material_language: q17_material_language || 'Tiếng Việt',
      assessment_types: Array.isArray(q18_assessment_types) ? q18_assessment_types.join(', ') : 'Chưa xác định',
      result_display: Array.isArray(q19_result_display) ? q19_result_display.join(', ') : 'Chưa xác định',
      assessment_frequency: processRadioWithOther(q20_assessment_frequency, q20_assessment_frequency_other),
      
      // Fallback values
      start_level: q7_current_level || start_level,
      duration_days: q11_program_days || duration_days,
      duration_hours: duration_hours,
      expected_outcome: q5_specific_goal || expected_outcome
    };

    // ✅ KIỂM TRA DỮ LIỆU BẮT BUỘC (FIXED)
    if (!finalData.roadmap_name || !finalData.category || !finalData.current_level || !finalData.program_days || !finalData.specific_goal) {
      return res.status(400).json({ success: false, error: "Thiếu thông tin bắt buộc để tạo lộ trình" });
    }

    const actualDays = parseInt(finalData.program_days);
    const totalHours = parseFloat(finalData.duration_hours) || actualDays * 2;
    
    if (isNaN(actualDays) || actualDays <= 0 || actualDays > MAX_AI_DAYS) {
      return res.status(400).json({ success: false, error: `Số ngày phải từ 1 đến ${MAX_AI_DAYS}` });
    }
    
    if (isNaN(totalHours) || totalHours <= 0) {
      return res.status(400).json({ success: false, error: "Tổng số giờ không hợp lệ" });
    }

    const hoursPerDay = Math.round((totalHours / actualDays) * 100) / 100;
    const roadmapStartDate = new Date(); // Ngày bắt đầu = ngày tạo roadmap
    roadmapStartDate.setHours(0, 0, 0, 0);
    console.log(`Generating AI roadmap: ${finalData.roadmap_name} (${actualDays} days, ${hoursPerDay}h/day)`);

    // ✅ TẠO PROMPT TỪ DỮ LIỆU 20 CÂU HỎI (FIXED: đầy đủ tất cả fields)
    const promptTemplate = await getPromptTemplate();
        
    let userPrompt = promptTemplate.prompt_template;
    let systemPrompt = promptTemplate.json_format_response;
    console.log('finalData.current_job:',finalData.current_job);    
    const variableMapping = {
        'CATEGORY': finalData.category,
        'SUB_CATEGORY': finalData.category_detail,
        'ROADMAP_NAME': finalData.roadmap_name,
        'MAIN_PURPOSE': finalData.main_purpose,
        'SPECIFIC_GOAL': finalData.specific_goal,
        'CURRENT_JOB': finalData.current_job || 'Không cung cấp',
        'STUDY_TIME': finalData.learning_duration,
        'CURRENT_LEVEL': finalData.current_level,
        'SKILLS_TO_IMPROVE': Array.isArray(finalData.skills_text) ? finalData.skills_text.join(', ') : finalData.skills_text,
        'DAILY_TIME': finalData.daily_time,
        'WEEKLY_FREQUENCY': finalData.weekly_sessions,
        'TOTAL_DURATION': finalData.program_days,
        'LEARNING_STYLE': Array.isArray(finalData.learning_styles) ? finalData.learning_styles.join(', ') : finalData.learning_styles,
        'LEARNING_METHOD': Array.isArray(finalData.learning_combinations) ? finalData.learning_combinations.join(', ') : finalData.learning_combinations,
        'DIFFICULTIES': finalData.challenges,
        'MOTIVATION': finalData.motivation,
        'MATERIAL_TYPE': Array.isArray(finalData.material_types) ? finalData.material_types.join(', ') : finalData.material_types,
        'MATERIAL_LANGUAGE': finalData.material_language,
        'ASSESSMENT_TYPE': finalData.assessment_types,
        'RESULT_DISPLAY': finalData.result_display,
        'ASSESSMENT_FREQUENCY': finalData.assessment_frequency
    };

    Object.keys(variableMapping).forEach(key => {
        userPrompt = userPrompt.replace(new RegExp(`<${key}>`, 'g'), variableMapping[key]);
    });
    console.log('Final userPrompt:', userPrompt);
    // LƯU LỊCH SỬ SỚM TRƯỚC KHI GỬI AI
    const historyResult = await pool.query(
      `INSERT INTO ai_query_history (user_id, prompt_content, status) 
       VALUES ($1, $2, 'PENDING') RETURNING id`,
      [
        req.user.id, 
        JSON.stringify({ 
          roadmap_name: finalData.roadmap_name,
          category: finalData.category,
          duration_days: actualDays,
          timestamp: new Date().toISOString(),
          userPrompt: userPrompt
        })
      ]
    );
    historyId = historyResult.rows[0].id;
    console.log(`Created AI history record #${historyId}`);

    const estimatedTokensPerDay = TOKENS_PER_DAY;
    const desiredTokens = Math.min(actualDays * estimatedTokensPerDay, MAX_AI_TOKENS - SAFETY_MARGIN_TOKENS);

    let aiResponse = null;
    let attempts = 0;
    const MAX_ATTEMPTS = 2;

    //console.log('userPrompt:',userPrompt,'systemPrompt:',systemPrompt)
    while (attempts < MAX_ATTEMPTS && !aiResponse) {
      attempts++;
      try {
        console.log(`AI attempt ${attempts}/${MAX_ATTEMPTS}...`);
        const completion = await callOpenAIWithFallback({
          messages: [
            { role: "system", content: "Bạn là một chuyên gia thiết kế lộ trình học, trả về JSON duy nhất như yêu cầu (không văn bản thêm): " || String(systemPrompt) },
            { role: "user", content: String(userPrompt) }           
          ],
          desiredCompletionTokens: desiredTokens
        });

        const text = completion?.choices?.[0]?.message?.content?.trim();
        if (text) {
          aiResponse = text;
          break;
        }
      } catch (e) {
        console.error(`AI attempt ${attempts} failed:`, e.message);
        if (attempts === MAX_ATTEMPTS) throw e;
      }
    }

    if (!aiResponse) {
      throw new Error("AI không trả về kết quả sau nhiều lần thử");
    }

    //console.log('aiResponse:',aiResponse);
    let roadmapData = null;
    
    const jsonMatch = aiResponse.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
    const jsonText = jsonMatch ? jsonMatch[1] : aiResponse;
    
    try {
      roadmapData = JSON.parse(jsonText);
    } catch (e) {
      const cleaned = jsonText
        .replace(/[\u2018\u2019]/g, "'")
        .replace(/[\u201C\u201D]/g, '"')
        .replace(/,\s*([}\]])/g, '$1');
      
      try {
        roadmapData = JSON.parse(cleaned);
      } catch (e2) {
        console.error("Failed to parse AI response as JSON");
        throw new Error("AI trả về format không hợp lệ");
      }
    }

    let analysis = roadmapData.analysis  || 'Không có phân tích';

    let days = null;
    if (roadmapData && Array.isArray(roadmapData.roadmap)) {
      days = roadmapData.roadmap;
    } else if (Array.isArray(roadmapData)) {
      days = roadmapData;
    } else {
      throw new Error("AI response không chứa mảng roadmap");
    }

    if (days.length !== actualDays) {
      console.warn(`AI returned ${days.length} days instead of ${actualDays}, padding...`);
      if (days.length < actualDays) {
        for (let i = days.length; i < actualDays; i++) {
          days.push({
            day_number: i + 1,
            daily_goal: `Ôn tập và củng cố kiến thức ngày ${i + 1}`,
            learning_content: `Ôn lại các kiến thức đã học từ đầu khóa. Làm bài tập tổng hợp và kiểm tra hiểu biết.`,
            practice_exercises: `Làm bài tập tổng hợp các chủ đề đã học`,
            learning_materials: `Tài liệu ôn tập tổng hợp`,
            study_guide: `Ôn tập toàn bộ nội dung, làm bài kiểm tra tổng hợp`,
            study_duration_hours: hoursPerDay
          });
        }
      } else {
        days = days.slice(0, actualDays);
      }
    }

    const normalizedDays = [];
    for (let i = 0; i < actualDays; i++) {
      const d = days[i] || {};
      const normalized = {
        day_number: i + 1,
        daily_goal: String(d.daily_goal || d.goal || `Mục tiêu ngày ${i + 1}`).trim().substring(0, 150),
        learning_content: String(d.learning_content || d.content || `Nội dung học tập ngày ${i + 1}`).trim().substring(0, 500),
        practice_exercises: String(d.practice_exercises || d.exercises || `Bài tập thực hành ngày ${i + 1}`).trim().substring(0, 300),
        learning_materials: String(d.learning_materials || d.materials || `Tài liệu học tập ngày ${i + 1}`).trim().substring(0, 300),
        study_guide: String(d.study_guide || d.guide || `Hướng dẫn học tập ngày ${i + 1}`).trim().substring(0, 300),
        study_duration_hours: parseFloat(d.study_duration_hours || d.hours || hoursPerDay)
      };

      normalizedDays.push(normalized);
    }

    console.log(`AI generated ${normalizedDays.length} days successfully`);

    
    // LINK ENRICHMENT (GIỮ NGUYÊN LOGIC)
    console.log(`🔗 Fetching specific links for ${normalizedDays.length} days...`);
    
    const fallbackLinks = getFallbackLinks(finalData.category);
    console.log(`🔗 ===== LINK ENRICHMENT START (${normalizedDays.length} days) =====`);
        
    /*const enrichmentPromises = normalizedDays.map(async (day, index) => {
      console.log(`\n┏━━ Day ${day.day_number} START ━━┓`);
      
      const topic = day.daily_goal;
      const content = day.learning_content;
      
      let exerciseLink = await getSpecificExerciseLink(topic, finalData.category, day.day_number, content);
      let materialLink = await getSpecificMaterialLink(topic, finalData.category, day.day_number, content);
      
      if (!exerciseLink) {
        exerciseLink = fallbackLinks.exercises[index % fallbackLinks.exercises.length];
        console.log(`⚠️ Day ${day.day_number}: Using FALLBACK exercise → ${exerciseLink}`);
      } else {
        console.log(`🎉 Day ${day.day_number}: AI exercise SUCCESS → ${exerciseLink}`);
      }

      if (!materialLink) {
        materialLink = fallbackLinks.materials[index % fallbackLinks.materials.length];
        console.log(`⚠️ Day ${day.day_number}: Using FALLBACK material → ${materialLink}`);
      } else {
        console.log(`🎉 Day ${day.day_number}: AI material SUCCESS → ${materialLink}`);
      }
      
      console.log(`┗━━ Day ${day.day_number} END ━━┛\n`);

      return {
        ...day,
        practice_exercises: `${day.practice_exercises} - Link: ${exerciseLink}`,
        learning_materials: `${day.learning_materials} - Link: ${materialLink}`
      };
    });*/

    //const enrichedDays = await Promise.all(enrichmentPromises);
    const enrichedDays = normalizedDays

    console.log(`\n✅ ===== LINK ENRICHMENT COMPLETE =====`);
    console.log(`📊 Total days processed: ${enrichedDays.length}`);

    console.log(`✅ Successfully enriched roadmap with ${enrichedDays.length} days`);
    // ✅ ENRICHED DAYS - THÊM TRƯỜNG study_date & completion_status
    const enrichedDaysWithDates = enrichedDays.map((day, index) => {
      const studyDate = new Date(roadmapStartDate);
      studyDate.setDate(studyDate.getDate() + index); // Mỗi ngày cộng thêm 1
      
      return {
        day_number: day.day_number,
        study_date: studyDate.toISOString().split('T')[0], // YYYY-MM-DD
        daily_goal: day.daily_goal,
        learning_content: day.learning_content,
        practice_exercises: day.practice_exercises,
        learning_materials: day.learning_materials,
        study_guide: day.study_guide,
        study_duration_hours: day.study_duration_hours,
        completion_status: 'NOT_STARTED' // ✅ Mặc định
      };
    });
    // UPDATE SUCCESS
    if (historyId) {
      await pool.query(
        `UPDATE ai_query_history 
         SET status = 'SUCCESS', 
             response_tokens = $1,
             updated_at = CURRENT_TIMESTAMP 
         WHERE id = $2`,
        [enrichedDaysWithDates.length, historyId]
      );
      console.log(`Updated AI history #${historyId} to SUCCESS`);
    }

    console.log(`✅ data analysis: ${analysis}`);

    return res.json({
      success: true,
      message: "Tạo lộ trình AI thành công",
      analysis: analysis,
      data: enrichedDaysWithDates, // ✅ Trả về đầy đủ 9 trường
      metadata: {
        total_days: enrichedDaysWithDates.length,
        start_date: roadmapStartDate.toISOString().split('T')[0],
        hours_per_day: hoursPerDay,
        total_hours: totalHours,
        history_id: historyId
      }
    });

  } catch (error) {
    console.error("❌❌❌ AI GENERATION ERROR FULL:", error);
    console.error("❌ Error message:", error.message);
    console.error("❌ Error stack:", error.stack);
    // UPDATE FAIL
    if (historyId) {
      await pool.query(
        `UPDATE ai_query_history 
         SET status = 'FAIL', 
             error_message = $1,
             updated_at = CURRENT_TIMESTAMP 
         WHERE id = $2`,
        [error.message || 'Unknown error', historyId]
      ).catch(err => console.error('Failed to update history:', err));
    }
    
    return res.status(500).json({
      success: false,
      error: error.message || "Lỗi khi tạo lộ trình AI"
    });
  }
});

// ========== ROADMAP CRUD ENDPOINTS ==========

app.get("/api/roadmaps", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM learning_roadmaps WHERE user_id = $1 ORDER BY created_at DESC`, [req.user.id]);
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error("Error fetching roadmaps:", err && err.message ? err.message : err);
    res.status(500).json({ success: false, error: "Không thể lấy danh sách lộ trình" });
  }
});
// Thêm endpoint này vào server.js, sau dòng app.get("/api/roadmaps", ...)


app.post("/api/roadmaps", requireAuth, async (req, res) => {
  try {
    const { roadmapData, roadmap_analyst } = req.body;
    const { roadmap_name, category, sub_category, start_level, duration_days, duration_hours, expected_outcome, days, history_id } = roadmapData;
    
    if (!roadmap_name || !category || !start_level || !duration_days || !duration_hours || !expected_outcome) {
      return res.status(400).json({ success: false, error: "Thiếu thông tin bắt buộc" });
    }
    
    const roadmapResult = await pool.query(
      `INSERT INTO learning_roadmaps (roadmap_name, category, sub_category, start_level, user_id, duration_days, duration_hours, expected_outcome,roadmap_analyst)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING roadmap_id, created_at`,
      [roadmap_name, category, sub_category || null, start_level, req.user.id, duration_days, duration_hours, expected_outcome, roadmap_analyst]
    );
    
    const roadmapId = roadmapResult.rows[0].roadmap_id;
    const roadmapCreatedAt = new Date(roadmapResult.rows[0].created_at);
    roadmapCreatedAt.setHours(0, 0, 0, 0);
    
    // Link với AI history nếu có
    if (history_id) {
      await pool.query(
        `UPDATE ai_query_history SET roadmap_id = $1 WHERE id = $2`,
        [roadmapId, history_id]
      ).catch(err => console.warn('Could not link AI history:', err));
    }
    
    // ✅ INSERT CHI TIẾT - TỰ ĐỘNG TÍNH study_date
    if (Array.isArray(days)) {
      for (let i = 0; i < days.length; i++) {
        const day = days[i];
        const dayNumber = parseInt(day.day_number) || (i + 1);
        
        // ✅ Tính study_date = roadmap created_at + (dayNumber - 1) ngày
        const studyDate = new Date(roadmapCreatedAt);
        studyDate.setDate(studyDate.getDate() + (dayNumber - 1));
        const studyDateStr = studyDate.toISOString().split('T')[0]; // YYYY-MM-DD
        
        await pool.query(
          `INSERT INTO learning_roadmap_details 
           (roadmap_id, day_number, daily_goal, learning_content, practice_exercises, 
            learning_materials, study_duration_hours, study_date, completion_status,usage_instructions)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          [
            roadmapId,
            dayNumber,
            day.daily_goal || day.goal || "",
            day.learning_content || day.content || "",
            day.practice_exercises || day.exercises || "",
            day.learning_materials || day.materials || "",
            parseFloat(day.study_duration_hours || day.hours || 2),
            studyDateStr,
            'NOT_STARTED', // ✅ Mặc định
            day.study_guide
          ]
        );
      }
    }

    //Insert vào bảng lộ trình học của hệ thống
    const roadmapSystemResult = await pool.query(
      `INSERT INTO learning_roadmaps_system (roadmap_name, category, sub_category, start_level, total_user_learning, duration_days, duration_hours, overall_rating,learning_effectiveness,roadmap_analyst)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING roadmap_id, created_at`,
      [roadmap_name, category, sub_category || null, start_level, 1, duration_days, duration_hours, 0, 0,roadmap_analyst]
    );
    const roadmapSystemId = roadmapSystemResult.rows[0].roadmap_id;
    // ✅ INSERT CHI TIẾT -
    if (Array.isArray(days)) {
      for (let i = 0; i < days.length; i++) {
        const day = days[i];
        const dayNumber = parseInt(day.day_number) || (i + 1);
        
        await pool.query(
          `INSERT INTO learning_roadmap_details_system 
           (roadmap_id, day_number, daily_goal, learning_content, practice_exercises, 
            learning_materials, study_duration_hours,usage_instructions)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [
            roadmapSystemId,
            dayNumber,
            day.daily_goal || day.goal || "",
            day.learning_content || day.content || "",
            day.practice_exercises || day.exercises || "",
            day.learning_materials || day.materials || "",
            parseFloat(day.study_duration_hours || day.hours || 2),
            day.study_guide
          ]
        );
      }
    }
    
    res.json({ success: true, roadmap_id: roadmapId, message: "Tạo lộ trình thành công" });
  } catch (err) {
    console.error("Error creating roadmap:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể tạo lộ trình" });
  }
});

//Tạo lộ trình mới từ danh sách lộ trình của hệ thống
app.post("/api/roadmap_from_system", requireAuth, async (req, res) => {
  try {
    const { roadmapDataSystem, roadmap_analyst } = req.body;
    //console.log('days:',roadmapDataSystem.days)
    const { roadmap_name, category, sub_category, start_level, duration_days, duration_hours } = roadmapDataSystem;
    

    if (!roadmap_name || !category || !start_level || !duration_days || !duration_hours) {
      //console.log('thiếu data:',roadmap_name,'category:',category,'start_level:',start_level,'duration_days',duration_days,'duration_hours:',duration_hours,'expected_outcome:',expected_outcome)
      return res.status(400).json({ success: false, error: "Thiếu thông tin bắt buộc" });
    }
    
    const roadmapResult = await pool.query(
      `INSERT INTO learning_roadmaps (roadmap_name, category, sub_category, start_level, user_id, duration_days, duration_hours,roadmap_analyst)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING roadmap_id, created_at`,
      [roadmap_name, category, sub_category || null, start_level, req.user.id, duration_days, duration_hours, roadmap_analyst]
    );
   
    const roadmapId = roadmapResult.rows[0].roadmap_id;
    console.log('roadmapId:',roadmapId)
    const roadmapCreatedAt = new Date(roadmapResult.rows[0].created_at);
    roadmapCreatedAt.setHours(0, 0, 0, 0);
    
    
    // ✅ INSERT CHI TIẾT - TỰ ĐỘNG TÍNH study_date
    //const { roadmapDataSystem, roadmap_analyst } = req.body;
    //console.log('days:',roadmapDataSystem.days)
    const days = roadmapDataSystem?.days || [];
    if (Array.isArray(days)) {
      for (let i = 0; i < days.length; i++) {
        const day = days[i];
        const dayNumber = parseInt(day.day_number) || (i + 1);
        //console.log('dayNumber:',dayNumber)
        
        // ✅ Tính study_date = roadmap created_at + (dayNumber - 1) ngày
        const studyDate = new Date(roadmapCreatedAt);
        studyDate.setDate(studyDate.getDate() + (dayNumber - 1));
        const studyDateStr = studyDate.toISOString().split('T')[0]; // YYYY-MM-DD
        //console.log('study_guide:',day.study_guide,'-studyDateStr:',studyDateStr,'-dayNumber:',dayNumber,'-day.daily_goal:',day.daily_goal,'-day.learning_content:',day.learning_content,'-day.practice_exercise:',day.practice_exercises,'-day.learning_materials:',day.learning_materials,'-day.study_duration_hours:',day.study_duration_hours)

        await pool.query(
          `INSERT INTO learning_roadmap_details 
           (roadmap_id, day_number, daily_goal, learning_content, practice_exercises, 
            learning_materials, study_duration_hours, study_date, completion_status,usage_instructions)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          [
            roadmapId,
            dayNumber,
            day.daily_goal || day.goal || "",
            day.learning_content || day.content || "",
            day.practice_exercises || day.exercises || "",
            day.learning_materials || day.materials || "",
            parseFloat(day.study_duration_hours || day.hours || 2),
            studyDateStr,
            'NOT_STARTED', // ✅ Mặc định
            day.study_guide
          ]
        );
      }
    }
    
    res.json({ success: true, roadmap_id: roadmapId, message: "Tạo lộ trình thành công" });
  } catch (err) {
    //console.error("Error creating roadmap:", err?.message || err);
    console.log("Error creating roadmap:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể tạo lộ trình" });
  }
});
app.post("/api/roadmaps/upload", requireAuth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: "Không có file được upload" });
    }

    const workbook = XLSX.read(req.file.buffer, { type: 'buffer' });
    const sheetName = workbook.SheetNames[0];
    const sheet = workbook.Sheets[sheetName];
    const data = XLSX.utils.sheet_to_json(sheet);

    if (data.length === 0) {
      return res.status(400).json({ success: false, error: "File Excel rỗng" });
    }

    // ✅ Validate 8 cột bắt buộc (chỉ check tên cột tồn tại)
    const requiredColumns = [
      'day_number',
      'day_study', 
      'daily_goal', 
      'learning_content', 
      'practice_exercises', 
      'learning_materials',
      'guide_learning',
      'study_duration_hours'
    ];
    
    const firstRow = data[0];
    const missingColumns = requiredColumns.filter(col => !(col in firstRow));
    
    if (missingColumns.length > 0) {
      return res.status(400).json({ 
        success: false, 
        error: `Thiếu các cột bắt buộc: ${missingColumns.join(', ')}` 
      });
    }

    // ✅ CHỈ VALIDATION day_number VÀ study_duration_hours
    const errors = [];
    
    for (let i = 0; i < data.length; i++) {
      const row = data[i];
      const rowNumber = i + 2; // +2 vì: +1 cho header, +1 cho index từ 0
      
      // ✅ Validate day_number phải là số nguyên dương liên tiếp từ 1
      const dayNumber = parseInt(row.day_number);
      const expectedDayNumber = i + 1;
      
      if (isNaN(dayNumber) || dayNumber !== expectedDayNumber) {
        errors.push(`Hàng ${rowNumber}: Số ngày không hợp lệ (mong đợi ${expectedDayNumber}, nhận được "${row.day_number}")`);
      }
      
      // ✅ Validate study_duration_hours phải là số > 0
      const hours = parseFloat(String(row.study_duration_hours || '').replace(/[^\d.]/g, ''));
      
      if (isNaN(hours) || hours <= 0) {
        errors.push(`Hàng ${rowNumber}: Số giờ học không hợp lệ (phải là số > 0, nhận được "${row.study_duration_hours}")`);
      }
    }
    
    // ✅ Nếu có lỗi, trả về danh sách lỗi
    if (errors.length > 0) {
      return res.status(400).json({ 
        success: false, 
        error: `File Excel có ${errors.length} lỗi:\n${errors.join('\n')}`,
        details: errors
      });
    }

    // Lấy thông tin roadmap từ body
    const { roadmap_name, category, sub_category, start_level, expected_outcome } = req.body;
    
    if (!roadmap_name || !category || !start_level || !expected_outcome) {
      return res.status(400).json({ success: false, error: "Thiếu thông tin lộ trình" });
    }

    const duration_days = data.length;
    const duration_hours = data.reduce((sum, row) => {
      const hours = parseFloat(String(row.study_duration_hours || '0').replace(/[^\d.]/g, '')) || 0;
      return sum + hours;
    }, 0);

    // ✅ CHECK: Có bất kỳ day_study nào invalid không?
    let hasInvalidDayStudy = false;
    
    for (let i = 0; i < data.length; i++) {
      const row = data[i];
      let isValid = false;
      
      if (row.day_study) {
        try {
          // Nếu Excel trả về serial number (Excel date)
          if (typeof row.day_study === 'number') {
            const excelEpoch = new Date(1899, 11, 30);
            const jsDate = new Date(excelEpoch.getTime() + row.day_study * 86400000);
            if (!isNaN(jsDate.getTime())) {
              isValid = true;
            }
          } 
          // Nếu là string hoặc Date object
          else {
            const parsed = new Date(row.day_study);
            if (!isNaN(parsed.getTime())) {
              isValid = true;
            }
          }
        } catch (e) {
          isValid = false;
        }
      }
      
      if (!isValid) {
        hasInvalidDayStudy = true;
        break; // Chỉ cần 1 ngày invalid là đủ
      }
    }

    // Tạo roadmap
    const roadmapResult = await pool.query(
      `INSERT INTO learning_roadmaps 
       (roadmap_name, category, sub_category, start_level, user_id, duration_days, duration_hours, expected_outcome)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) 
       RETURNING roadmap_id, created_at`,
      [roadmap_name, category, sub_category || null, start_level, req.user.id, duration_days, duration_hours, expected_outcome]
    );
    
    const roadmapId = roadmapResult.rows[0].roadmap_id;
    const roadmapCreatedAt = new Date(roadmapResult.rows[0].created_at);
    roadmapCreatedAt.setHours(0, 0, 0, 0);

    // ✅ Insert chi tiết
    for (let i = 0; i < data.length; i++) {
      const row = data[i];
      const dayNumber = parseInt(row.day_number);
      
      let studyDateStr = null;
      
      // ✅ Nếu CÓ BẤT KỲ day_study NÀO INVALID → Set NULL cho TẤT CẢ
      if (hasInvalidDayStudy) {
        studyDateStr = null; // Hoặc 'N/A' nếu muốn string
      } else {
        // Parse day_study từ Excel
        if (row.day_study) {
          try {
            // Nếu Excel trả về serial number (Excel date)
            if (typeof row.day_study === 'number') {
              const excelEpoch = new Date(1899, 11, 30);
              const jsDate = new Date(excelEpoch.getTime() + row.day_study * 86400000);
              studyDateStr = jsDate.toISOString().split('T')[0];
            } 
            // Nếu là string hoặc Date object
            else {
              const parsed = new Date(row.day_study);
              if (!isNaN(parsed.getTime())) {
                studyDateStr = parsed.toISOString().split('T')[0];
              }
            }
          } catch (e) {
            studyDateStr = null;
          }
        }
      }
      
      // ✅ CÁC TRƯỜNG KHÁC: Chấp nhận bất kỳ giá trị nào (kể cả rỗng)
      await pool.query(
        `INSERT INTO learning_roadmap_details 
         (roadmap_id, day_number, daily_goal, learning_content, practice_exercises, 
          learning_materials, usage_instructions, study_duration_hours, study_date, completion_status)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [
          roadmapId,
          dayNumber,
          String(row.daily_goal || '').trim() || '', // Có thể rỗng
          String(row.learning_content || '').trim() || '', // Có thể rỗng
          String(row.practice_exercises || '').trim() || '', // Có thể rỗng
          String(row.learning_materials || '').trim() || '', // Có thể rỗng
          String(row.guide_learning || '').trim() || '', // Có thể rỗng
          parseFloat(String(row.study_duration_hours).replace(/[^\d.]/g, '')), // Đã validate > 0
          studyDateStr, // null nếu có day_study invalid
          'NOT_STARTED'
        ]
      );
    }

    // ✅ Thêm warning message nếu có invalid day_study
    const message = hasInvalidDayStudy 
      ? `Upload thành công lộ trình với ${data.length} ngày học. ⚠️ Cảnh báo: Phát hiện ngày học không hợp lệ, tất cả ngày học đã được set là N/A.`
      : `Upload thành công lộ trình với ${data.length} ngày học`;

    res.json({ 
      success: true, 
      roadmap_id: roadmapId, 
      message: message,
      warning: hasInvalidDayStudy ? 'Một hoặc nhiều ngày học không hợp lệ' : null
    });

  } catch (error) {
    console.error("Upload error:", error);
    res.status(500).json({ success: false, error: error.message || "Lỗi khi upload file" });
  }
});
app.get("/api/roadmaps/:id/details", requireAuth, async (req, res) => {
  try {
    const roadmapId = parseInt(req.params.id);
    
    // Check quyền
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
    
    // ✅ LẤY ĐẦY ĐỦ 9 TRƯỜNG
    const result = await pool.query(`
      SELECT 
        detail_id,
        day_number,
        study_date,
        daily_goal,
        learning_content,
        practice_exercises,
        learning_materials,
        study_duration_hours,
        completion_status,
        created_at,
        updated_at,
        completed_at
      FROM learning_roadmap_details 
      WHERE roadmap_id = $1 
      ORDER BY day_number ASC
    `, [roadmapId]);
    
    // ✅ Format response với đầy đủ 9 trường
    const formattedData = result.rows.map(row => ({
      detail_id: row.detail_id,
      day_number: row.day_number,
      study_date: row.study_date ? new Date(row.study_date).toLocaleDateString('vi-VN') : null,
      study_date_iso: row.study_date,
      daily_goal: row.daily_goal,
      learning_content: row.learning_content,
      practice_exercises: row.practice_exercises,
      learning_materials: row.learning_materials,
      study_duration_hours: row.study_duration_hours,
      completion_status: row.completion_status,
      created_at: row.created_at,
      updated_at: row.updated_at,
      completed_at: row.completed_at
    }));
    
    res.json({ success: true, data: formattedData });
  } catch (err) {
    console.error("Error fetching roadmap details:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể lấy chi tiết lộ trình" });
  }
});

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

app.delete("/api/roadmaps/:id", requireAuth, async (req, res) => {
    try {
        const roadmapId = parseInt(req.params.id);
        
        // Verify ownership
        const checkQuery = `
            SELECT roadmap_id FROM learning_roadmaps 
            WHERE roadmap_id = $1 AND user_id = $2
        `;
        const checkResult = await pool.query(checkQuery, [roadmapId, req.user.id]);
        
        if (checkResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                error: 'Lộ trình không tìm thấy hoặc bạn không có quyền xóa'
            });
        }
        
        // Delete roadmap (cascade sẽ tự động xóa details)
        await pool.query('DELETE FROM learning_roadmaps WHERE roadmap_id = $1', [roadmapId]);
        
        res.json({
            success: true,
            message: 'Đã xóa lộ trình thành công'
        });
    } catch (error) {
        console.error('Error deleting roadmap:', error);
        res.status(500).json({
            success: false,
            error: 'Không thể xóa lộ trình'
        });
    }
});
// Add this to server.js
app.get("/api/roadmaps/progress", requireAuth, async (req, res) => {
  try {
    // ✅ VALIDATE user.id trước khi query
    const userId = parseInt(req.user?.id);
    if (!userId || isNaN(userId)) {
      console.error('❌ Invalid user ID:', req.user?.id);
      return res.status(401).json({ 
        success: false, 
        error: "Invalid user session"
      });
    }

    console.log('📊 Progress API called by user:', userId);
    
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todayStr = today.toISOString().split('T')[0];
    
    console.log('📅 Today:', todayStr);
    
    // ✅ QUERY với explicit casting
    const result = await pool.query(`
      SELECT 
        d.detail_id,
        d.day_number,
        d.study_date,
        d.daily_goal,
        d.learning_content,
        d.practice_exercises,
        d.study_duration_hours,
        d.completion_status,
        r.roadmap_id,
        r.roadmap_name,
        r.category
      FROM learning_roadmap_details d
      JOIN learning_roadmaps r ON d.roadmap_id = r.roadmap_id
      WHERE r.user_id = $1::integer
        AND r.status = 'ACTIVE'
      ORDER BY 
        CASE WHEN d.study_date IS NULL THEN 1 ELSE 0 END,
        d.study_date ASC NULLS LAST, 
        d.day_number ASC
    `, [userId]);
    
    console.log('📋 Found', result.rows.length, 'tasks');
    
    const tasks = result.rows || [];
    
    const today_tasks = [];
    const upcoming_tasks = [];
    const overdue_tasks = [];
    
    tasks.forEach(task => {
      // ✅ NẾU KHÔNG CÓ STUDY_DATE -> ĐƯA VÀO UPCOMING
      if (!task.study_date) {
        upcoming_tasks.push(task);
        return;
      }
      
      try {
        const taskDate = new Date(task.study_date);
        if (isNaN(taskDate.getTime())) {
          console.warn('⚠️ Invalid date for task', task.detail_id);
          upcoming_tasks.push(task);
          return;
        }
        
        taskDate.setHours(0, 0, 0, 0);
        const taskDateStr = taskDate.toISOString().split('T')[0];
        
        if (taskDateStr === todayStr) {
          today_tasks.push(task);
        } else if (taskDateStr > todayStr) {
          upcoming_tasks.push(task);
        } else {
          // Quá hạn chỉ khi chưa hoàn thành
          if (task.completion_status !== 'COMPLETED' && task.completion_status !== 'SKIPPED') {
            overdue_tasks.push(task);
          }
        }
      } catch (dateError) {
        console.warn('⚠️ Date parse error for task', task.detail_id, ':', dateError.message);
        upcoming_tasks.push(task);
      }
    });
    
    console.log('✅ Categorized:', {
      today: today_tasks.length,
      upcoming: upcoming_tasks.length,
      overdue: overdue_tasks.length
    });
    
    res.json({ 
      success: true, 
      today: today_tasks,
      upcoming: upcoming_tasks.slice(0, 10),
      overdue: overdue_tasks
    });
    
  } catch (err) {
    console.error("❌❌❌ ERROR in /api/roadmaps/progress:");
    console.error("Message:", err?.message);
    console.error("Stack:", err?.stack);
    console.error("Code:", err?.code);
    console.error("Detail:", err?.detail);
    
    res.status(500).json({ 
      success: false, 
      error: "Không thể lấy tiến độ",
      details: process.env.NODE_ENV === 'development' ? err?.message : undefined
    });
  }
});
app.get("/api/roadmaps/:id", requireAuth, async (req, res) => {
  try {
    // ✅ DEBUG: Log đầu vào
    console.log('🔍 /api/roadmaps/:id - req.params.id:', req.params.id);
    console.log('🔍 req.user:', JSON.stringify(req.user, null, 2));
    console.log('🔍 req.user.id type:', typeof req.user?.id);
    console.log('🔍 req.user.id value:', req.user?.id);
    
    const roadmapId = parseInt(req.params.id);
    console.log('🔍 roadmapId after parseInt:', roadmapId, 'isNaN:', isNaN(roadmapId));
    
    if (isNaN(roadmapId)) {
      console.error('❌ Invalid roadmap ID');
      return res.status(400).json({ success: false, error: "ID lộ trình không hợp lệ" });
    }
    
    // ✅ VALIDATE user.id
    const userId = parseInt(req.user?.id);
    console.log('🔍 userId after parseInt:', userId, 'isNaN:', isNaN(userId));
    
    if (!userId || isNaN(userId)) {
      console.error('❌ Invalid user ID:', req.user?.id);
      return res.status(401).json({ success: false, error: "Phiên đăng nhập không hợp lệ" });
    }
    
    // Check quyền
    console.log('🔍 Checking ownership with roadmapId:', roadmapId);
    const roadmapCheck = await pool.query(
      "SELECT user_id FROM learning_roadmaps WHERE roadmap_id = $1::integer", 
      [roadmapId]
    );
    
    console.log('✅ Ownership check result, rows:', roadmapCheck.rows.length);
    if (roadmapCheck.rows.length > 0) {
      console.log('🔍 Owner user_id:', roadmapCheck.rows[0].user_id, 'type:', typeof roadmapCheck.rows[0].user_id);
      console.log('🔍 Current user_id:', userId, 'type:', typeof userId);
    }
    
    if (roadmapCheck.rows.length === 0) {
      console.warn('⚠️ Roadmap not found');
      return res.status(404).json({ success: false, error: "Lộ trình không tồn tại" });
    }
    
    // ✅ So sánh với type coercion
    const ownerId = parseInt(roadmapCheck.rows[0].user_id);
    console.log('🔍 Comparing ownerId:', ownerId, 'with userId:', userId);
    
    if (ownerId !== userId) {
      console.error('❌ Access denied. Owner:', ownerId, 'User:', userId);
      return res.status(403).json({ success: false, error: "Không có quyền truy cập" });
    }
    
    console.log('✅ Access granted');
    
    // Lấy thông tin roadmap
    const roadmapQuery = `
      SELECT 
        roadmap_id,
        roadmap_name,
        category,
        sub_category,
        start_level,
        duration_days,
        duration_hours,
        status,
        expected_outcome,
        progress_percentage,
        total_studied_hours,
        overall_rating,
        learning_effectiveness,
        difficulty_suitability,
        content_relevance,
        engagement_level,
        detailed_feedback,
        recommended_category,
        actual_learning_outcomes,
        improvement_suggestions,
        would_recommend,
        roadmap_analyst,
        created_at,
        updated_at
      FROM learning_roadmaps
      WHERE roadmap_id = $1::integer
    `;
    
    console.log('🔍 Fetching roadmap details');
    const roadmapResult = await pool.query(roadmapQuery, [roadmapId]);
    console.log('✅ Roadmap details fetched');
    
    // Lấy chi tiết các ngày học
    const detailsQuery = `
      SELECT 
        detail_id,
        day_number,
        study_date,
        daily_goal,
        learning_content,
        practice_exercises,
        learning_materials,
        usage_instructions,
        study_duration_hours,
        completion_status,
        created_at,
        updated_at,
        completed_at
      FROM learning_roadmap_details 
      WHERE roadmap_id = $1::integer
      ORDER BY day_number ASC
    `;
    
    console.log('🔍 Fetching roadmap day details');
    const detailsResult = await pool.query(detailsQuery, [roadmapId]);
    console.log('✅ Day details fetched, count:', detailsResult.rows.length);
    
    res.json({ 
      success: true, 
      data: {
        roadmap: roadmapResult.rows[0],
        details: detailsResult.rows
      }
    });
    
  } catch (err) {
    console.error("❌❌❌ ERROR in /api/roadmaps/:id:");
    console.error("Message:", err?.message);
    console.error("Stack:", err?.stack);
    console.error("Code:", err?.code);
    console.error("Detail:", err?.detail);
    console.error("Position:", err?.position);
    
    res.status(500).json({ 
      success: false, 
      error: "Không thể lấy thông tin lộ trình",
      debug: process.env.NODE_ENV === 'development' ? err?.message : undefined
    });
  }
});

// ========== AUTHENTICATION ENDPOINTS ==========

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

// ========== USER ENDPOINTS (for logged-in users) ==========

app.get("/api/users/me", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, username, email, role, created_at 
       FROM users 
       WHERE id = $1`,
      [req.user.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Người dùng không tồn tại" });
    }
    
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error("Error fetching user:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể lấy thông tin người dùng" });
  }
});

app.get("/api/users", requireAdmin, async (req, res) => {
  try {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    const result = await pool.query(
      `SELECT id, name, username, email, role, created_at 
       FROM users 
       ORDER BY created_at DESC`
    );
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error("Error fetching users:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể lấy danh sách người dùng" });
  }
});

app.get("/api/users/:id", requireAdmin, async (req, res) => {
  try {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    const userId = parseInt(req.params.id);
    if (isNaN(userId)) {
      return res.status(400).json({ success: false, error: "ID không hợp lệ" });
    }
    
    const result = await pool.query(
      `SELECT id, name, username, email, role, created_at 
       FROM users 
       WHERE id = $1`,
      [userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Người dùng không tồn tại" });
    }
    
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error("Error fetching user:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể lấy thông tin người dùng" });
  }
});

app.delete("/api/users/:id", requireAdmin, async (req, res) => {
  try {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    
    const userId = parseInt(req.params.id);
    
    if (isNaN(userId)) {
      return res.status(400).json({ success: false, error: "ID không hợp lệ" });
    }
    
    if (userId === req.user.id) {
      return res.status(400).json({ success: false, error: "Không thể xóa chính mình" });
    }
    
    const result = await pool.query(
      `DELETE FROM users WHERE id = $1 RETURNING id, username`,
      [userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Người dùng không tồn tại" });
    }
    
    res.json({ success: true, message: `Đã xóa người dùng ${result.rows[0].username} thành công` });
  } catch (err) {
    console.error("Error deleting user:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể xóa người dùng" });
  }
});

// ========== ADMIN USER MANAGEMENT ENDPOINTS ==========

app.get("/api/admin/users", requireAdmin, async (req, res) => {
  try {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    const result = await pool.query(
      `SELECT id, name, username, email, role, created_at 
       FROM users 
       ORDER BY created_at DESC`
    );
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error("Error fetching users:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể lấy danh sách người dùng" });
  }
});

app.get("/api/admin/users/:id", requireAdmin, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    if (isNaN(userId)) {
      return res.status(400).json({ success: false, error: "ID không hợp lệ" });
    }
    
    const result = await pool.query(
      `SELECT id, name, username, email, role, created_at 
       FROM users 
       WHERE id = $1`,
      [userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Người dùng không tồn tại" });
    }
    
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error("Error fetching user:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể lấy thông tin người dùng" });
  }
});

app.put("/api/admin/users/:id/role", requireAdmin, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const { role } = req.body;
    
    if (isNaN(userId)) {
      return res.status(400).json({ success: false, error: "ID không hợp lệ" });
    }
    
    if (!role || !["user", "admin"].includes(role.toLowerCase())) {
      return res.status(400).json({ success: false, error: "Role không hợp lệ. Chỉ chấp nhận 'user' hoặc 'admin'" });
    }
    
    const result = await pool.query(
      `UPDATE users 
       SET role = $1 
       WHERE id = $2 
       RETURNING id, name, username, email, role`,
      [role.toLowerCase(), userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Người dùng không tồn tại" });
    }
    
    res.json({ success: true, message: "Cập nhật role thành công", data: result.rows[0] });
  } catch (err) {
    console.error("Error updating user role:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể cập nhật role" });
  }
});

app.put("/api/admin/users/:id", requireAdmin, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const { name, email } = req.body;
    
    if (isNaN(userId)) {
      return res.status(400).json({ success: false, error: "ID không hợp lệ" });
    }
    
    const updates = [];
    const values = [];
    let paramCount = 1;
    
    if (name) {
      updates.push(`name = $${paramCount++}`);
      values.push(name.trim());
    }
    if (email) {
      const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!EMAIL_RE.test(email)) {
        return res.status(400).json({ success: false, error: "Email không đúng định dạng" });
      }
      updates.push(`email = $${paramCount++}`);
      values.push(email.trim());
    }
    
    if (updates.length === 0) {
      return res.status(400).json({ success: false, error: "Không có dữ liệu để cập nhật" });
    }
    
    values.push(userId);
    
    const result = await pool.query(
      `UPDATE users 
       SET ${updates.join(", ")}
       WHERE id = $${paramCount}
       RETURNING id, name, username, email, role`,
      values
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Người dùng không tồn tại" });
    }
    
    res.json({ success: true, message: "Cập nhật thông tin thành công", data: result.rows[0] });
  } catch (err) {
    console.error("Error updating user:", err?.message || err);
    if (err.code === "23505") {
      return res.status(409).json({ success: false, error: "Email đã được sử dụng" });
    }
    res.status(500).json({ success: false, error: "Không thể cập nhật thông tin người dùng" });
  }
});

app.delete("/api/admin/users/:id", requireAdmin, async (req, res) => {
  try {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    const userId = parseInt(req.params.id);
    
    if (isNaN(userId)) {
      return res.status(400).json({ success: false, error: "ID không hợp lệ" });
    }
    
    if (userId === req.user.id) {
      return res.status(400).json({ success: false, error: "Không thể xóa chính mình" });
    }
    
    const result = await pool.query(
      `DELETE FROM users WHERE id = $1 RETURNING id, username`,
      [userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Người dùng không tồn tại" });
    }
    
    res.json({ success: true, message: `Đã xóa người dùng ${result.rows[0].username} thành công` });
  } catch (err) {
    console.error("Error deleting user:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể xóa người dùng" });
  }
});

app.get("/api/admin/stats", requireAdmin, async (req, res) => {
  try {
    const totalUsers = await pool.query("SELECT COUNT(*) as count FROM users");
    const totalRoadmaps = await pool.query("SELECT COUNT(*) as count FROM learning_roadmaps");
    const activeRoadmaps = await pool.query("SELECT COUNT(*) as count FROM learning_roadmaps WHERE status = 'ACTIVE'");
    const completedRoadmaps = await pool.query("SELECT COUNT(*) as count FROM learning_roadmaps WHERE status = 'COMPLETED'");
    
    res.json({
      success: true,
      data: {
        totalUsers: parseInt(totalUsers.rows[0].count),
        totalRoadmaps: parseInt(totalRoadmaps.rows[0].count),
        activeRoadmaps: parseInt(activeRoadmaps.rows[0].count),
        completedRoadmaps: parseInt(completedRoadmaps.rows[0].count)
      }
    });
  } catch (err) {
    console.error("Error fetching stats:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể lấy thống kê" });
  }
});

// ============ CATEGORY API ENDPOINTS ============

app.get("/api/categories", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.id, c.name, c.description, c.created_at,
        (SELECT json_agg(
          json_build_object('id', s.id, 'name', s.name, 'description', s.description)
          ORDER BY s.name
        ) 
         FROM sub_categories s WHERE s.category_id = c.id) as sub_categories
      FROM categories c
      ORDER BY c.name
    `);
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error("Error fetching categories:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể lấy danh mục" });
  }
});

app.post("/api/admin/categories", requireAdmin, async (req, res) => {
  try {
    const { name, description } = req.body;
    
    if (!name || !name.trim()) {
      return res.status(400).json({ success: false, error: "Tên danh mục không được để trống" });
    }
    
    const result = await pool.query(
      `INSERT INTO categories (name, description) VALUES ($1, $2) RETURNING *`,
      [name.trim(), description?.trim() || null]
    );
    res.json({ success: true, data: result.rows[0], message: "Tạo danh mục thành công" });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ success: false, error: "Danh mục đã tồn tại" });
    }
    console.error(err);
    res.status(500).json({ success: false, error: "Không thể tạo danh mục" });
  }
});

app.put("/api/admin/categories/:id", requireAdmin, async (req, res) => {
  try {
    const { name, description } = req.body;
    const result = await pool.query(
      `UPDATE categories SET name = $1, description = $2 WHERE id = $3 RETURNING *`,
      [name.trim(), description?.trim() || null, req.params.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Danh mục không tồn tại" });
    }
    
    res.json({ success: true, data: result.rows[0], message: "Cập nhật thành công" });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ success: false, error: "Tên danh mục đã tồn tại" });
    }
    res.status(500).json({ success: false, error: "Không thể cập nhật" });
  }
});

app.delete("/api/admin/categories/:id", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`DELETE FROM categories WHERE id = $1 RETURNING name`, [req.params.id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Danh mục không tồn tại" });
    }
    
    res.json({ success: true, message: `Đã xóa danh mục "${result.rows[0].name}"` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: "Không thể xóa danh mục" });
  }
});

app.post("/api/admin/sub-categories", requireAdmin, async (req, res) => {
  try {
    const { category_id, name, description } = req.body;
    
    if (!category_id || !name?.trim()) {
      return res.status(400).json({ success: false, error: "Thiếu thông tin bắt buộc" });
    }
    
    const result = await pool.query(
      `INSERT INTO sub_categories (category_id, name, description) VALUES ($1, $2, $3) RETURNING *`,
      [category_id, name.trim(), description?.trim() || null]
    );
    res.json({ success: true, data: result.rows[0], message: "Tạo danh mục con thành công" });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ success: false, error: "Danh mục con đã tồn tại" });
    }
    res.status(500).json({ success: false, error: "Không thể tạo danh mục con" });
  }
});

app.delete("/api/admin/sub-categories/:id", requireAdmin, async (req, res) => {
  try {
    await pool.query(`DELETE FROM sub_categories WHERE id = $1`, [req.params.id]);
    res.json({ success: true, message: "Đã xóa danh mục con" });
  } catch (err) {
    res.status(500).json({ success: false, error: "Không thể xóa" });
  }
});

// ========== AI HISTORY ENDPOINTS ==========

app.get("/api/admin/ai-history", requireAdmin, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const offset = parseInt(req.query.offset) || 0;
    
    const result = await pool.query(`
      SELECT 
        h.id, 
        h.query_time, 
        h.prompt_content, 
        h.status, 
        h.error_message,
        h.response_tokens,
        h.roadmap_id, 
        r.roadmap_name, 
        u.username,
        u.email
      FROM ai_query_history h
      LEFT JOIN learning_roadmaps r ON h.roadmap_id = r.roadmap_id
      LEFT JOIN users u ON h.user_id = u.id
      ORDER BY h.query_time DESC
      LIMIT $1 OFFSET $2
    `, [limit, offset]);
    
    const countResult = await pool.query(`SELECT COUNT(*) as total FROM ai_query_history`);
    
    res.json({ 
      success: true, 
      data: result.rows,
      total: parseInt(countResult.rows[0].total)
    });
  } catch (err) {
    console.error("Error fetching AI history:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể lấy lịch sử AI" });
  }
});

app.delete("/api/admin/ai-history/:id", requireAdmin, async (req, res) => {
  try {
    const historyId = parseInt(req.params.id);
    await pool.query(`DELETE FROM ai_query_history WHERE id = $1`, [historyId]);
    res.json({ success: true, message: "Đã xóa lịch sử" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: "Không thể xóa" });
  }
});

// ========== FRONTEND ROUTES ==========

app.get("/", (req, res) => {
  const tryFiles = ["main.html", "login.html", "register.html"];
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

// ========== START SERVER ==========

const PORT = parseInt(process.env.PORT || "5000", 10);
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`ℹ️  Local: http://localhost:${PORT}/`);
});

// ========== VERSION 2 ==========
/*const generateRoadmapSchema = Joi.object({
    category: Joi.string().required(),
    subCategory: Joi.string().required(),
    roadmapName: Joi.string().required(),
    mainPurpose: Joi.string().required(),
    specificGoal: Joi.string().required(),
    currentJob: Joi.string().allow(''),
    studyTime: Joi.string().required(),
    currentLevel: Joi.string().required(),
    skillsToImprove: Joi.array().items(Joi.string()).min(1).required(),
    dailyTime: Joi.string().required(),
    weeklyFrequency: Joi.string().required(),
    totalDuration: Joi.string().required(),
    learningStyle: Joi.array().items(Joi.string()).min(1).required(),
    learningMethod: Joi.array().items(Joi.string()).min(1).required(),
    difficulties: Joi.string().required(),
    motivation: Joi.string().required(),
    materialType: Joi.array().items(Joi.string()).min(1).required(),
    materialLanguage: Joi.string().required(),
    assessmentType: Joi.string().required(),
    resultDisplay: Joi.string().required(),
    assessmentFrequency: Joi.string().required()
});

const saveRoadmapSchema = Joi.object({
    formData: Joi.object().required(),
    analysis: Joi.string().required(),
    roadmap: Joi.array().items(
        Joi.object({
            day: Joi.number().required(),
            goal: Joi.string().required(),
            content: Joi.string().required(),
            exercises: Joi.string().allow(''),
            materials: Joi.string().required(),
            instructions: Joi.string().allow(''),
            duration: Joi.string().required()
        })
    ).min(1).required(),
    aiPromptLog: Joi.alternatives().try(Joi.string(), Joi.number()).required()
});

// =====================================================
// HELPER FUNCTIONS
// =====================================================



async function logAIPrompt(userId, formData, prompt, status) {
    const query = `
        INSERT INTO ai_prompt_logs (
            user_id, category, sub_category, full_prompt, form_data, status
        ) VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING log_id
    `;
    
    const result = await pool.query(query, [
        userId,
        formData.category,
        formData.subCategory,
        prompt,
        JSON.stringify(formData),
        status
    ]);
    
    return result.rows[0].log_id;
}

async function updateAILog(logId, updates) {
    const fields = [];
    const values = [];
    let idx = 1;

    Object.keys(updates).forEach(key => {
        fields.push(`${key} = $${idx}`);
        values.push(updates[key]);
        idx++;
    });

    values.push(logId);

    const query = `
        UPDATE ai_prompt_logs
        SET ${fields.join(', ')}, updated_at = CURRENT_TIMESTAMP
        WHERE log_id = $${idx}
    `;

    await pool.query(query, values);
}

async function callAIService(prompt, aiPrompt_system, actualDays = 30, hoursPerDay = 1) {
  try {
    actualDays = Number(actualDays) || 30;
    hoursPerDay = Number(hoursPerDay) || hoursPerDay || 1;
    console.log('callAIService start days=', actualDays, '-h/day=', hoursPerDay, '-prompt=', prompt);

    const roadmapStartDate = new Date();
    roadmapStartDate.setHours(0,0,0,0);

    // calculate safe tokens per day so we don't exceed model cap
    const maxAvailable = Math.max( MIN_COMPLETION_TOKENS, (MAX_AI_TOKENS - SAFETY_MARGIN_TOKENS) );
    const safeTokensPerDay = Math.max(256, Math.floor(maxAvailable / Math.max(1, actualDays))); // conservative lower bound
    const desiredTokens = Math.min(maxAvailable, actualDays * safeTokensPerDay);

    let aiResponseText = null;
    let attempts = 0;
    const MAX_ATTEMPTS_LOCAL = 2;

    const messages = [
      { role: "system", content: "Bạn là một chuyên gia thiết kế lộ trình học, trả về JSON duy nhất như yêu cầu (không văn bản thêm): " || aiPrompt_system },
      { role: "user", content: prompt }
    ];

    while (attempts < MAX_ATTEMPTS_LOCAL && !aiResponseText) {
      attempts++;
      try {
        console.log(`AI attempt ${attempts}/${MAX_ATTEMPTS_LOCAL}, desiredTokens=${desiredTokens}`);
        const completion = await callOpenAIWithFallback({
          messages,
          desiredCompletionTokens: desiredTokens
        });
        const text = completion?.choices?.[0]?.message?.content?.trim();
        if (text) aiResponseText = text;
      } catch (e) {
        console.error(`AI attempt ${attempts} failed:`, e && e.message);
        if (attempts === MAX_ATTEMPTS_LOCAL) throw e;
      }
    }

    if (!aiResponseText) throw new Error("AI không trả về kết quả");

    // helper parse JSON block
    const extractJson = (s) => {
      const m = s.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
      return m ? m[1] : s;
    };

    let jsonText = extractJson(aiResponseText);
    let parsed;
    try { parsed = JSON.parse(jsonText); }
    catch (e) {
      const cleaned = jsonText.replace(/[\u2018\u2019]/g,"'").replace(/[\u201C\u201D]/g,'"').replace(/,\s*([}\]])/g,'$1');
      parsed = JSON.parse(cleaned);
    }

    let days = Array.isArray(parsed.roadmap) ? parsed.roadmap : (Array.isArray(parsed) ? parsed : []);
    // if AI returned fewer days than requested, try to ask it to continue (simple continuation loop)
    let totalAttemptsContinue = 0;
    while (days.length < actualDays && totalAttemptsContinue < 3) {
      totalAttemptsContinue++;
      const missingFrom = days.length + 1;
      const contPrompt = `Bạn đã trả ${days.length} ngày. Vui lòng tiếp tục trả phần còn lại từ ngày ${missingFrom} đến ${actualDays} cùng định dạng JSON như trước, chỉ trả mảng "roadmap" cho các ngày còn thiếu.`;
      console.log('Requesting continuation:', contPrompt);
      const contCompletion = await callOpenAIWithFallback({
        messages: [{ role: "system", content: "Tiếp tục JSON trước đó" }, { role: "user", content: contPrompt }],
        desiredCompletionTokens: Math.min(desiredTokens, Math.max(512, safeTokensPerDay * (actualDays - days.length)))
      });
      const contText = contCompletion?.choices?.[0]?.message?.content?.trim();
      if (!contText) break;
      const contJsonText = extractJson(contText);
      try {
        const contParsed = JSON.parse(contJsonText);
        const contDays = Array.isArray(contParsed.roadmap) ? contParsed.roadmap : (Array.isArray(contParsed) ? contParsed : []);
        if (contDays.length === 0) break;
        days = days.concat(contDays);
      } catch (e) {
        // ignore and break if cannot parse continuation
        console.warn('Continuation parse failed:', e.message);
        break;
      }
    }

    // normalize & pad/truncate
    const normalized = [];
    for (let i = 0; i < actualDays; i++) {
      const src = days[i] || {};
      const day_number = Number(src.day_number ?? src.day ?? (i+1));
      const daily_goal = String(src.daily_goal ?? src.goal ?? '').trim() || `Mục tiêu ngày ${i+1}`;
      const learning_content = String(src.learning_content ?? src.content ?? '').trim() || '';
      const practice_exercises = String(src.practice_exercises ?? src.exercises ?? '').trim() || '';
      const learning_materials = String(src.learning_materials ?? src.materials ?? '').trim() || '';
      const study_guide = String(src.study_guide ?? src.instructions ?? src.guide ?? '').trim() || '';
      const study_duration_hours = parseFloat(src.study_duration_hours ?? src.duration ?? src.hours ?? hoursPerDay) || hoursPerDay;

      normalized.push({
        day_number,
        daily_goal,
        learning_content,
        practice_exercises,
        learning_materials,
        study_guide,
        study_duration_hours,
        completion_status: 'NOT_STARTED',
        study_date: new Date(roadmapStartDate.getTime() + (i * 86400000)).toISOString().split('T')[0]
      });
    }

    return { analysis: parsed.analysis || '', roadmap: normalized, tokensUsed: 0 };
  } catch (err) {
    console.error('callAIService error:', err && err.message ? err.message : err);
    throw err;
  }
}
// ...existing code...

function parseAIResponse(aiResponse) {
    return {
        analysis: aiResponse.analysis,
        roadmap: aiResponse.roadmap
    };
}

// =====================================================
// API ROUTES
// =====================================================

// POST /api/ai/generate-roadmap-with-custom-prompt
app.post("/api/ai/generate-roadmap-with-custom-prompt", requireAuth, async (req, res) => {
    const startTime = Date.now();
    
    try {
        const { error, value } = generateRoadmapSchema.validate(req.body);
        if (error) {
            return res.status(400).json({
                error: 'Invalid input data',
                details: error.details[0].message
            });
        }

        const promptTemplate = await getPromptTemplate();
        
        let aiPrompt = promptTemplate.prompt_template;
        let aiPrompt_system = promptTemplate.json_format_response;
        
        const variableMapping = {
            'CATEGORY': value.category,
            'SUB_CATEGORY': value.subCategory,
            'ROADMAP_NAME': value.roadmapName,
            'MAIN_PURPOSE': value.mainPurpose,
            'SPECIFIC_GOAL': value.specificGoal,
            'CURRENT_JOB': value.currentJob || 'Không cung cấp',
            'STUDY_TIME': value.studyTime,
            'CURRENT_LEVEL': value.currentLevel,
            'SKILLS_TO_IMPROVE': Array.isArray(value.skillsToImprove) ? value.skillsToImprove.join(', ') : value.skillsToImprove,
            'DAILY_TIME': value.dailyTime,
            'WEEKLY_FREQUENCY': value.weeklyFrequency,
            'TOTAL_DURATION': value.totalDuration,
            'LEARNING_STYLE': Array.isArray(value.learningStyle) ? value.learningStyle.join(', ') : value.learningStyle,
            'LEARNING_METHOD': Array.isArray(value.learningMethod) ? value.learningMethod.join(', ') : value.learningMethod,
            'DIFFICULTIES': value.difficulties,
            'MOTIVATION': value.motivation,
            'MATERIAL_TYPE': Array.isArray(value.materialType) ? value.materialType.join(', ') : value.materialType,
            'MATERIAL_LANGUAGE': value.materialLanguage,
            'ASSESSMENT_TYPE': value.assessmentType,
            'RESULT_DISPLAY': value.resultDisplay,
            'ASSESSMENT_FREQUENCY': value.assessmentFrequency
        };

        Object.keys(variableMapping).forEach(key => {
            aiPrompt = aiPrompt.replace(new RegExp(`<${key}>`, 'g'), variableMapping[key]);
        });

        const logId = await logAIPrompt(req.user.id, value, aiPrompt, 'PENDING');

        try {
            const actualDays = value.totalDuration; //parseInt(finalData.program_days);
            const hoursPerDay = value.dailyTime; //Math.round((totalHours / actualDays) * 100) / 100;

            // gọi AI với số ngày và hoursPerDay
            const aiResponse = await callAIService(aiPrompt, aiPrompt_system, actualDays, hoursPerDay);
            // parsedResponse = aiResponse (already {analysis, roadmap})
            const parsedResponse = {
              analysis: aiResponse.analysis,
              roadmap: aiResponse.roadmap
            };

            console.log('parsedResponse:',JSON.stringify(parsedResponse));
            
            await updateAILog(logId, {
                status: 'SUCCESS',
                ai_response: JSON.stringify(parsedResponse),
                processing_time: Date.now() - startTime,
                tokens_used: aiResponse.tokensUsed || 0,
                ai_model: process.env.AI_MODEL || 'mock'
            });

            res.json({
                success: true,
                data: parsedResponse,
                logId: logId
            });

        } catch (aiError) {
            await updateAILog(logId, {
                status: 'FAILED',
                error_message: aiError.message,
                processing_time: Date.now() - startTime
            });
            throw aiError;
        }

    } catch (error) {
        console.error('Error generating roadmap:', error);
        res.status(500).json({
            error: 'AI generation failed',
            //message: 'Không thể tạo lộ trình với AI'
            message: error.message || 'Lỗi' || req.body
        });
    }
});

// POST /api/ai/save-roadmap
app.post("/api/ai/save-roadmap", requireAuth, async (req, res) => {
    const client = await pool.connect();

    try {
        const { error, value } = saveRoadmapSchema.validate(req.body);
        if (error) {
            return res.status(400).json({
                error: 'Invalid input data',
                details: error.details[0].message
            });
        }

        await client.query('BEGIN');

        const { formData, analysis, roadmap, aiPromptLog } = value;

        const totalDays = roadmap.length;
        const totalHours = roadmap.reduce((sum, day) => {
            const hours = parseFloat(day.duration.replace(/[^\d.]/g, '')) || 0;
            return sum + hours;
        }, 0);

        const userId = req.user.id;

        const roadmapQuery = `
            INSERT INTO learning_roadmaps (
                roadmap_name, category, sub_category, start_level, user_id,
                duration_days, duration_hours, roadmap_analyst, status, 
                expected_outcome, progress_percentage, total_studied_hours
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'ACTIVE', $9, 0.00, 0.00)
            RETURNING roadmap_id
        `;

        const roadmapResult = await client.query(roadmapQuery, [
            formData.roadmapName,
            formData.category,
            formData.subCategory || null,
            formData.currentLevel,
            userId,
            totalDays,
            totalHours,
            analysis,
            formData.specificGoal
        ]);

        const roadmapId = roadmapResult.rows[0].roadmap_id;

        for (const day of roadmap) {
            const detailQuery = `
                INSERT INTO learning_roadmap_details (
                    roadmap_id, day_number, daily_goal, learning_content,
                    practice_exercises, learning_materials, usage_instructions,
                    study_duration_hours, completion_status, study_date
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            `;

            const durationHours = parseFloat(day.duration.replace(/[^\d.]/g, '')) || 0;

            await client.query(detailQuery, [
                roadmapId,
                day.day,
                day.goal,
                day.content,
                day.exercises || null,
                day.materials,
                day.instructions || null,
                durationHours,
                'NOT_STARTED',
                null
            ]);
        }

        const logQuery = `
            UPDATE ai_prompt_logs
            SET roadmap_id = $1
            WHERE log_id = $2
        `;

        await client.query(logQuery, [roadmapId, aiPromptLog]);

        await client.query('COMMIT');

        res.status(201).json({
            success: true,
            message: 'Lộ trình đã được lưu thành công',
            data: {
                roadmap_id: roadmapId
            }
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error saving roadmap:', error);
        res.status(500).json({
            error: 'Database transaction failed',
            message: 'Không thể lưu lộ trình'
        });
    } finally {
        client.release();
    }
});
*/
const updateDetailStatusSchema = Joi.object({
    detailId: Joi.number().required(),
    status: Joi.string().valid('NOT_STARTED', 'IN_PROGRESS', 'COMPLETED', 'SKIPPED').required(),
    studyDate: Joi.string().allow(null, '')
});

app.get("/api/roadmap", requireAuth, async (req, res) => {
  try {
    // ✅ DEBUG: Log toàn bộ req.user
    console.log('🔍 /api/roadmap - req.user:', JSON.stringify(req.user, null, 2));
    console.log('🔍 req.user.id type:', typeof req.user?.id);
    console.log('🔍 req.user.id value:', req.user?.id);
    
    const userId = req.user?.id;
    
    // ✅ VALIDATE trước khi parse
    if (!userId) {
      console.error('❌ userId is falsy:', userId);
      return res.status(401).json({ message: 'User ID missing' });
    }
    
    // ✅ Parse và validate
    const userIdInt = parseInt(userId);
    console.log('🔍 After parseInt:', userIdInt, 'isNaN:', isNaN(userIdInt));
    
    if (isNaN(userIdInt)) {
      console.error('❌ userId cannot be parsed to int:', userId);
      return res.status(401).json({ message: 'Invalid user ID format' });
    }
    
    const query = `
      SELECT 
        roadmap_id,
        roadmap_name,
        category,
        sub_category,
        start_level,
        duration_days,
        duration_hours,
        status,
        progress_percentage,
        total_studied_hours,
        overall_rating,
        roadmap_analyst,
        expected_outcome,
        created_at
      FROM learning_roadmaps
      WHERE user_id = $1::integer
      ORDER BY created_at DESC
    `;

    console.log('🔍 Executing query with userId:', userIdInt);
    
    const result = await pool.query(query, [userIdInt]);
    
    console.log('✅ Query success, rows:', result.rows.length);

    res.json({
      success: true,
      data: result.rows
    });

  } catch (error) {
    console.error('❌❌❌ ERROR in /api/roadmap:');
    console.error('Message:', error?.message);
    console.error('Stack:', error?.stack);
    console.error('Code:', error?.code);
    console.error('Detail:', error?.detail);
    console.error('Position:', error?.position);
    
    res.status(500).json({
      error: 'Database query failed',
      message: 'Không thể lấy danh sách lộ trình',
      debug: process.env.NODE_ENV === 'development' ? error?.message : undefined
    });
  }
});

app.get("/api/roadmap/:id", requireAuth, async (req, res) => {
  try {
    // ✅ DEBUG: Log toàn bộ thông tin
    console.log('🔍 /api/roadmap/:id - req.params.id:', req.params.id);
    console.log('🔍 req.user:', JSON.stringify(req.user, null, 2));
    console.log('🔍 req.user.id type:', typeof req.user?.id);
    console.log('🔍 req.user.id value:', req.user?.id);
    
    const roadmapId = parseInt(req.params.id);
    console.log('🔍 roadmapId after parseInt:', roadmapId, 'isNaN:', isNaN(roadmapId));
    
    if (isNaN(roadmapId)) {
      console.error('❌ Invalid roadmap ID:', req.params.id);
      return res.status(400).json({
        error: 'Invalid roadmap ID',
        message: 'ID lộ trình không hợp lệ'
      });
    }
    
    // ✅ VALIDATE user.id
    const userId = parseInt(req.user?.id);
    console.log('🔍 userId after parseInt:', userId, 'isNaN:', isNaN(userId));
    
    if (!userId || isNaN(userId)) {
      console.error('❌ Invalid user ID:', req.user?.id);
      return res.status(401).json({
        error: 'Invalid user session',
        message: 'Phiên đăng nhập không hợp lệ'
      });
    }

    const roadmapQuery = `
      SELECT * FROM learning_roadmaps
      WHERE roadmap_id = $1::integer AND user_id = $2::integer
    `;

    console.log('🔍 Executing roadmapQuery with:', { roadmapId, userId });
    
    const roadmapResult = await pool.query(roadmapQuery, [roadmapId, userId]);
    
    console.log('✅ roadmapQuery success, rows:', roadmapResult.rows.length);

    if (roadmapResult.rows.length === 0) {
      console.warn('⚠️ Roadmap not found or no access');
      return res.status(404).json({
        error: 'Roadmap not found',
        message: 'Lộ trình học không tìm thấy'
      });
    }

    const detailsQuery = `
      SELECT * FROM learning_roadmap_details
      WHERE roadmap_id = $1::integer
      ORDER BY day_number ASC
    `;

    console.log('🔍 Executing detailsQuery with roadmapId:', roadmapId);
    
    const detailsResult = await pool.query(detailsQuery, [roadmapId]);
    
    console.log('✅ detailsQuery success, rows:', detailsResult.rows.length);

    res.json({
      success: true,
      data: {
        roadmap: roadmapResult.rows[0],
        details: detailsResult.rows
      }
    });

  } catch (error) {
    console.error('❌❌❌ ERROR in /api/roadmap/:id:');
    console.error('Message:', error?.message);
    console.error('Stack:', error?.stack);
    console.error('Code:', error?.code);
    console.error('Detail:', error?.detail);
    console.error('Position:', error?.position);
    console.error('Query:', error?.query);
    
    res.status(500).json({
      error: 'Database query failed',
      message: 'Không thể lấy dữ liệu lộ trình',
      debug: process.env.NODE_ENV === 'development' ? error?.message : undefined
    });
  }
});
// cập nhật trạng thái của lộ trình
app.put("/api/roadmap/:id/update-status", requireAuth, async (req, res) => {
// PUT /api/roadmap/:id/update-status - Update trạng thái chi tiết
    const client = await pool.connect();

    try {
        const roadmapId = parseInt(req.params.id);
        const { error, value } = updateDetailStatusSchema.validate(req.body);

        if (error) {
            return res.status(400).json({
                error: 'Invalid input data',
                details: error.details[0].message
            });
        }

        const { detailId, status, studyDate } = value;

       // sanitize inputs
        const statusStr = String(status);
        /*let studyDateVal = (typeof studyDate === 'string' && studyDate.trim() === '') ? null : studyDate;
        if (studyDateVal) {
          // ensure YYYY-MM-DD string (Postgres DATE)
          const d = new Date(studyDateVal);
          if (!isNaN(d)) studyDateVal = d.toISOString().slice(0, 10);
          else studyDateVal = null;
        }*/
        const detailIdNum = parseInt(detailId, 10);
        const roadmapIdNum = parseInt(roadmapId, 10);

        await client.query('BEGIN');

        // Update detail status (explicit casts)
        const updateDetailQuery = `
            UPDATE learning_roadmap_details
            SET 
                completion_status = $1::varchar,
                updated_at = CURRENT_TIMESTAMP,
                completed_at = CASE 
                    WHEN $1::varchar = 'COMPLETED' THEN CURRENT_TIMESTAMP
                    ELSE completed_at
                END
            WHERE detail_id = $2::int AND roadmap_id = $3::int
            RETURNING detail_id, completion_status, study_date, roadmap_id
        `;
        /*study_date = (
            CASE 
                WHEN $2 IS NOT NULL THEN $2::date
                WHEN $1::varchar = 'COMPLETED' THEN CURRENT_DATE
                ELSE study_date
            END
        )::date,*/
        const detailResult = await client.query(updateDetailQuery, [
            statusStr,
            //studyDateVal,
            detailIdNum,
            roadmapIdNum
        ]);

        if (detailResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({
                error: 'Detail not found',
                message: 'Chi tiết lộ trình không tìm thấy'
            });
        }

        // Calculate progress
        const progressQuery = `
        SELECT 
          COUNT(*) FILTER (WHERE completion_status = 'COMPLETED') as completed_count,
          COUNT(*) as total_count,
          COALESCE(SUM(study_duration_hours) FILTER (WHERE completion_status = 'COMPLETED'), 0) as total_studied_hours
        FROM learning_roadmap_details
        WHERE roadmap_id = $1
      `;

      const progressResult = await client.query(progressQuery, [roadmapId]);

      // Coerce DB strings -> numbers
      const completed_count = Number(progressResult.rows[0].completed_count) || 0;
      const total_count = Number(progressResult.rows[0].total_count) || 0;
      const total_studied_hours = Number(progressResult.rows[0].total_studied_hours) || 0;

      const progressPercentage = total_count === 0 ? 0 : (completed_count / total_count) * 100;

      // Update roadmap progress — cast params explicitly in SQL
      const updateProgressQuery = `
        UPDATE learning_roadmaps
        SET 
          progress_percentage = $1::numeric,
          total_studied_hours = $2::numeric,
          updated_at = CURRENT_TIMESTAMP
        WHERE roadmap_id = $3::int
        RETURNING roadmap_id, progress_percentage, total_studied_hours
      `;

      const updateValues = [
        Number(progressPercentage.toFixed(2)), // numeric
        total_studied_hours,
        roadmapId
      ];

      const roadmapResult = await client.query(updateProgressQuery, updateValues);

        await client.query('COMMIT');

        res.json({
            success: true,
            message: 'Đã cập nhật trạng thái thành công',
            data: {
                detail: detailResult.rows[0],
                roadmap: roadmapResult.rows[0]
            }
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error updating status:', error);
        res.status(500).json({
            error: 'Database transaction failed',
            message: 'Không thể cập nhật trạng thái'
        });
    } finally {
        client.release();
    }
});

const submitEvaluationSchema = Joi.object({
    overall_rating: Joi.number().min(1).max(5).required(),
    learning_effectiveness: Joi.number().min(1).max(5).required(),
    difficulty_suitability: Joi.number().min(1).max(5).required(),
    content_relevance: Joi.number().min(1).max(5).required(),
    engagement_level: Joi.number().min(1).max(5).required(),
    detailed_feedback: Joi.string().allow(''),
    recommended_category: Joi.string().allow(''),
    actual_learning_outcomes: Joi.string().allow(''),
    improvement_suggestions: Joi.string().allow(''),
    would_recommend: Joi.boolean()
});

// cập nhật các đánh giá của lộ trình
app.post("/api/roadmap/:id/submit-evaluation", requireAuth, async (req, res) => {
// POST /api/roadmap/:id/submit-evaluation - Submit đánh giá
    const client = await pool.connect();

    try {
        const roadmapId = parseInt(req.params.id);
        const { error, value } = submitEvaluationSchema.validate(req.body);

        if (error) {
            return res.status(400).json({
                error: 'Invalid input data',
                details: error.details[0].message
            });
        }

        await client.query('BEGIN');

        // Verify roadmap belongs to user
        const verifyQuery = `
            SELECT roadmap_id FROM learning_roadmaps
            WHERE roadmap_id = $1 AND user_id = $2
        `;

        const verifyResult = await client.query(verifyQuery, [roadmapId, req.user.id]);

        if (verifyResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({
                error: 'Roadmap not found',
                message: 'Lộ trình không tìm thấy'
            });
        }

        // Update roadmap with evaluation
        const updateQuery = `
            UPDATE learning_roadmaps
            SET 
                overall_rating = $1,
                learning_effectiveness = $2,
                difficulty_suitability = $3,
                content_relevance = $4,
                engagement_level = $5,
                detailed_feedback = $6,
                recommended_category = $7,
                actual_learning_outcomes = $8,
                improvement_suggestions = $9,
                would_recommend = $10,
                updated_at = CURRENT_TIMESTAMP
            WHERE roadmap_id = $11
            RETURNING roadmap_id, overall_rating, status
        `;

        const result = await client.query(updateQuery, [
            value.overall_rating,
            value.learning_effectiveness,
            value.difficulty_suitability,
            value.content_relevance,
            value.engagement_level,
            value.detailed_feedback || null,
            value.recommended_category || null,
            value.actual_learning_outcomes || null,
            value.improvement_suggestions || null,
            value.would_recommend || false,
            roadmapId
        ]);

        await client.query('COMMIT');

        res.json({
            success: true,
            message: 'Đánh giá đã được lưu thành công',
            data: result.rows[0]
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error submitting evaluation:', error);
        res.status(500).json({
            error: 'Database transaction failed',
            message: 'Không thể lưu đánh giá'
        });
    } finally {
        client.release();
    }
});

// =====================================================
// ADMIN ROUTES
// =====================================================

app.post("/api/admin/prompt/save", requireAdmin, async (req, res) => {
// POST /api/admin/prompt/save
    try {
        const userId = req.user.id;
        const { promptContent, jsonFormat } = req.body;

        /*const requiredVars = [
            'CATEGORY', 'SUB_CATEGORY', 'ROADMAP_NAME',
            'MAIN_PURPOSE', 'SPECIFIC_GOAL', 'CURRENT_JOB', 'STUDY_TIME',
            'CURRENT_LEVEL', 'SKILLS_TO_IMPROVE', 'DAILY_TIME', 'WEEKLY_FREQUENCY',
            'TOTAL_DURATION', 'LEARNING_STYLE', 'LEARNING_METHOD', 'DIFFICULTIES',
            'MOTIVATION', 'MATERIAL_TYPE', 'MATERIAL_LANGUAGE', 'ASSESSMENT_TYPE',
            'RESULT_DISPLAY', 'ASSESSMENT_FREQUENCY'
        ];

        const missingVars = [];
        requiredVars.forEach(varName => {
            if (!promptContent.includes(`<${varName}>`)) {
                missingVars.push(varName);
            }
        });

        if (missingVars.length > 0) {
            return res.status(400).json({
                error: 'Invalid prompt template',
                message: `Các biến bắt buộc bị xóa/sửa: ${missingVars.join(', ')}`,
                missingVariables: missingVars
            });
        }*/

        const query = `
            UPDATE admin_settings
            SET 
                prompt_template = $1,
                json_format_response = $2,
                updated_at = CURRENT_TIMESTAMP,
                updated_by = $3
            WHERE setting_key = 'prompt_template'
            RETURNING setting_id
        `;

        const result = await pool.query(query, [
            promptContent,
            jsonFormat,
            userId
        ]);

        if (result.rows.length === 0) {
            const insertQuery = `
                INSERT INTO admin_settings (
                    setting_key, prompt_template, json_format_response, updated_by
                ) VALUES ('prompt_template', $1, $2, $3)
                RETURNING setting_id
            `;

            await pool.query(insertQuery, [
                promptContent,
                jsonFormat,
                req.user.id
            ]);
        }

        res.json({
            success: true,
            message: 'Prompt mẫu đã được lưu thành công',
            updatedAt: new Date()
        });

    } catch (error) {
        console.error('Error saving prompt template:', error);
        res.status(500).json({
            error: 'Database error',
            message: 'Không thể lưu Prompt mẫu'
        });
    }
});

app.post("/api/admin/prompt", requireAdmin, async (req, res) => {
// GET /api/admin/prompt
    try {
        const query = `
            SELECT 
                setting_id,
                prompt_template,
                json_format_response,
                updated_at,
                updated_by
            FROM admin_settings
            WHERE setting_key = 'prompt_template'
        `;

        const result = await pool.query(query);

        if (result.rows.length === 0) {
            return res.status(404).json({
                error: 'Prompt template not found',
                message: 'Chưa có Prompt mẫu nào'
            });
        }

        res.json({
            success: true,
            data: result.rows[0]
        });

    } catch (error) {
        console.error('Error fetching prompt template:', error);
        res.status(500).json({
            error: 'Database query failed',
            message: 'Không thể lấy Prompt mẫu'
        });
    }
});

// =====================================================
// API ENDPOINTS - MAIN.HTML
// =====================================================

/**
 * GET /api/categories/top
 * Lấy top 6 lĩnh vực có nhiều lộ trình nhất
 */
app.get('/api/categories/top', async (req, res) => {
    try {
        const query = `
            SELECT 
                c.id,
                c.name,
                c.description,
                COUNT(lr.roadmap_id) as roadmap_count
            FROM categories c
            LEFT JOIN learning_roadmaps_system lr ON lr.category = c.name
            GROUP BY c.id, c.name, c.description
            HAVING COUNT(lr.roadmap_id) > 0
            ORDER BY roadmap_count DESC
            LIMIT 6
        `;
        
        const result = await pool.query(query);
        res.json(result.rows);
        
    } catch (error) {
        console.error('Error fetching top categories:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            message: error.message 
        });
    }
});

/**
 * GET /api/roadmaps/category/:categoryName
 * Lấy thông tin category và tất cả lộ trình thuộc category đó (hệ thống)
 */
app.get('/api/roadmapsystem/category/:categoryName', async (req, res) => {
  try {
    const categoryName  = req.params.categoryName;
    const { page = 1, limit = 12 } = req.query;
    const offset = (page - 1) * limit;
    //console.log("categoryName",categoryName);
    const queryC = `
      SELECT 
        id,
        name,
        description,
        created_at
      FROM categories
      WHERE id = $1
    `;
    
    const result = await pool.query(queryC, [parseInt(categoryName)]);
    //console.log ('result.rows[0].name 2=',result.rows[0].name);

    // Get category info
    const countQuery = `
        SELECT COUNT(*) as total
      FROM learning_roadmaps_system
      WHERE category = $1
    `;
    const countResult = await pool.query(countQuery, [result.rows[0].name]);

    //console.log('categoryResult.rows.length=', countResult.rows.length);
   
    
    // Get all roadmaps for this category
    const query = `
        SELECT 
        roadmap_id,
        roadmap_name,
        category,
        sub_category,
        start_level,
        total_user_learning,
        duration_days,
        duration_hours,
        overall_rating,
        learning_effectiveness,
        created_at,
        updated_at
      FROM learning_roadmaps_system
      WHERE category = $1
      ORDER BY created_at DESC
      LIMIT $2 OFFSET $3
    `;
    const roadmaps = await pool.query(query, [result.rows[0].name, limit, offset]);
   //console.log('roadmaps.rows=', roadmaps.rows);

    res.json({
      success: true,
      data: roadmaps.rows,
      pagination: {
        total: parseInt(countResult.rows[0].total),
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(countResult.rows[0].total / limit)
      }
    });
  } catch (error) {
    console.log('Error fetching roadmaps by category:', error);
    console.error('Error fetching roadmaps by category:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể tải danh sách lộ trình'
    });
  }
});


// =====================================================
// API: Lấy chi tiết 1 lộ trình system
// =====================================================
app.get('/api/roadmapsystem/:roadmapId', async (req, res) => {
  try {
    const { roadmapId } = req.params;
    
    const query = `
      SELECT 
        roadmap_id,
        roadmap_name,
        category,
        sub_category,
        start_level,
        total_user_learning,
        duration_days,
        duration_hours,
        overall_rating,
        learning_effectiveness,
        created_at,
        updated_at,
        roadmap_analyst
      FROM learning_roadmaps_system
      WHERE roadmap_id = $1
    `;
    
    const result = await pool.query(query, [roadmapId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Không tìm thấy lộ trình'
      });
    }
    
    res.json({
      success: true,
      data: result.rows[0]
    });
  } catch (error) {
    console.error('Error fetching roadmap details:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể tải thông tin lộ trình'
    });
  }
});


// =====================================================
// API: Lấy chi tiết các ngày học của lộ trình
// =====================================================
app.get('/api/roadmapsystem/:roadmapId/details', async (req, res) => {
  try {
    const roadmapId = req.params.roadmapId;
    //console.log ('roadmapId=',roadmapId);
    const query = `
      SELECT 
        detail_id,
        roadmap_id,
        day_number,
        study_date,
        daily_goal,
        learning_content,
        practice_exercises,
        learning_materials,
        usage_instructions,
        study_duration_hours,
        completion_status,
        created_at,
        updated_at,
        completed_at
      FROM learning_roadmap_details_system
      WHERE roadmap_id = $1
      ORDER BY day_number ASC
    `;
    
    const result = await pool.query(query, [parseInt(roadmapId)]);
    
    res.json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error('Error fetching roadmap day details:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể tải chi tiết lộ trình'
    });
  }
});

// =====================================================
// API: Lấy thông tin category cụ thể
// =====================================================
app.get('/api/categories/:categoryName', async (req, res) => {
  try {
    const categoryName  = req.params.categoryName;
    //console.log ('categoryName',categoryName);
    const query = `
      SELECT 
        id,
        name,
        description,
        created_at
      FROM categories
      WHERE id = $1
    `;
    
    const result = await pool.query(query, [parseInt(categoryName)]);
    //console.log ('result.rows[0].name=',result.rows[0].name);
    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Không tìm thấy lĩnh vực'
      });
    }
     //console.log ('result.rows[0]',result.rows[0]);
    res.json({
      success: true,
      data: result.rows[0]
    });
  } catch (error) {
    console.error('Error fetching category:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể tải thông tin lĩnh vực'
    });
  }
});

