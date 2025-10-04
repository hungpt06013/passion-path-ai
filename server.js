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

// Link validation with timeout and retry
const linkCache = new Map();
const LINK_CACHE_TTL = 3600000; // 1 hour

async function validateUrlQuick(url, timeout = 5000) {
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
      
      const isValid = response && response.status >= 200 && response.status < 400;
      linkCache.set(url, { valid: isValid, timestamp: Date.now() });
      return isValid;
    } catch (e) {
      clearTimeout(timeoutId);
      linkCache.set(url, { valid: false, timestamp: Date.now() });
      return false;
    }
  } catch (e) {
    return false;
  }
}

// Get specific exercise link from AI
async function getSpecificExerciseLink(topic, category, dayNumber) {
  try {
    const systemPrompt = `Bạn là chuyên gia tìm kiếm bài tập lập trình. Trả về CHỈ MỘT URL cụ thể (không phải trang chủ) dẫn đến bài tập/challenge trên các trang như HackerRank, LeetCode, Codeforces, GeeksForGeeks. URL phải dẫn trực tiếp đến một bài tập cụ thể, KHÔNG phải dashboard hay trang danh sách.`;
    
    const userPrompt = `Tìm 1 URL bài tập cụ thể cho: "${topic}" (Category: ${category}, Day: ${dayNumber}). 
Ví dụ tốt: https://www.hackerrank.com/challenges/variable-sized-arrays/problem
Ví dụ XẤU: https://www.hackerrank.com/dashboard
Trả về CHỈ URL, không giải thích.`;

    const completion = await callOpenAIWithFallback({
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt }
      ],
      desiredCompletionTokens: 200
    });

    const text = completion?.choices?.[0]?.message?.content?.trim();
    if (!text) return null;

    const urlMatch = text.match(/https?:\/\/[^\s"'\)\]\s]+/);
    if (!urlMatch) return null;

    const url = urlMatch[0];
    
    if (url.includes('/dashboard') || url.includes('/problems$') || url.endsWith('.com') || url.endsWith('.com/')) {
      return null;
    }

    const isValid = await validateUrlQuick(url);
    return isValid ? url : null;
  } catch (e) {
    console.warn(`Exercise link error for day ${dayNumber}:`, e.message);
    return null;
  }
}

// Get specific learning material link from AI
async function getSpecificMaterialLink(topic, category, dayNumber) {
  try {
    const systemPrompt = `Bạn là chuyên gia tìm kiếm tài liệu học tập. Trả về CHỈ MỘT URL cụ thể (không phải trang chủ) dẫn đến bài học/tutorial chi tiết trên các trang như GeeksForGeeks, MDN, W3Schools, TutorialsPoint. URL phải dẫn trực tiếp đến một bài học cụ thể, KHÔNG phải trang chủ.`;
    
    const userPrompt = `Tìm 1 URL tài liệu cụ thể cho: "${topic}" (Category: ${category}, Day: ${dayNumber}).
Ví dụ tốt: https://www.geeksforgeeks.org/introduction-to-dynamic-programming-data-structures-and-algorithm-tutorials
Ví dụ XẤU: https://www.geeksforgeeks.org
Trả về CHỈ URL, không giải thích.`;

    const completion = await callOpenAIWithFallback({
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt }
      ],
      desiredCompletionTokens: 200
    });

    const text = completion?.choices?.[0]?.message?.content?.trim();
    if (!text) return null;

    const urlMatch = text.match(/https?:\/\/[^\s"'\)\]\s]+/);
    if (!urlMatch) return null;

    const url = urlMatch[0];
    
    if (url.endsWith('.com') || url.endsWith('.com/') || url.endsWith('.org') || url.endsWith('.org/')) {
      return null;
    }

    const isValid = await validateUrlQuick(url);
    return isValid ? url : null;
  } catch (e) {
    console.warn(`Material link error for day ${dayNumber}:`, e.message);
    return null;
  }
}

// Fallback links by category
const FALLBACK_LINKS = {
  programming: {
    exercises: [
      "https://www.hackerrank.com/challenges/solve-me-first/problem",
      "https://leetcode.com/problems/two-sum/",
      "https://www.codewars.com/kata/523b4ff7adca849afe000035"
    ],
    materials: [
      "https://www.geeksforgeeks.org/learn-data-structures-and-algorithms-dsa-tutorial/",
      "https://developer.mozilla.org/en-US/docs/Learn",
      "https://www.w3schools.com/js/DEFAULT.asp"
    ]
  },
  english: {
    exercises: [
      "https://www.englishclub.com/grammar/",
      "https://www.perfect-english-grammar.com/grammar-exercises.html"
    ],
    materials: [
      "https://www.bbc.co.uk/learningenglish/english/",
      "https://www.britishcouncil.org/english"
    ]
  },
  math: {
    exercises: [
      "https://www.khanacademy.org/math",
      "https://www.mathsisfun.com/algebra/index.html"
    ],
    materials: [
      "https://www.khanacademy.org/math",
      "https://en.wikipedia.org/wiki/Mathematics"
    ]
  },
  default: {
    exercises: [
      "https://www.khanacademy.org/",
      "https://www.coursera.org/"
    ],
    materials: [
      "https://en.wikipedia.org/",
      "https://www.youtube.com/education"
    ]
  }
};

function getFallbackLinks(category) {
  const cat = (category || '').toLowerCase();
  if (cat.includes('program') || cat.includes('code')) return FALLBACK_LINKS.programming;
  if (cat.includes('english') || cat.includes('tiếng anh')) return FALLBACK_LINKS.english;
  if (cat.includes('math') || cat.includes('toán')) return FALLBACK_LINKS.math;
  return FALLBACK_LINKS.default;
}

// Main AI roadmap generation endpoint
app.post("/api/generate-roadmap-ai", requireAuth, async (req, res) => {
  try {
    if (!process.env.OPENAI_API_KEY) {
      return res.status(503).json({ success: false, error: "Tính năng AI chưa được cấu hình. Vui lòng liên hệ quản trị viên." });
    }

    const { roadmap_name, category, sub_category, start_level, duration_days, duration_hours, expected_outcome } = req.body;
    
    if (!roadmap_name || !category || !start_level || !duration_days || !duration_hours || !expected_outcome) {
      return res.status(400).json({ success: false, error: "Thiếu thông tin bắt buộc để tạo lộ trình" });
    }

    const actualDays = parseInt(duration_days);
    const totalHours = parseFloat(duration_hours);
    
    if (isNaN(actualDays) || actualDays <= 0 || actualDays > MAX_AI_DAYS) {
      return res.status(400).json({ success: false, error: `Số ngày phải từ 1 đến ${MAX_AI_DAYS}` });
    }
    
    if (isNaN(totalHours) || totalHours <= 0) {
      return res.status(400).json({ success: false, error: "Tổng số giờ không hợp lệ" });
    }

    const hoursPerDay = Math.round((totalHours / actualDays) * 100) / 100;

    console.log(`🤖 Generating AI roadmap: ${roadmap_name} (${actualDays} days, ${hoursPerDay}h/day)`);

    const systemPrompt = `Bạn là chuyên gia thiết kế lộ trình học tập chuyên nghiệp. 

NHIỆM VỤ: Tạo lộ trình học ${actualDays} ngày với cấu trúc JSON chính xác.

YÊU CẦU BẮT BUỘC:
1. Trả về CHỈ MỘT object JSON với key "roadmap" chứa array ${actualDays} phần tử
2. Mỗi object trong array phải có CHÍNH XÁC các trường:
   - day_number: số ngày (1 đến ${actualDays})
   - daily_goal: mục tiêu cụ thể của ngày đó (30-80 ký tự, VD: "Nắm vững cú pháp biến và kiểu dữ liệu trong JavaScript")
   - learning_content: nội dung chi tiết (150-300 ký tự, bao gồm: khái niệm chính, ví dụ cụ thể, lưu ý quan trọng)
   - practice_exercises: mô tả bài tập (50-150 ký tự, VD: "Viết 5 chương trình nhỏ sử dụng var, let, const và so sánh khác biệt")
   - learning_materials: mô tả tài liệu (30-100 ký tự, VD: "Tài liệu MDN về JavaScript variables và scope")
   - study_duration_hours: ${hoursPerDay}

QUY TẮC:
- Nội dung phải tuần tự, logic, từ dễ đến khó
- Mỗi ngày phải khác biệt, không lặp lại
- daily_goal phải súc tích, rõ ràng
- learning_content phải chi tiết, có ví dụ cụ thể
- practice_exercises phải thực tế, có thể làm được
- KHÔNG đưa URL vào learning_materials (server sẽ tự động thêm)
- Sử dụng tiếng Việt

ĐỊNH DẠNG XUẤT:
{
  "roadmap": [
    {
      "day_number": 1,
      "daily_goal": "Mục tiêu ngày 1...",
      "learning_content": "Nội dung chi tiết...",
      "practice_exercises": "Bài tập thực hành...",
      "learning_materials": "Tài liệu học tập...",
      "study_duration_hours": ${hoursPerDay}
    }
  ]
}`;

    const userPrompt = `Tạo lộ trình học ${actualDays} ngày cho:
- Tên lộ trình: ${roadmap_name}
- Danh mục: ${category}${sub_category ? ` / ${sub_category}` : ''}
- Trình độ bắt đầu: ${start_level}
- Mục tiêu cuối khóa: ${expected_outcome}
- Thời gian mỗi ngày: ${hoursPerDay} giờ

Hãy tạo lộ trình chi tiết, thực tế, dễ theo dõi.`;

    const estimatedTokensPerDay = TOKENS_PER_DAY;
    const desiredTokens = Math.min(actualDays * estimatedTokensPerDay, MAX_AI_TOKENS - SAFETY_MARGIN_TOKENS);

    let aiResponse = null;
    let attempts = 0;
    const MAX_ATTEMPTS = 2;

    while (attempts < MAX_ATTEMPTS && !aiResponse) {
      attempts++;
      try {
        console.log(`🔄 AI attempt ${attempts}/${MAX_ATTEMPTS}...`);
        const completion = await callOpenAIWithFallback({
          messages: [
            { role: "system", content: systemPrompt },
            { role: "user", content: userPrompt }
          ],
          desiredCompletionTokens: desiredTokens
        });

        const text = completion?.choices?.[0]?.message?.content?.trim();
        if (text) {
          aiResponse = text;
          break;
        }
      } catch (e) {
        console.error(`❌ AI attempt ${attempts} failed:`, e.message);
        if (attempts === MAX_ATTEMPTS) throw e;
      }
    }

    if (!aiResponse) {
      throw new Error("AI không trả về kết quả sau nhiều lần thử");
    }

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

    let days = null;
    if (roadmapData && Array.isArray(roadmapData.roadmap)) {
      days = roadmapData.roadmap;
    } else if (Array.isArray(roadmapData)) {
      days = roadmapData;
    } else {
      throw new Error("AI response không chứa mảng roadmap");
    }

    if (days.length !== actualDays) {
      console.warn(`⚠️ AI returned ${days.length} days instead of ${actualDays}, padding...`);
      if (days.length < actualDays) {
        for (let i = days.length; i < actualDays; i++) {
          days.push({
            day_number: i + 1,
            daily_goal: `Ôn tập và củng cố kiến thức ngày ${i + 1}`,
            learning_content: `Ôn lại các kiến thức đã học từ đầu khóa. Làm bài tập tổng hợp và kiểm tra hiểu biết.`,
            practice_exercises: `Làm bài tập tổng hợp các chủ đề đã học`,
            learning_materials: `Tài liệu ôn tập tổng hợp`,
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
        daily_goal: String(d.daily_goal || d.goal || `Mục tiêu ngày ${i + 1}`).trim(),
        learning_content: String(d.learning_content || d.content || `Nội dung học tập ngày ${i + 1}`).trim(),
        practice_exercises: String(d.practice_exercises || d.exercises || `Bài tập thực hành ngày ${i + 1}`).trim(),
        learning_materials: String(d.learning_materials || d.materials || `Tài liệu học tập ngày ${i + 1}`).trim(),
        study_duration_hours: parseFloat(d.study_duration_hours || d.hours || hoursPerDay)
      };

      if (normalized.daily_goal.length < 20) {
        normalized.daily_goal = `Ngày ${i + 1}: ${normalized.daily_goal} - ${category}`.slice(0, 80);
      }
      if (normalized.learning_content.length < 100) {
        normalized.learning_content = `${normalized.learning_content} Học và thực hành các khái niệm cơ bản, làm ví dụ minh họa, ghi chú lại kiến thức quan trọng.`;
      }
      if (normalized.practice_exercises.length < 30) {
        normalized.practice_exercises = `Thực hành: ${normalized.daily_goal}. Làm bài tập từ cơ bản đến nâng cao.`;
      }

      normalizedDays.push(normalized);
    }

    console.log(`✅ AI generated ${normalizedDays.length} days successfully`);

    console.log(`🔗 Fetching specific exercise and material links...`);
    
    const fallbackLinks = getFallbackLinks(category);
    const enrichmentPromises = normalizedDays.map(async (day, index) => {
      const topic = day.daily_goal;
      
      const [exerciseLink, materialLink] = await Promise.all([
        getSpecificExerciseLink(topic, category, day.day_number),
        getSpecificMaterialLink(topic, category, day.day_number)
      ]);

      let finalExerciseLink = exerciseLink;
      let finalMaterialLink = materialLink;

      if (!finalExerciseLink) {
        const fallbackExercise = fallbackLinks.exercises[index % fallbackLinks.exercises.length];
        const isValid = await validateUrlQuick(fallbackExercise);
        if (isValid) finalExerciseLink = fallbackExercise;
      }

      if (!finalMaterialLink) {
        const fallbackMaterial = fallbackLinks.materials[index % fallbackLinks.materials.length];
        const isValid = await validateUrlQuick(fallbackMaterial);
        if (isValid) finalMaterialLink = fallbackMaterial;
      }

      return {
        ...day,
        practice_exercises: finalExerciseLink 
          ? `${day.practice_exercises} - Link: ${finalExerciseLink}`
          : day.practice_exercises,
        learning_materials: finalMaterialLink 
          ? `${day.learning_materials} - Link: ${finalMaterialLink}`
          : day.learning_materials
      };
    });

    const enrichedDays = await Promise.all(enrichmentPromises);

    console.log(`✅ Successfully enriched roadmap with ${enrichedDays.length} days`);

    return res.json({
      success: true,
      message: "Tạo lộ trình AI thành công",
      data: enrichedDays,
      metadata: {
        total_days: enrichedDays.length,
        hours_per_day: hoursPerDay,
        total_hours: totalHours
      }
    });

  } catch (error) {
    console.error("❌ AI Generation Error:", error.message || error);
    
    const days = parseInt(req.body.duration_days) || 7;
    const hours = parseFloat(req.body.duration_hours) || 14;
    const hoursPerDay = hours / days;
    const fallbackLinks = getFallbackLinks(req.body.category || 'default');
    
    const fallbackRoadmap = [];
    for (let i = 0; i < days; i++) {
      fallbackRoadmap.push({
        day_number: i + 1,
        daily_goal: `Ngày ${i + 1}: Học ${req.body.roadmap_name || 'chủ đề'}`,
        learning_content: `Nội dung học tập chi tiết cho ngày ${i + 1}. Tìm hiểu các khái niệm cơ bản, thực hành qua ví dụ và làm bài tập.`,
        practice_exercises: `Bài tập thực hành ngày ${i + 1} - Link: ${fallbackLinks.exercises[i % fallbackLinks.exercises.length]}`,
        learning_materials: `Tài liệu học tập ngày ${i + 1} - Link: ${fallbackLinks.materials[i % fallbackLinks.materials.length]}`,
        study_duration_hours: hoursPerDay
      });
    }

    return res.status(500).json({
      success: false,
      error: error.message || "Lỗi khi tạo lộ trình AI",
      data: fallbackRoadmap
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

// GET own user info
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

// GET all users (requires admin) - alias for backward compatibility
app.get("/api/users", requireAdmin, async (req, res) => {
  try {
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

// GET single user by ID (requires admin) - alias for backward compatibility
app.get("/api/users/:id", requireAdmin, async (req, res) => {
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

// ========== ADMIN USER MANAGEMENT ENDPOINTS ==========

app.get("/api/admin/users", requireAdmin, async (req, res) => {
  try {
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
      updates.push(`name = ${paramCount++}`);
      values.push(name.trim());
    }
    if (email) {
      const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!EMAIL_RE.test(email)) {
        return res.status(400).json({ success: false, error: "Email không đúng định dạng" });
      }
      updates.push(`email = ${paramCount++}`);
      values.push(email.trim());
    }
    
    if (updates.length === 0) {
      return res.status(400).json({ success: false, error: "Không có dữ liệu để cập nhật" });
    }
    
    values.push(userId);
    
    const result = await pool.query(
      `UPDATE users 
       SET ${updates.join(", ")}
       WHERE id = ${paramCount}
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

// ========== FRONTEND ROUTES ==========

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

// ========== START SERVER ==========

const PORT = parseInt(process.env.PORT || "5000", 10);
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`ℹ️  Local: http://localhost:${PORT}/`);
});
