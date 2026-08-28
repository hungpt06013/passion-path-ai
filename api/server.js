// ============================================================================
// SERVER.JS - AI-POWERED LEARNING ROADMAP SYSTEM
// ============================================================================

// ============================================================================
// 1. IMPORT MODULES & CONFIGURATION
// ============================================================================

import express from "express";
import { Pool } from "pg";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { search as ddgSearch, SafeSearchType } from 'duck-duck-scrape';
import PQueue from "p-queue";
import multer from "multer";
import XLSX from "xlsx";
import Joi from "joi";
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import nodemailer from 'nodemailer';
import cors from "cors";
import crypto from "crypto";

dotenv.config();

const FRONTEND_URL = (process.env.FRONTEND_URL || 'http://localhost:5000').replace(/\/$/, '');

const app = express();

// ============================================================================
// 2. CONSTANTS & ENVIRONMENT VARIABLES
// ============================================================================

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.resolve(process.env.PUBLIC_DIR || path.join(__dirname, "public"));

// AI Limits
const MIN_AI_DAYS = 15;
const AI_GENERATION_LIMIT_PER_USER = 1;
async function getAIGenerationLimit() {
  try {
    const r = await pool.query("SELECT config_value FROM system_config WHERE config_key = 'ai_generation_limit' LIMIT 1");
    if (r.rows.length > 0) {
      const v = parseInt(r.rows[0].config_value);
      if (!isNaN(v) && v >= 0) return v;
    }
  } catch (e) { console.warn('getAIGenerationLimit error:', e.message); }
  return AI_GENERATION_LIMIT_PER_USER;
}
const TOKENS_PER_DAY = parseInt(process.env.TOKENS_PER_DAY || "800", 10);
const MIN_COMPLETION_TOKENS = 128;

// Timezone
const VIETNAM_TIMEZONE_OFFSET = 7 * 60 * 60 * 1000;

// Link Validation
const LINK_VALIDATION_CONFIG = {
  MAX_RETRY_ATTEMPTS: 1,
  FAIL_THRESHOLD_PERCENT: 5,
  MIN_FAIL_COUNT: 1,
  VALIDATION_TIMEOUT: 8000,
  BATCH_VALIDATION_DELAY: 200,
  ERROR_PATTERNS: [
    /oops/i,
    /sorry.*page.*doesn't exist/i,
    /we can't find/i,
    /404/i,
    /page not found/i,
    /content not available/i,
    /no longer available/i,
    /moved or deleted/i,
    /The requested page could not be found/i,
    /Video này không còn hoạt động/i,
    /Not Found/i,
    /page can't be found/i
  ]
};

// ============================================================================
// 3. CORS CONFIGURATION
// ============================================================================

const rawAllowed = (process.env.ALLOWED_ORIGINS || "").trim();
if (rawAllowed) {
  const allowedList = rawAllowed.split(",").map((s) => s.trim()).filter(Boolean);
  app.use(cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedList.indexOf(origin) !== -1) return callback(null, true);
      return callback(new Error("CORS not allowed from origin " + origin));
    }
  }));
} else {
  if ((process.env.NODE_ENV || "development") === "production") {
    console.warn("⚠️ ALLOWED_ORIGINS not set in production. This is insecure.");
  }
  app.use(cors());
}

// ============================================================================
// 4. EMAIL CONFIGURATION
// ============================================================================

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

transporter.verify(function(error, success) {
  if (error) {
    console.error('❌ Email configuration error:', error.message);
  } else {
    console.log('✅ Email server is ready');
  }
});

// ============================================================================
// 5. AI CLIENTS INITIALIZATION (Gemini free tier - key pool)
// ============================================================================

function loadKeyPool(prefix) {
  const keys = [];
  const regex = new RegExp(`^${prefix}_(\\d+)$`);
  const indices = [];
  for (const envKey of Object.keys(process.env)) {
    const match = envKey.match(regex);
    if (match) indices.push(parseInt(match[1], 10));
  }
  indices.sort((a, b) => a - b);
  for (const idx of indices) {
    const val = (process.env[`${prefix}_${idx}`] || "").trim().replace(/^['"]|['"]$/g, "");
    if (val) keys.push(val);
  }
  if (keys.length === 0) {
    const single = (process.env[prefix] || "").trim().replace(/^['"]|['"]$/g, "");
    if (single) keys.push(single);
  }
  return keys;
}

const GEMINI_API_KEYS = loadKeyPool("GEMINI_API_KEY");
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-3.6-flash";
const GEMINI_MATERIALS_MODEL = process.env.GEMINI_MATERIALS_MODEL || "gemini-3.6-flash";
const GEMINI_DAILY_QUOTA_PER_KEY = parseInt(process.env.GEMINI_DAILY_QUOTA_PER_KEY || "1500", 10); // RPD free tier

if (GEMINI_API_KEYS.length === 0) {
  console.warn("⚠️ Không có GEMINI_API_KEY nào - tính năng AI sẽ không hoạt động");
} else {
  console.log(`✅ Gemini key pool: ${GEMINI_API_KEYS.length} key(s), quota/ngày mỗi key: ${GEMINI_DAILY_QUOTA_PER_KEY}`);
}

// ============================================================================
// 5b. SEARCH API KEY POOLS (Brave -> Tavily -> DuckDuckGo)
// ============================================================================

const SERPAPI_API_KEYS = loadKeyPool("SERPAPI_API_KEY");
const TAVILY_API_KEYS = loadKeyPool("TAVILY_API_KEY");
const SERPAPI_MONTHLY_QUOTA = parseInt(process.env.SERPAPI_MONTHLY_QUOTA || "100", 10); // free tier SerpAPI ~100 search/tháng
const TAVILY_MONTHLY_QUOTA = parseInt(process.env.TAVILY_MONTHLY_QUOTA || "1000", 10);

console.log(`✅ Search key pool: ${SERPAPI_API_KEYS.length} SerpAPI key(s), ${TAVILY_API_KEYS.length} Tavily key(s)`);

// ============================================================================
// 5c. FIRECRAWL KEY POOL (dùng để cào nội dung trang -> viết cột "hướng dẫn")
// ============================================================================

const FIRECRAWL_API_KEYS = loadKeyPool("FIRECRAWL_API_KEY");
const FIRECRAWL_MONTHLY_QUOTA = parseInt(process.env.FIRECRAWL_MONTHLY_QUOTA || "500", 10); // free tier Firecrawl ~500 credit/tháng

console.log(`✅ Firecrawl key pool: ${FIRECRAWL_API_KEYS.length} key(s)`);

// ============================================================================
// 6. MIDDLEWARE SETUP
// ============================================================================

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());

// Multer - File upload
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ext !== '.xlsx' && ext !== '.xls') {
      return cb(new Error('Chỉ chấp nhận file Excel (.xlsx, .xls)'));
    }
    cb(null, true);
  }
});

// ============================================================================
// 7. STATIC FILES SERVING
// ============================================================================

if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir));
  console.log(`✅ Serving static files from: ${publicDir}`);
} else {
  console.warn(`⚠️ Static folder not found: ${publicDir}`);
}

const dataDir = path.join(publicDir, 'Data');
if (fs.existsSync(dataDir)) {
  app.use('/Data', express.static(dataDir));
  console.log(`✅ Serving Data folder from: ${dataDir}`);
} else {
  console.warn(`⚠️ Data folder not found: ${dataDir}`);
}

// ============================================================================
// 8. DATABASE CONNECTION
// ============================================================================

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
    port: parseInt(process.env.DB_PORT || process.env.PGPORT || "5432", 10)
  };
}

const pool = new Pool(poolConfig);

// Test database connection
(async function testDB() {
  try {
    const client = await pool.connect();
    try {
      await client.query("SET client_encoding = 'UTF8'");
      await client.query("SET time zone 'Asia/Ho_Chi_Minh'");
    } catch (e) {
      console.warn("⚠️ Could not set client_encoding or time zone:", e.message);
    }
    client.release();
    console.log(`✅ PostgreSQL connected`);
  } catch (err) {
    console.error("❌ PostgreSQL connection failed:", err.message || err);
  }
})();

// ============================================================================
// 9. GOOGLE OAUTH CONFIGURATION
// ============================================================================

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:5000/api/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails[0].value;
    const name = profile.displayName;
    const googleId = profile.id;
    
    let result = await pool.query('SELECT * FROM users WHERE email = $1 LIMIT 1', [email]);
    
    let user;
    
    if (result.rows.length > 0) {
      user = result.rows[0];
    } else {
      const username = email.split('@')[0] + '_' + Math.random().toString(36).substr(2, 5);
      const randomPassword = Math.random().toString(36).slice(-12) + 'Aa1!';
      const hashedPassword = await hashPassword(randomPassword, 10);
      
      result = await pool.query(
        `INSERT INTO users (name, username, email, password, created_at) 
         VALUES ($1, $2, $3, $4, (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')) 
         RETURNING *`,
        [name, username, email, hashedPassword]
      );
      
      user = result.rows[0];
    }
    
    return done(null, user);
  } catch (error) {
    return done(error, null);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    done(null, result.rows[0]);
  } catch (error) {
    done(error, null);
  }
});

// ============================================================================
// 10. DATABASE INITIALIZATION
// ============================================================================

async function initDB() {
  try {
    // Bảng users
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
      );
    `);

    // Bảng categories
    await pool.query(`
      CREATE TABLE IF NOT EXISTS categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) UNIQUE NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
      );
    `);

    // Bảng sub_categories
    await pool.query(`
      CREATE TABLE IF NOT EXISTS sub_categories (
        id SERIAL PRIMARY KEY,
        category_id INTEGER NOT NULL REFERENCES categories(id) ON DELETE CASCADE,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh'),
        UNIQUE(category_id, name)
      );
    `);

    // Bảng learning_roadmaps
    await pool.query(`
      CREATE TABLE IF NOT EXISTS learning_roadmaps (
        roadmap_id SERIAL PRIMARY KEY,
        roadmap_name VARCHAR(255) NOT NULL,
        category VARCHAR(100) NOT NULL,
        sub_category VARCHAR(100),
        start_level VARCHAR(20) CHECK (start_level IN ('Mới bắt đầu', 'Cơ bản', 'Trung bình', 'Khá tốt', 'Nâng cao')),
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
        detailed_feedback TEXT,
        actual_learning_outcomes TEXT,
        improvement_suggestions TEXT,
        roadmap_analyst TEXT,
        created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh'),
        updated_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
      );
    `);

    // Bảng learning_roadmap_details
    await pool.query(`
      CREATE TABLE IF NOT EXISTS learning_roadmap_details (
        detail_id SERIAL PRIMARY KEY,
        roadmap_id INTEGER NOT NULL REFERENCES learning_roadmaps(roadmap_id) ON DELETE CASCADE,
        day_number INTEGER NOT NULL,
        daily_goal VARCHAR(500) NOT NULL,
        learning_content TEXT NOT NULL,
        practice_exercises TEXT,
        learning_materials VARCHAR(1000),
        usage_instructions TEXT,
        study_duration DECIMAL(4,2) NOT NULL CHECK (study_duration > 0),
        completion_status VARCHAR(20) DEFAULT 'NOT_STARTED' CHECK (completion_status IN ('NOT_STARTED', 'IN_PROGRESS', 'COMPLETED', 'SKIPPED')),
        study_date DATE,
        created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh'),
        updated_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh'),
        completed_at TIMESTAMP,
        UNIQUE(roadmap_id, day_number)
      );
    `);

    // Bảng learning_roadmaps_system
    await pool.query(`
      CREATE TABLE IF NOT EXISTS learning_roadmaps_system (
        roadmap_id SERIAL PRIMARY KEY,
        roadmap_name VARCHAR(255) NOT NULL,
        category VARCHAR(100) NOT NULL,
        sub_category VARCHAR(100),
        start_level VARCHAR(20),
        total_user_learning INTEGER DEFAULT 0,
        duration_days INTEGER NOT NULL,
        duration_hours DECIMAL(6,2) NOT NULL,
        overall_rating DECIMAL(2,1),
        learning_effectiveness INTEGER,
        roadmap_analyst TEXT,
        is_hidden BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh'),
        updated_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
      );
    `);

    // Bảng learning_roadmap_details_system
    await pool.query(`
      CREATE TABLE IF NOT EXISTS learning_roadmap_details_system (
        detail_id SERIAL PRIMARY KEY,
        roadmap_id INTEGER NOT NULL REFERENCES learning_roadmaps_system(roadmap_id) ON DELETE CASCADE,
        day_number INTEGER NOT NULL,
        daily_goal VARCHAR(500) NOT NULL,
        learning_content TEXT NOT NULL,
        practice_exercises TEXT,
        learning_materials VARCHAR(1000),
        usage_instructions TEXT,
        study_duration DECIMAL(4,2) NOT NULL,
        created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh'),
        updated_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh'),
        UNIQUE(roadmap_id, day_number)
      );
    `);

    // Bảng ai_query_history
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ai_query_history (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        query_time TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh'),
        prompt_content TEXT NOT NULL,
        status VARCHAR(20) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'SUCCESS', 'FAIL', 'TIMEOUT')),
        roadmap_id INTEGER REFERENCES learning_roadmaps(roadmap_id) ON DELETE SET NULL,
        error_message TEXT,
        response_tokens INTEGER,
        created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh'),
        updated_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
      );
    `);

    // Bảng admin_settings
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin_settings (
        setting_id SERIAL PRIMARY KEY,
        setting_key VARCHAR(100) UNIQUE NOT NULL,
        prompt_template TEXT,
        json_format_response TEXT,
        manual_prompt_template TEXT,
        created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh'),
        updated_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh'),
        updated_by INTEGER REFERENCES users(id)
      );
    `);

// Bảng user_feedback
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_feedback (
        feedback_id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        rating_1 INTEGER CHECK (rating_1 >= 1 AND rating_1 <= 5),
        rating_2 INTEGER CHECK (rating_2 >= 1 AND rating_2 <= 5),
        rating_3 INTEGER CHECK (rating_3 >= 1 AND rating_3 <= 5),
        rating_4 INTEGER CHECK (rating_4 >= 1 AND rating_4 <= 5),
        rating_5 INTEGER CHECK (rating_5 >= 1 AND rating_5 <= 5),
        rating_6 INTEGER CHECK (rating_6 >= 1 AND rating_6 <= 5),
        rating_7 INTEGER CHECK (rating_7 >= 1 AND rating_7 <= 5),
        rating_8 INTEGER CHECK (rating_8 >= 1 AND rating_8 <= 5),
        question_1 TEXT,
        question_2 TEXT,
        question_3 TEXT,
        created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
      );
    `);

    // Bảng quiz_questions - lưu 5 câu hỏi trắc nghiệm mỗi ngày (hoặc cuối chương)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS quiz_questions (
        quiz_id SERIAL PRIMARY KEY,
        roadmap_id INTEGER NOT NULL REFERENCES learning_roadmaps(roadmap_id) ON DELETE CASCADE,
        day_number INTEGER NOT NULL,
        is_chapter_review BOOLEAN DEFAULT FALSE,
        question_order INTEGER NOT NULL,
        question_text TEXT NOT NULL,
        option_a TEXT NOT NULL,
        option_b TEXT NOT NULL,
        option_c TEXT NOT NULL,
        option_d TEXT NOT NULL,
        correct_option CHAR(1) NOT NULL CHECK (correct_option IN ('A','B','C','D')),
        created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
      );
    `);
    await pool.query(`ALTER TABLE "quiz_questions" ADD COLUMN IF NOT EXISTS "explanation" TEXT;`);
    // Bảng quiz_attempts - lưu kết quả mỗi lần user làm quiz
    await pool.query(`
      CREATE TABLE IF NOT EXISTS quiz_attempts (
        attempt_id SERIAL PRIMARY KEY,
        roadmap_id INTEGER NOT NULL REFERENCES learning_roadmaps(roadmap_id) ON DELETE CASCADE,
        day_number INTEGER NOT NULL,
        is_chapter_review BOOLEAN DEFAULT FALSE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        score INTEGER NOT NULL,
        passed BOOLEAN NOT NULL,
        answers JSONB,
        attempted_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
      );
    `);

    // Bảng password_reset_codes
    await pool.query(`
      CREATE TABLE IF NOT EXISTS password_reset_codes (
        id SERIAL PRIMARY KEY,
        email TEXT NOT NULL,
        code VARCHAR(6) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        used BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
      );
    `);
    // Bảng search_api_usage - theo dõi quota các key SerpAPI/Tavily/Firecrawl
    await pool.query(`
      CREATE TABLE IF NOT EXISTS search_api_usage (
        id SERIAL PRIMARY KEY,
        provider VARCHAR(20) NOT NULL,
        key_index INTEGER NOT NULL,
        period VARCHAR(10) NOT NULL,
        used_count INTEGER NOT NULL DEFAULT 0,
        quota_limit INTEGER NOT NULL,
        updated_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh'),
        UNIQUE(provider, key_index, period)
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS system_config (
        config_key VARCHAR(100) PRIMARY KEY,
        config_value TEXT
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS roadmap_certificates (
        certificate_id SERIAL PRIMARY KEY,
        roadmap_id INTEGER NOT NULL REFERENCES learning_roadmaps(roadmap_id) ON DELETE CASCADE,
        milestone_percent SMALLINT NOT NULL CHECK (milestone_percent IN (25,50,75,100)),
        certificate_code VARCHAR(50) NOT NULL,
        awarded_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh'),
        UNIQUE(roadmap_id, milestone_percent)
      );
    `);
    await pool.query(`ALTER TABLE "search_api_usage" ALTER COLUMN "period" TYPE VARCHAR(10);`);
    await pool.query(`ALTER TABLE "learning_roadmaps" ADD COLUMN IF NOT EXISTS "study_weekdays" VARCHAR(20);`);
    await pool.query(`ALTER TABLE "learning_roadmaps" ADD COLUMN IF NOT EXISTS "streak_tier" INTEGER DEFAULT 0;`);
    await pool.query(`ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "ai_roadmap_generations_used" INTEGER DEFAULT 0;`);
    await pool.query(`ALTER TABLE "learning_roadmaps" ADD COLUMN IF NOT EXISTS "pass_threshold" INTEGER DEFAULT 80;`);
    await pool.query(`ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "avatar_url" TEXT;`);
    await pool.query(`ALTER TABLE "learning_roadmap_details" ADD COLUMN IF NOT EXISTS "quiz_content" TEXT;`);
    await pool.query(`ALTER TABLE "learning_roadmap_details_system" ADD COLUMN IF NOT EXISTS "quiz_content" TEXT;`);


    // Tạo indexes
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_roadmaps_user_id ON learning_roadmaps(user_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_roadmaps_status ON learning_roadmaps(status);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_roadmap_details_roadmap_id ON learning_roadmap_details(roadmap_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_roadmap_details_completion ON learning_roadmap_details(completion_status);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_roadmap_details_study_date ON learning_roadmap_details(study_date);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_ai_history_user ON ai_query_history(user_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_ai_history_time ON ai_query_history(query_time DESC);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_user_feedback_user ON user_feedback(user_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_user_feedback_created ON user_feedback(created_at DESC);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_reset_email ON password_reset_codes(email);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_reset_code ON password_reset_codes(code);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_search_usage_period ON search_api_usage(provider, period);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_quiz_questions_roadmap ON quiz_questions(roadmap_id, day_number);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_quiz_attempts_roadmap ON quiz_attempts(roadmap_id, day_number, user_id);`);
    // Reset sequences
    await pool.query(`SELECT setval('categories_id_seq', COALESCE((SELECT MAX(id) FROM categories), 1));`);
    await pool.query(`SELECT setval('learning_roadmaps_roadmap_id_seq', COALESCE((SELECT MAX(roadmap_id) FROM learning_roadmaps), 1));`);
    await pool.query(`SELECT setval('learning_roadmaps_system_roadmap_id_seq', COALESCE((SELECT MAX(roadmap_id) FROM learning_roadmaps_system), 1));`);
    await pool.query(`SELECT setval('learning_roadmap_details_detail_id_seq', COALESCE((SELECT MAX(detail_id) FROM learning_roadmap_details), 1));`);
    await pool.query(`SELECT setval('learning_roadmap_details_system_detail_id_seq', COALESCE((SELECT MAX(detail_id) FROM learning_roadmap_details_system), 1));`);
    await pool.query(`SELECT setval('quiz_questions_quiz_id_seq', COALESCE((SELECT MAX(quiz_id) FROM quiz_questions), 1));`);
    await pool.query(`SELECT setval('quiz_attempts_attempt_id_seq', COALESCE((SELECT MAX(attempt_id) FROM quiz_attempts), 1));`);

    console.log("✅ DB initialized");
  } catch (err) {
    console.error("❌ DB init error:", err && err.message ? err.message : err);
  }
}

initDB();

// ============================================================================
// 11. HELPER FUNCTIONS - Authentication
// ============================================================================

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

function getCleanSecret() {
  const rawSecret = process.env.JWT_SECRET || "dev_local_secret";
  return rawSecret.replace(/^['"]|['"]$/g, "");
}

function makeToken(userId) {
  return jwt.sign(
    { userId }, 
    getCleanSecret(),
    { 
      expiresIn: "2h",
      algorithm: 'HS256'
    }
  );
}

// ============================================================================
// 12. HELPER FUNCTIONS - Timezone & Date
// ============================================================================

function getVietnamDate() {
  // Dùng Intl để lấy đúng giờ VN, tránh lỗi khi server chạy ở timezone khác
  return new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Ho_Chi_Minh' }));
}

function toVietnamDateString(date) {
  const d = new Date(date);
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function formatTimestampForAPI(timestamp) {
  if (!timestamp) return null;
  const rawDate = new Date(timestamp);
  if (isNaN(rawDate)) return null;
  // DB lưu giờ VN dạng TIMESTAMP WITHOUT TIMEZONE → pg đọc vào coi như UTC
  // Trừ 7h để ra UTC thật, frontend sẽ cộng lại +7 khi hiển thị
  return new Date(rawDate.getTime() - VIETNAM_TIMEZONE_OFFSET).toISOString();
}

// ============================================================================
// 13. HELPER FUNCTIONS - User Role
// ============================================================================

function getMaxDaysForUser(userRole) {
  return 120;
}

// ============================================================================
// 14. HELPER FUNCTIONS - Email
// ============================================================================

function generateResetCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendResetEmail(email, code) {
  const mailOptions = {
    from: `"Con đường đam mê" <${process.env.EMAIL_FROM}>`,
    to: email,
    subject: 'Mã xác thực đặt lại mật khẩu',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px;">
        <div style="text-align: center; margin-bottom: 30px;">
          <h1 style="color: #007bff; margin: 0;">Con đường đam mê</h1>
          <p style="color: #6c757d; font-size: 14px;">AI-Powered Learning Path</p>
        </div>
        
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
          <h2 style="color: #333; margin-top: 0;">Đặt lại mật khẩu</h2>
          <p style="color: #555; line-height: 1.6;">
            Bạn đã yêu cầu đặt lại mật khẩu. Sử dụng mã xác thực dưới đây để tiếp tục:
          </p>
          
          <div style="background: white; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
            <div style="font-size: 32px; font-weight: bold; color: #007bff; letter-spacing: 8px;">
              ${code}
            </div>
          </div>
          
          <p style="color: #dc3545; font-size: 14px; margin-bottom: 0;">
            ⚠️ Mã này sẽ hết hạn sau <strong>10 phút</strong>
          </p>
        </div>
        
        <div style="border-top: 1px solid #e0e0e0; padding-top: 20px; color: #6c757d; font-size: 12px;">
          <p>Nếu bạn không yêu cầu đặt lại mật khẩu, vui lòng bỏ qua email này.</p>
          <p style="margin-bottom: 0;">Đây là email tự động, vui lòng không trả lời.</p>
        </div>
      </div>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    return true;
  } catch (error) {
    console.error('❌ Send email error:', error);
    return false;
  }
}

// ============================================================================
// 15. HELPER FUNCTIONS - AI Prompts
// ============================================================================

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
Bạn là chuyên gia giáo dục <CATEGORY> -- <SUB_CATEGORY> có 15+ năm kinh nghiệm, chuyên thiết kế lộ trình học tập cá nhân hóa dựa trên nguồn tài liệu giảng dạy uy tín, được đánh giá cao trên thế giới.

**II/ Thông tin thu thập từ học viên:**
- Tên lộ trình: <ROADMAP_NAME>
- Câu 1 - Mục đích bạn học điều này: <MAIN_PURPOSE>
- Câu 2 - Sau khi hoàn thành lộ trình, bạn muốn dùng kỹ năng này vào việc gì cụ thể trong cuộc sống/công việc: <APPLICATION_GOAL>
- Câu 2b - Kỳ thi/chứng chỉ/deadline cụ thể (nếu có): <TARGET_MILESTONE>
- Câu 3 - Trình độ hiện tại (tự đánh giá): <CURRENT_LEVEL>
- Câu 4 - Đánh giá từng kỹ năng con (thang 1-5): <SKILL_BREAKDOWN>
- Câu 5 - Hiện đã làm/biết được những gì cụ thể: <KNOWN_SKILLS>
- Câu 6 - Kỹ năng/chủ đề yếu nhất muốn cải thiện trước: <SKILLS_TO_IMPROVE>
- Câu 7 - Thời gian học mỗi ngày (phút): <DAILY_TIME>
- Câu 8 - Ngày học trong tuần: <STUDY_DAYS_OF_WEEK>
- Câu 9 - Tổng số ngày của lộ trình: <TOTAL_DURATION>
- Câu 10 - Hình thức tiếp thu tốt nhất: <LEARNING_STYLE>
- Câu 11 - Nhịp học ưa thích: <LEARNING_METHOD>
- Câu 12 - Điều khiến buổi học "đáng nhớ"/hứng thú nhất: <ENGAGEMENT_TRIGGER>
- Câu 13 - Chủ đề mong muốn cho ví dụ/bài tập: <THEME_PREFERENCE>
- Câu 14 - Loại tài liệu học hiệu quả nhất: <MATERIAL_TYPE>
- Câu 15 - Điều gì thường khiến bạn bỏ cuộc hoặc mất động lực giữa chừng: <DEMOTIVATION_TRIGGER>
- Câu 16 - Ngưỡng "Đạt" cho quiz/đánh giá: <PASS_THRESHOLD>
- Câu 17 - Số câu hỏi quiz cuối ngày / kiểm tra cuối chương: <QUIZ_DAY_LENGTH> câu/ngày, <QUIZ_CHAPTER_LENGTH> câu/chương
- Câu 18 - Ngôn ngữ tài liệu mong muốn: <MATERIAL_LANGUAGE>

**III/ Yêu cầu AI trả lời**
Dựa trên thông tin trên, thiết kế lộ trình học <CATEGORY> -- <SUB_CATEGORY> gồm đúng 2 mục:

1. PHÂN TÍCH HIỆN TRẠNG (tối đa 200 từ): tính khả thi mục tiêu trong <TOTAL_DURATION> ngày, tiêu chí đánh giá và cách đo lường kết quả, chiến lược phân chia nội dung từ dễ đến khó theo tuần, lời khuyên thực tiễn ngắn gọn.

2. LỘ TRÌNH HỌC CHI TIẾT THEO NGÀY: mỗi ngày gồm mục tiêu, nội dung học, bài tập thực hành, tài liệu học (link đã kiểm chứng, miễn phí, còn hoạt động), hướng dẫn sử dụng tài liệu (nêu rõ vì sao chọn nguồn này, học đúng phần/phút/bài nào), thời lượng học, và một bộ <QUIZ_DAY_LENGTH> câu hỏi trắc nghiệm (quiz) tự soạn bám sát đúng nội dung của ngày đó (mỗi câu có 4 phương án A/B/C/D, chỉ 1 đáp án đúng, kèm giải thích ngắn gọn vì sao đáp án đó đúng, không dùng câu hỏi chung chung). Cứ mỗi 6 ngày liên tiếp (một "chương") và luôn ở ngày cuối cùng của lộ trình, ngoài quiz thường của ngày đó, còn thêm một bộ <QUIZ_CHAPTER_LENGTH> câu hỏi kiểm tra tổng hợp cuối chương rút từ toàn bộ nội dung của chương đó.

Áp dụng <THEME_PREFERENCE> xuyên suốt vào ví dụ, tình huống trong nội dung học và bài tập. Tận dụng <ENGAGEMENT_TRIGGER> để thiết kế cách trình bày bài học hấp dẫn. Lưu ý <DEMOTIVATION_TRIGGER> của học viên để thiết kế nhịp độ, cách trình bày giúp hạn chế bỏ cuộc giữa chừng.

Chỉ trả về JSON đúng định dạng sau, không thêm chữ nào khác ngoài JSON:
{
  "analysis": "Phân tích hiện trạng (tối đa 200 từ)...",
  "roadmap": [
    {
      "day_number": 1,
      "daily_goal": "Mục tiêu ngày 1",
      "learning_content": "Nội dung học tập chi tiết",
      "practice_exercises": "Bài tập thực hành",
      "learning_materials": "https://example.com/material",
      "study_guide": "Hướng dẫn chi tiết: vì sao chọn nguồn / học đúng phần nào / làm gì sau đó",
      "study_duration": 1.0,
      "quiz": [
        {
          "question_text": "Nội dung câu hỏi 1",
          "option_a": "Phương án A",
          "option_b": "Phương án B",
          "option_c": "Phương án C",
          "option_d": "Phương án D",
          "correct_option": "A",
          "explanation": "Giải thích ngắn gọn vì sao đáp án đúng là A"
        }
      ],
      "chapter_review_quiz": []
    }
  ]
}
Lưu ý: mảng "quiz" luôn có đúng <QUIZ_DAY_LENGTH> phần tử cho MỌI ngày. Mảng "chapter_review_quiz" có đúng <QUIZ_CHAPTER_LENGTH> phần tử CHỈ ở ngày cuối mỗi chương (cứ 6 ngày) và ngày cuối cùng của lộ trình, các ngày khác để mảng rỗng [].`;
}

function getDefaultManualPrompt() {
  return `**THIẾT KẾ LỘ TRÌNH HỌC CÁ NHÂN HÓA: <CATEGORY> -- <SUB_CATEGORY>**

**I/ Vai trò của AI**
Bạn là một chuyên gia giáo dục <CATEGORY> -- <SUB_CATEGORY> có 15+ năm kinh nghiệm.

**II/ Thông tin từ học viên:**
- Tên lộ trình: <ROADMAP_NAME>
- Mục đích chính: <MAIN_PURPOSE>
- Mục tiêu cụ thể: <APPLICATION_GOAL>
- Công việc hiện tại: <CURRENT_JOB>
- Đã học được: <STUDY_TIME>
- Trình độ hiện tại: <CURRENT_LEVEL>
- Kỹ năng muốn cải thiện: <SKILLS_TO_IMPROVE>
- Thời gian học mỗi ngày: <DAILY_TIME>
- Số buổi mỗi tuần: <WEEKLY_FREQUENCY>
- Tổng thời gian lộ trình: <TOTAL_DURATION> ngày
- Phong cách học: <LEARNING_STYLE>
- Phương pháp học: <LEARNING_METHOD>
- Khó khăn: <DIFFICULTIES>
- Động lực: <MOTIVATION>
- Loại tài liệu ưa thích: <MATERIAL_TYPE>
- Ngôn ngữ tài liệu: <MATERIAL_LANGUAGE>
- Loại đánh giá: <ASSESSMENT_TYPE>
- Điều khiến bỏ cuộc/mất động lực: <DEMOTIVATION_TRIGGER>
- Số câu quiz cuối ngày / kiểm tra cuối chương: <QUIZ_DAY_LENGTH> câu/ngày, <QUIZ_CHAPTER_LENGTH> câu/chương
- Tần suất đánh giá: <ASSESSMENT_FREQUENCY>

**III/ Yêu cầu**
Tạo lộ trình với 7 cột theo định dạng Excel:
1. day_number (số ngày)
2. day_study (ngày học thực tế, format dd/mm/yyyy, ô excel phải có dấu ' ở đầu)
3. daily_goal (Mục tiêu ngày)
4. learning_content (Nội dung học tập)
5. practice_exercises (Bài tập thực hành)
6. learning_materials (Công cụ/Tài liệu học tập - LINK CỤ THỂ)
7. guide_learning (Hướng dẫn sử dụng)
8. study_duration (Thời gian học - số giờ, format số thập phân vd: 1.5)

**QUAN TRỌNG:**
- day_number phải tăng đều từ 1 đến <TOTAL_DURATION>
- day_study phải theo format dd/mm/yyyy (ví dụ: '01/01/2025) và có dấu ' ở đầu trong Excel
- Tất cả các cột phải có giá trị, không để trống`;
}

function getHardcodedJsonFormat() {
  return JSON.stringify({
    "analysis": "Phân tích chi tiết về trình độ, mục tiêu và phương pháp học phù hợp...",
    "roadmap": [
      {
        "day_number": 1,
        "daily_goal": "Mục tiêu ngày 1",
        "learning_content": "Nội dung học tập chi tiết",
        "practice_exercises": "Bài tập thực hành",
        "learning_materials": "https://example.com/material",
        "study_guide": "Hướng dẫn chi tiết cách học",
        "study_duration": 1.0
      }
    ]
  }, null, 2);
}

// ============================================================================
// 16. HELPER FUNCTIONS - Duration and Day Parsing
// ============================================================================

function parseDurationToHours(value) {
  if (!value) return 0;
  
  const str = String(value).trim().toLowerCase();
  
  if (/^\d+([.,]\d+)?$/.test(str)) {
    return parseFloat(str.replace(',', '.'));
  }
  
  const minutesMatch = str.match(/^(\d+)m$/);
  if (minutesMatch) {
    return parseInt(minutesMatch[1]) / 60;
  }
  
  const hoursMatch = str.match(/^(\d+(?:[.,]\d+)?)h$/);
  if (hoursMatch) {
    return parseFloat(hoursMatch[1].replace(',', '.'));
  }
  
  const combinedMatch = str.match(/^(\d+)h\s*(\d+)m$/);
  if (combinedMatch) {
    const hours = parseInt(combinedMatch[1]);
    const minutes = parseInt(combinedMatch[2]);
    return hours + (minutes / 60);
  }
  
  console.warn(`⚠️ Invalid duration format: "${value}" - returning 0`);
  return 0;
}

function isValidDuration(value) {
  const hours = parseDurationToHours(value);
  return hours >= 0.05;
}
    function parseDayStudy(dayStudyValue) {
      if (!dayStudyValue || dayStudyValue.toString().trim() === '') {
        return null;
      }
      
      try {
        // Xử lý Excel serial number
        if (typeof dayStudyValue === 'number') {
          const excelEpoch = new Date(1899, 11, 30);
          const rawDate = new Date(excelEpoch.getTime() + dayStudyValue * 86400000);
          return rawDate.toLocaleDateString('en-CA', { timeZone: 'Asia/Ho_Chi_Minh' });
        }
        
        const dayStudyStr = dayStudyValue.toString().trim().replace(/^'/, '');
        
        // Thử parse với dấu /
        let parts = dayStudyStr.split('/');
        if (parts.length === 3) {
          let day = parseInt(parts[0], 10);
          let month = parseInt(parts[1], 10);
          let year = parseInt(parts[2], 10);
          
          if (year < 100) {
            year += 2000;
          }
          
          if (!isNaN(day) && !isNaN(month) && !isNaN(year)) {
            const monthStr = String(month).padStart(2, '0');
            const dayStr = String(day).padStart(2, '0');
            return `${year}-${monthStr}-${dayStr}`;
          }
        }
        
        // Thử parse với dấu -
        parts = dayStudyStr.split('-');
        if (parts.length === 3) {
          if (parts[0].length === 4) {
            // Format: yyyy-mm-dd
            let year = parseInt(parts[0], 10);
            let month = parseInt(parts[1], 10);
            let day = parseInt(parts[2], 10);
            
            if (!isNaN(day) && !isNaN(month) && !isNaN(year)) {
              const monthStr = String(month).padStart(2, '0');
              const dayStr = String(day).padStart(2, '0');
              return `${year}-${monthStr}-${dayStr}`;
            }
          } else {
            // Format: dd-mm-yyyy
            let day = parseInt(parts[0], 10);
            let month = parseInt(parts[1], 10);
            let year = parseInt(parts[2], 10);
            
            if (year < 100) {
              year += 2000;
            }
            
            if (!isNaN(day) && !isNaN(month) && !isNaN(year)) {
              const monthStr = String(month).padStart(2, '0');
              const dayStr = String(day).padStart(2, '0');
              return `${year}-${monthStr}-${dayStr}`;
            }
          }
        }
        
        // Fallback: thử parse trực tiếp
        const directParse = new Date(dayStudyStr);
        if (!isNaN(directParse.getTime())) {
          return directParse.toLocaleDateString('en-CA', { timeZone: 'Asia/Ho_Chi_Minh' });
        }
        
        return null;
      } catch (e) {
        return null;
      }
    }

// ============================================================================
// 16b. HELPER FUNCTIONS - Weekday Scheduling & Streak
// ============================================================================

// ISO weekday: 1=Thứ 2 ... 7=Chủ nhật
function parseWeekdaysParam(value) {
  let arr = [];
  if (Array.isArray(value)) arr = value;
  else if (typeof value === 'string' && value) arr = value.split(',');
  const nums = arr.map(v => parseInt(v, 10)).filter(n => !isNaN(n) && n >= 1 && n <= 7);
  return [...new Set(nums)].sort((a, b) => a - b);
}

function isoWeekday(date) {
  const d = date.getDay(); // 0=CN..6=T7
  return d === 0 ? 7 : d;
}

// Sinh ra `count` ngày học bắt đầu từ startDate (bao gồm), chỉ rơi vào các thứ trong weekdays.
// weekdays rỗng => fallback ngày liên tục (tương thích dữ liệu cũ).
function generateStudyDatesByWeekdays(startDate, weekdays, count) {
  const cursor = new Date(startDate);
  cursor.setHours(0, 0, 0, 0);
  const dates = [];
  if (!weekdays || weekdays.length === 0) {
    for (let i = 0; i < count; i++) dates.push(new Date(cursor.getTime() + i * 86400000));
    return dates;
  }
  const set = new Set(weekdays);
  let safety = 0;
  while (dates.length < count && safety < count * 20 + 400) {
    if (set.has(isoWeekday(cursor))) dates.push(new Date(cursor));
    cursor.setDate(cursor.getDate() + 1);
    safety++;
  }
  return dates;
}

const WEEKDAY_LABELS_VN = { 1: 'Thứ 2', 2: 'Thứ 3', 3: 'Thứ 4', 4: 'Thứ 5', 5: 'Thứ 6', 6: 'Thứ 7', 7: 'Chủ nhật' };

const STREAK_TIER_PERCENTS = [100/6, 200/6, 300/6, 400/6, 500/6, 100];

function computeStreakTier(progressPercent) {
  let tier = 0;
  for (let i = 0; i < STREAK_TIER_PERCENTS.length; i++) {
    if (progressPercent >= STREAK_TIER_PERCENTS[i] - 0.001) tier = i + 1;
  }
  return tier;
}

// Dời các ngày trễ hạn (chưa hoàn thành, chưa bỏ qua, quá ngày học) tới ngày hợp lệ gần nhất từ hôm nay,
// giữ nguyên thứ trong tuần đã chọn.
async function rescheduleMissedDaysIfNeeded(client, roadmapId) {
  const roadmapRes = await client.query(
    `SELECT study_weekdays FROM learning_roadmaps WHERE roadmap_id = $1`, [roadmapId]
  );
  if (roadmapRes.rows.length === 0) return { rescheduled: false, hasOverdueToday: false };

  const weekdays = parseWeekdaysParam(roadmapRes.rows[0].study_weekdays || '');
  const todayStr = toVietnamDateString(getVietnamDate());

  const detailsRes = await client.query(
    `SELECT detail_id, day_number, study_date, completion_status
     FROM learning_roadmap_details WHERE roadmap_id = $1 ORDER BY day_number ASC`,
    [roadmapId]
  );
  const details = detailsRes.rows;
  if (details.length === 0) return { rescheduled: false, hasOverdueToday: false };

  let missedIndex = -1;
  for (let i = 0; i < details.length; i++) {
    const d = details[i];
    if (!d.study_date) continue;
    const dStr = toVietnamDateString(new Date(d.study_date));
    if (dStr < todayStr && d.completion_status !== 'COMPLETED' && d.completion_status !== 'SKIPPED') {
      missedIndex = i;
      break;
    }
  }

  let rescheduled = false;
  if (missedIndex !== -1) {
    const pending = details.slice(missedIndex).filter(
      d => d.completion_status !== 'COMPLETED' && d.completion_status !== 'SKIPPED'
    );
    if (pending.length > 0) {
      const newDates = generateStudyDatesByWeekdays(getVietnamDate(), weekdays, pending.length);
      for (let i = 0; i < pending.length; i++) {
        await client.query(
          `UPDATE learning_roadmap_details SET study_date = $1, updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh') WHERE detail_id = $2`,
          [toVietnamDateString(newDates[i]), pending[i].detail_id]
        );
      }
      rescheduled = true;
    }
  }

  const afterRes = await client.query(
    `SELECT study_date, completion_status FROM learning_roadmap_details WHERE roadmap_id = $1`,
    [roadmapId]
  );
  const hasOverdueToday = afterRes.rows.some(d => {
    if (!d.study_date) return false;
    const dStr = toVietnamDateString(new Date(d.study_date));
    return dStr <= todayStr && d.completion_status !== 'COMPLETED' && d.completion_status !== 'SKIPPED';
  });

  return { rescheduled, hasOverdueToday };
}

async function updateStreakTier(client, roadmapId) {
  const progressRes = await client.query(
    `SELECT 
       COUNT(*) FILTER (WHERE completion_status = 'COMPLETED') as completed,
       COUNT(*) as total
     FROM learning_roadmap_details WHERE roadmap_id = $1`,
    [roadmapId]
  );
  const completed = Number(progressRes.rows[0].completed) || 0;
  const total = Number(progressRes.rows[0].total) || 0;
  const percent = total === 0 ? 0 : (completed / total) * 100;
  const newTier = computeStreakTier(percent);

  const result = await client.query(
    `UPDATE learning_roadmaps SET streak_tier = GREATEST(streak_tier, $1) WHERE roadmap_id = $2 RETURNING streak_tier`,
    [newTier, roadmapId]
  );
  return result.rows[0].streak_tier;
}

// ============================================================================
// 17. HELPER FUNCTIONS - AI Response Parsing
// ============================================================================

// Quét chuỗi JSON theo đúng cấu trúc ngoặc (bỏ qua ngoặc nằm trong string) để tìm
// vị trí kết thúc của phần tử cuối cùng CÒN NGUYÊN VẸN trong mảng "roadmap".
function extractCompleteRoadmapArray(fullText) {
  const key = '"roadmap"';
  const keyIdx = fullText.indexOf(key);
  if (keyIdx === -1) return null;

  const arrStart = fullText.indexOf('[', keyIdx);
  if (arrStart === -1) return null;

  let depth = 0;
  let inStr = false;
  let esc = false;
  let lastCompleteEnd = -1;

  for (let i = arrStart + 1; i < fullText.length; i++) {
    const c = fullText[i];
    if (esc) { esc = false; continue; }
    if (c === '\\') { esc = true; continue; }
    if (c === '"') { inStr = !inStr; continue; }
    if (inStr) continue;

    if (c === '{') {
      depth++;
    } else if (c === '}') {
      depth--;
      if (depth === 0) lastCompleteEnd = i + 1;
    } else if (c === ']' && depth === 0) {
      break;
    }
  }

  if (lastCompleteEnd === -1) return null;

  const header = fullText.substring(0, arrStart + 1);
  const arrContent = fullText.substring(arrStart + 1, lastCompleteEnd);
  return header + arrContent + ']}';
}

function repairTruncatedJson(text) {
  const precise = extractCompleteRoadmapArray(text);
  if (precise) {
    try {
      JSON.parse(precise);
      return precise;
    } catch (e) { /* rơi xuống phương án dự phòng */ }
  }

  let s = text;
  const lastGoodComma = s.lastIndexOf('},');
  const lastGoodBracket = s.lastIndexOf('}\n');

  function countUnbalanced(str) {
    let depthCurly = 0, depthSquare = 0, inStr = false, esc = false;
    for (let i = 0; i < str.length; i++) {
      const c = str[i];
      if (esc) { esc = false; continue; }
      if (c === '\\') { esc = true; continue; }
      if (c === '"') { inStr = !inStr; continue; }
      if (inStr) continue;
      if (c === '{') depthCurly++;
      else if (c === '}') depthCurly--;
      else if (c === '[') depthSquare++;
      else if (c === ']') depthSquare--;
    }
    return { depthCurly, depthSquare, inStr };
  }

  const safeCutIdx = Math.max(lastGoodComma, lastGoodBracket);
  if (safeCutIdx > 0) {
    s = s.substring(0, safeCutIdx + 1);
    s = s.replace(/,\s*$/, '');
  }

  const { depthCurly, depthSquare, inStr } = countUnbalanced(s);
  if (inStr) s += '"';
  s += ']'.repeat(Math.max(0, depthSquare));
  s += '}'.repeat(Math.max(0, depthCurly));

  return s;
}

function parseAIResponse(aiResponseText) {
  const jsonMatch = aiResponseText.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
  const jsonText = jsonMatch ? jsonMatch[1] : aiResponseText;

  const basicClean = (str) => str
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201C\u201D]/g, '"')
    .replace(/,\s*([}\]])/g, '$1')
    .replace(/^\s*[\r\n]+/gm, '')
    .replace(/\\(?!["\\/bfnrtu])/g, '\\\\')
    .trim();

  try {
    return JSON.parse(jsonText);
  } catch (e1) {
    try {
      return JSON.parse(basicClean(jsonText));
    } catch (e2) {
      // JSON có khả năng bị cắt cụt (hết token) -> thử tự chữa
      console.warn('⚠️ JSON parse lỗi, thử repair (unterminated/truncated):', e2.message);
      try {
        const repaired = repairTruncatedJson(basicClean(jsonText));
        const parsed = JSON.parse(repaired);
        console.log(`✅ Repair JSON thành công, roadmap còn ${Array.isArray(parsed.roadmap) ? parsed.roadmap.length : 0} ngày (có thể bị thiếu so với yêu cầu)`);
        return parsed;
      } catch (e3) {
        console.error('❌ Không thể repair JSON:', e3.message);
        throw e2;
      }
    }
  }
}

function normalizeQuizArray(arr, maxLength = 12) {
  if (!Array.isArray(arr)) return [];
  return arr.slice(0, maxLength).map(q => ({
    question_text: String((q && (q.question_text || q.question)) || '').trim().substring(0, 1000),
    option_a: String((q && q.option_a) || '').trim().substring(0, 500),
    option_b: String((q && q.option_b) || '').trim().substring(0, 500),
    option_c: String((q && q.option_c) || '').trim().substring(0, 500),
    option_d: String((q && q.option_d) || '').trim().substring(0, 500),
    correct_option: (q && ['A', 'B', 'C', 'D'].includes(String(q.correct_option || '').toUpperCase()))
      ? String(q.correct_option).toUpperCase()
      : 'A',
    explanation: String((q && q.explanation) || '').trim().substring(0, 1000)
  })).filter(q => q.question_text);
}

const CHAPTER_SIZE_DAYS = 6;

function normalizeDays(days, targetCount, hoursPerDay, startDate, weekdays = []) {
  const studyDates = generateStudyDatesByWeekdays(startDate, weekdays, targetCount);
  const normalized = [];

  for (let i = 0; i < targetCount; i++) {
    const src = days[i] || {};
    const dayNumber = i + 1;
    const isChapterEnd = (dayNumber % CHAPTER_SIZE_DAYS === 0) || (dayNumber === targetCount);
    normalized.push({
      day_number: dayNumber,
      daily_goal: String(src.daily_goal || src.goal || `Mục tiêu ngày ${dayNumber}`).trim().substring(0, 500),
      learning_content: String(src.learning_content || src.content || '').trim().substring(0, 1000),
      practice_exercises: String(src.practice_exercises || src.exercises || '').trim().substring(0, 1000),
      learning_materials: String(src.learning_materials || src.materials || '').trim(),
      study_guide: String(src.study_guide || src.usage_instructions || src.instructions || '').trim().substring(0, 2000),
      study_duration: parseFloat(src.study_duration || src.hours || hoursPerDay) || hoursPerDay,
      completion_status: 'NOT_STARTED',
      study_date: toVietnamDateString(studyDates[i]),
      quiz: normalizeQuizArray(src.quiz),
      chapter_review_quiz: isChapterEnd ? normalizeQuizArray(src.chapter_review_quiz) : []
    });
  }

  return normalized;
}
// ============================================================================
// 16c. HELPER FUNCTIONS - Chia batch gọi Gemini để tránh bị cắt JSON do quá token
// ============================================================================

const TOKENS_PER_DAY_ESTIMATE = 1000; // ước lượng gồm cả nội dung ngày + quiz 5 câu
const CHAPTER_REVIEW_EXTRA_TOKENS = 900; // token phụ trội cho ngày có thêm chapter_review_quiz (5 câu nữa)
const MODEL_MAX_OUTPUT_TOKENS = 65000; // trần an toàn cho 1 lần gọi Gemini
const PREFERRED_BATCH_COUNT = 2;
const FALLBACK_BATCH_COUNT = 3;

// Đếm số ngày "chapter-end" (bội số của CHAPTER_SIZE_DAYS hoặc ngày cuối lộ trình) trong 1 khoảng
// ngày -> các ngày này tốn thêm token vì phải sinh thêm chapter_review_quiz.
function countChapterEndDaysInRange(startDay, endDay, totalDays) {
  let count = 0;
  for (let d = startDay; d <= endDay; d++) {
    if (d % CHAPTER_SIZE_DAYS === 0 || d === totalDays) count++;
  }
  return count;
}

// Tính kế hoạch chia batch: ưu tiên 2 batch, nếu ước lượng token/batch vượt trần thì chuyển sang 3 batch
function computeBatchPlan(totalDays) {
  let numBatches = PREFERRED_BATCH_COUNT;
  let batchSize = Math.ceil(totalDays / numBatches);

  if (batchSize * TOKENS_PER_DAY_ESTIMATE > MODEL_MAX_OUTPUT_TOKENS) {
    numBatches = FALLBACK_BATCH_COUNT;
    batchSize = Math.ceil(totalDays / numBatches);
  }

  const batches = [];
  let start = 1;
  while (start <= totalDays) {
    const end = Math.min(start + batchSize - 1, totalDays);
    batches.push({ startDay: start, endDay: end, count: end - start + 1 });
    start = end + 1;
  }

  console.log(`📦 Batch plan: ${numBatches} batch(es) cho ${totalDays} ngày -> ${batches.map(b => `[${b.startDay}-${b.endDay}]`).join(', ')}`);
  return batches;
}

// Chuẩn hóa dữ liệu 1 batch, gán đúng day_number tuyệt đối (không phải index+1 cục bộ)
function normalizeDaysBatch(days, batchStartDay, batchCount, hoursPerDay, studyDatesForBatch, totalDays, quizDayLength = 5, quizChapterLength = 10) {
  const normalized = [];

  for (let i = 0; i < batchCount; i++) {
    const src = days[i] || {};
    const dayNumber = batchStartDay + i;
    const isChapterEnd = (dayNumber % CHAPTER_SIZE_DAYS === 0) || (dayNumber === totalDays);

    normalized.push({
      day_number: dayNumber,
      daily_goal: String(src.daily_goal || src.goal || `Mục tiêu ngày ${dayNumber}`).trim().substring(0, 500),
      learning_content: String(src.learning_content || src.content || '').trim().substring(0, 1000),
      practice_exercises: String(src.practice_exercises || src.exercises || '').trim().substring(0, 1000),
      learning_materials: String(src.learning_materials || src.materials || '').trim(),
      study_guide: String(src.study_guide || src.usage_instructions || src.instructions || '').trim().substring(0, 2000),
      study_duration: parseFloat(src.study_duration || src.hours || hoursPerDay) || hoursPerDay,
      completion_status: 'NOT_STARTED',
      study_date: toVietnamDateString(studyDatesForBatch[i]),
      quiz: normalizeQuizArray(src.quiz, quizDayLength),
      chapter_review_quiz: isChapterEnd ? normalizeQuizArray(src.chapter_review_quiz, quizChapterLength) : []
    });
  }

  return normalized;
}

// Nếu 1 vài ngày trong batch bị thiếu learning_content/practice_exercises (JSON bị cắt do
// vượt maxOutputTokens, hoặc model bỏ sót), gọi lại Gemini 1 lần nữa CHỈ cho đúng những ngày
// còn thiếu đó để lấp đầy, thay vì để trống. Trả về map { day_number: rowFromAI }.
async function fillMissingDaysContent(missingDays, { category, roadmapName, hoursPerDay, actualDays }) {
  if (!Array.isArray(missingDays) || missingDays.length === 0) return {};

  const dayNumbersList = missingDays.map(d => d.day_number);
  const needsChapterReview = dayNumbersList.some(d => d % CHAPTER_SIZE_DAYS === 0 || d === actualDays);

  const systemPrompt = `Bạn là chuyên gia thiết kế lộ trình học. Lộ trình "${roadmapName}" (${category}) dài ${actualDays} ngày.
Ở lần gọi trước, các ngày sau bị thiếu nội dung do lỗi kỹ thuật. Hãy CHỈ tạo lại nội dung đầy đủ cho đúng các ngày có day_number: ${dayNumbersList.join(', ')} (không tạo thêm ngày nào khác).
Mỗi ngày cần đầy đủ: daily_goal, learning_content (nội dung kiến thức chi tiết), practice_exercises (bài tập thực hành), study_duration, và 1 mảng "quiz" gồm đúng 5 câu hỏi trắc nghiệm (4 phương án A/B/C/D, 1 đáp án đúng) bám sát nội dung ngày đó.
${needsChapterReview ? `Với ngày nào trong số đó là bội số của ${CHAPTER_SIZE_DAYS} hoặc là ngày cuối cùng của lộ trình (day_number = ${actualDays}), bắt buộc thêm cả mảng "chapter_review_quiz" gồm 5 câu hỏi tổng hợp; các ngày còn lại để chapter_review_quiz là mảng rỗng.` : ''}

Trả về JSON format:
{
  "roadmap": [
    {
      "day_number": ${dayNumbersList[0]},
      "daily_goal": "...",
      "learning_content": "...",
      "practice_exercises": "...",
      "study_duration": ${hoursPerDay},
      "quiz": [
        {"question_text": "...", "option_a": "...", "option_b": "...", "option_c": "...", "option_d": "...", "correct_option": "A", "explanation": "..."}
      ],
      "chapter_review_quiz": []
    }
  ]
}`;

  const userPrompt = `Mục tiêu tạm thời (có thể tinh chỉnh lại cho hợp lý) của các ngày cần tạo lại:\n` +
    missingDays.map(d => `- Ngày ${d.day_number}: ${d.daily_goal}`).join('\n');

  const desiredCompletionTokens = Math.min(
    missingDays.length * (TOKENS_PER_DAY_ESTIMATE +CHAPTER_REVIEW_EXTRA_TOKENS) + 500,
    MODEL_MAX_OUTPUT_TOKENS
  );

  const response = (await callGeminiForMainContent({ systemPrompt, userPrompt, desiredCompletionTokens })).trim();
  if (!response) return {};

  const parsed = parseAIResponse(response);
  const rows = Array.isArray(parsed.roadmap) ? parsed.roadmap : [];

  const byDayNumber = {};
  rows.forEach(row => {
    const dn = parseInt(row.day_number);
    if (dn) byDayNumber[dn] = row;
  });
  return byDayNumber;
}

// Tóm tắt ngắn gọn vài ngày cuối của batch trước để giữ mạch nội dung liền lạc giữa các batch
function buildContinuitySummary(previousDays, maxItems = 3) {
  if (!Array.isArray(previousDays) || previousDays.length === 0) return '';
  const lastDays = previousDays.slice(-maxItems);
  return lastDays.map(d => `- Ngày ${d.day_number}: ${d.daily_goal} (${(d.learning_content || '').substring(0, 120)}...)`).join('\n');
}
// Insert nhiều dòng cùng lúc bằng 1 câu lệnh SQL (thay vì await tuần tự từng dòng) để
// giảm số round-trip tới DB. Postgres giới hạn ~65535 tham số/câu lệnh nên chia lô nhỏ.
async function bulkInsert(client, insertPrefixSql, rows, chunkSize = 500) {
  for (let offset = 0; offset < rows.length; offset += chunkSize) {
    const chunk = rows.slice(offset, offset + chunkSize);
    const params = [];
    const valuesSql = chunk.map((row, i) => {
      const placeholders = row.map((_, j) => `$${i * row.length + j + 1}`).join(',');
      params.push(...row);
      return `(${placeholders})`;
    }).join(',');
    await client.query(`${insertPrefixSql} VALUES ${valuesSql}`, params);
  }
}

// ============================================================================
// 18. HELPER FUNCTIONS - Link Validation
// ============================================================================

async function validateUrlSmart(url, maxRetries = 2, timeout = 8000) {
  // Không chấp nhận link khoá học (miễn phí lẫn trả phí) làm tài liệu lý thuyết/thực hành
  if (isCoursePlatformUrl(url)) {
    console.log(`❌ Course platform (không cho phép): ${url}`);
    return { valid: false, reason: 'course_platform_excluded', url };
  }

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);
      
      const response = await fetch(url, {
        method: 'GET',
        redirect: 'follow',
        signal: controller.signal,
        headers: { 
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
      });
      
      clearTimeout(timeoutId);
      
      if (!response.ok) {
            // Allow 403 (forbidden) as valid per product requirement: user may still access
            if (response.status === 403) {
              console.log(`⚠️ HTTP 403 (allowed): ${url}`);
              return { valid: true, reason: `http_403_allowed`, url };
            }
            console.log(`❌ HTTP ${response.status}: ${url}`);
            return { valid: false, reason: `http_${response.status}`, url };
      }
      
      const html = await response.text();
      
      const titleMatch = html.match(/<title[^>]*>(.*?)<\/title>/i);
      const h1Match = html.match(/<h1[^>]*>(.*?)<\/h1>/i);
      
      const titleText = titleMatch ? titleMatch[1].toLowerCase() : '';
      const h1Text = h1Match ? h1Match[1].toLowerCase() : '';
      
      const errorPhrases = [
        'page not found',
        'sorry, this page',
        'oops',
        'error 404',
        '404 error',
        'không tìm thấy',
        'not available',
        'removed or deleted',
        'could not be found'
      ];
      
      for (const phrase of errorPhrases) {
        if (titleText.includes(phrase) || h1Text.includes(phrase)) {
          console.log(`❌ Error phrase in title/h1: "${phrase}"`);
          return { valid: false, reason: 'error_page', url };
        }
      }
      
      const contentType = response.headers.get('content-type') || '';
      // Allow PDFs as valid learning materials
      if (contentType.includes('application/pdf')) {
        console.log(`✅ PDF content allowed: ${url}`);
        return { valid: true, url };
      }

      if (!contentType.includes('text/html')) {
        console.log(`⚠️ Non-HTML content: ${contentType}`);
        return { valid: false, reason: 'non_html', url };
      }
      
      const bodyMatch = html.match(/<body[^>]*>([\s\S]*)<\/body>/i);
      if (bodyMatch) {
        const bodyContent = bodyMatch[1]
          .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
          .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
          .replace(/<[^>]+>/g, '')
          .replace(/\s+/g, ' ')
          .trim();
        
        if (bodyContent.length < 100) {
          console.log(`❌ Insufficient content: ${bodyContent.length} chars`);
          return { valid: false, reason: 'empty_page', url };
        }
      }
      
      console.log(`✅ Valid: ${url}`);
      return { valid: true, url };
      
    } catch (error) {
      if (error.name === 'AbortError') {
        console.log(`⏱️ Timeout: ${url}`);
      } else {
        console.log(`❌ Network error: ${error.message}`);
      }
      
      if (attempt === maxRetries) {
        return { valid: false, reason: 'network_error', url };
      }
      
      await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
    }
  }
  
  return { valid: false, reason: 'max_retries', url };
}

async function validateBatchLinksEnhanced(days, options = {}) {
  const category = options.category || '';
  const subCategory = options.subCategory || '';
  const results = new Array(days.length);

  const queue = new PQueue({ concurrency: 5 });

  const tasks = days.map((day, i) => queue.add(async () => {
    const rawLinks = String(day.learning_materials || '')
      .split('\n')
      .map(l => l.trim())
      .filter(Boolean);
    const link = rawLinks[0] || '';

    if (!link) {
      results[i] = {
        index: i,
        dayNumber: day.day_number || i + 1,
        valid: false,
        reason: 'no_link',
        originalUrl: '',
        validatedUrl: ''
      };
      return;
    }

    // Validate từng link trong danh sách, giữ lại những link hợp lệ
    const validLinks = [];
    for (const l of rawLinks) {
      const v = await validateUrlSmart(l, 2, LINK_VALIDATION_CONFIG.VALIDATION_TIMEOUT);
      if (v.valid) validLinks.push(l);
    }
    if (validLinks.length > 0) {
      day.learning_materials = validLinks.join('\n');
    }

    const validation = await validateUrlSmart(
      link,
      2,
      LINK_VALIDATION_CONFIG.VALIDATION_TIMEOUT
    );

    const result = {
      index: i,
      dayNumber: day.day_number || i + 1,
      valid: validation.valid,
      originalUrl: link,
      validatedUrl: validation.url,
      reason: validation.reason || null
    };

    const icon = validation.valid ? '✅' : '❌';
    const reasonLabel = validation.reason ? ` (${validation.reason})` : '';
    console.log(`📋 Day ${day.day_number || i + 1}: ${icon} ${link.substring(0, 80)}...${reasonLabel}`);

    if (!validation.valid) {
      try {
        const combinedCategory = subCategory ? `(${category}) - (${subCategory})` : `(${category})`;
        const tavilyQuery = `${combinedCategory} - (${day.daily_goal}) tutorial hướng dẫn`.trim().substring(0, 200);
        const tavilyResults = await searchWithTavilyOnly(tavilyQuery, 3);
        if (Array.isArray(tavilyResults) && tavilyResults.length > 0) {
          const first = tavilyResults[0];
          const newUrl = String(first.url || '').trim();
          if (newUrl) {
            day.learning_materials = newUrl;
            day.study_guide = `Hướng dẫn truy cập: Mở trang ${newUrl} → nếu là PDF thì tải về và đọc phần liên quan; nếu là trang web, nhấn vào "Bắt đầu/Start" hoặc mở "Mục lục/Table of Contents" và tìm phần liên quan đến "${day.daily_goal}".`;
            result.valid = true;
            result.validatedUrl = newUrl;
            result.reason = 'tavily_generated';
            console.log(`🔧 Day ${day.day_number || i + 1}: Tavily generated replacement link: ${newUrl}`);
          }
        }
      } catch (err) {
        console.warn(`⚠️ Tavily repair failed for day ${day.day_number || i + 1}: ${err.message}`);
      }
    }

    results[i] = result;
  }));

  await Promise.all(tasks);
  return results;
}

function createGoogleSearchFallback(day, category, subCategory = '') {
  const combined = `${category}${subCategory ? ' - ' + subCategory : ''}`.trim();
  const searchQuery = encodeURIComponent(`${day.daily_goal} ${combined} tutorial hướng dẫn`);
  const googleSearchUrl = `https://www.google.com/search?q=${searchQuery}`;

  let fallbackGuide = `${day.study_guide || ''}`;
  fallbackGuide = fallbackGuide.replace(/\n/g, '<br>');

  // Explicit step-by-step guidance for users
  const explicit = `Hướng dẫn truy cập: Mở trang ${googleSearchUrl} → nhấn vào kết quả có tiêu đề phù hợp; nếu là trang khóa học, nhấn 'Bắt đầu/Start' hoặc mở 'Mục lục' và tìm phần liên quan đến "${day.daily_goal}".`;

  return {
    learning_materials: googleSearchUrl,
    study_guide: (fallbackGuide ? fallbackGuide + '<br>' : '') + explicit
  };
}

// ============================================================================
// 19. HELPER FUNCTIONS - AI API Calls (Gemini + Search Key Pool)
// ============================================================================

function getCurrentPeriodMonth() {
  const vnNow = getVietnamDate();
  const year = vnNow.getFullYear();
  const month = String(vnNow.getMonth() + 1).padStart(2, '0');
  return `${year}-${month}`;
}

function getCurrentPeriodDay() {
  const vnNow = getVietnamDate();
  const year = vnNow.getFullYear();
  const month = String(vnNow.getMonth() + 1).padStart(2, '0');
  const day = String(vnNow.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

async function reserveKeySlot(provider, keyIndex, period, quotaLimit) {
  const result = await pool.query(
    `INSERT INTO search_api_usage (provider, key_index, period, used_count, quota_limit)
     VALUES ($1, $2, $3, 1, $4)
     ON CONFLICT (provider, key_index, period)
     DO UPDATE SET used_count = search_api_usage.used_count + 1,
                    updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
     WHERE search_api_usage.used_count < search_api_usage.quota_limit
     RETURNING used_count`,
    [provider, keyIndex, period, quotaLimit]
  );
  return result.rows.length > 0;
}

async function acquireKeyFromPool(provider, keys, period, quotaLimit, excludeIndexes = new Set()) {
  for (let i = 0; i < keys.length; i++) {
    if (excludeIndexes.has(i)) continue; // bỏ qua key vừa bị lỗi trong lượt này
    const ok = await reserveKeySlot(provider, i, period, quotaLimit);
    if (ok) return { key: keys[i], keyIndex: i };
  }
  return null;
}

async function callGeminiRaw({ apiKey, model, systemPrompt, userPrompt, temperature = 0.7, maxOutputTokens = 8000, jsonMode = true }) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
  const combinedPrompt = systemPrompt ? `${systemPrompt}\n\n${userPrompt}` : userPrompt;

  const body = {
    contents: [{ role: "user", parts: [{ text: combinedPrompt }] }],
    generationConfig: {
      temperature,
      maxOutputTokens,
      ...(jsonMode ? { responseMimeType: "application/json" } : {})
    }
  };

  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });

  if (res.status === 429) {
      const errText = await res.text();          // ✅ THÊM
      console.warn(`🔴 Gemini 429 body: ${errText.substring(0, 800)}`); // ✅ THÊM
      const err = new Error("Gemini rate limited (429)");
      err.isRateLimit = true;
      err.rawBody = errText;                      // ✅ THÊM (tuỳ chọn, để dùng sau)
      throw err;
  }

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Gemini API lỗi ${res.status}: ${errText.substring(0, 500)}`);
  }

  const data = await res.json();
  const text = data?.candidates?.[0]?.content?.parts?.map(p => p.text || "").join("") || "";
  if (!text) {
    const finishReason = data?.candidates?.[0]?.finishReason;
    throw new Error(`Gemini trả về rỗng (finishReason: ${finishReason || 'unknown'})`);
  }
  return text;
}

// Gọi Gemini bằng key pool: duyệt qua các key còn quota trong ngày, key nào hết thì thử key kế
async function callGemini({ model, systemPrompt, userPrompt, temperature = 0.7, maxOutputTokens = 8000, jsonMode = true }) {
  if (GEMINI_API_KEYS.length === 0) throw new Error("Chưa cấu hình GEMINI_API_KEY nào");

  const period = getCurrentPeriodDay();
  let lastErr;
  const excludeIndexes = new Set(); // ✅ THÊM: key đã thử và lỗi trong lượt gọi này

  for (let i = 0; i < GEMINI_API_KEYS.length; i++) {
    const slot = await acquireKeyFromPool('gemini', GEMINI_API_KEYS, period, GEMINI_DAILY_QUOTA_PER_KEY, excludeIndexes); // ✅ truyền excludeIndexes
    if (!slot) {
      console.warn(`⚠️ Toàn bộ ${GEMINI_API_KEYS.length} Gemini key đã hết quota hoặc bị rate limit ngày ${period}`);
      break;
    }

    try {
      const text = await callGeminiRaw({
        apiKey: slot.key, model, systemPrompt, userPrompt, temperature, maxOutputTokens, jsonMode
      });
      console.log(`🔑 Gemini key #${slot.keyIndex + 1}/${GEMINI_API_KEYS.length} → OK`);
      return text;
    } catch (err) {
      lastErr = err;
      excludeIndexes.add(slot.keyIndex); // ✅ THÊM: đánh dấu key này đã lỗi, lần sau bỏ qua
      if (err.isRateLimit) {
        console.warn(`⏳ Gemini key #${slot.keyIndex + 1} bị rate limit (429), thử key khác...`);
        continue;
      } else {
        console.warn(`⚠️ Gemini key #${slot.keyIndex + 1} lỗi: ${err.message}`);
        await new Promise(r => setTimeout(r, 1500));
      }
    }
  }

  throw lastErr || new Error("Không còn Gemini key nào khả dụng");
}

async function callGeminiForMainContent({ systemPrompt, userPrompt, desiredCompletionTokens }) {
  const capped = Math.max(MIN_COMPLETION_TOKENS, Math.min(desiredCompletionTokens, 65000));
  console.log(`📤 Gemini call (main content): model=${GEMINI_MODEL}, tokens=${capped}`);
  return await callGemini({
    model: GEMINI_MODEL,
    systemPrompt,
    userPrompt,
    temperature: 0.8,
    maxOutputTokens: capped,
    jsonMode: true
  });
}

async function searchDuckDuckGo(query, maxResults = 5) {
  try {
    const result = await ddgSearch(query, { safeSearch: SafeSearchType.MODERATE });
    if (!result || !Array.isArray(result.results)) return [];
    return result.results.slice(0, maxResults).map(r => ({
      title: (r.title || '').replace(/<\/?b>/g, ''),
      url: r.url,
      description: (r.description || '').replace(/<\/?b>/g, '').substring(0, 200)
    }));
  } catch (err) {
    console.warn(`⚠️ DuckDuckGo search lỗi cho "${query}": ${err.message}`);
    return [];
  }
}

async function searchSerpApiWithKey(apiKey, query, maxResults = 5) {
  const url = `https://serpapi.com/search.json?engine=google&q=${encodeURIComponent(query)}&num=${maxResults}&hl=vi&api_key=${apiKey}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`SerpAPI lỗi ${res.status}`);
  const data = await res.json();

  // SerpAPI có thể trả lỗi 200 kèm field "error" (vd hết quota) -> coi như lỗi để rớt xuống Tavily
  if (data?.error) throw new Error(`SerpAPI: ${data.error}`);

  const results = data?.organic_results || [];
  return results.slice(0, maxResults).map(r => ({
    title: r.title || '',
    url: r.link,
    description: (r.snippet || '').substring(0, 200)
  })).filter(r => !!r.url);
}

// Các nền tảng khóa học (miễn phí lẫn trả phí) -> không được dùng làm link tài liệu lý thuyết/thực hành,
// vì mục tiêu là tài liệu/bài viết cụ thể, không phải trang bán/tổ chức khóa học.
// Danh sách domain "sạch" để truyền cho Tavily exclude_domains (phải là tên miền, không có path).
const COURSE_PLATFORM_DOMAINS = [
  'coursera.org', 'udemy.com', 'edx.org', 'udacity.com', 'khanacademy.org',
  'pluralsight.com', 'skillshare.com', 'brilliant.org', 'futurelearn.com',
  'masterclass.com', 'codecademy.com', 'datacamp.com',
  'unica.vn', 'kyna.vn', 'edumall.vn', 'gitiho.com', 'kteam.vn'
];
// Danh sách mở rộng (có thể gồm path) để tự lọc thêm phía server, phòng khi Tavily không loại hết.
const COURSE_PLATFORM_URL_SUBSTRINGS = [...COURSE_PLATFORM_DOMAINS, 'linkedin.com/learning', 'topcv.vn/hoc'];

function isCoursePlatformUrl(url) {
  const lower = String(url || '').toLowerCase();
  return COURSE_PLATFORM_URL_SUBSTRINGS.some(domain => lower.includes(domain));
}

// Nhận diện trang "khóa học" (course) qua nội dung tiêu đề/mô tả, để bắt cả những trang bán/tổ
// chức khóa học KHÔNG nằm trong danh sách domain đã biết (vd 1 blog cá nhân bán khoá học riêng).
const COURSE_KEYWORDS = [
  'khóa học', 'khoá học', 'course', 'enroll now', 'đăng ký khóa học', 'đăng ký học ngay',
  'học phí', 'chứng chỉ hoàn thành', 'certificate of completion', 'bootcamp',
  'lộ trình học', 'combo khóa học', 'mua khóa học', 'nâng cấp tài khoản premium'
];

// Nhận diện trang thiên về bài tập/đề bài (dùng để: KHÔNG chọn làm link lý thuyết,
// và ưu tiên chọn làm link thực hành).
const EXERCISE_KEYWORDS = [
  'bài tập', 'exercise', 'exercises', 'problem set', 'leetcode', 'hackerrank',
  'codewars', 'giải bài', 'lời giải', 'solution', 'practice problems', 'coding challenge', 'đề bài'
];

function resultTextMatches(candidate, keywords) {
  const text = `${candidate?.title || ''} ${candidate?.description || ''} ${candidate?.url || ''}`.toLowerCase();
  return keywords.some(k => text.includes(k));
}

function isCourseLikeResult(candidate) {
  return isCoursePlatformUrl(candidate?.url) || resultTextMatches(candidate, COURSE_KEYWORDS);
}

// Chọn ứng viên tốt nhất từ danh sách kết quả: luôn loại trang khóa học, có thể tránh/ưu tiên
// thêm theo từ khóa (vd tránh trang thuần bài tập khi chọn link lý thuyết), và loại các URL đã dùng.
function pickBestCandidate(results, { excludeUrls = [], avoidKeywords = [], preferKeywords = [] } = {}) {
  const usable = (results || []).filter(r =>
    String(r?.url || '').trim() &&
    !isCourseLikeResult(r) &&
    !excludeUrls.includes(String(r.url).trim())
  );
  if (usable.length === 0) return null;

  if (preferKeywords.length > 0) {
    const preferred = usable.find(r => resultTextMatches(r, preferKeywords));
    if (preferred) return preferred;
  }
  if (avoidKeywords.length > 0) {
    const notAvoided = usable.find(r => !resultTextMatches(r, avoidKeywords));
    if (notAvoided) return notAvoided;
  }
  return usable[0];
}

async function searchTavilyWithKey(apiKey, query, maxResults = 5) {
  const res = await fetch('https://api.tavily.com/search', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      api_key: apiKey, query, search_depth: 'basic', max_results: maxResults,
      exclude_domains: COURSE_PLATFORM_DOMAINS
    })
  });
  if (!res.ok) throw new Error(`Tavily API lỗi ${res.status}`);
  const data = await res.json();
  return (data.results || [])
    .map(r => ({
      title: r.title, url: r.url, description: (r.content || '').substring(0, 200)
    }))
    .filter(r => !isCourseLikeResult(r));
}

async function searchWithKeyPool(query, maxResults = 5) {
  const period = getCurrentPeriodMonth();

  if (SERPAPI_API_KEYS.length > 0) {
    const slot = await acquireKeyFromPool('serpapi', SERPAPI_API_KEYS, period, SERPAPI_MONTHLY_QUOTA);
    if (slot) {
      try {
        const results = await searchSerpApiWithKey(slot.key, query, maxResults);
        if (results.length > 0) {
          console.log(`🔑 SerpAPI key #${slot.keyIndex + 1}/${SERPAPI_API_KEYS.length} → ${results.length} kết quả`);
          return results;
        }
      } catch (err) {
        console.warn(`⚠️ SerpAPI key #${slot.keyIndex + 1} lỗi: ${err.message}`);
      }
    } else {
      console.warn(`⚠️ Toàn bộ ${SERPAPI_API_KEYS.length} SerpAPI key đã hết quota tháng ${period}`);
    }
  }

  if (TAVILY_API_KEYS.length > 0) {
    const slot = await acquireKeyFromPool('tavily', TAVILY_API_KEYS, period, TAVILY_MONTHLY_QUOTA);
    if (slot) {
      try {
        const results = await searchTavilyWithKey(slot.key, query, maxResults);
        if (results.length > 0) {
          console.log(`🔑 Tavily key #${slot.keyIndex + 1}/${TAVILY_API_KEYS.length} → ${results.length} kết quả`);
          return results;
        }
      } catch (err) {
        console.warn(`⚠️ Tavily key #${slot.keyIndex + 1} lỗi: ${err.message}`);
      }
    } else {
      console.warn(`⚠️ Toàn bộ ${TAVILY_API_KEYS.length} Tavily key đã hết quota tháng ${period}`);
    }
  }

  console.log(`🦆 Dùng DuckDuckGo (fallback cuối) cho: "${query}"`);
  return await searchDuckDuckGo(query, maxResults);
}

async function searchWithTavilyOnly(query, maxResults = 5) {
  if (!Array.isArray(TAVILY_API_KEYS) || TAVILY_API_KEYS.length === 0) {
    console.warn(`⚠️ Tavily: không có API key, bỏ qua tìm tài liệu cho "${query}"`);
    return [];
  }

  const period = getCurrentPeriodMonth();
  const slot = await acquireKeyFromPool('tavily', TAVILY_API_KEYS, period, TAVILY_MONTHLY_QUOTA);
  if (!slot) {
    console.warn(`⚠️ Tavily: toàn bộ ${TAVILY_API_KEYS.length} key đã hết quota tháng ${period}`);
    return [];
  }

  try {
    const results = await searchTavilyWithKey(slot.key, query, maxResults);
    if (results.length > 0) {
      console.log(`✅ Tavily key #${slot.keyIndex + 1}/${TAVILY_API_KEYS.length} → ${results.length} kết quả cho: "${query}"`);
      return results;
    }

    console.warn(`⚠️ Tavily key #${slot.keyIndex + 1}/${TAVILY_API_KEYS.length} → không có kết quả cho: "${query}"`);
  } catch (err) {
    console.warn(`❌ Tavily key #${slot.keyIndex + 1}/${TAVILY_API_KEYS.length} lỗi: ${err.message}`);
  }

  return [];
}

// ============================================================================
// 19b. FIRECRAWL - Cào nội dung trang web để viết cột "Hướng dẫn sử dụng"
// ============================================================================

async function firecrawlScrapeWithKey(apiKey, url) {
  const res = await fetch('https://api.firecrawl.dev/v1/scrape', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      url,
      formats: ['markdown'],
      onlyMainContent: true,
      timeout: 15000
    })
  });

  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    throw new Error(`Firecrawl lỗi ${res.status}: ${errText.substring(0, 200)}`);
  }

  const data = await res.json();
  if (data?.success === false) throw new Error(`Firecrawl: ${data?.error || 'unknown error'}`);

  const markdown = data?.data?.markdown || data?.markdown || '';
  return markdown.trim();
}

// Cào bằng key pool: hết quota/lỗi key này thì thử key kế tiếp
async function firecrawlScrapeWithKeyPool(url) {
  if (FIRECRAWL_API_KEYS.length === 0 || !url) return null;
  const period = getCurrentPeriodMonth();

  for (let i = 0; i < FIRECRAWL_API_KEYS.length; i++) {
    const slot = await acquireKeyFromPool('firecrawl', FIRECRAWL_API_KEYS, period, FIRECRAWL_MONTHLY_QUOTA);
    if (!slot) {
      console.warn(`⚠️ Toàn bộ ${FIRECRAWL_API_KEYS.length} Firecrawl key đã hết quota tháng ${period}`);
      return null;
    }
    try {
      const content = await firecrawlScrapeWithKey(slot.key, url);
      if (content) {
        console.log(`🔑 Firecrawl key #${slot.keyIndex + 1}/${FIRECRAWL_API_KEYS.length} → cào được ${content.length} ký tự (${url})`);
        // Giới hạn độ dài để tiết kiệm token khi đưa vào prompt Gemini
        return content.substring(0, 6000);
      }
    } catch (err) {
      console.warn(`⚠️ Firecrawl key #${slot.keyIndex + 1} lỗi (${url}): ${err.message}`);
    }
  }
  return null;
}

// Dựa vào kết quả tìm kiếm từ Tavily để viết hướng dẫn sử dụng chi tiết
async function generateGuideFromSearchResults({ dailyGoal, learningContent, searchResults }) {
  const safeResults = Array.isArray(searchResults) ? searchResults.slice(0, 3) : [];
  if (safeResults.length === 0) return "";

  const topResult = safeResults[0] || {};
  const title = String(topResult.title || '').trim();
  const description = String(topResult.description || '').trim().replace(/\s+/g, ' ').slice(0, 300);
  const fallback = description || 'nội dung chính của tài liệu được đề xuất';

  const guidance = `Bắt đầu từ tài liệu "${title || 'đề xuất đầu tiên'}" để đạt mục tiêu "${dailyGoal}". Với nội dung "${learningContent}", hãy ưu tiên đọc phần giới thiệu trước, sau đó tập trung vào phần ${fallback}. Nếu tài liệu có mục lục, hãy chọn phần liên quan trực tiếp đến mục tiêu học hôm nay trước, rồi mới thực hành theo ví dụ.`;

  return guidance.trim();
}

// Ghép đủ 4 thành phần (danh mục, danh mục chi tiết, mục tiêu ngày, nội dung học/bài tập do Gemini
// trả ra) thành 1 câu query tìm kiếm, có cắt bớt độ dài từng phần để tổng query không quá dài.
function buildMaterialSearchQuery({ category, subCategory, dailyGoal, contentText, suffix }) {
  const truncate = (s, n) => String(s || '').trim().replace(/\s+/g, ' ').substring(0, n);
  const parts = [
    truncate(category, 60),
    truncate(subCategory, 60),
    truncate(dailyGoal, 100),
    truncate(contentText, 150)
  ].filter(Boolean);
  return `${parts.join(' - ')} ${suffix || ''}`.trim().substring(0, 350);
}

async function callFreeSearchForMaterials({ days, category, subCategory = '', temperature = 0.5 }) {
  if (!Array.isArray(days) || days.length === 0) {
    throw new Error("Days array không hợp lệ hoặc rỗng");
  }

  const validDays = days.filter(d => d && d.day_number && d.daily_goal && d.learning_content);
  if (validDays.length === 0) {
    return [];
  }

  console.log(`📊 Xử lý ${validDays.length} ngày bằng Tavily only (song song, concurrency=5), mỗi ngày tìm 2 link (lý thuyết + thực hành)`);

  const queue = new PQueue({ concurrency: 5 });

  const tasks = validDays.map(day => queue.add(async () => {
    // Link 1 (lý thuyết): query gồm đủ 4 thành phần - danh mục, danh mục chi tiết, mục tiêu ngày, nội dung học
    const theoryQuery = buildMaterialSearchQuery({
      category, subCategory,
      dailyGoal: day.daily_goal,
      contentText: day.learning_content,
      suffix: 'tutorial hướng dẫn'
    });
    // Link 2 (thực hành): query gồm đủ 4 thành phần - danh mục, danh mục chi tiết, mục tiêu ngày, bài tập thực hành
    const practiceBasis = (day.practice_exercises || '').trim();
    const practiceQuery = buildMaterialSearchQuery({
      category, subCategory,
      dailyGoal: day.daily_goal,
      contentText: practiceBasis,
      suffix: 'bài tập thực hành exercise practice'
    });

    // Link 1 (lý thuyết) và Link 2 (thực hành) độc lập nhau -> tìm song song thay vì tuần tự
    // (lấy nhiều kết quả hơn để có đủ ứng viên sau khi loại khóa học/lọc theo vai trò)
    const [theoryResults, practiceResults] = await Promise.all([
      searchWithTavilyOnly(theoryQuery, 8),
      practiceBasis ? searchWithTavilyOnly(practiceQuery, 8) : Promise.resolve([])
    ]);

    // Link lý thuyết: KHÔNG được là trang khóa học (đã lọc từ searchWithTavilyOnly), và ưu tiên
    // tránh chọn trang thuần bài tập (nếu còn ứng viên khác) -> tránh nhầm link 1 thành link bài tập.
    const theoryCandidate = pickBestCandidate(theoryResults, { avoidKeywords: EXERCISE_KEYWORDS });
    const theoryUrl = theoryCandidate ? String(theoryCandidate.url).trim() : "";

    // Link thực hành: KHÔNG được trùng link lý thuyết, KHÔNG được là trang khóa học, và ưu tiên
    // chọn đúng trang có bài tập/đề bài cụ thể (không phải bài viết lý thuyết chung chung).
    const practiceCandidate = pickBestCandidate(practiceResults, {
      excludeUrls: theoryUrl ? [theoryUrl] : [],
      preferKeywords: EXERCISE_KEYWORDS
    });
    const practiceUrl = practiceCandidate ? String(practiceCandidate.url).trim() : "";

    // Sinh hướng dẫn sử dụng cho lý thuyết & thực hành cũng độc lập nhau -> chạy song song
    const [theoryGuide, practiceGuide] = await Promise.all([
      theoryUrl
        ? generateGuideFromSearchResults({
            dailyGoal: day.daily_goal || '',
            learningContent: day.learning_content || '',
            searchResults: theoryResults
          }).catch(err => {
            console.warn(`⚠️ Tavily guide (lý thuyết) lỗi ngày ${day.day_number}: ${err.message}`);
            return "";
          })
        : Promise.resolve(""),
      practiceCandidate
        ? generateGuideFromSearchResults({
            dailyGoal: `Thực hành: ${practiceBasis}`,
            learningContent: day.practice_exercises || day.learning_content || '',
            searchResults: [practiceCandidate, ...practiceResults.filter(r => r !== practiceCandidate)]
          }).catch(err => {
            console.warn(`⚠️ Tavily guide (thực hành) lỗi ngày ${day.day_number}: ${err.message}`);
            return "";
          })
        : Promise.resolve("")
    ]);

    const learningMaterialsParts = [theoryUrl, practiceUrl].filter(Boolean);
    const learningMaterials = learningMaterialsParts.join('\n');

    const guideParts = [];
    if (theoryGuide) guideParts.push(`📘 Lý thuyết: ${theoryGuide}`);
    if (practiceGuide) guideParts.push(`✏️ Thực hành: ${practiceGuide}`);
    const usageInstructions = guideParts.length > 0 ? guideParts.join('\n\n') : (day.study_guide || '');

    return {
      day_number: day.day_number,
      learning_materials: learningMaterials,
      usage_instructions: usageInstructions
    };
  }));

  const allMaterials = await Promise.all(tasks);

  console.log(`✅ Tổng materials thu được: ${allMaterials.length}`);
  return allMaterials;
}
// ============================================================================
// 20. MIDDLEWARE - Authentication
// ============================================================================

async function requireAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.replace(/^Bearer\s+/i, "").trim();
  
  if (!token) {
    return res.status(401).json({ message: "Không có token" });
  }
  
  if ((token.match(/\./g) || []).length !== 2) {
    return res.status(401).json({ message: "Token không hợp lệ" });
  }
  
  try {
    const payload = jwt.verify(token, getCleanSecret(), {
      algorithms: ['HS256']
    });
    
    if (!payload.userId) {
      return res.status(401).json({ message: "Token không chứa userId" });
    }
    
    const result = await pool.query(
      "SELECT id, username, role FROM users WHERE id = $1 LIMIT 1", 
      [payload.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ message: "Người dùng không tồn tại" });
    }
    
    req.user = result.rows[0];
    next();
    
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ 
        message: "Token đã hết hạn, vui lòng đăng nhập lại",
        code: "TOKEN_EXPIRED"
      });
    }
    
    if (err.name === "JsonWebTokenError") {
      console.error("JWT Error:", err.message);
      return res.status(401).json({ 
        message: "Token không hợp lệ",
        code: "INVALID_TOKEN"
      });
    }
    
    console.error("Auth error (requireAuth):", err);
    return res.status(401).json({ 
      message: "Xác thực thất bại",
      code: "AUTH_FAILED"
    });
  }
}

async function requireAdmin(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.replace(/^Bearer\s+/i, "").trim();
  
  if (!token) {
    return res.status(401).json({ message: "Không có token" });
  }
  
  if ((token.match(/\./g) || []).length !== 2) {
    return res.status(401).json({ message: "Token không hợp lệ" });
  }
  
  try {
    const payload = jwt.verify(token, getCleanSecret(), {
      algorithms: ['HS256']
    });
    
    if (!payload.userId) {
      return res.status(401).json({ message: "Token không chứa userId" });
    }
    
    const result = await pool.query(
      "SELECT id, username, role FROM users WHERE id = $1 LIMIT 1", 
      [payload.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ message: "Người dùng không tồn tại" });
    }
    
    const user = result.rows[0];
    
    if (user.role && String(user.role).toLowerCase() === "admin") {
      req.user = user;
      return next();
    }
    
    const adminName = (process.env.ADMIN_USERNAME || "").trim();
    if (adminName && user.username === adminName) {
      req.user = user;
      return next();
    }
    
    return res.status(403).json({ message: "Yêu cầu quyền admin" });
    
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ 
        message: "Token đã hết hạn, vui lòng đăng nhập lại",
        code: "TOKEN_EXPIRED"
      });
    }
    
    if (err.name === "JsonWebTokenError") {
      console.error("JWT Error:", err.message);
      return res.status(401).json({ 
        message: "Token không hợp lệ",
        code: "INVALID_TOKEN"
      });
    }
    
    console.error("Auth error (requireAdmin):", err);
    return res.status(401).json({ 
      message: "Xác thực thất bại",
      code: "AUTH_FAILED"
    });
  }
}

// ============================================================================
// 21. VALIDATION SCHEMAS
// ============================================================================

const submitEvaluationSchema = Joi.object({
  overall_rating: Joi.number().min(1).max(5).required(),
  learning_effectiveness: Joi.number().min(1).max(5).required(),
  difficulty_suitability: Joi.number().min(1).max(5).required(),
  content_relevance: Joi.number().min(1).max(5).required(),
  engagement_level: Joi.number().min(1).max(5).required(),
  detailed_feedback: Joi.string().allow(''),
  actual_learning_outcomes: Joi.string().allow(''),
  improvement_suggestions: Joi.string().allow(''),
  would_recommend: Joi.boolean()
});

// ============================================================================
// 22. API ENDPOINTS - LUỒNG XÁC THỰC & NGƯỜI DÙNG (7 endpoints)
// ============================================================================

// 1. POST /api/register/request-verification - Gửi mã xác thực qua email
app.post("/api/register/request-verification", async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email || !email.trim()) {
      return res.status(400).json({
        success: false,
        error: 'Email không được để trống'
      });
    }
    
    const normalizedEmail = email.trim().toLowerCase();
    
    // Kiểm tra email đã tồn tại chưa
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE LOWER(email) = $1',
      [normalizedEmail]
    );
    
    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        success: false,
        error: 'Email đã được sử dụng'
      });
    }
    
    // Tạo mã xác thực
    const code = generateResetCode();
    const vnNow = getVietnamDate();
    const expiresAt = new Date(vnNow.getTime() + 10 * 60 * 1000);
    
    // Lưu mã vào database
    await pool.query(
      `INSERT INTO password_reset_codes (email, code, expires_at) 
       VALUES ($1, $2, $3)`,
      [normalizedEmail, code, expiresAt]
    );
    
    // Gửi email
    const mailOptions = {
      from: `"Con đường đam mê" <${process.env.EMAIL_FROM}>`,
      to: normalizedEmail,
      subject: 'Mã xác thực đăng ký tài khoản',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px;">
          <div style="text-align: center; margin-bottom: 30px;">
            <h1 style="color: #007bff; margin: 0;">Con đường đam mê</h1>
            <p style="color: #6c757d; font-size: 14px;">AI-Powered Learning Path</p>
          </div>
          
          <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
            <h2 style="color: #333; margin-top: 0;">Xác thực email đăng ký</h2>
            <p style="color: #555; line-height: 1.6;">
              Cảm ơn bạn đã đăng ký tài khoản! Sử dụng mã xác thực dưới đây để hoàn tất đăng ký:
            </p>
            
            <div style="background: white; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
              <div style="font-size: 32px; font-weight: bold; color: #007bff; letter-spacing: 8px;">
                ${code}
              </div>
            </div>
            
            <p style="color: #dc3545; font-size: 14px; margin-bottom: 0;">
              ⚠️ Mã này sẽ hết hạn sau <strong>10 phút</strong>
            </p>
          </div>
          
          <div style="border-top: 1px solid #e0e0e0; padding-top: 20px; color: #6c757d; font-size: 12px;">
            <p>Nếu bạn không yêu cầu đăng ký, vui lòng bỏ qua email này.</p>
            <p style="margin-bottom: 0;">Đây là email tự động, vui lòng không trả lời.</p>
          </div>
        </div>
      `
    };
    
    await transporter.sendMail(mailOptions);
    
    res.json({
      success: true,
      message: 'Mã xác thực đã được gửi đến email của bạn',
      expiresIn: 600
    });
    
  } catch (error) {
    console.error('Error requesting verification code:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể xử lý yêu cầu'
    });
  }
});

// 2. POST /api/register/verify-code - Xác thực mã verification
app.post("/api/register/verify-code", async (req, res) => {
  try {
    const { email, code } = req.body;
    
    if (!email || !code) {
      return res.status(400).json({
        success: false,
        error: 'Email và mã xác thực không được để trống'
      });
    }
    
    const normalizedEmail = email.trim().toLowerCase();
    
    const result = await pool.query(
      `SELECT id, expires_at, used 
       FROM password_reset_codes 
       WHERE email = $1 AND code = $2 
       ORDER BY created_at DESC 
       LIMIT 1`,
      [normalizedEmail, code.trim()]
    );
    
    if (result.rows.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Mã xác thực không đúng'
      });
    }
    
    const resetCode = result.rows[0];
    
    if (resetCode.used) {
      return res.status(400).json({
        success: false,
        error: 'Mã xác thực đã được sử dụng'
      });
    }
    
    const vnNow = getVietnamDate();
    const expiresAtRaw = new Date(resetCode.expires_at);
    const expiresAtVN = new Date(expiresAtRaw.getTime() - VIETNAM_TIMEZONE_OFFSET);
    
    if (vnNow > expiresAtVN) {
      return res.status(400).json({
        success: false,
        error: 'Mã xác thực đã hết hạn'
      });
    }
    
    // Đánh dấu mã đã sử dụng
    await pool.query(
      'UPDATE password_reset_codes SET used = TRUE WHERE id = $1',
      [resetCode.id]
    );
    
    res.json({
      success: true,
      message: 'Mã xác thực hợp lệ'
    });
    
  } catch (error) {
    console.error('Error verifying code:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể xác thực mã'
    });
  }
});

// 3. POST /api/register - Đăng ký tài khoản
app.post("/api/register", async (req, res) => {
  const { name, username, email, password } = req.body;
  
  if (!name || !username || !email || !password) {
    return res.status(400).json({ message: "Thiếu dữ liệu!" });
  }
  
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
    
    if (Object.keys(errors).length > 0) {
      return res.status(400).json({ message: "Dữ liệu mật khẩu không hợp lệ.", errors });
    }
    
    const existing = await pool.query(
      "SELECT id FROM users WHERE username = $1 OR email = $2", 
      [normalizedUsername, normalizedEmail]
    );
    
    if (existing.rows.length > 0) {
      return res.status(409).json({ message: "Tên đăng nhập hoặc email đã tồn tại!" });
    }
    
    const hashed = await hashPassword(password, 10);
    
    const result = await pool.query(
      `INSERT INTO users (name, username, email, password, created_at) 
       VALUES ($1,$2,$3,$4, (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')) 
       RETURNING id, name, username, email, created_at`,
      [name.trim(), normalizedUsername, normalizedEmail, hashed]
    );
    
    const user = result.rows[0];
    const token = makeToken(user.id);
    
    res.json({ 
      message: "Đăng ký thành công!", 
      token, 
      user: {
        ...user,
        created_at: formatTimestampForAPI(user.created_at)
      }
    });
  } catch (err) {
    console.error("❌ SQL Error (register):", err && err.message ? err.message : err);
    if (err.code === "23505") {
      return res.status(409).json({ message: "Tên đăng nhập hoặc email đã tồn tại!" });
    }
    res.status(500).json({ message: "Lỗi server khi đăng ký!" });
  }
});

// 4. POST /api/login - Đăng nhập
app.post("/api/login", async (req, res) => {
  try {
    const body = (req.body && typeof req.body === "object") ? req.body : {};
    let username = body.username ? String(body.username).trim() : "";
    let email = body.email ? String(body.email).trim() : "";
    let password = body.password ? String(body.password) : "";
    
    if (!password || (!username && !email)) {
      return res.status(400).json({ message: "Thiếu tên đăng nhập hoặc email, hoặc mật khẩu!" });
    }
    
    const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (email && !EMAIL_RE.test(email)) {
      return res.status(400).json({ message: "Email không đúng định dạng!" });
    }
    
    let result;
    let user;
    
    if (username && email) {
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
      result = await pool.query(
        "SELECT id, name, username, email, password FROM users WHERE username = $1 LIMIT 1", 
        [username]
      );
      if (result.rows.length === 0) {
        return res.status(401).json({ message: "Sai tên đăng nhập hoặc mật khẩu!" });
      }
      user = result.rows[0];
    } else {
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
      user: { 
        id: user.id, 
        name: user.name, 
        username: user.username, 
        email: user.email 
      } 
    });
  } catch (err) {
    console.error("❌ SQL Error (login):", err && err.message ? err.message : err);
    return res.status(500).json({ message: "Lỗi server khi đăng nhập!" });
  }
});

// 5. GET /api/me - Lấy thông tin user từ token (public endpoint)
app.get("/api/me", async (req, res) => {
  const auth = req.headers.authorization || "";
  const token = auth.replace(/^Bearer\s+/i, "").trim();
  
  if (!token) {
    return res.status(401).json({ message: "Không có token" });
  }
  
  if ((token.match(/\./g) || []).length !== 2) {
    return res.status(401).json({ message: "Token không hợp lệ" });
  }
  
  try {
    const payload = jwt.verify(token, getCleanSecret(), {
      algorithms: ['HS256']
    });
    
    const result = await pool.query(
      "SELECT id, name, username, email, role, created_at, ai_roadmap_generations_used, avatar_url FROM users WHERE id = $1", 
      [payload.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Người dùng không tồn tại" });
    }

    const u = result.rows[0];
    const isAdmin = String(u.role || '').toLowerCase() === 'admin';
    const aiLimit = await getAIGenerationLimit();
    const aiRemaining = isAdmin ? null : Math.max(0, aiLimit - (u.ai_roadmap_generations_used || 0));

    res.json({ user: { ...u, ai_generations_remaining: aiRemaining } });
  } catch (err) {
    if (err && err.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Token đã hết hạn, vui lòng đăng nhập lại" });
    }
    console.error("Auth error:", err && err.message ? err.message : err);
    return res.status(401).json({ message: "Token không hợp lệ" });
  }
});

// PUT /api/users/me/password - Đổi mật khẩu (yêu cầu mật khẩu cũ, requireAuth)
app.put("/api/users/me/password", requireAuth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
      return res.status(400).json({ success: false, error: "Thiếu mật khẩu cũ hoặc mật khẩu mới" });
    }

    const pw = String(newPassword);
    if (pw.length < 8 || !/[A-Z]/.test(pw) || !/[a-z]/.test(pw) || !/[0-9]/.test(pw) || !/[^A-Za-z0-9]/.test(pw)) {
      return res.status(400).json({
        success: false,
        error: "Mật khẩu mới phải có ít nhất 8 ký tự, gồm chữ hoa, chữ thường, số và ký tự đặc biệt"
      });
    }

    const result = await pool.query("SELECT password FROM users WHERE id = $1", [req.user.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Người dùng không tồn tại" });
    }

    const match = await comparePassword(oldPassword, result.rows[0].password);
    if (!match) {
      return res.status(401).json({ success: false, error: "Mật khẩu cũ không đúng" });
    }

    const hashedNew = await hashPassword(newPassword, 10);
    await pool.query("UPDATE users SET password = $1 WHERE id = $2", [hashedNew, req.user.id]);

    res.json({ success: true, message: "Đổi mật khẩu thành công" });
  } catch (err) {
    console.error("Error changing password:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể đổi mật khẩu" });
  }
});

// PUT /api/users/me/profile - Cập nhật tên, username, email, avatar (requireAuth)
app.put("/api/users/me/profile", requireAuth, async (req, res) => {
  try {
    const { name, username, email, avatar_url } = req.body;
    const updates = [];
    const values = [];
    let paramCount = 1;

    if (name !== undefined) {
      if (!name.trim()) return res.status(400).json({ success: false, error: "Tên không được để trống" });
      updates.push(`name = $${paramCount++}`);
      values.push(name.trim());
    }
    if (username !== undefined) {
      const uname = String(username).trim();
      if (!/^[a-zA-Z0-9._-]{3,35}$/.test(uname)) {
        return res.status(400).json({ success: false, error: "Tên đăng nhập chỉ được chứa chữ, số, . _ - và 3-35 ký tự" });
      }
      updates.push(`username = $${paramCount++}`);
      values.push(uname);
    }
    if (email !== undefined) {
      const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!EMAIL_RE.test(email)) {
        return res.status(400).json({ success: false, error: "Email không đúng định dạng" });
      }
      updates.push(`email = $${paramCount++}`);
      values.push(String(email).trim());
    }
    if (avatar_url !== undefined) {
      updates.push(`avatar_url = $${paramCount++}`);
      values.push(avatar_url || null);
    }

    if (updates.length === 0) {
      return res.status(400).json({ success: false, error: "Không có dữ liệu để cập nhật" });
    }

    values.push(req.user.id);

    const result = await pool.query(
      `UPDATE users SET ${updates.join(", ")} WHERE id = $${paramCount} RETURNING id, name, username, email, role, avatar_url`,
      values
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Người dùng không tồn tại" });
    }

    res.json({ success: true, message: "Cập nhật hồ sơ thành công", data: result.rows[0] });
  } catch (err) {
    console.error("Error updating profile:", err?.message || err);
    if (err.code === "23505") {
      return res.status(409).json({ success: false, error: "Tên đăng nhập hoặc email đã được sử dụng" });
    }
    res.status(500).json({ success: false, error: "Không thể cập nhật hồ sơ" });
  }
});

// POST /api/cloudinary/signature - Tạo chữ ký để frontend upload avatar thẳng lên Cloudinary
app.post("/api/cloudinary/signature", requireAuth, async (req, res) => {
  try {
    const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
    const apiKey = process.env.CLOUDINARY_API_KEY;
    const apiSecret = process.env.CLOUDINARY_API_SECRET;

    if (!cloudName || !apiKey || !apiSecret) {
      return res.status(503).json({ success: false, error: "Tính năng upload ảnh chưa được cấu hình" });
    }

    const timestamp = Math.round(Date.now() / 1000);
    const folder = "passion_path_avatars";
    const transformation = "q_auto,f_auto,w_150,h_150,c_fill";

    const paramsToSign = `folder=${folder}&timestamp=${timestamp}&transformation=${transformation}`;
    const signature = crypto.createHash('sha1').update(paramsToSign + apiSecret).digest('hex');

    res.json({
      success: true,
      data: { signature, timestamp, apiKey, cloudName, folder, transformation }
    });
  } catch (err) {
    console.error("Error creating Cloudinary signature:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể tạo chữ ký upload" });
  }
});

// Kiểm tra ngày `dayNumber` có bị khoá không: ngày 1 luôn mở; ngày N>1 chỉ mở khi ngày N-1 đã COMPLETED
async function isDayUnlocked(roadmapId, dayNumber) {
  if (dayNumber <= 1) return true;
  const r = await pool.query(
    `SELECT completion_status FROM learning_roadmap_details WHERE roadmap_id = $1 AND day_number = $2`,
    [roadmapId, dayNumber - 1]
  );
  if (r.rows.length === 0) return true;
  return r.rows[0].completion_status === 'COMPLETED';
}

// Sau mỗi lần nộp quiz, tính lại xem ngày đó đã đủ điều kiện "Hoàn thành" chưa: cần đạt quiz
// thường VÀ bài kiểm tra chương (nếu ngày đó có), dựa trên điểm cao nhất trong mọi lần làm.
const CERTIFICATE_MILESTONES = [
  { percent: 25, code: 'BRZ' },
  { percent: 50, code: 'SIL' },
  { percent: 75, code: 'GOL' },
  { percent: 100, code: 'ACH' }
];

async function awardCertificatesIfEligible(client, roadmapId, progressPercentage) {
  const dateCode = toVietnamDateString(getVietnamDate()).replace(/-/g, '');
  const newlyAwarded = [];
  for (const m of CERTIFICATE_MILESTONES) {
    if (progressPercentage + 0.001 < m.percent) continue;
    const certificateCode = `PPAI-${m.code}-${roadmapId}-${dateCode}`;
    const result = await client.query(
      `INSERT INTO roadmap_certificates (roadmap_id, milestone_percent, certificate_code)
       VALUES ($1, $2, $3)
       ON CONFLICT (roadmap_id, milestone_percent) DO NOTHING
       RETURNING milestone_percent, certificate_code, awarded_at`,
      [roadmapId, m.percent, certificateCode]
    );
    if (result.rows.length > 0) newlyAwarded.push(result.rows[0]);
  }
  return newlyAwarded;
}

async function recomputeDayCompletion(roadmapId, dayNumber, userId) {
  const chapterExists = await pool.query(
    `SELECT EXISTS(SELECT 1 FROM quiz_questions WHERE roadmap_id = $1 AND day_number = $2 AND is_chapter_review = true) AS has_chapter`,
    [roadmapId, dayNumber]
  );
  const hasChapter = chapterExists.rows[0].has_chapter;

  const passedRes = await pool.query(
    `SELECT
       bool_or(passed) FILTER (WHERE is_chapter_review = false) AS normal_passed,
       bool_or(passed) FILTER (WHERE is_chapter_review = true) AS chapter_passed
     FROM quiz_attempts
     WHERE roadmap_id = $1 AND day_number = $2 AND user_id = $3`,
    [roadmapId, dayNumber, userId]
  );
  const { normal_passed, chapter_passed } = passedRes.rows[0];
  if (!normal_passed || (hasChapter && !chapter_passed)) return { completed: false, newCertificates: [] };

  const updateRes = await pool.query(
    `UPDATE learning_roadmap_details
     SET completion_status = 'COMPLETED',
         completed_at = COALESCE(completed_at, (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')),
         updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
     WHERE roadmap_id = $1 AND day_number = $2 AND completion_status <> 'COMPLETED'
     RETURNING detail_id`,
    [roadmapId, dayNumber]
  );
  if (updateRes.rows.length === 0) return { completed: true, newCertificates: [] };

  const progressRes = await pool.query(
    `SELECT
       COUNT(*) FILTER (WHERE completion_status = 'COMPLETED') as completed_count,
       COUNT(*) as total_count,
       COALESCE(SUM(study_duration) FILTER (WHERE completion_status = 'COMPLETED'), 0) as total_studied_hours
     FROM learning_roadmap_details WHERE roadmap_id = $1`,
    [roadmapId]
  );
  const completed_count = Number(progressRes.rows[0].completed_count) || 0;
  const total_count = Number(progressRes.rows[0].total_count) || 0;
  const total_studied_hours = Number(progressRes.rows[0].total_studied_hours) || 0;
  const progressPercentage = total_count === 0 ? 0 : (completed_count / total_count) * 100;

  await pool.query(
    `UPDATE learning_roadmaps
     SET progress_percentage = $1::numeric,
         total_studied_hours = $2::numeric,
         updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
     WHERE roadmap_id = $3`,
    [Number(progressPercentage.toFixed(2)), total_studied_hours, roadmapId]
  );

  await updateStreakTier(pool, roadmapId);
  const newCertificates = await awardCertificatesIfEligible(pool, roadmapId, progressPercentage);
  return { completed: true, newCertificates };
}

// GET /api/roadmaps/:id/quiz-summary - Danh sách ngày có quiz + trạng thái đã làm
app.get("/api/roadmaps/:id/quiz-summary", requireAuth, async (req, res) => {
  try {
    const roadmapId = parseInt(req.params.id);

    const ownershipCheck = await pool.query(
      "SELECT user_id FROM learning_roadmaps WHERE roadmap_id = $1", [roadmapId]
    );
    if (ownershipCheck.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Lộ trình không tồn tại" });
    }
    if (ownershipCheck.rows[0].user_id !== req.user.id) {
      return res.status(403).json({ success: false, error: "Không có quyền truy cập" });
    }

    const daysResult = await pool.query(
      `SELECT DISTINCT day_number, is_chapter_review FROM quiz_questions WHERE roadmap_id = $1 ORDER BY day_number ASC`,
      [roadmapId]
    );

    const attemptsResult = await pool.query(
      `SELECT day_number, is_chapter_review, MAX(score) as best_score, bool_or(passed) as ever_passed
       FROM quiz_attempts WHERE roadmap_id = $1 AND user_id = $2
       GROUP BY day_number, is_chapter_review`,
      [roadmapId, req.user.id]
    );

    const attemptsMap = {};
    attemptsResult.rows.forEach(a => {
      attemptsMap[`${a.day_number}_${a.is_chapter_review}`] = {
        best_score: Number(a.best_score),
        ever_passed: a.ever_passed
      };
    });

    const data = daysResult.rows.map(d => ({
      day_number: d.day_number,
      is_chapter_review: d.is_chapter_review,
      attempt: attemptsMap[`${d.day_number}_${d.is_chapter_review}`] || null
    }));

    res.json({ success: true, data });
  } catch (err) {
    console.error("Error fetching quiz summary:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể tải thông tin quiz" });
  }
});

// GET /api/roadmaps/:id/quiz/:dayNumber - Lấy 5 câu quiz của ngày (ẩn đáp án đúng)
app.get("/api/roadmaps/:id/quiz/:dayNumber", requireAuth, async (req, res) => {
  try {
    const roadmapId = parseInt(req.params.id);
    const dayNumber = parseInt(req.params.dayNumber);
    const isChapterReview = req.query.chapter === 'true';

    const ownershipCheck = await pool.query(
      "SELECT user_id, pass_threshold FROM learning_roadmaps WHERE roadmap_id = $1", [roadmapId]
    );
    if (ownershipCheck.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Lộ trình không tồn tại" });
    }
    const isOwner = ownershipCheck.rows[0].user_id === req.user.id;
    if (!isOwner && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: "Không có quyền truy cập" });
    }

    // Chỉ khoá ngày theo tiến độ thật của chủ lộ trình; admin xem/thử quiz hộ thì không bị khoá.
    if (isOwner && !(await isDayUnlocked(roadmapId, dayNumber))) {
      return res.status(403).json({
        success: false,
        error: `Vui lòng hoàn thành bài kiểm tra của ngày ${dayNumber - 1} để mở khoá ngày này.`
      });
    }

    const questionsResult = await pool.query(
      `SELECT quiz_id, question_order, question_text, option_a, option_b, option_c, option_d
       FROM quiz_questions
       WHERE roadmap_id = $1 AND day_number = $2 AND is_chapter_review = $3
       ORDER BY question_order ASC`,
      [roadmapId, dayNumber, isChapterReview]
    );

    if (questionsResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Chưa có quiz cho ngày này" });
    }

    const attemptResult = await pool.query(
      `SELECT score, passed, answers, attempted_at
       FROM quiz_attempts
       WHERE roadmap_id = $1 AND day_number = $2 AND is_chapter_review = $3 AND user_id = $4
       ORDER BY attempted_at DESC LIMIT 1`,
      [roadmapId, dayNumber, isChapterReview, req.user.id]
    );

    res.json({
      success: true,
      data: {
        questions: questionsResult.rows,
        pass_threshold: ownershipCheck.rows[0].pass_threshold || 80,
        last_attempt: attemptResult.rows[0] || null
      }
    });
  } catch (err) {
    console.error("Error fetching quiz:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể tải quiz" });
  }
});

// POST /api/roadmaps/:id/quiz/:dayNumber/submit - Nộp bài, chấm điểm server-side
app.post("/api/roadmaps/:id/quiz/:dayNumber/submit", requireAuth, async (req, res) => {
  try {
    const roadmapId = parseInt(req.params.id);
    const dayNumber = parseInt(req.params.dayNumber);
    const isChapterReview = req.query.chapter === 'true';
    const { answers } = req.body;

    const ownershipCheck = await pool.query(
      "SELECT user_id, pass_threshold FROM learning_roadmaps WHERE roadmap_id = $1", [roadmapId]
    );
    if (ownershipCheck.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Lộ trình không tồn tại" });
    }
    const isOwner = ownershipCheck.rows[0].user_id === req.user.id;
    if (!isOwner && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: "Không có quyền truy cập" });
    }
    const passThreshold = ownershipCheck.rows[0].pass_threshold || 80;

    // Chỉ khoá ngày theo tiến độ thật của chủ lộ trình; admin xem/thử quiz hộ thì không bị khoá.
    if (isOwner && !(await isDayUnlocked(roadmapId, dayNumber))) {
      return res.status(403).json({
        success: false,
        error: `Vui lòng hoàn thành bài kiểm tra của ngày ${dayNumber - 1} để mở khoá ngày này.`
      });
    }

    const questionsResult = await pool.query(
      `SELECT question_order, correct_option, explanation FROM quiz_questions
       WHERE roadmap_id = $1 AND day_number = $2 AND is_chapter_review = $3
       ORDER BY question_order ASC`,
      [roadmapId, dayNumber, isChapterReview]
    );

    if (questionsResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Không tìm thấy quiz" });
    }

    let score = 0;
    const correctAnswers = {};
    const explanations = {};
    questionsResult.rows.forEach(q => {
      correctAnswers[q.question_order] = q.correct_option;
      explanations[q.question_order] = q.explanation || '';
      const userAnswer = answers ? answers[q.question_order] : null;
      if (userAnswer && String(userAnswer).toUpperCase() === q.correct_option) score++;
    });

    const totalQuestions = questionsResult.rows.length;
    const percent = (score / totalQuestions) * 100;
    const passed = percent >= passThreshold;

    await pool.query(
      `INSERT INTO quiz_attempts (roadmap_id, day_number, is_chapter_review, user_id, score, passed, answers)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [roadmapId, dayNumber, isChapterReview, req.user.id, score, passed, JSON.stringify(answers || {})]
    );

    // Chỉ cập nhật trạng thái "Hoàn thành" thật sự của lộ trình khi chính chủ lộ trình làm bài;
    // admin xem/thử quiz hộ không được phép làm thay đổi tiến độ của người dùng, nên day_completed
    // luôn là false trong trường hợp đó (không có gì thật sự được cập nhật).
    const completionResult = isOwner
      ? await recomputeDayCompletion(roadmapId, dayNumber, req.user.id)
      : { completed: false, newCertificates: [] };

    res.json({
      success: true,
      data: {
        score, total: totalQuestions, passed, pass_threshold: passThreshold, correct_answers: correctAnswers, explanations,
        day_completed: completionResult.completed,
        new_certificates: completionResult.newCertificates
      }
    });
  } catch (err) {
    console.error("Error submitting quiz:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể nộp bài" });
  }
});

// GET /api/certificates - Toàn bộ chứng chỉ của user hiện tại (dùng cho profile.html)
app.get("/api/certificates", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT rc.certificate_id, rc.roadmap_id, rc.milestone_percent, rc.certificate_code, rc.awarded_at,
              lr.roadmap_name, lr.category
       FROM roadmap_certificates rc
       JOIN learning_roadmaps lr ON lr.roadmap_id = rc.roadmap_id
       WHERE lr.user_id = $1
       ORDER BY rc.awarded_at DESC`,
      [req.user.id]
    );
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error("Error fetching certificates:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể tải chứng chỉ" });
  }
});

// GET /api/roadmaps/:id/certificates - Chứng chỉ của riêng 1 lộ trình (dùng cho roadmap_details.html?mine=true)
app.get("/api/roadmaps/:id/certificates", requireAuth, async (req, res) => {
  try {
    const roadmapId = parseInt(req.params.id);
    const ownershipCheck = await pool.query(
      "SELECT user_id FROM learning_roadmaps WHERE roadmap_id = $1", [roadmapId]
    );
    if (ownershipCheck.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Lộ trình không tồn tại" });
    }
    if (ownershipCheck.rows[0].user_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: "Không có quyền truy cập" });
    }
    const result = await pool.query(
      `SELECT certificate_id, milestone_percent, certificate_code, awarded_at
       FROM roadmap_certificates WHERE roadmap_id = $1 ORDER BY milestone_percent ASC`,
      [roadmapId]
    );
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error("Error fetching roadmap certificates:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể tải chứng chỉ" });
  }
});

// 6. GET /api/users/me - Lấy thông tin chi tiết user (requireAuth)
app.get("/api/users/me", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, username, email, role, created_at, avatar_url 
       FROM users 
       WHERE id = $1`,
      [req.user.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Người dùng không tồn tại" });
    }
    
    const user = result.rows[0];
    res.json({ 
      success: true, 
      data: {
        ...user,
        created_at: formatTimestampForAPI(user.created_at)
      }
    });
  } catch (err) {
    console.error("Error fetching user:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể lấy thông tin người dùng" });
  }
});

// 7. GET /api/users - Lấy danh sách tất cả users (requireAdmin)
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
    
    const formattedUsers = result.rows.map(user => ({
      ...user,
      created_at: formatTimestampForAPI(user.created_at)
    }));
    
    res.json({ success: true, data: formattedUsers });
  } catch (err) {
    console.error("Error fetching users:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể lấy danh sách người dùng" });
  }
});

// ============================================================================
// 23. API ENDPOINTS - LUỒNG GOOGLE OAUTH (2 endpoints)
// ============================================================================

// 1. GET /api/auth/google - Khởi tạo OAuth flow
app.get('/api/auth/google', passport.authenticate('google', {
  scope: ['profile', 'email'],
  session: false
}));

// 2. GET /api/auth/google/callback - Xử lý callback từ Google
app.get('/api/auth/google/callback', 
  passport.authenticate('google', { 
    session: false, 
    failureRedirect: `${FRONTEND_URL}/login.html?error=google_auth_failed` 
  }),
  async (req, res) => {
    try {
      const user = req.user;
      const token = makeToken(user.id);
      res.redirect(`${FRONTEND_URL}/login.html?token=${token}&success=google_login`);
    } catch (error) {
      console.error('Google OAuth callback error:', error);
      res.redirect(`${FRONTEND_URL}/login.html?error=auth_callback_failed`);
    }
  }
);

// ============================================================================
// 24. API ENDPOINTS - LUỒNG QUÊN MẬT KHẨU (3 endpoints)
// ============================================================================

// 1. POST /api/password-reset/request - Yêu cầu reset password
app.post("/api/password-reset/request", async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email || !email.trim()) {
      return res.status(400).json({
        success: false,
        error: 'Email không được để trống'
      });
    }
    
    const normalizedEmail = email.trim().toLowerCase();
    
    const userCheck = await pool.query(
      'SELECT id, email FROM users WHERE LOWER(email) = $1',
      [normalizedEmail]
    );
    
    if (userCheck.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Email không tồn tại trong hệ thống'
      });
    }
    
    const code = generateResetCode();
    const vnNow = getVietnamDate();
    const expiresAt = new Date(vnNow.getTime() + 10 * 60 * 1000);
    
    await pool.query(
      `INSERT INTO password_reset_codes (email, code, expires_at) 
       VALUES ($1, $2, $3)`,
      [normalizedEmail, code, expiresAt]
    );
    
    const emailSent = await sendResetEmail(normalizedEmail, code);
    
    if (!emailSent) {
      return res.status(500).json({
        success: false,
        error: 'Không thể gửi email. Vui lòng thử lại sau.'
      });
    }
    
    res.json({
      success: true,
      message: 'Mã xác thực đã được gửi đến email của bạn',
      expiresIn: 600
    });
    
  } catch (error) {
    console.error('Error requesting reset code:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể xử lý yêu cầu'
    });
  }
});

// 2. POST /api/password-reset/verify - Xác thực mã reset
app.post("/api/password-reset/verify", async (req, res) => {
  try {
    const { email, code } = req.body;
    
    if (!email || !code) {
      return res.status(400).json({
        success: false,
        error: 'Email và mã xác thực không được để trống'
      });
    }
    
    const normalizedEmail = email.trim().toLowerCase();
    
    const result = await pool.query(
      `SELECT id, expires_at, used 
       FROM password_reset_codes 
       WHERE email = $1 AND code = $2 
       ORDER BY created_at DESC 
       LIMIT 1`,
      [normalizedEmail, code.trim()]
    );
    
    if (result.rows.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Mã xác thực không đúng'
      });
    }
    
    const resetCode = result.rows[0];
    
    if (resetCode.used) {
      return res.status(400).json({
        success: false,
        error: 'Mã xác thực đã được sử dụng'
      });
    }
    
    const vnNow = getVietnamDate();
    const expiresAtRaw = new Date(resetCode.expires_at);
    const expiresAtVN = new Date(expiresAtRaw.getTime() - VIETNAM_TIMEZONE_OFFSET);
    
    if (vnNow > expiresAtVN) {
      return res.status(400).json({
        success: false,
        error: 'Mã xác thực đã hết hạn'
      });
    }
    
    res.json({
      success: true,
      message: 'Mã xác thực hợp lệ'
    });
    
  } catch (error) {
    console.error('Error verifying code:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể xác thực mã'
    });
  }
});

// 3. POST /api/password-reset/reset - Đặt lại mật khẩu mới
app.post("/api/password-reset/reset", async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    
    if (!email || !code || !newPassword) {
      return res.status(400).json({
        success: false,
        error: 'Thiếu thông tin bắt buộc'
      });
    }
    
    if (newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        error: 'Mật khẩu phải có ít nhất 8 ký tự'
      });
    }
    
    const normalizedEmail = email.trim().toLowerCase();
    
    const codeResult = await pool.query(
      `SELECT id, expires_at, used 
       FROM password_reset_codes 
       WHERE email = $1 AND code = $2 
       ORDER BY created_at DESC 
       LIMIT 1`,
      [normalizedEmail, code.trim()]
    );
    
    if (codeResult.rows.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Mã xác thực không đúng'
      });
    }
    
    const resetCode = codeResult.rows[0];
    
    if (resetCode.used) {
      return res.status(400).json({
        success: false,
        error: 'Mã xác thực đã được sử dụng'
      });
    }
    
    const vnNow = getVietnamDate();
    const expiresAtRaw = new Date(resetCode.expires_at);
    const expiresAtVN = new Date(expiresAtRaw.getTime() - VIETNAM_TIMEZONE_OFFSET);
    
    if (vnNow > expiresAtVN) {
      return res.status(400).json({
        success: false,
        error: 'Mã xác thực đã hết hạn'
      });
    }
    
    const hashedPassword = await hashPassword(newPassword, 10);
    
    await pool.query(
      'UPDATE users SET password = $1 WHERE LOWER(email) = $2',
      [hashedPassword, normalizedEmail]
    );
    
    await pool.query(
      'UPDATE password_reset_codes SET used = TRUE WHERE id = $1',
      [resetCode.id]
    );
    
    res.json({
      success: true,
      message: 'Đặt lại mật khẩu thành công'
    });
    
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể đặt lại mật khẩu'
    });
  }
});

// ============================================================================
// 25. API ENDPOINTS - LUỒNG TẠO LỘ TRÌNH - AI GENERATION (6 endpoints)
// ============================================================================

// 1. POST /api/generate-roadmap-ai - Tạo lộ trình bằng AI
app.post("/api/generate-roadmap-ai", requireAuth, async (req, res) => {
  let historyId = null;
  const startTime = Date.now();
  
  try {
    console.log('🚀 AI REQUEST RECEIVED');
    
    if (GEMINI_API_KEYS.length === 0) {
      return res.status(503).json({ 
        success: false, 
        error: "Tính năng AI chưa được cấu hình." 
      });
    }
    if (String(req.user.role || '').toLowerCase() !== 'admin') {
      const aiLimit = await getAIGenerationLimit();
      const usageRes = await pool.query(
        'SELECT ai_roadmap_generations_used FROM users WHERE id = $1', [req.user.id]
      );
      const used = usageRes.rows[0]?.ai_roadmap_generations_used || 0;
      if (used >= aiLimit) {
        return res.status(403).json({
          success: false,
          code: 'AI_LIMIT_REACHED',
          error: `Bạn đã sử dụng hết lượt tạo lộ trình bằng AI (giới hạn ${aiLimit} lần/tài khoản). Vui lòng dùng nút "Tạo lộ trình thủ công" để tiếp tục tạo lộ trình.`
        });
      }
    }
    const {
      roadmap_name, category, sub_category, start_level, duration_days, duration_hours, expected_outcome,
      pass_threshold,
      q1_roadmap_name, q2_category, q3_category_detail,
      q4_main_purpose,
      q5_specific_goal, q5b_target_milestone,
      q7_current_level, q7_skill_breakdown, q8_known_skills, q9_skills_to_improve,
      q9_daily_time, q10_weekly_days, q11_program_days,
      q13_learning_style, q13_learning_style_other,
      q14_learning_method, q14_learning_method_other,
      q15_engagement_trigger, q16_theme_preference,
      q17_material_type, q17_material_type_other,
      q18_material_language,
      q19_pass_threshold,
      q22_demotivation_trigger,
      q23_quiz_day_length,
      q24_quiz_chapter_length
    } = req.body;

    const processArrayWithOther = (arr, otherValue) => {
      if (!Array.isArray(arr)) return '';
      const filtered = arr.filter(v => v && v !== 'Khác' && v !== 'AI gợi ý');
      if (otherValue && otherValue.trim()) filtered.push(otherValue.trim());
      return filtered.length > 0 ? filtered.join(', ') : 'Chưa xác định';
    };

    const processRadioWithOther = (value, otherValue) => {
      if (!value) return 'Chưa xác định';
      if (value === 'Khác' && otherValue && otherValue.trim()) return otherValue.trim();
      return value;
    };

    const finalData = {
      roadmap_name: q1_roadmap_name || roadmap_name,
      category: q2_category || category,
      category_detail: q3_category_detail || sub_category,
      main_purpose: q4_main_purpose || 'Chưa xác định',
      specific_goal: q5_specific_goal || expected_outcome,
      target_milestone: q5b_target_milestone || 'Không có, học tự do',
      current_level: q7_current_level || start_level,
      skill_breakdown: q7_skill_breakdown || 'Chưa xác định',
      known_skills: q8_known_skills || 'Chưa xác định',
      skills_to_improve: q9_skills_to_improve || 'Chưa xác định',
      daily_time: (() => {
        const minutes = parseInt(q9_daily_time) || 0;
        if (minutes === 0) return '0m';
        const hours = Math.floor(minutes / 60);
        const remainingMinutes = minutes % 60;
        if (hours === 0) return `${minutes}m`;
        if (remainingMinutes === 0) return `${hours}h`;
        return `${hours}h ${remainingMinutes}m`;
      })(),
      weekly_sessions: (() => {
        const w = parseWeekdaysParam(q10_weekly_days);
        return w.length > 0 ? w.map(d => WEEKDAY_LABELS_VN[d]).join(', ') : 'Chưa xác định';
      })(),
      program_days: q11_program_days || duration_days,
      learning_style: processArrayWithOther(q13_learning_style, q13_learning_style_other),
      learning_method: processRadioWithOther(q14_learning_method, q14_learning_method_other),
      engagement_trigger: q15_engagement_trigger || 'Chưa xác định',
      theme_preference: q16_theme_preference || 'Chưa xác định',
      material_type: processArrayWithOther(q17_material_type, q17_material_type_other),
      material_language: q18_material_language || 'Tiếng Việt',
      pass_threshold: q19_pass_threshold || pass_threshold || '80',
      demotivation_trigger: q22_demotivation_trigger || 'Chưa xác định',
      quiz_day_length: parseInt(q23_quiz_day_length) || 5,
      quiz_chapter_length: parseInt(q24_quiz_chapter_length) || 10,
      start_level: q7_current_level || start_level,
      duration_days: q11_program_days || duration_days,
      duration_hours: duration_hours,
      expected_outcome: q5_specific_goal || expected_outcome
    };

    finalData.pass_threshold = parseInt(finalData.pass_threshold) || 80;
    if (!finalData.roadmap_name || !finalData.category || !finalData.current_level || 
        !finalData.program_days || !finalData.specific_goal) {
      return res.status(400).json({ 
        success: false, 
        error: "Thiếu thông tin bắt buộc để tạo lộ trình" 
      });
    }

    const actualDays = parseInt(finalData.program_days);
    const dailyMinutes = parseInt(q9_daily_time) || 0;

    if (dailyMinutes < 15 || dailyMinutes > 720) {
      return res.status(400).json({ 
        success: false, 
        error: "Thời gian học mỗi ngày phải từ 15-720 phút" 
      });
    }

    const hoursPerDay = dailyMinutes / 60;
    const totalHours = hoursPerDay * actualDays;

    const userRole = req.user?.role || 'user';
    const MAX_DAYS_FOR_USER = getMaxDaysForUser(userRole);

    if (isNaN(actualDays) || actualDays < MIN_AI_DAYS || actualDays > MAX_DAYS_FOR_USER) {
      return res.status(400).json({ 
        success: false, 
        error: `Số ngày phải từ ${MIN_AI_DAYS} đến ${MAX_DAYS_FOR_USER} (Role: ${userRole})` 
      });
    }

    const roadmapStartDate = getVietnamDate();
    roadmapStartDate.setHours(0, 0, 0, 0);

    console.log(`Generating AI roadmap: ${finalData.roadmap_name} (${actualDays} days, ${hoursPerDay}h/day)`);

    // STEP 1: Gemini generates main content — CHIA BATCH để tránh JSON bị cắt do quá token
    const promptTemplate = await getPromptTemplate();
    let baseUserPrompt = promptTemplate.prompt_template;

    baseUserPrompt += `\n\n**QUAN TRỌNG:** 
- KHÔNG cần tạo learning_materials và usage_instructions
- Chỉ tạo: day_number, daily_goal, learning_content, practice_exercises, study_duration`;

    const variableMapping = {
      'CATEGORY': finalData.category,
      'SUB_CATEGORY': finalData.category_detail,
      'ROADMAP_NAME': finalData.roadmap_name,
      'MAIN_PURPOSE': finalData.main_purpose,
      'APPLICATION_GOAL': finalData.specific_goal,
      'TARGET_MILESTONE': finalData.target_milestone,
      'CURRENT_LEVEL': finalData.current_level,
      'SKILL_BREAKDOWN': finalData.skill_breakdown,
      'KNOWN_SKILLS': finalData.known_skills,
      'SKILLS_TO_IMPROVE': finalData.skills_to_improve,
      'DAILY_TIME': finalData.daily_time,
      'STUDY_DAYS_OF_WEEK': finalData.weekly_sessions,
      'TOTAL_DURATION': finalData.program_days,
      'LEARNING_STYLE': finalData.learning_style,
      'LEARNING_METHOD': finalData.learning_method,
      'ENGAGEMENT_TRIGGER': finalData.engagement_trigger,
      'THEME_PREFERENCE': finalData.theme_preference,
      'MATERIAL_TYPE': finalData.material_type,
      'MATERIAL_LANGUAGE': finalData.material_language,
      'DEMOTIVATION_TRIGGER': finalData.demotivation_trigger,
      'PASS_THRESHOLD': finalData.pass_threshold,
      'QUIZ_DAY_LENGTH': finalData.quiz_day_length || 5,
      'QUIZ_CHAPTER_LENGTH': finalData.quiz_chapter_length || 10
    };

    Object.keys(variableMapping).forEach(key => {
      baseUserPrompt = baseUserPrompt.replace(new RegExp(`<${key}>`, 'g'), variableMapping[key]);
    });

    // Save history
    const historyResult = await pool.query(
      `INSERT INTO ai_query_history (user_id, prompt_content, status) 
       VALUES ($1, $2, 'PENDING') RETURNING id`,
      [req.user.id, JSON.stringify({ 
        roadmap_name: finalData.roadmap_name,
        category: finalData.category,
        duration_days: actualDays,
        timestamp: getVietnamDate().toISOString()
      })]
    );
    historyId = historyResult.rows[0].id;

    const selectedWeekdays = parseWeekdaysParam(q10_weekly_days);
    // Tính trước toàn bộ study_date cho cả lộ trình (không phụ thuộc batch)
    const fullStudyDates = generateStudyDatesByWeekdays(roadmapStartDate, selectedWeekdays, actualDays);

    const quizDayLength = parseInt(finalData.quiz_day_length) || 5;
    const quizChapterLength = parseInt(finalData.quiz_chapter_length) || 10;
    const batchPlan = computeBatchPlan(actualDays);

    let days = [];
    let analysis = '';

    // ✅ STREAMING: từ đây trả kết quả dần theo NDJSON (mỗi dòng 1 JSON event) thay vì
    // bắt client chờ toàn bộ pipeline (AI + tìm tài liệu + validate link) xong mới thấy gì.
    res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache');
    if (typeof res.flushHeaders === 'function') res.flushHeaders();
    const sendEvent = (type, payload) => {
      res.write(JSON.stringify({ type, ...payload }) + '\n');
    };

    for (let batchIndex = 0; batchIndex < batchPlan.length; batchIndex++) {
      const batch = batchPlan[batchIndex];
      const isFirstBatch = batchIndex === 0;

      console.log(`📞 Phase 1 - Batch ${batchIndex + 1}/${batchPlan.length}: ngày ${batch.startDay}-${batch.endDay} (${batch.count} ngày)`);

      const continuitySummary = isFirstBatch ? '' : buildContinuitySummary(days, 3);

      let batchUserPrompt = baseUserPrompt;
      batchUserPrompt += `\n\n**YÊU CẦU RIÊNG CHO LẦN GỌI NÀY (batch ${batchIndex + 1}/${batchPlan.length}):**
- Lộ trình tổng thể dài ${actualDays} ngày. Lần gọi này CHỈ tạo đúng ${batch.count} ngày, có day_number từ ${batch.startDay} đến ${batch.endDay} (không được lệch số).
- day_number PHẢI là số tuyệt đối trong toàn bộ lộ trình (ví dụ ngày đầu tiên của batch này là ${batch.startDay}, không phải 1), để nối liền mạch với các batch khác.
- Nội dung phải tiếp nối logic, độ khó tăng dần đúng theo vị trí các ngày này trong toàn bộ lộ trình ${actualDays} ngày (không lặp lại nội dung đã dạy ở các ngày trước).
${continuitySummary ? `- Tóm tắt vài ngày gần nhất đã tạo ở batch trước (để tiếp nối mạch nội dung, không lặp lại):\n${continuitySummary}` : ''}`;

      let batchSystemPrompt = `Bạn là chuyên gia thiết kế lộ trình học.
Đây là lần gọi ${batchIndex + 1}/${batchPlan.length} để tạo TỪNG PHẦN của một lộ trình tổng thể dài ${actualDays} ngày. Lần này CHỈ tạo đúng ${batch.count} ngày, day_number từ ${batch.startDay} đến ${batch.endDay}, KHÔNG bao gồm learning_materials và usage_instructions.
Mỗi ngày phải kèm 1 mảng "quiz" gồm đúng ${quizDayLength} câu hỏi trắc nghiệm (4 phương án A/B/C/D, 1 đáp án đúng, kèm "explanation" giải thích ngắn gọn vì sao đáp án đó đúng) bám sát learning_content/practice_exercises của chính ngày đó.
Cứ mỗi 6 ngày liên tiếp (tính theo day_number tuyệt đối trong TOÀN BỘ lộ trình ${actualDays} ngày) và ở ngày cuối cùng của lộ trình (day_number = ${actualDays}), thêm mảng "chapter_review_quiz" gồm ${quizChapterLength} câu hỏi tổng hợp cả chương; các ngày khác để chapter_review_quiz là mảng rỗng.
${isFirstBatch ? 'Vì đây là batch đầu tiên, hãy điền đầy đủ trường "analysis" (phân tích hiện trạng, tối đa 200 từ).' : 'Vì đây KHÔNG phải batch đầu tiên, để trường "analysis" là chuỗi rỗng "".'}

Trả về JSON format:
{
  "analysis": ${isFirstBatch ? '"Phân tích chi tiết..."' : '""'},
  "roadmap": [
    {
      "day_number": ${batch.startDay},
      "daily_goal": "...",
      "learning_content": "...",
      "practice_exercises": "...",
      "study_duration": ${hoursPerDay},
      "quiz": [
        {"question_text": "...", "option_a": "...", "option_b": "...", "option_c": "...", "option_d": "...", "correct_option": "A", "explanation": "..."}
      ],
      "chapter_review_quiz": []
    }
  ]
}`;

      // Ngày "chapter-end" (mỗi 6 ngày + ngày cuối lộ trình) tốn thêm token vì phải sinh thêm
      // chapter_review_quiz -> cộng thêm buffer để tránh Gemini bị cắt JSON giữa chừng (đặc biệt
      // hay rơi vào đúng ngày cuối cùng của lộ trình, vì đó luôn là 1 ngày chapter-end).
      const chapterDaysInBatch = countChapterEndDaysInRange(batch.startDay, batch.endDay, actualDays);
      const batchDesiredTokens = Math.min(
        batch.count * TOKENS_PER_DAY_ESTIMATE + chapterDaysInBatch * CHAPTER_REVIEW_EXTRA_TOKENS,
        MODEL_MAX_OUTPUT_TOKENS
      );

      const batchAiResponse = (await callGeminiForMainContent({
        systemPrompt: batchSystemPrompt,
        userPrompt: batchUserPrompt,
        desiredCompletionTokens: batchDesiredTokens
      })).trim();

      if (!batchAiResponse) {
        throw new Error(`Gemini không trả về kết quả cho batch ${batchIndex + 1}/${batchPlan.length} (ngày ${batch.startDay}-${batch.endDay})`);
      }

      const batchParsed = parseAIResponse(batchAiResponse);
      const batchDaysRaw = batchParsed.roadmap || [];

      if (isFirstBatch && batchParsed.analysis) {
        analysis = batchParsed.analysis;
      }

      const studyDatesForBatch = fullStudyDates.slice(batch.startDay - 1, batch.endDay);
      const normalizedBatchDays = normalizeDaysBatch(
        batchDaysRaw,
        batch.startDay,
        batch.count,
        hoursPerDay,
        studyDatesForBatch,
        actualDays,
        quizDayLength,
        quizChapterLength
      );

      // Phát hiện ngày bị thiếu nội dung (thường do JSON bị cắt cụt ở gần cuối response,
      // hay gặp nhất ở ngày cuối cùng của lộ trình vì ngày đó luôn nặng token hơn do có
      // thêm chapter_review_quiz) -> gọi lại Gemini để lấp đầy đúng những ngày đó.
      const missingContentDays = normalizedBatchDays.filter(d => {
        if (!d.learning_content || !d.practice_exercises) return true;
        if (!Array.isArray(d.quiz) || d.quiz.length === 0) return true;
        const isChapterEnd = (d.day_number % CHAPTER_SIZE_DAYS === 0) || (d.day_number === actualDays);
        if (isChapterEnd && (!Array.isArray(d.chapter_review_quiz) || d.chapter_review_quiz.length === 0)) return true;
        return false;
      });
      if (missingContentDays.length > 0) {
        console.warn(`⚠️ Batch ${batchIndex + 1}: ${missingContentDays.length} ngày thiếu nội dung (ngày ${missingContentDays.map(d => d.day_number).join(', ')}), đang gọi lại Gemini để lấp đầy...`);
        try {
          const filledByDayNumber = await fillMissingDaysContent(missingContentDays, {
            category: finalData.category,
            roadmapName: finalData.roadmap_name,
            hoursPerDay,
            actualDays
          });
          let filledCount = 0;
          normalizedBatchDays.forEach(day => {
            const src = filledByDayNumber[day.day_number];
            if (!src) return;
            filledCount++;
            day.daily_goal = String(src.daily_goal || src.goal || day.daily_goal).trim().substring(0, 500);
            day.learning_content = String(src.learning_content || src.content || day.learning_content).trim().substring(0, 1000);
            day.practice_exercises = String(src.practice_exercises || src.exercises || day.practice_exercises).trim().substring(0, 1000);
            if (Array.isArray(src.quiz) && src.quiz.length > 0) {
              day.quiz = normalizeQuizArray(src.quiz, quizDayLength);
            }
            const isChapterEnd = (day.day_number % CHAPTER_SIZE_DAYS === 0) || (day.day_number === actualDays);
            if (isChapterEnd && Array.isArray(src.chapter_review_quiz) && src.chapter_review_quiz.length > 0) {
              day.chapter_review_quiz = normalizeQuizArray(src.chapter_review_quiz, quizChapterLength);
            }
          });
          console.log(`✅ Đã lấp đầy ${filledCount}/${missingContentDays.length} ngày thiếu nội dung`);
        } catch (err) {
          console.warn(`⚠️ Lấp đầy ngày thiếu nội dung thất bại: ${err.message}`);
        }
      }

      days = days.concat(normalizedBatchDays);
      // Đẩy ngay các ngày vừa tạo cho client hiển thị, không cần chờ Phase 2/3/4 (tìm tài liệu + validate link)
      sendEvent('batch', { days: normalizedBatchDays, batchIndex: batchIndex + 1, totalBatches: batchPlan.length });

      console.log(`✅ Batch ${batchIndex + 1}/${batchPlan.length} hoàn tất: ${normalizedBatchDays.length}/${batch.count} ngày`);
    }

    if (!analysis) analysis = 'Không có phân tích';

    console.log(`✅ Phase 1 complete (tất cả batch): ${days.length}/${actualDays} ngày được tạo`);

    if (String(req.user.role || '').toLowerCase() !== 'admin') {
      await pool.query(
        'UPDATE users SET ai_roadmap_generations_used = ai_roadmap_generations_used + 1 WHERE id = $1',
        [req.user.id]
      );
      console.log(`📊 Đã trừ 1 lượt tạo AI cho user #${req.user.id}`);
    }

    // STEP 2: Tavily only for materials and instructions
    console.log(`📞 Phase 2: Tavily only for materials and instructions...`);
    
    let claudeMaterials = [];
    try {
      claudeMaterials = await callFreeSearchForMaterials({
        days: days,
        category: finalData.category,
        subCategory: finalData.category_detail,
        temperature: 0.5
      });
      console.log(`✅ Nhận được ${claudeMaterials.length} materials từ Tavily only`);
    } catch (error) {
      console.warn(`⚠️ Tavily enrich thất bại:`, error.message);
    }

    // Merge materials into days
    for (const material of claudeMaterials) {
      const day = days.find(d => d.day_number === material.day_number);
      if (day) {
        day.learning_materials = material.learning_materials;
        day.study_guide = material.usage_instructions || day.study_guide;
      }
    }

    // STEP 3: Validate all links
    console.log('🔍 Phase 3: Validating links...');

    const validationResults = await validateBatchLinksEnhanced(days, { category: finalData.category, subCategory: finalData.category_detail });
    const failedDays = validationResults
      .filter(r => !r.valid)
      .map(r => days[r.index]);

    console.log(`📊 Validation: ${failedDays.length}/${days.length} failed`);

    let finalDays = [...days];

    // STEP 4: Google Search fallback
    if (failedDays.length > 0) {
      console.log(`🔍 Phase 4: Applying Google Search fallback for ${failedDays.length} days...`);
      
      for (const failed of failedDays) {
        const idx = finalDays.findIndex(d => d.day_number === failed.day_number);
        if (idx !== -1) {
          const fallback = createGoogleSearchFallback(finalDays[idx], finalData.category, finalData.category_detail);
          finalDays[idx].learning_materials = fallback.learning_materials;
          finalDays[idx].study_guide = fallback.study_guide;
          console.log(`🔗 Day ${failed.day_number}: Google Search fallback applied`);
        }
      }
    }

    const processingTime = Date.now() - startTime;

    console.log(`\n📊 FINAL REPORT:`);
    console.log(`✅ Total days: ${finalDays.length}`);
    console.log(`✅ Valid links: ${finalDays.length - failedDays.length}`);
    console.log(`🔍 Google Search fallback: ${failedDays.length}`);
    console.log(`⏱️ Processing time: ${(processingTime/1000).toFixed(2)}s`);

    // Gửi tài liệu/hướng dẫn học cuối cùng của tất cả các ngày (sau validate + fallback) 1 lần,
    // để client cập nhật vào các ngày đã hiển thị từ trước thay vì phải chờ tới đây mới thấy gì.
    sendEvent('materials_final', {
      materials: finalDays.map(d => ({
        day_number: d.day_number,
        learning_materials: d.learning_materials || '',
        study_guide: d.study_guide || ''
      }))
    });

    await pool.query(
      `UPDATE ai_query_history
      SET status = 'SUCCESS',
          response_tokens = $1,
          updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
      WHERE id = $2`,
      [finalDays.length, historyId]
    );

    sendEvent('done', {
      success: true,
      message: "Tạo lộ trình AI thành công",
      analysis: analysis,
      metadata: {
        total_days: finalDays.length,
        start_date: roadmapStartDate.toISOString().split('T')[0],
        study_weekdays: selectedWeekdays,
        hours_per_day: hoursPerDay,
        total_hours: totalHours,
        history_id: historyId,
        validation_stats: {
          claude_generated: days.length,
          claude_failed: failedDays.length,
          google_fallback_used: failedDays.length,
          processing_time_seconds: (processingTime / 1000).toFixed(2)
        }
      }
    });
    return res.end();

  } catch (error) {
    console.error("❌ AI GENERATION ERROR:", error.message);

    if (historyId) {
      await pool.query(
        `UPDATE ai_query_history
         SET status = 'FAIL',
             error_message = $1,
             updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
         WHERE id = $2`,
        [error.message, historyId]
      );
    }

    const errorMessage = "Hiện tại hệ thống AI đang bận hoặc gặp sự cố, vui lòng thử lại sau ít phút. Lượt tạo lộ trình của bạn KHÔNG bị trừ.";

    // Nếu đã bắt đầu stream (đã gửi header/dữ liệu) thì không thể res.json() nữa,
    // phải báo lỗi qua 1 dòng NDJSON rồi kết thúc response.
    if (res.headersSent) {
      try {
        res.write(JSON.stringify({ type: 'error', error: errorMessage }) + '\n');
      } catch (writeErr) {
        console.error('❌ Failed to write error event:', writeErr.message);
      }
      return res.end();
    }

    return res.status(500).json({
      success: false,
      error: errorMessage
    });
  }
});

// 2. POST /api/get-manual-prompt - Lấy manual prompt template
app.post("/api/get-manual-prompt", requireAuth, async (req, res) => {
  try {
    const query = `
      SELECT manual_prompt_template
      FROM admin_settings
      WHERE setting_key = 'prompt_template'
      LIMIT 1
    `;
    
    const result = await pool.query(query);
    
    let manualPromptTemplate = '';
    if (result.rows.length > 0 && result.rows[0].manual_prompt_template) {
      manualPromptTemplate = result.rows[0].manual_prompt_template;
    } else {
      const defaultPath = path.join(dataDir, 'default_prompt.txt');
      if (fs.existsSync(defaultPath)) {
        manualPromptTemplate = fs.readFileSync(defaultPath, 'utf8');
      } else {
        manualPromptTemplate = getDefaultManualPrompt();
      }
    }
    
    // Thay thế các biến với dữ liệu từ request
    const { formData } = req.body;
    
    const variableMapping = {
      'CATEGORY': formData.category || '',
      'SUB_CATEGORY': formData.category_detail || '',
      'ROADMAP_NAME': formData.roadmap_name || '',
      'MAIN_PURPOSE': formData.main_purpose || '',
      'APPLICATION_GOAL': formData.specific_goal || '',
      'CURRENT_JOB': formData.current_job || '',
      'STUDY_TIME': formData.learning_duration || '',
      'CURRENT_LEVEL': formData.current_level || '',
      'SKILLS_TO_IMPROVE': formData.skills_text || '',
      'DAILY_TIME': formData.daily_time || '',
      'WEEKLY_FREQUENCY': formData.weekly_sessions || '',
      'TOTAL_DURATION': formData.program_days || '',
      'LEARNING_STYLE': Array.isArray(formData.learning_styles) ? formData.learning_styles.join(', ') : formData.learning_styles || '',
      'LEARNING_METHOD': Array.isArray(formData.learning_combinations) ? formData.learning_combinations.join(', ') : formData.learning_combinations || '',
      'DIFFICULTIES': Array.isArray(formData.challenges) ? formData.challenges.join(', ') : formData.challenges || '',
      'MOTIVATION': Array.isArray(formData.motivation) ? formData.motivation.join(', ') : formData.motivation || '',
      'DEMOTIVATION_TRIGGER': formData.demotivation_trigger || '',
      'MATERIAL_TYPE': Array.isArray(formData.material_types) ? formData.material_types.join(', ') : formData.material_types || '',
      'MATERIAL_LANGUAGE': formData.material_language || '',
      'ASSESSMENT_TYPE': Array.isArray(formData.assessment_types) ? formData.assessment_types.join(', ') : formData.assessment_types || '',
      'QUIZ_DAY_LENGTH': formData.quiz_day_length || 5,
      'QUIZ_CHAPTER_LENGTH': formData.quiz_chapter_length || 10,
      'ASSESSMENT_FREQUENCY': formData.assessment_frequency || ''
    };
    
    let finalPrompt = manualPromptTemplate;
    Object.keys(variableMapping).forEach(key => {
      finalPrompt = finalPrompt.replace(new RegExp(`<${key}>`, 'g'), variableMapping[key]);
    });
    
    res.json({
      success: true,
      prompt: finalPrompt
    });
  } catch (error) {
    console.error('Error generating manual prompt:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể tạo prompt'
    });
  }
});

// 3. POST /api/check-roadmap-exists - Kiểm tra lộ trình đã tồn tại
app.post("/api/check-roadmap-exists", requireAuth, async (req, res) => {
  try {
    const { roadmap_name, category } = req.body;
    const userId = req.user.id;
    
    if (!roadmap_name || !category) {
      return res.status(400).json({
        success: false,
        error: 'Thiếu thông tin roadmap_name hoặc category'
      });
    }
    
    // Bước 1: Kiểm tra xem người dùng có phải là người tạo ra lộ trình này trong hệ thống hay không
    const creatorCheckQuery = `
      SELECT lrs.roadmap_id
      FROM learning_roadmaps_system lrs
      WHERE lrs.roadmap_name = $1 
        AND lrs.category = $2
        AND EXISTS (
          SELECT 1 
          FROM learning_roadmaps lr
          WHERE lr.roadmap_name = lrs.roadmap_name
            AND (lr.category = lrs.category OR SPLIT_PART(lr.category, ' - ', 1) = lrs.category)
            AND lr.user_id = $3
            AND (lr.overall_rating >= 4 OR lr.learning_effectiveness >= 4)
          LIMIT 1
        )
      LIMIT 1
    `;
    
    const creatorResult = await pool.query(creatorCheckQuery, [
      roadmap_name, 
      category, 
      userId
    ]);
    
    if (creatorResult.rows.length > 0) {
      return res.json({
        success: false,
        isCreator: true,
        message: 'Bạn là người tạo ra lộ trình này, không thể học lại!'
      });
    }
    
    // Bước 2: Kiểm tra xem người dùng đã có lộ trình này chưa
    const existingQuery = `
      SELECT roadmap_id, roadmap_name
      FROM learning_roadmaps
      WHERE roadmap_name = $1 
        AND (category = $2 OR SPLIT_PART(category, ' - ', 1) = $2)
        AND user_id = $3
      LIMIT 1
    `;
    
    const existingResult = await pool.query(existingQuery, [
      roadmap_name,
      category,
      userId
    ]);
    
    if (existingResult.rows.length > 0) {
      return res.json({
        success: false,
        exists: true,
        roadmapId: existingResult.rows[0].roadmap_id,
        message: 'Bạn đã có lộ trình này rồi!'
      });
    }
    
    // Bước 3: Người dùng có thể tạo lộ trình này
    return res.json({
      success: true,
      canCreate: true,
      message: 'Có thể tạo lộ trình'
    });
    
  } catch (error) {
    console.error('Error checking roadmap exists:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể kiểm tra lộ trình'
    });
  }
});

// 4. POST /api/roadmaps - Tạo lộ trình thủ công
app.post("/api/roadmaps", requireAuth, async (req, res) => {
  try {
    const { roadmapData, roadmap_analyst, history_id } = req.body;
    const { roadmap_name, category, sub_category, start_level, duration_days, duration_hours, expected_outcome, days, study_weekdays } = roadmapData;

    if (!roadmap_name || !category || !start_level || !duration_days || !duration_hours || !expected_outcome) {
      return res.status(400).json({ success: false, error: "Thiếu thông tin bắt buộc" });
    }

    const weekdaysArr = parseWeekdaysParam(study_weekdays);
    const weekdaysStr = weekdaysArr.join(',');

    const roadmapResult = await pool.query(
      `INSERT INTO learning_roadmaps (roadmap_name, category, sub_category, start_level, user_id, duration_days, duration_hours, expected_outcome, roadmap_analyst, study_weekdays, pass_threshold, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11, (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')) RETURNING roadmap_id, created_at`,
      [roadmap_name, category, sub_category || null, start_level, req.user.id, duration_days, duration_hours, expected_outcome, roadmap_analyst || null, weekdaysStr || null, parseInt(roadmapData.pass_threshold) || 80]
    );

    const roadmapId = roadmapResult.rows[0].roadmap_id;

    const roadmapCreatedAtRaw = new Date(roadmapResult.rows[0].created_at);
    const roadmapCreatedAt = new Date(roadmapCreatedAtRaw.getTime() - VIETNAM_TIMEZONE_OFFSET);
    roadmapCreatedAt.setHours(0, 0, 0, 0);

    if (history_id) {
      await pool.query(
        `UPDATE ai_query_history SET roadmap_id = $1, updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh') WHERE id = $2`,
        [roadmapId, history_id]
      ).catch(err => console.error('❌ Failed to link AI history:', err));
    }

if (Array.isArray(days) && days.length > 0) {
      const studyDates = generateStudyDatesByWeekdays(roadmapCreatedAt, weekdaysArr, days.length);

      // Gom toàn bộ dòng cần insert trước, rồi ghi hàng loạt trong 1 transaction
      // thay vì await tuần tự từng ngày/từng câu quiz (nhanh hơn nhiều với lộ trình dài).
      const dayRows = [];
      const quizRows = [];

      days.forEach((day, i) => {
        const dayNumber = parseInt(day.day_number) || (i + 1);
        const studyDateStr = toVietnamDateString(studyDates[i]);

        dayRows.push([
          roadmapId, dayNumber,
          day.daily_goal || day.goal || "",
          day.learning_content || day.content || "",
          day.practice_exercises || day.exercises || "",
          day.learning_materials || day.materials || "",
          parseFloat(day.study_duration || day.hours || 2),
          studyDateStr, 'NOT_STARTED',
          day.study_guide || day.usage_instructions || ""
        ]);

        const pushQuizRows = (quizArr, isChapterReview) => {
          if (!Array.isArray(quizArr)) return;
          quizArr.forEach((q, qi) => {
            if (!q || !q.question_text) return;
            quizRows.push([
              roadmapId, dayNumber, isChapterReview, qi + 1,
              q.question_text,
              q.option_a || '', q.option_b || '', q.option_c || '', q.option_d || '',
              q.correct_option || 'A',
              q.explanation || ''
            ]);
          });
        };
        pushQuizRows(day.quiz, false);
        pushQuizRows(day.chapter_review_quiz, true);
      });

      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        if (dayRows.length > 0) {
          await bulkInsert(client,
            `INSERT INTO learning_roadmap_details
             (roadmap_id, day_number, daily_goal, learning_content, practice_exercises,
              learning_materials, study_duration, study_date, completion_status, usage_instructions)`,
            dayRows
          );
        }
        if (quizRows.length > 0) {
          await bulkInsert(client,
            `INSERT INTO quiz_questions
             (roadmap_id, day_number, is_chapter_review, question_order, question_text, option_a, option_b, option_c, option_d, correct_option, explanation)`,
            quizRows
          );
        }
        await client.query('COMMIT');
      } catch (err) {
        await client.query('ROLLBACK');
        throw err;
      } finally {
        client.release();
      }
    }

    res.json({ success: true, roadmap_id: roadmapId, message: "Tạo lộ trình thành công" });
  } catch (err) {
    console.error("Error creating roadmap:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể tạo lộ trình" });
  }
});

// 5. POST /api/roadmap_from_system - Copy lộ trình từ system
app.post("/api/roadmap_from_system", requireAuth, async (req, res) => {
  let client;
  try {
    client = await pool.connect();
    const { roadmapDataSystem } = req.body;
    const { roadmap_name, category, sub_category, start_level, duration_days, duration_hours, roadmap_analyst } = roadmapDataSystem;
    
    if (!roadmap_name || !category || !start_level || !duration_days || !duration_hours) {
      return res.status(400).json({ success: false, error: "Thiếu thông tin bắt buộc" });
    }
    
    await client.query('BEGIN');
    
    const vietnamToday = getVietnamDate();
    vietnamToday.setHours(0, 0, 0, 0);
    
    const roadmapResult = await client.query(
      `INSERT INTO learning_roadmaps (roadmap_name, category, sub_category, start_level, user_id, duration_days, duration_hours, roadmap_analyst, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8, (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')) RETURNING roadmap_id`,
      [roadmap_name, category, sub_category || null, start_level, req.user.id, duration_days, duration_hours, roadmap_analyst || null]
    );
   
    const roadmapId = roadmapResult.rows[0].roadmap_id;
    
    const days = roadmapDataSystem?.days || [];
    if (Array.isArray(days)) {
      for (let i = 0; i < days.length; i++) {
        const day = days[i];
        const dayNumber = parseInt(day.day_number) || (i + 1);
        
        const studyDate = new Date(vietnamToday);
        studyDate.setDate(studyDate.getDate() + (dayNumber - 1));
        const studyDateStr = toVietnamDateString(studyDate);

        await client.query(
          `INSERT INTO learning_roadmap_details 
           (roadmap_id, day_number, daily_goal, learning_content, practice_exercises, 
            learning_materials, study_duration, study_date, completion_status, usage_instructions)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          [
            roadmapId,
            dayNumber,
            day.daily_goal || day.goal || "",
            day.learning_content || day.content || "",
            day.practice_exercises || day.exercises || "",
            day.learning_materials || day.materials || "",
            parseFloat(day.study_duration || day.hours || 2),
            studyDateStr,
            'NOT_STARTED',
            day.usage_instructions || day.study_guide || ""
          ]
        );
      }
    }
    
    const updateSystemQuery = `
      UPDATE learning_roadmaps_system
      SET total_user_learning = total_user_learning + 1,
          updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
      WHERE roadmap_name = $1 AND category = $2
      RETURNING roadmap_id, total_user_learning
    `;
    
    const systemUpdate = await client.query(updateSystemQuery, [roadmap_name, category]);
    
    await client.query('COMMIT');
    
    res.json({ 
      success: true, 
      roadmap_id: roadmapId, 
      message: "Tạo lộ trình thành công",
      system_learners: systemUpdate.rows[0]?.total_user_learning || null
    });
    
  } catch (err) {
    await client.query('ROLLBACK');
    console.error("Error creating roadmap:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể tạo lộ trình" });
  } finally {
    client.release();
  }
});

// 6. POST /api/roadmaps/upload - Upload lộ trình từ file Excel
app.post("/api/roadmaps/upload", requireAuth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: "Không có file được upload" });
    }

    const workbook = XLSX.read(req.file.buffer, { type: 'buffer' });
    const sheetName = workbook.SheetNames[0];
    const sheet = workbook.Sheets[sheetName];
    
    const data = XLSX.utils.sheet_to_json(sheet, {
      raw: false,
      defval: '',
      header: 1
    });

    if (data.length < 2) {
      return res.status(400).json({ success: false, error: "File Excel phải có ít nhất 2 dòng (header + data)" });
    }

    const roadmapAnalyst = (data[0] && data[0][0]) ? String(data[0][0]).trim() : '';
    const headers = data[1].map(h => String(h).trim().toLowerCase().replace(/\s+/g, '_'));

    const requiredColumns = [
      'day_number', 'day_study', 'daily_goal', 'learning_content', 
      'practice_exercises', 'learning_materials', 'guide_learning', 'study_duration'
    ];
    
    const missingColumns = requiredColumns.filter((col, idx) => headers[idx] !== col);
    
    if (missingColumns.length > 0) {
      return res.status(400).json({ 
        success: false, 
        error: `Dữ liệu trong file excel bị sai cấu trúc. Thiếu các cột: ${missingColumns.join(', ')}`
      });
    }

    const hasQuizColumn = headers[8] === 'quiz_json';

    const normalizedData = [];
    for (let i = 2; i < data.length; i++) {
      const row = data[i];
      if (!row || row.length === 0 || !row[0]) continue;
      
      const normalized = {};
      headers.forEach((header, idx) => {
        normalized[header] = row[idx] || '';
      });
      if (hasQuizColumn) normalized.quiz_json = row[8] || '';
      normalizedData.push(normalized);
    }

    if (normalizedData.length === 0) {
      return res.status(400).json({ success: false, error: "File Excel không có dữ liệu chi tiết" });
    }

    // Validation
    const errors = [];
    let hasInvalidDayStudy = false;
    
    for (let i = 0; i < normalizedData.length; i++) {
      const row = normalizedData[i];
      const rowNumber = i + 3;
      
      const dayNumber = parseInt(row.day_number);
      const expectedDayNumber = i + 1;
      
      if (isNaN(dayNumber) || dayNumber !== expectedDayNumber) {
        errors.push(`Hàng ${rowNumber}: day_number không hợp lệ`);
      }
      
      if (!isValidDuration(row.study_duration)) {
        errors.push(`Hàng ${rowNumber}: study_duration không hợp lệ`);
      }

      // ✅ BẮT BUỘC: learning_content phải có dữ liệu
      if (!row.learning_content || !String(row.learning_content).trim()) {
        errors.push(`Hàng ${rowNumber}: learning_content không được để trống`);
      }

      // ✅ BẮT BUỘC: day_study phải có dữ liệu và đúng định dạng
      if (!row.day_study || !String(row.day_study).trim()) {
        hasInvalidDayStudy = true;
        errors.push(`Hàng ${rowNumber}: day_study không được để trống`);
      } else {
        const studyDateStr = parseDayStudy(row.day_study);
        if (!studyDateStr || !/^\d{4}-\d{2}-\d{2}$/.test(studyDateStr)) {
          hasInvalidDayStudy = true;
          errors.push(`Hàng ${rowNumber}: day_study không đúng định dạng`);
        }
      }

      if (hasQuizColumn && row.quiz_json && String(row.quiz_json).trim()) {
        try {
          const parsedQuiz = JSON.parse(row.quiz_json);
          if (!Array.isArray(parsedQuiz.quiz)) {
            errors.push(`Hàng ${rowNumber}: cột quiz_json thiếu mảng "quiz"`);
          }
        } catch (e) {
          errors.push(`Hàng ${rowNumber}: cột quiz_json không phải JSON hợp lệ`);
        }
      }
    }
    
    if (errors.length > 0) {
      return res.status(400).json({ 
        success: false, 
        error: `File Excel có ${errors.length} lỗi:\n${errors.join('\n')}`
      });
    }

    const { roadmap_name, category, sub_category, start_level } = req.body;

    if (!roadmap_name || !category || !sub_category || !start_level) {
      return res.status(400).json({ 
        success: false, 
        error: "Thiếu thông tin lộ trình" 
      });
    }

    const duration_days = normalizedData.length;
    const duration_hours = normalizedData.reduce((sum, row) => {
      return sum + parseDurationToHours(row.study_duration);
    }, 0);

    const roadmapResult = await pool.query(
      `INSERT INTO learning_roadmaps 
       (roadmap_name, category, sub_category, start_level, user_id, duration_days, duration_hours, roadmap_analyst, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8, (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')) 
       RETURNING roadmap_id, created_at`,
      [roadmap_name, category, sub_category || null, start_level, req.user.id, duration_days, duration_hours, roadmapAnalyst || null]
    );
    
    const roadmapId = roadmapResult.rows[0].roadmap_id;

    for (let i = 0; i < normalizedData.length; i++) {
      const row = normalizedData[i];
      const dayNumber = parseInt(row.day_number);
      
      let studyDateStr = null;
      
      if (!hasInvalidDayStudy && row.day_study && row.day_study.trim() !== '') {
        studyDateStr = parseDayStudy(row.day_study);
      }
      
      await pool.query(
        `INSERT INTO learning_roadmap_details 
        (roadmap_id, day_number, daily_goal, learning_content, practice_exercises, 
          learning_materials, usage_instructions, study_duration, study_date, completion_status)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [
          roadmapId,
          dayNumber,
          String(row.daily_goal || '').trim() || '',
          String(row.learning_content || '').trim() || '',
          String(row.practice_exercises || '').trim() || '',
          String(row.learning_materials || '').trim() || '',
          String(row.guide_learning || '').trim() || '',
          parseDurationToHours(row.study_duration),
          studyDateStr,
          'NOT_STARTED'
        ]
      );

      if (hasQuizColumn && row.quiz_json && String(row.quiz_json).trim()) {
        try {
          const parsedQuiz = JSON.parse(row.quiz_json);
          const insertQuizRow = async (q, order, isChapterReview) => {
            if (!q || !q.question_text) return;
            await pool.query(
              `INSERT INTO quiz_questions
               (roadmap_id, day_number, is_chapter_review, question_order, question_text, option_a, option_b, option_c, option_d, correct_option, explanation)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
              [roadmapId, dayNumber, isChapterReview, order, q.question_text, q.option_a || '', q.option_b || '', q.option_c || '', q.option_d || '', q.correct_option || 'A', q.explanation || '']
            );
          };
          const quizArr = Array.isArray(parsedQuiz.quiz) ? parsedQuiz.quiz : [];
          const chapterArr = Array.isArray(parsedQuiz.chapter_review_quiz) ? parsedQuiz.chapter_review_quiz : [];
          for (let qi = 0; qi < quizArr.length; qi++) await insertQuizRow(quizArr[qi], qi + 1, false);
          for (let qi = 0; qi < chapterArr.length; qi++) await insertQuizRow(chapterArr[qi], qi + 1, true);
        } catch (e) {
          console.error(`Bỏ qua quiz_json không hợp lệ ở ngày ${dayNumber}:`, e.message);
        }
      }
    }

    const message = hasInvalidDayStudy 
      ? `Upload thành công lộ trình với ${normalizedData.length} ngày học. ⚠️ Cảnh báo: Phát hiện ngày học không hợp lệ.`
      : `Upload thành công lộ trình với ${normalizedData.length} ngày học`;

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

// ============================================================================
// 26. API ENDPOINTS - LUỒNG QUẢN LÝ LỘ TRÌNH (7 endpoints)
// ============================================================================

// 1. GET /api/roadmaps - Lấy danh sách lộ trình của user
app.get("/api/roadmaps", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM learning_roadmaps WHERE user_id = $1 ORDER BY created_at DESC`, 
      [req.user.id]
    );
    
    const formattedRows = result.rows.map(row => ({
      ...row,
      created_at: formatTimestampForAPI(row.created_at),
      updated_at: formatTimestampForAPI(row.updated_at)
    }));
    
    res.json({ success: true, data: formattedRows });
  } catch (err) {
    console.error("Error fetching roadmaps:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể lấy danh sách lộ trình" });
  }
});

// 2. GET /api/roadmaps/progress - Lấy tổng hợp tiến độ học tập
app.get("/api/roadmaps/progress", requireAuth, async (req, res) => {
  try {
    const userId = parseInt(req.user?.id);
    
    if (!userId || isNaN(userId)) {
      return res.status(401).json({ 
        success: false, 
        error: "Phiên đăng nhập không hợp lệ"
      });
    }
    
    const todayVN = getVietnamDate();
    todayVN.setHours(0, 0, 0, 0);
    const todayStr = toVietnamDateString(todayVN);
    
    const result = await pool.query(`
      SELECT 
        d.detail_id,
        d.day_number,
        d.study_date,
        d.daily_goal,
        d.learning_content,
        d.practice_exercises,
        d.study_duration,
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
    
    const tasks = result.rows || [];
    const today_tasks = [];
    const upcoming_tasks = [];
    const overdue_tasks = [];
    
    tasks.forEach(task => {
      if (!task.study_date) {
        upcoming_tasks.push(task);
        return;
      }
      
      try {
        const taskDateRaw = new Date(task.study_date);
        // study_date là DATE column → pg trả về midnight UTC, dùng Intl để lấy đúng ngày VN
        const taskDateStr = taskDateRaw.toLocaleDateString('en-CA', { timeZone: 'Asia/Ho_Chi_Minh' });
        
        if (!taskDateStr || taskDateStr === 'Invalid Date') {
          upcoming_tasks.push(task);
          return;
        }
        
        if (taskDateStr === todayStr) {
          today_tasks.push(task);
        } else if (taskDateStr > todayStr) {
          upcoming_tasks.push(task);
        } else {
          if (task.completion_status !== 'COMPLETED' && task.completion_status !== 'SKIPPED') {
            overdue_tasks.push(task);
          }
        }
      } catch (dateError) {
        upcoming_tasks.push(task);
      }
    });
    
    res.json({ 
      success: true, 
      today: today_tasks,
      upcoming: upcoming_tasks.slice(0, 10),
      overdue: overdue_tasks
    });
    
  } catch (err) {
    console.error("Error in /api/roadmaps/progress:", err);
    res.status(500).json({ 
      success: false, 
      error: "Không thể lấy tiến độ"
    });
  }
});
// 3. GET /api/roadmaps/:id - Lấy chi tiết 1 lộ trình
app.get("/api/roadmaps/:id", requireAuth, async (req, res) => {
  try {
    const roadmapId = parseInt(req.params.id);
    
    if (isNaN(roadmapId)) {
      return res.status(400).json({ success: false, error: "ID lộ trình không hợp lệ" });
    }
    
    const userId = parseInt(req.user?.id);
    const userRole = req.user?.role || 'user';
    
    if (!userId || isNaN(userId)) {
      return res.status(401).json({ success: false, error: "Phiên đăng nhập không hợp lệ" });
    }

    const ownershipCheck = await pool.query(
      "SELECT roadmap_id, user_id FROM learning_roadmaps WHERE roadmap_id = $1::integer", 
      [roadmapId]
    );
    
    if (ownershipCheck.rows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: "Lộ trình không tồn tại" 
      });
    }
    
    const ownerId = parseInt(ownershipCheck.rows[0].user_id);
    
    if (ownerId !== userId && userRole !== 'admin') {
      return res.status(403).json({ 
        success: false, 
        error: "Bạn không có quyền truy cập lộ trình này" 
      });
    }

    const scheduleClient = await pool.connect();
    let scheduleInfo = { rescheduled: false, hasOverdueToday: false };
    try {
      scheduleInfo = await rescheduleMissedDaysIfNeeded(scheduleClient, roadmapId);
    } finally {
      scheduleClient.release();
    }
    
    const roadmapQuery = `
      SELECT 
        roadmap_id, roadmap_name, category, sub_category, start_level,
        duration_days, duration_hours, status, expected_outcome,
        progress_percentage, total_studied_hours, overall_rating,
        learning_effectiveness, difficulty_suitability, content_relevance,
        engagement_level, detailed_feedback, actual_learning_outcomes,
        improvement_suggestions, would_recommend, roadmap_analyst,
        streak_tier, study_weekdays,
        created_at, updated_at
      FROM learning_roadmaps
      WHERE roadmap_id = $1::integer
    `;
    
    const roadmapResult = await pool.query(roadmapQuery, [roadmapId]);
    
    if (!roadmapResult.rows || roadmapResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Không tìm thấy lộ trình'
      });
    }

    const detailsQuery = `
      SELECT 
        detail_id, day_number, study_date, daily_goal, learning_content,
        practice_exercises, learning_materials, usage_instructions,
        study_duration, completion_status, created_at, updated_at, completed_at
      FROM learning_roadmap_details 
      WHERE roadmap_id = $1::integer
      ORDER BY day_number ASC
    `;
    
    const detailsResult = await pool.query(detailsQuery, [roadmapId]);
    
    const roadmap = roadmapResult.rows[0];
    const formattedRoadmap = {
      ...roadmap,
      created_at: formatTimestampForAPI(roadmap.created_at),
      updated_at: formatTimestampForAPI(roadmap.updated_at)
    };
    
    const formattedDetails = detailsResult.rows.map(detail => ({
      ...detail,
      study_date: detail.study_date ? toVietnamDateString(new Date(detail.study_date)) : null,
      created_at: formatTimestampForAPI(detail.created_at),
      updated_at: formatTimestampForAPI(detail.updated_at),
      completed_at: formatTimestampForAPI(detail.completed_at)
    }));
    
    res.json({ 
      success: true, 
      data: {
        roadmap: { ...formattedRoadmap, has_overdue: scheduleInfo.hasOverdueToday, was_rescheduled: scheduleInfo.rescheduled },
        details: formattedDetails
      }
    });
    
  } catch (err) {
    console.error("ERROR in /api/roadmaps/:id:", err);
    res.status(500).json({ 
      success: false, 
      error: "Không thể lấy thông tin lộ trình"
    });
  }
});

// 4. GET /api/roadmaps/:id/details - Lấy chi tiết từng ngày học
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
    
    const result = await pool.query(`
      SELECT 
        detail_id, day_number, study_date, daily_goal, learning_content,
        practice_exercises, learning_materials, study_duration,
        completion_status, created_at, updated_at, completed_at
      FROM learning_roadmap_details 
      WHERE roadmap_id = $1 
      ORDER BY day_number ASC
    `, [roadmapId]);
    
    const formattedData = result.rows.map(row => {
      let studyDateFormatted = null;
      
      if (row.study_date) {
        const rawDate = new Date(row.study_date);
        const vnDateStr = rawDate.toLocaleDateString('en-CA', { timeZone: 'Asia/Ho_Chi_Minh' });
        const [year, month, day] = vnDateStr.split('-');
        studyDateFormatted = `${day}/${month}/${year}`;
      }
      
      return {
        ...row,
        study_date: studyDateFormatted,
        study_date_iso: row.study_date,
        created_at: formatTimestampForAPI(row.created_at),
        updated_at: formatTimestampForAPI(row.updated_at),
        completed_at: formatTimestampForAPI(row.completed_at)
      };
    });
    
    res.json({ success: true, data: formattedData });
  } catch (err) {
    console.error("Error fetching roadmap details:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể lấy chi tiết lộ trình" });
  }
});

// 6. PUT /api/roadmaps/:id/update-details - Cập nhật thông tin chi tiết lộ trình
app.put("/api/roadmaps/:id/update-details", requireAuth, async (req, res) => {
  const client = await pool.connect();
  
  try {
    const roadmapId = parseInt(req.params.id);
    const { existingRows, newRows, deletedIds, roadmap_analyst } = req.body;
    
    const ownershipCheck = await client.query(
      "SELECT roadmap_id, user_id FROM learning_roadmaps WHERE roadmap_id = $1",
      [roadmapId]
    );
    
    if (ownershipCheck.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Lộ trình không tồn tại" });
    }
    
    if (ownershipCheck.rows[0].user_id !== req.user.id) {
      return res.status(403).json({ success: false, error: "Không có quyền chỉnh sửa" });
    }
    
    await client.query('BEGIN');
    
    const updatedAnalysis = roadmap_analyst || null;
    
    await client.query(
      'DELETE FROM learning_roadmap_details WHERE roadmap_id = $1',
      [roadmapId]
    );
    
    const allRowsToInsert = [];
    
    if (existingRows && existingRows.length > 0) {
      existingRows.forEach(detail => {
        allRowsToInsert.push({
          day_number: detail.day_number,
          study_date: detail.study_date || null,
          daily_goal: detail.daily_goal,
          learning_content: detail.learning_content,
          practice_exercises: detail.practice_exercises,
          learning_materials: detail.learning_materials,
          usage_instructions: detail.usage_instructions,
          study_duration: parseDurationToHours(detail.study_duration),
          completion_status: detail.completion_status || 'NOT_STARTED'
        });
      });
    }
    
    if (newRows && newRows.length > 0) {
      newRows.forEach(detail => {
        allRowsToInsert.push({
          day_number: detail.day_number,
          study_date: detail.study_date || null,
          daily_goal: detail.daily_goal,
          learning_content: detail.learning_content,
          practice_exercises: detail.practice_exercises,
          learning_materials: detail.learning_materials,
          usage_instructions: detail.usage_instructions,
          study_duration: parseDurationToHours(detail.study_duration),
          completion_status: detail.completion_status || 'NOT_STARTED'
        });
      });
    }
    
    for (const detail of allRowsToInsert) {
      const insertQuery = `
        INSERT INTO learning_roadmap_details (
          roadmap_id, day_number, study_date, daily_goal, 
          learning_content, practice_exercises, learning_materials,
          usage_instructions, study_duration, completion_status
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      `;
      
      await client.query(insertQuery, [
        roadmapId,
        detail.day_number,
        detail.study_date,
        detail.daily_goal,
        detail.learning_content,
        detail.practice_exercises,
        detail.learning_materials,
        detail.usage_instructions,
        detail.study_duration,
        detail.completion_status
      ]);
    }
    
    const totalDays = allRowsToInsert.length;
    const totalHours = allRowsToInsert.reduce((sum, d) => sum + d.study_duration, 0);
    
    const progressQuery = `
      SELECT 
        COUNT(*) FILTER (WHERE completion_status = 'COMPLETED') as completed_count,
        COUNT(*) as total_count
      FROM learning_roadmap_details
      WHERE roadmap_id = $1
    `;
    
    const progressResult = await client.query(progressQuery, [roadmapId]);
    const completed_count = Number(progressResult.rows[0].completed_count) || 0;
    const total_count = Number(progressResult.rows[0].total_count) || 0;
    const progressPercentage = total_count === 0 ? 0 : (completed_count / total_count) * 100;
    
    const updateRoadmapQuery = updatedAnalysis 
      ? `UPDATE learning_roadmaps 
         SET duration_hours = $1, duration_days = $2, progress_percentage = $3,
             roadmap_analyst = $4, updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh') 
         WHERE roadmap_id = $5`
      : `UPDATE learning_roadmaps 
         SET duration_hours = $1, duration_days = $2, progress_percentage = $3,
             updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh') 
         WHERE roadmap_id = $4`;
    
    const updateParams = updatedAnalysis 
      ? [totalHours, totalDays, Number(progressPercentage.toFixed(2)), updatedAnalysis, roadmapId]
      : [totalHours, totalDays, Number(progressPercentage.toFixed(2)), roadmapId];
    
    await client.query(updateRoadmapQuery, updateParams);
    
    // Check và update system nếu rating >= 4
// Check và update system nếu rating >= 4
    const ratingQuery = `
      SELECT overall_rating, learning_effectiveness, roadmap_name, category
      FROM learning_roadmaps
      WHERE roadmap_id = $1
    `;
    const ratingResult = await client.query(ratingQuery, [roadmapId]);

    if (ratingResult.rows.length > 0) {
      const roadmap = ratingResult.rows[0];
      const overall_rating = parseInt(roadmap.overall_rating) || 0;
      const learning_effectiveness = parseInt(roadmap.learning_effectiveness) || 0;
      
      if (overall_rating >= 4 || learning_effectiveness >= 4) {
        // ✅ LẤY ĐÚNG CATEGORY NAME (bỏ phần " - description")
        let categoryName = roadmap.category;
        if (categoryName.includes(' - ')) {
          categoryName = categoryName.split(' - ')[0].trim();
        }
        
        const systemCheckQuery = `
          SELECT roadmap_id 
          FROM learning_roadmaps_system 
          WHERE roadmap_name = $1 AND category = $2
          LIMIT 1
        `;
        const systemCheck = await client.query(systemCheckQuery, [
          roadmap.roadmap_name,
          categoryName
        ]);
        
        if (systemCheck.rows.length > 0) {
          const systemRoadmapId = systemCheck.rows[0].roadmap_id;
          
          // ✅ XÓA TOÀN BỘ CHI TIẾT CŨ
          await client.query(
            'DELETE FROM learning_roadmap_details_system WHERE roadmap_id = $1',
            [systemRoadmapId]
          );
          
          // ✅ INSERT LẠI TOÀN BỘ CHI TIẾT MỚI
          for (let i = 0; i < allRowsToInsert.length; i++) {
            const detail = allRowsToInsert[i];
            const insertSystemDetailQuery = `
              INSERT INTO learning_roadmap_details_system (
                roadmap_id, day_number, daily_goal, learning_content,
                practice_exercises, learning_materials, usage_instructions,
                study_duration
              ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            `;
            
            await client.query(insertSystemDetailQuery, [
              systemRoadmapId,
              detail.day_number,
              detail.daily_goal,
              detail.learning_content,
              detail.practice_exercises,
              detail.learning_materials,
              detail.usage_instructions,
              detail.study_duration
            ]);
          }
          
          // ✅ CẬP NHẬT THÔNG TIN TỔNG QUAN (duration_days, duration_hours, roadmap_analyst)
          await client.query(
            `UPDATE learning_roadmaps_system 
             SET roadmap_analyst = $1, 
                 duration_days = $2, 
                 duration_hours = $3,
                 updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh') 
             WHERE roadmap_id = $4`,
            [updatedAnalysis, totalDays, totalHours, systemRoadmapId]
          );
          
          console.log(`✅ Đã đồng bộ ${allRowsToInsert.length} ngày vào system roadmap #${systemRoadmapId}`);
        }
      }
    }
    
    await client.query('COMMIT');

    res.json({
      success: true,
      message: 'Đã lưu thay đổi thành công!',
      stats: {
        updated: existingRows?.length || 0,
        inserted: newRows?.length || 0,
        deleted: deletedIds?.length || 0,
        total: allRowsToInsert.length,
        progress: progressPercentage.toFixed(2) + '%'
      }
    });
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error saving changes:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Không thể lưu thay đổi'
    });
  } finally {
    client.release();
  }
});

// 7. DELETE /api/roadmaps/:id - Xóa lộ trình
app.delete("/api/roadmaps/:id", requireAuth, async (req, res) => {
  const client = await pool.connect();
  
  try {
    const roadmapId = parseInt(req.params.id);
    
    // Xác minh quyền sở hữu
    const checkQuery = `
      SELECT 
        lr.roadmap_id, 
        lr.roadmap_name, 
        lr.category, 
        lr.overall_rating,
        lr.learning_effectiveness,
        lr.user_id,
        EXISTS(
          SELECT 1 FROM learning_roadmaps_system lrs
          WHERE lrs.roadmap_name = lr.roadmap_name
          AND (
            lrs.category = lr.category 
            OR SPLIT_PART(lr.category, ' - ', 1) = lrs.category
          )
        ) as exists_in_system
      FROM learning_roadmaps lr
      WHERE lr.roadmap_id = $1 AND lr.user_id = $2
    `;
    
    const checkResult = await client.query(checkQuery, [roadmapId, req.user.id]);
    
    if (checkResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Lộ trình không tìm thấy hoặc bạn không có quyền xóa'
      });
    }

    await client.query('BEGIN');
    
    const roadmap = checkResult.rows[0];
    
    // Nếu lộ trình tồn tại trong system
    if (roadmap.exists_in_system) {
      const systemRoadmapQuery = `
        SELECT roadmap_id, total_user_learning
        FROM learning_roadmaps_system 
        WHERE roadmap_name = $1 
        AND (
          category = SPLIT_PART($2, ' - ', 1)
          OR category = $2
        )
        LIMIT 1
      `;
      
      const systemResult = await client.query(systemRoadmapQuery, [
        roadmap.roadmap_name,
        roadmap.category
      ]);
      
      if (systemResult.rows.length > 0) {
        const systemRoadmapId = systemResult.rows[0].roadmap_id;
        
        // Giảm total_user_learning
        await client.query(
          `UPDATE learning_roadmaps_system 
           SET total_user_learning = GREATEST(0, total_user_learning - 1),
               updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
           WHERE roadmap_id = $1`,
          [systemRoadmapId]
        );
        
        // Kiểm tra xem còn user nào học lộ trình này không
        const remainingUsersQuery = `
          SELECT COUNT(*) as count
          FROM learning_roadmaps
          WHERE roadmap_name = $1
          AND (
            category = $2
            OR SPLIT_PART(category, ' - ', 1) = SPLIT_PART($2, ' - ', 1)
          )
          AND roadmap_id != $3
        `;
        
        const remainingResult = await client.query(remainingUsersQuery, [
          roadmap.roadmap_name,
          roadmap.category,
          roadmapId
        ]);
        
        const remainingUsers = parseInt(remainingResult.rows[0].count) || 0;
        
        // Nếu không còn user nào → Xóa khỏi system
        if (remainingUsers === 0) {
          await client.query(
            'DELETE FROM learning_roadmap_details_system WHERE roadmap_id = $1',
            [systemRoadmapId]
          );
          
          await client.query(
            'DELETE FROM learning_roadmaps_system WHERE roadmap_id = $1',
            [systemRoadmapId]
          );
        }
      }
    }
    
    // Xóa roadmap của user (cascade tự động xóa details)
    await client.query('DELETE FROM learning_roadmaps WHERE roadmap_id = $1', [roadmapId]);
    
    await client.query('COMMIT');
    
    res.json({
      success: true,
      message: 'Đã xóa lộ trình thành công'
    });
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error deleting roadmap:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể xóa lộ trình'
    });
  } finally {
    client.release();
  }
});


// ============================================================================
// 27. API ENDPOINTS - LUỒNG LỘ TRÌNH (4 endpoints)
// ============================================================================

// 1. GET /api/roadmap - Lấy danh sách lộ trình của user (legacy endpoint)
app.get("/api/roadmap", requireAuth, async (req, res) => {
  try {
    const userId = parseInt(req.user?.id);
    
    if (!userId || isNaN(userId)) {
      return res.status(401).json({ 
        success: false, 
        error: "Phiên đăng nhập không hợp lệ" 
      });
    }
    
    const vnToday = getVietnamDate();
    vnToday.setHours(0, 0, 0, 0);
    const todayStr = toVietnamDateString(vnToday);
    
    const query = `
      SELECT 
        r.roadmap_id, r.roadmap_name, r.category, r.sub_category, r.start_level,
        r.duration_days, r.duration_hours, r.progress_percentage, r.total_studied_hours,
        r.overall_rating, r.learning_effectiveness, r.difficulty_suitability,
        r.content_relevance, r.engagement_level, r.roadmap_analyst, r.expected_outcome,
        r.created_at,
        COUNT(d.detail_id) FILTER (WHERE d.completion_status = 'IN_PROGRESS') as in_progress_count,
        COUNT(d.detail_id) FILTER (WHERE d.completion_status = 'COMPLETED') as completed_count,
        COUNT(d.detail_id) FILTER (WHERE d.completion_status = 'SKIPPED') as skipped_count,
        COUNT(d.detail_id) as total_days
      FROM learning_roadmaps r
      LEFT JOIN learning_roadmap_details d ON r.roadmap_id = d.roadmap_id
      WHERE r.user_id = $1::integer
      GROUP BY r.roadmap_id
      ORDER BY r.created_at DESC
    `;
    
    const result = await pool.query(query, [userId]);
    
    const processedRows = result.rows.map(row => {
      let computed_status = 'NOT_STARTED';
      
      if (row.total_days > 0 && row.skipped_count === row.total_days) {
        computed_status = 'SKIPPED';
      } else if (row.progress_percentage > 0 || row.in_progress_count > 0 || row.completed_count > 0) {
        computed_status = 'IN_PROGRESS';
      }
      
      if (row.progress_percentage >= 100 || (row.total_days > 0 && row.completed_count === row.total_days)) {
        computed_status = 'COMPLETED';
      }
      
      return {
        ...row,
        status: computed_status,
        created_at: formatTimestampForAPI(row.created_at)
      };
    });
    
    res.json({ success: true, data: processedRows });
  } catch (error) {
    console.error('Error in /api/roadmap:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Không thể lấy danh sách lộ trình' 
    });
  }
});

// 2. GET /api/roadmap/:id - Lấy chi tiết lộ trình (legacy)
app.get("/api/roadmap/:id", requireAuth, async (req, res) => {
  try {
    const roadmapId = parseInt(req.params.id);
    
    if (isNaN(roadmapId)) {
      return res.status(400).json({ success: false, error: "ID lộ trình không hợp lệ" });
    }
    
    const userId = parseInt(req.user?.id);
    const userRole = req.user?.role || 'user';
    
    if (!userId || isNaN(userId)) {
      return res.status(401).json({ success: false, error: "Phiên đăng nhập không hợp lệ" });
    }
    
    // Kiểm tra quyền truy cập
    const ownershipCheck = await pool.query(
      "SELECT roadmap_id, user_id FROM learning_roadmaps WHERE roadmap_id = $1::integer", 
      [roadmapId]
    );
    
    if (ownershipCheck.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Lộ trình không tồn tại" });
    }
    
    const ownerId = parseInt(ownershipCheck.rows[0].user_id);
    
    if (ownerId !== userId && userRole !== 'admin') {
      return res.status(403).json({ success: false, error: "Bạn không có quyền truy cập lộ trình này" });
    }
    
    // Lấy thông tin roadmap
    const roadmapQuery = `
      SELECT 
        roadmap_id, roadmap_name, category, sub_category, start_level,
        duration_days, duration_hours, status, expected_outcome,
        progress_percentage, total_studied_hours, overall_rating,
        learning_effectiveness, difficulty_suitability, content_relevance,
        engagement_level, detailed_feedback, actual_learning_outcomes,
        improvement_suggestions, would_recommend, roadmap_analyst,
        created_at, updated_at
      FROM learning_roadmaps
      WHERE roadmap_id = $1::integer
    `;
    
    const roadmapResult = await pool.query(roadmapQuery, [roadmapId]);
    
    if (!roadmapResult.rows || roadmapResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Không tìm thấy lộ trình' });
    }
    
    // Lấy chi tiết các ngày học
    const detailsQuery = `
      SELECT * FROM learning_roadmap_details
      WHERE roadmap_id = $1::integer
      ORDER BY day_number ASC
    `;
    
    const detailsResult = await pool.query(detailsQuery, [roadmapId]);
    
    const roadmap = roadmapResult.rows[0];
    const formattedRoadmap = {
      ...roadmap,
      created_at: formatTimestampForAPI(roadmap.created_at),
      updated_at: formatTimestampForAPI(roadmap.updated_at)
    };
    
    const formattedDetails = detailsResult.rows.map(detail => ({
      ...detail,
      study_date: detail.study_date ? toVietnamDateString(new Date(detail.study_date)) : null,
      created_at: formatTimestampForAPI(detail.created_at),
      updated_at: formatTimestampForAPI(detail.updated_at),
      completed_at: formatTimestampForAPI(detail.completed_at)
    }));
    
    res.json({ 
      success: true, 
      data: {
        roadmap: formattedRoadmap,
        details: formattedDetails
      }
    });
  } catch (error) {
    console.error('Error in /api/roadmap/:id:', error);
    res.status(500).json({ success: false, error: 'Không thể lấy thông tin lộ trình' });
  }
});

// 4. POST /api/roadmap/:id/submit-evaluation - Gửi đánh giá lộ trình
app.post("/api/roadmap/:id/submit-evaluation", requireAuth, async (req, res) => {
  const client = await pool.connect();
  
  try {
    const roadmapId = parseInt(req.params.id);
    const { error, value } = submitEvaluationSchema.validate(req.body);
    
    if (error) {
      return res.status(400).json({
        success: false,
        error: 'Dữ liệu không hợp lệ',
        details: error.details[0].message
      });
    }
    
    await client.query('BEGIN');
    
    // Xác minh quyền sở hữu
    const verifyQuery = `
      SELECT roadmap_id, roadmap_name, category 
      FROM learning_roadmaps
      WHERE roadmap_id = $1 AND user_id = $2
    `;
    
    const verifyResult = await client.query(verifyQuery, [roadmapId, req.user.id]);
    
    if (verifyResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, error: 'Lộ trình không tìm thấy' });
    }
    
    const roadmap = verifyResult.rows[0];
    
    // Parse và đảm bảo là integer
    const overall_rating = Math.round(parseFloat(value.overall_rating));
    const learning_effectiveness = Math.round(parseFloat(value.learning_effectiveness));
    const difficulty_suitability = Math.round(parseFloat(value.difficulty_suitability));
    const content_relevance = Math.round(parseFloat(value.content_relevance));
    const engagement_level = Math.round(parseFloat(value.engagement_level));
    
    // Cập nhật đánh giá
    const updateQuery = `
      UPDATE learning_roadmaps
      SET 
        overall_rating = $1::integer,
        learning_effectiveness = $2::integer,
        difficulty_suitability = $3::integer,
        content_relevance = $4::integer,
        engagement_level = $5::integer,
        detailed_feedback = $6,
        actual_learning_outcomes = $7,
        improvement_suggestions = $8,
        would_recommend = $9,
        updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
      WHERE roadmap_id = $10
      RETURNING *
    `;
    
    const result = await client.query(updateQuery, [
      overall_rating, learning_effectiveness, difficulty_suitability,
      content_relevance, engagement_level,
      value.detailed_feedback || null,
      value.actual_learning_outcomes || null,
      value.improvement_suggestions || null,
      value.would_recommend || false,
      roadmapId
    ]);
    
    const updatedRoadmap = result.rows[0];
    
    // Lấy category name đúng từ bảng categories
    const getCategoryNameQuery = `
      SELECT c.name as category_name
      FROM categories c
      WHERE c.name = SPLIT_PART($1, ' - ', 1)
         OR c.name || ' - ' || c.description = $1
      LIMIT 1
    `;
    
    const categoryResult = await client.query(getCategoryNameQuery, [roadmap.category]);
    
    let categoryName = roadmap.category;
    
    if (categoryResult.rows.length > 0) {
      categoryName = categoryResult.rows[0].category_name;
    } else {
      const parts = roadmap.category.split(' - ');
      categoryName = parts[0].trim();
    }
    
    // Kiểm tra xem có tồn tại trong system không
    const checkSystemQuery = `
      SELECT roadmap_id 
      FROM learning_roadmaps_system 
      WHERE roadmap_name = $1 AND category = $2
      LIMIT 1
    `;
    
    const existingSystem = await client.query(checkSystemQuery, [
      roadmap.roadmap_name,
      categoryName
    ]);
    
    const systemExists = existingSystem.rows.length > 0;
    const systemRoadmapId = systemExists ? existingSystem.rows[0].roadmap_id : null;
    
    // Logic đánh giá: overall_rating >= 4 OR learning_effectiveness >= 4
    const meetsQualityCriteria = (overall_rating >= 4 || learning_effectiveness >= 4);
    
    if (meetsQualityCriteria) {
      if (!systemExists) {
        // Insert vào learning_roadmaps_system
        const insertSystemQuery = `
          INSERT INTO learning_roadmaps_system (
            roadmap_name, category, sub_category, start_level,
            total_user_learning, duration_days, duration_hours,
            overall_rating, learning_effectiveness, roadmap_analyst
          ) VALUES ($1, $2, $3, $4, 1, $5, $6, $7, $8, $9)
          RETURNING roadmap_id
        `;
        
        const systemResult = await client.query(insertSystemQuery, [
          updatedRoadmap.roadmap_name, categoryName, updatedRoadmap.sub_category,
          updatedRoadmap.start_level, updatedRoadmap.duration_days, updatedRoadmap.duration_hours,
          overall_rating, learning_effectiveness, updatedRoadmap.roadmap_analyst
        ]);
        
        const newSystemRoadmapId = systemResult.rows[0].roadmap_id;
        
        // Copy chi tiết
        const copyDetailsQuery = `
          INSERT INTO learning_roadmap_details_system (
            roadmap_id, day_number, daily_goal, learning_content,
            practice_exercises, learning_materials, usage_instructions,
            study_duration
          )
          SELECT 
            $1, day_number, daily_goal, learning_content,
            practice_exercises, learning_materials, usage_instructions,
            study_duration
          FROM learning_roadmap_details
          WHERE roadmap_id = $2
          ORDER BY day_number ASC
        `;
        
        await client.query(copyDetailsQuery, [newSystemRoadmapId, roadmapId]);
      } else {
        // Cập nhật rating trong system
        const updateSystemQuery = `
          UPDATE learning_roadmaps_system
          SET 
            overall_rating = $1::integer,
            learning_effectiveness = $2::integer,
            updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
          WHERE roadmap_id = $3
        `;
        
        await client.query(updateSystemQuery, [
          overall_rating, learning_effectiveness, systemRoadmapId
        ]);
      }
    } else if (systemExists) {
      // Không đủ điều kiện và đã tồn tại: Xóa khỏi system
      await client.query(
        'DELETE FROM learning_roadmap_details_system WHERE roadmap_id = $1',
        [systemRoadmapId]
      );
      
      await client.query(
        'DELETE FROM learning_roadmaps_system WHERE roadmap_id = $1',
        [systemRoadmapId]
      );
    }
    
    await client.query('COMMIT');
    
    res.json({
      success: true,
      message: 'Đánh giá đã được lưu thành công',
      data: {
        ...updatedRoadmap,
        created_at: formatTimestampForAPI(updatedRoadmap.created_at),
        updated_at: formatTimestampForAPI(updatedRoadmap.updated_at)
      }
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error submitting evaluation:', error);
    res.status(500).json({ success: false, error: 'Không thể lưu đánh giá' });
  } finally {
    client.release();
  }
});

// ============================================================================
// 28. API ENDPOINTS - LUỒNG LỘ TRÌNH HỆ THỐNG (7 endpoints)
// ============================================================================

// 1. GET /api/categories - Lấy danh sách tất cả categories
app.get("/api/categories", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.id, c.name || ' - ' || c.description name, c.description, c.created_at,
        (SELECT json_agg(
          json_build_object('id', s.id, 'name', s.name, 'description', s.description)
          ORDER BY s.id
        ) 
         FROM sub_categories s WHERE s.category_id = c.id) as sub_categories
      FROM categories c
      ORDER BY c.id
    `);
    
    const formattedCategories = result.rows.map(cat => ({
      ...cat,
      created_at: formatTimestampForAPI(cat.created_at)
    }));
    
    res.json({ success: true, data: formattedCategories });
  } catch (err) {
    console.error("Error fetching categories:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể lấy danh mục" });
  }
});

// 2. GET /api/categories/top - Lấy top categories phổ biến
app.get('/api/categories/top', async (req, res) => {
    try {
        // ✅ BƯỚC 1: Đếm roadmap KHÔNG BỊ ẨN trong learning_roadmaps_system
        const query = `
            SELECT 
                c.id,
                c.name,
                c.description,
                COUNT(DISTINCT lrs.roadmap_id) as roadmap_count
            FROM categories c
            LEFT JOIN learning_roadmaps_system lrs 
                ON LOWER(TRIM(lrs.category)) = LOWER(TRIM(c.name))
            WHERE lrs.roadmap_id IS NOT NULL
              AND (lrs.is_hidden IS NULL OR lrs.is_hidden = FALSE)
            GROUP BY c.id, c.name, c.description
            HAVING COUNT(DISTINCT lrs.roadmap_id) > 0
            ORDER BY roadmap_count DESC
            LIMIT 30
        `;
        
        const result = await pool.query(query);
        
        console.log('📊 Top Categories Query Result:', result.rows);
        
        // ✅ BƯỚC 2: Nếu không có category nào, trả về array rỗng
        if (result.rows.length === 0) {
            console.log('⚠️ No categories with roadmaps found');
            return res.json([]);
        }
        
        res.json(result.rows);
        
    } catch (error) {
        console.error('❌ Error fetching top categories:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            message: error.message 
        });
    }
});

// 3. GET /api/categories/:categoryName - Lấy thông tin 1 category by ID
app.get('/api/categories/:categoryName', async (req, res) => {
  try {
    const categoryName = req.params.categoryName;
    
    const query = `
      SELECT id, name, description, created_at
      FROM categories
      WHERE id = $1
    `;
    
    const result = await pool.query(query, [parseInt(categoryName)]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Không tìm thấy lĩnh vực'
      });
    }
    
    const category = result.rows[0];
    res.json({
      success: true,
      data: {
        ...category,
        created_at: formatTimestampForAPI(category.created_at)
      }
    });
  } catch (error) {
    console.error('Error fetching category:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể tải thông tin lĩnh vực'
    });
  }
});

// 4. GET /api/categories/:categoryId/sub-categories - Lấy sub-categories của 1 category
app.get("/api/categories/:categoryId/sub-categories", async (req, res) => {
  try {
    const categoryId = parseInt(req.params.categoryId);
    
    if (isNaN(categoryId)) {
      return res.status(400).json({ 
        success: false, 
        error: "Category ID không hợp lệ" 
      });
    }
    
    const query = `
      SELECT id, name || ' - ' || description name, description, created_at
      FROM sub_categories
      WHERE category_id = $1
      ORDER BY id ASC
    `;
    
    const result = await pool.query(query, [categoryId]);
    
    const formattedSubCategories = result.rows.map(sub => ({
      ...sub,
      created_at: formatTimestampForAPI(sub.created_at)
    }));
    
    res.json({ success: true, data: formattedSubCategories });
  } catch (err) {
    console.error("Error fetching sub-categories:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể lấy danh mục con" });
  }
});

// 5. GET /api/roadmapsystem/category/:categoryName - Danh sách system roadmaps theo category
app.get('/api/roadmapsystem/category/:categoryName', async (req, res) => {
  try {
    const categoryName  = req.params.categoryName;
    const { page = 1, limit = 12 } = req.query;
    const offset = (page - 1) * limit;
    
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

    // ✅ FIX: Thêm điều kiện is_hidden vào COUNT
    const countQuery = `
      SELECT COUNT(*) as total
      FROM learning_roadmaps_system
      WHERE category = $1
        AND (overall_rating >= 4 OR learning_effectiveness >= 4)
        AND (is_hidden IS NULL OR is_hidden = FALSE)
    `;
    const countResult = await pool.query(countQuery, [result.rows[0].name]);
    
    // ✅ Query chính đã có is_hidden rồi - GIỮ NGUYÊN
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
        AND (overall_rating >= 4 OR learning_effectiveness >= 4)
        AND (is_hidden IS NULL OR is_hidden = FALSE)
      ORDER BY created_at DESC
      LIMIT $2 OFFSET $3
    `;
    const roadmaps = await pool.query(query, [result.rows[0].name, limit, offset]);

    // ✅ Format timestamps
    const formattedRoadmaps = roadmaps.rows.map(roadmap => ({
      ...roadmap,
      created_at: formatTimestampForAPI(roadmap.created_at),
      updated_at: formatTimestampForAPI(roadmap.updated_at)
    }));

    res.json({
      success: true,
      data: formattedRoadmaps,
      pagination: {
        total: parseInt(countResult.rows[0].total),
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(countResult.rows[0].total / limit)
      }
    });
  } catch (error) {
    console.error('Error fetching roadmaps by category:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể tải danh sách lộ trình'
    });
  }
});

// 6. GET /api/roadmapsystem/:roadmapId - Chi tiết 1 system roadmap
app.get('/api/roadmapsystem/:roadmapId', async (req, res) => {
  try {
    const { roadmapId } = req.params;
    
    const query = `
      SELECT 
        lrs.roadmap_id, lrs.roadmap_name, lrs.category, lrs.sub_category, lrs.start_level,
        lrs.total_user_learning, lrs.duration_days, lrs.duration_hours,
        lrs.created_at, lrs.updated_at, lrs.roadmap_analyst, c.id as category_id,
        COUNT(DISTINCT CASE 
          WHEN lr.overall_rating >= 4 THEN lr.user_id 
        END) as high_overall_rating_count,
        COUNT(DISTINCT CASE 
          WHEN lr.learning_effectiveness >= 4 THEN lr.user_id 
        END) as high_effectiveness_count
      FROM learning_roadmaps_system lrs
      LEFT JOIN categories c ON c.name = lrs.category
      LEFT JOIN learning_roadmaps lr 
        ON lr.roadmap_name = lrs.roadmap_name 
        AND (lr.category = lrs.category OR SPLIT_PART(lr.category, ' - ', 1) = lrs.category)
      WHERE lrs.roadmap_id = $1
      GROUP BY lrs.roadmap_id, c.id
    `;
    
    const result = await pool.query(query, [roadmapId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Không tìm thấy lộ trình'
      });
    }
    
    const roadmap = result.rows[0];
    const formattedRoadmap = {
      ...roadmap,
      created_at: formatTimestampForAPI(roadmap.created_at),
      updated_at: formatTimestampForAPI(roadmap.updated_at)
    };
    
    res.json({ success: true, data: formattedRoadmap });
  } catch (error) {
    console.error('Error fetching roadmap details:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể tải thông tin lộ trình'
    });
  }
});

// 7. GET /api/roadmapsystem/:roadmapId/details - Chi tiết các ngày học của system roadmap
app.get('/api/roadmapsystem/:roadmapId/details', async (req, res) => {
  try {
    const roadmapId = req.params.roadmapId;
    
    const query = `
      SELECT 
        detail_id,
        roadmap_id,
        day_number,
        daily_goal,
        learning_content,
        practice_exercises,
        learning_materials,
        usage_instructions,
        study_duration,
        created_at,
        updated_at
      FROM learning_roadmap_details_system
      WHERE roadmap_id = $1
      ORDER BY day_number ASC
    `;
    
    const result = await pool.query(query, [parseInt(roadmapId)]);
    
    const formattedDetails = result.rows.map(detail => ({
      ...detail,
      created_at: formatTimestampForAPI(detail.created_at),
      updated_at: formatTimestampForAPI(detail.updated_at)
    }));
    
    res.json({
      success: true,
      data: formattedDetails
    });
  } catch (error) {
    console.error('Error fetching roadmap day details:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể tải chi tiết lộ trình'
    });
  }
});

// ============================================================================
// 29. API ENDPOINTS - LUỒNG PHẢN HỒI HỆ THỐNG (3 endpoints)
// ============================================================================

// 1. POST /api/feedback/submit - Gửi feedback về hệ thống
app.post("/api/feedback/submit", requireAuth, async (req, res) => {
  try {
    const {
      rating_1, rating_2, rating_3, rating_4, rating_5, rating_6, rating_7, rating_8,
      question_1, question_2, question_3
    } = req.body;

    // Validate ratings (1-5)
    const ratings = [rating_1, rating_2, rating_3, rating_4, rating_5, rating_6, rating_7, rating_8];
    for (let i = 0; i < ratings.length; i++) {
      const rating = parseInt(ratings[i]);
      if (isNaN(rating) || rating < 1 || rating > 5) {
        return res.status(400).json({
          success: false,
          error: `Đánh giá ${i + 1} không hợp lệ (phải từ 1-5)`
        });
      }
    }

    const query = `
      INSERT INTO user_feedback (
        user_id, rating_1, rating_2, rating_3, rating_4, rating_5, 
        rating_6, rating_7, rating_8, question_1, question_2, question_3
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING feedback_id, created_at
    `;

    const result = await pool.query(query, [
      req.user.id,
      rating_1, rating_2, rating_3, rating_4, rating_5, rating_6, rating_7, rating_8,
      question_1 || null, question_2 || null, question_3 || null
    ]);

    res.json({
      success: true,
      message: 'Cảm ơn bạn đã gửi phản hồi!',
      data: {
        ...result.rows[0],
        created_at: formatTimestampForAPI(result.rows[0].created_at)
      }
    });

  } catch (error) {
    console.error('Error submitting feedback:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể gửi phản hồi'
    });
  }
});

// 2. GET /api/admin/feedback - Xem danh sách feedback (requireAdmin)
app.get("/api/admin/feedback", requireAdmin, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const offset = parseInt(req.query.offset) || 0;

    const query = `
      SELECT 
        f.feedback_id,
        f.user_id,
        u.name as user_name,
        u.email as user_email,
        f.rating_1, f.rating_2, f.rating_3, f.rating_4,
        f.rating_5, f.rating_6, f.rating_7, f.rating_8,
        f.question_1, f.question_2, f.question_3,
        f.created_at
      FROM user_feedback f
      LEFT JOIN users u ON f.user_id = u.id
      ORDER BY f.created_at DESC
      LIMIT $1 OFFSET $2
    `;

    const countQuery = `SELECT COUNT(*) as total FROM user_feedback`;

    const result = await pool.query(query, [limit, offset]);
    const countResult = await pool.query(countQuery);
    
    const formattedFeedback = result.rows.map(feedback => ({
      ...feedback,
      created_at: formatTimestampForAPI(feedback.created_at)
    }));

    res.json({
      success: true,
      data: formattedFeedback,
      total: parseInt(countResult.rows[0].total),
      pagination: {
        limit,
        offset,
        totalPages: Math.ceil(countResult.rows[0].total / limit)
      }
    });

  } catch (error) {
    console.error('Error fetching feedback:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể lấy danh sách phản hồi'
    });
  }
});

// 3. GET /api/admin/feedback/stats - Thống kê feedback
app.get("/api/admin/feedback/stats", requireAdmin, async (req, res) => {
  try {
    const query = `
      SELECT 
        COUNT(*) as total_feedback,
        AVG(rating_1) as avg_rating_1,
        AVG(rating_2) as avg_rating_2,
        AVG(rating_3) as avg_rating_3,
        AVG(rating_4) as avg_rating_4,
        AVG(rating_5) as avg_rating_5,
        AVG(rating_6) as avg_rating_6,
        AVG(rating_7) as avg_rating_7,
        AVG(rating_8) as avg_rating_8
      FROM user_feedback
    `;

    const result = await pool.query(query);
    
    res.json({
      success: true,
      data: result.rows[0]
    });

  } catch (error) {
    console.error('Error fetching feedback stats:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể lấy thống kê'
    });
  }
});

// ============================================================================
// 30. API ENDPOINTS - LUỒNG ADMIN - QUẢN LÝ USER (7 endpoints)
// ============================================================================

// 1. GET /api/users/:id - Lấy thông tin 1 user by ID (requireAdmin)
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
    
    const user = result.rows[0];
    res.json({ 
      success: true, 
      data: {
        ...user,
        created_at: formatTimestampForAPI(user.created_at)
      }
    });
  } catch (err) {
    console.error("Error fetching user:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể lấy thông tin người dùng" });
  }
});

// 2. DELETE /api/users/:id - Xóa user (requireAdmin)
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

// 3. GET /api/admin/users - Danh sách users với phân trang
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
    
    const formattedUsers = result.rows.map(user => ({
      ...user,
      created_at: formatTimestampForAPI(user.created_at)
    }));
    
    res.json({ success: true, data: formattedUsers });
  } catch (err) {
    console.error("Error fetching users:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể lấy danh sách người dùng" });
  }
});

// 4. GET /api/admin/users/:id - Lấy thông tin chi tiết 1 user
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
    
    const user = result.rows[0];
    res.json({ 
      success: true, 
      data: {
        ...user,
        created_at: formatTimestampForAPI(user.created_at)
      }
    });
  } catch (err) {
    console.error("Error fetching user:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể lấy thông tin người dùng" });
  }
});

// 5. PUT /api/admin/users/:id/role - Cập nhật role
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

// 6. PUT /api/admin/users/:id - Cập nhật thông tin user
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

// 7. DELETE /api/admin/users/:id - Xóa user (admin version)
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

// ============================================================================
// 31. API ENDPOINTS - LUỒNG ADMIN - QUẢN LÝ CÁC DANH MỤC VÀ CON (6 endpoints)
// ============================================================================

// 1. POST /api/admin/categories - Tạo category mới
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
    
    const category = result.rows[0];
    res.json({ 
      success: true, 
      data: {
        ...category,
        created_at: formatTimestampForAPI(category.created_at)
      },
      message: "Tạo danh mục thành công" 
    });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ success: false, error: "Danh mục đã tồn tại" });
    }
    console.error(err);
    res.status(500).json({ success: false, error: "Không thể tạo danh mục" });
  }
});

// 2. PUT /api/admin/categories/:id - Cập nhật category
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
    
    const category = result.rows[0];
    res.json({ 
      success: true, 
      data: {
        ...category,
        created_at: formatTimestampForAPI(category.created_at)
      },
      message: "Cập nhật thành công" 
    });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ success: false, error: "Tên danh mục đã tồn tại" });
    }
    res.status(500).json({ success: false, error: "Không thể cập nhật" });
  }
});

// 3. DELETE /api/admin/categories/:id - Xóa category
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

// 4. POST /api/admin/sub-categories - Tạo sub-category
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
    
    const subCategory = result.rows[0];
    res.json({ 
      success: true, 
      data: {
        ...subCategory,
        created_at: formatTimestampForAPI(subCategory.created_at)
      },
      message: "Tạo danh mục con thành công" 
    });
  } catch (err) {
if (err.code === '23505') {
      return res.status(409).json({ success: false, error: "Tên danh mục con đã tồn tại" });
    }
    console.error(err);
    res.status(500).json({ success: false, error: "Không thể cập nhật" });
  }
});

// 6. DELETE /api/admin/sub-categories/:id - Xóa sub-category
app.delete("/api/admin/sub-categories/:id", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `DELETE FROM sub_categories WHERE id = $1 RETURNING name`,
      [req.params.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Danh mục con không tồn tại" });
    }
    
    res.json({ success: true, message: `Đã xóa danh mục con "${result.rows[0].name}"` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: "Không thể xóa danh mục con" });
  }
});

// ============================================================================
// 31. API ENDPOINTS - LUỒNG ADMIN - QUẢN LÝ CÁC LỘ TRÌNH (4 endpoints)
// ============================================================================

// 1. GET /api/admin/roadmaps-system - Lấy danh sách tất cả lộ trình hệ thống
app.get("/api/admin/roadmaps-system", requireAdmin, async (req, res) => {
  try {
    const query = `
      SELECT 
        roadmap_id, roadmap_name, category, sub_category, start_level,
        total_user_learning, duration_days, duration_hours,
        overall_rating, learning_effectiveness, roadmap_analyst,
        is_hidden, created_at, updated_at
      FROM learning_roadmaps_system
      ORDER BY created_at DESC
    `;
    
    const result = await pool.query(query);
    
    const formattedData = result.rows.map(row => ({
      ...row,
      created_at: formatTimestampForAPI(row.created_at),
      updated_at: formatTimestampForAPI(row.updated_at)
    }));
    
    res.json({ success: true, data: formattedData });
  } catch (error) {
    console.error('Error fetching system roadmaps:', error);
    res.status(500).json({ success: false, error: 'Không thể tải lộ trình hệ thống' });
  }
});

// 2. GET /api/admin/roadmaps-system/:id - Lấy chi tiết 1 lộ trình hệ thống theo ID
app.get("/api/admin/roadmaps-system/:id", requireAdmin, async (req, res) => {
  try {
    const roadmapId = parseInt(req.params.id);
    
    const query = `
      SELECT * FROM learning_roadmap_details_system
      WHERE roadmap_id = $1
      ORDER BY day_number ASC
    `;
    
    const result = await pool.query(query, [roadmapId]);
    
    const formattedDetails = result.rows.map(row => ({
      ...row,
      created_at: formatTimestampForAPI(row.created_at),
      updated_at: formatTimestampForAPI(row.updated_at)
    }));
    
    res.json({ success: true, data: formattedDetails });
  } catch (error) {
    console.error('Error fetching system roadmap details:', error);
    res.status(500).json({ success: false, error: 'Không thể tải chi tiết' });
  }
});

// 3. GET /api/admin/roadmaps-user - Lấy danh sách tất cả lộ trình của users
app.get("/api/admin/roadmaps-user", requireAdmin, async (req, res) => {
  try {
    const query = `
      SELECT 
        r.roadmap_id, r.roadmap_name, r.category, r.sub_category, r.start_level,
        r.duration_days, r.duration_hours, r.status, r.progress_percentage,
        r.total_studied_hours, r.overall_rating, r.created_at, r.updated_at,
        u.name as user_name, u.email as user_email
      FROM learning_roadmaps r
      LEFT JOIN users u ON r.user_id = u.id
      ORDER BY r.created_at DESC
    `;
    
    const result = await pool.query(query);
    
    const formattedData = result.rows.map(row => ({
      ...row,
      created_at: formatTimestampForAPI(row.created_at),
      updated_at: formatTimestampForAPI(row.updated_at)
    }));
    
    res.json({ success: true, data: formattedData });
  } catch (error) {
    console.error('Error fetching user roadmaps:', error);
    res.status(500).json({ success: false, error: 'Không thể tải lộ trình người dùng' });
  }
});

// 4. PUT /api/admin/roadmaps-system/:id/toggle-hide - Ẩn/hiện lộ trình hệ thống
app.put("/api/admin/roadmaps-system/:id/toggle-hide", requireAdmin, async (req, res) => {
  try {
    const roadmapId = parseInt(req.params.id);
    const { is_hidden } = req.body;
    
    if (typeof is_hidden !== 'boolean') {
      return res.status(400).json({ success: false, error: 'is_hidden phải là boolean' });
    }
    
    const result = await pool.query(
      `UPDATE learning_roadmaps_system 
       SET is_hidden = $1, updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
       WHERE roadmap_id = $2
       RETURNING roadmap_id`,
      [is_hidden, roadmapId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Lộ trình không tồn tại' });
    }
    
    res.json({ 
      success: true, 
      message: is_hidden ? 'Đã ẩn lộ trình khỏi danh sách phổ biến' : 'Đã hiện lộ trình trong danh sách phổ biến'
    });
  } catch (error) {
    console.error('Error toggling hide roadmap:', error);
    res.status(500).json({ success: false, error: 'Không thể cập nhật' });
  }
});

// ============================================================================
// 32. API ENDPOINTS - LUỒNG ADMIN - CẤU HÌNH HỆ THỐNG (10 endpoints)
// ============================================================================

// 1. GET /api/admin/stats - Thống kê tổng quan
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

// 2. GET /api/admin/ai-history - Xem lịch sử AI queries
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
    
    const formattedHistory = result.rows.map(item => ({
      ...item,
      query_time: formatTimestampForAPI(item.query_time)
    }));
    
    res.json({ 
      success: true, 
      data: formattedHistory,
      total: parseInt(countResult.rows[0].total)
    });
  } catch (err) {
    console.error("Error fetching AI history:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể lấy lịch sử AI" });
  }
});

// 3. DELETE /api/admin/ai-history/:id - Xóa 1 record AI history
app.delete("/api/admin/ai-history/:id", requireAdmin, async (req, res) => {
  try {
    const historyId = parseInt(req.params.id);
    
    const result = await pool.query(
      `DELETE FROM ai_query_history WHERE id = $1 RETURNING id`,
      [historyId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Lịch sử không tồn tại" });
    }
    
    res.json({ success: true, message: "Đã xóa lịch sử" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: "Không thể xóa" });
  }
});

// 4. DELETE /api/admin/feedback/:feedbackId - Xóa feedback
app.delete('/api/admin/feedback/:feedbackId', requireAdmin, async (req, res) => {
  const client = await pool.connect();
  
  try {
    const feedbackId = parseInt(req.params.feedbackId);
    
    if (isNaN(feedbackId)) {
      return res.status(400).json({
        success: false,
        error: 'ID phản hồi không hợp lệ'
      });
    }
    
    await client.query('BEGIN');
    
    const deleteQuery = `
      DELETE FROM user_feedback
      WHERE feedback_id = $1
      RETURNING feedback_id
    `;
    
    const result = await client.query(deleteQuery, [feedbackId]);
    
    if (result.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({
        success: false,
        error: 'Không tìm thấy phản hồi'
      });
    }
    
    await client.query('COMMIT');
    
    res.json({
      success: true,
      message: 'Phản hồi đã được xóa thành công'
    });
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error deleting feedback:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể xóa phản hồi'
    });
  } finally {
    client.release();
  }
});
// 4b. GET /api/admin/quiz-stats - Thống kê điểm quiz học viên
app.get("/api/admin/quiz-stats", requireAdmin, async (req, res) => {
  try {
    const overall = await pool.query(`
      SELECT 
        COUNT(*) as total_attempts,
        COUNT(DISTINCT user_id) as total_students,
        COUNT(DISTINCT roadmap_id) as total_roadmaps,
        ROUND(AVG(score), 2) as avg_score,
        ROUND(100.0 * COUNT(*) FILTER (WHERE passed) / NULLIF(COUNT(*),0), 2) as pass_rate
      FROM quiz_attempts
    `);

    const byRoadmap = await pool.query(`
      SELECT 
        qa.roadmap_id,
        lr.roadmap_name,
        u2.name as owner_name,
        COUNT(*) as total_attempts,
        COUNT(DISTINCT qa.user_id) as students,
        ROUND(AVG(qa.score), 2) as avg_score,
        ROUND(100.0 * COUNT(*) FILTER (WHERE qa.passed) / NULLIF(COUNT(*),0), 2) as pass_rate,
        lr.pass_threshold
      FROM quiz_attempts qa
      LEFT JOIN learning_roadmaps lr ON qa.roadmap_id = lr.roadmap_id
      LEFT JOIN users u2 ON lr.user_id = u2.id
      GROUP BY qa.roadmap_id, lr.roadmap_name, u2.name, lr.pass_threshold
      ORDER BY total_attempts DESC
      LIMIT 100
    `);

    res.json({ success: true, data: { overall: overall.rows[0], by_roadmap: byRoadmap.rows } });
  } catch (err) {
    console.error('Error fetching quiz stats:', err?.message || err);
    res.status(500).json({ success: false, error: 'Không thể lấy thống kê quiz' });
  }
});

// 4c. PUT /api/admin/roadmaps/:id/pass-threshold - Sửa ngưỡng đạt
app.put("/api/admin/roadmaps/:id/pass-threshold", requireAdmin, async (req, res) => {
  try {
    const roadmapId = parseInt(req.params.id);
    const val = parseInt(req.body.pass_threshold);
    if (isNaN(val) || val < 0 || val > 100) {
      return res.status(400).json({ success: false, error: 'pass_threshold phải từ 0-100' });
    }
    const result = await pool.query(
      `UPDATE learning_roadmaps SET pass_threshold = $1, updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh') WHERE roadmap_id = $2 RETURNING roadmap_id, pass_threshold`,
      [val, roadmapId]
    );
    if (result.rows.length === 0) return res.status(404).json({ success: false, error: 'Lộ trình không tồn tại' });
    res.json({ success: true, message: 'Đã cập nhật ngưỡng đạt', data: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Không thể cập nhật ngưỡng đạt' });
  }
});
// 4d. GET /api/admin/ai-limit - Lấy giới hạn lượt tạo AI
app.get("/api/admin/ai-limit", requireAdmin, async (req, res) => {
  const limit = await getAIGenerationLimit();
  res.json({ success: true, data: { ai_generation_limit: limit } });
});

// 4e. POST /api/admin/ai-limit/save - Sửa giới hạn lượt tạo AI
app.post("/api/admin/ai-limit/save", requireAdmin, async (req, res) => {
  try {
    const val = parseInt(req.body.ai_generation_limit);
    if (isNaN(val) || val < 0) {
      return res.status(400).json({ success: false, error: 'Giá trị không hợp lệ' });
    }
    await pool.query(
      `INSERT INTO system_config (config_key, config_value) VALUES ('ai_generation_limit', $1)
       ON CONFLICT (config_key) DO UPDATE SET config_value = $1`,
      [String(val)]
    );
    res.json({ success: true, message: 'Đã cập nhật số lượt tạo AI', data: { ai_generation_limit: val } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Không thể cập nhật' });
  }
});
// 5. POST /api/admin/prompt/save - Lưu AI prompt template
app.post("/api/admin/prompt/save", requireAdmin, async (req, res) => {
  try {
    const userId = req.user.id;
    const { promptContent, jsonFormat } = req.body;
    
    const query = `
      UPDATE admin_settings
      SET 
        prompt_template = $1,
        json_format_response = $2,
        updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh'),
        updated_by = $3
      WHERE setting_key = 'prompt_template'
      RETURNING setting_id, updated_at
    `;

    const result = await pool.query(query, [promptContent, jsonFormat, userId]);

    if (result.rows.length === 0) {
      const insertQuery = `
        INSERT INTO admin_settings (
          setting_key, prompt_template, json_format_response, updated_by
        ) VALUES ('prompt_template', $1, $2, $3)
        RETURNING setting_id, created_at as updated_at
      `;

      const insertResult = await pool.query(insertQuery, [promptContent, jsonFormat, userId]);
      
      res.json({
        success: true,
        message: 'Prompt mẫu đã được lưu thành công',
        updatedAt: formatTimestampForAPI(insertResult.rows[0].updated_at)
      });
    } else {
      res.json({
        success: true,
        message: 'Prompt mẫu đã được lưu thành công',
        updatedAt: formatTimestampForAPI(result.rows[0].updated_at)
      });
    }

  } catch (error) {
    console.error('Error saving prompt template:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể lưu Prompt mẫu'
    });
  }
});

// 6. GET /api/admin/manual-prompt - Lấy manual prompt template
app.get("/api/admin/manual-prompt", requireAuth, async (req, res) => {
  try {
    const query = `
      SELECT manual_prompt_template
      FROM admin_settings
      WHERE setting_key = 'prompt_template'
      LIMIT 1
    `;
    
    const result = await pool.query(query);
    
    let manualPromptTemplate = '';
    
    if (result.rows.length > 0 && result.rows[0].manual_prompt_template) {
      manualPromptTemplate = result.rows[0].manual_prompt_template;
    } else {
      const defaultPath = path.join(dataDir, 'default_prompt.txt');
      if (fs.existsSync(defaultPath)) {
        manualPromptTemplate = fs.readFileSync(defaultPath, 'utf8');
      } else {
        manualPromptTemplate = getDefaultManualPrompt();
      }
    }
    
    res.json({
      success: true,
      data: {
        manual_prompt_template: manualPromptTemplate
      }
    });
  } catch (error) {
    console.error('Error fetching manual prompt:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể lấy manual prompt template'
    });
  }
});

// 7. POST /api/admin/manual-prompt/save - Lưu manual prompt template
app.post("/api/admin/manual-prompt/save", requireAdmin, async (req, res) => {
  try {
    const userId = req.user.id;
    const { manualPromptContent } = req.body;
    
    if (!manualPromptContent) {
      return res.status(400).json({
        success: false,
        error: 'Manual prompt content không được để trống'
      });
    }
    
    const query = `
      UPDATE admin_settings
      SET 
        manual_prompt_template = $1,
        updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh'),
        updated_by = $2
      WHERE setting_key = 'prompt_template'
      RETURNING setting_id, updated_at
    `;
    
    const result = await pool.query(query, [manualPromptContent, userId]);
    
    if (result.rows.length === 0) {
      const insertQuery = `
        INSERT INTO admin_settings (
          setting_key, manual_prompt_template, updated_by
        ) VALUES ('prompt_template', $1, $2)
        RETURNING setting_id, created_at as updated_at
      `;
      const insertResult = await pool.query(insertQuery, [manualPromptContent, userId]);
      
      res.json({
        success: true,
        message: 'Manual Prompt đã được lưu thành công',
        updatedAt: formatTimestampForAPI(insertResult.rows[0].updated_at)
      });
    } else {
      res.json({
        success: true,
        message: 'Manual Prompt đã được lưu thành công',
        updatedAt: formatTimestampForAPI(result.rows[0].updated_at)
      });
    }
  } catch (error) {
    console.error('Error saving manual prompt:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể lưu Manual Prompt'
    });
  }
});

// 8. POST /api/admin/manual-prompt/reset - Reset manual prompt về mặc định
app.post("/api/admin/manual-prompt/reset", requireAdmin, async (req, res) => {
  try {
    let manualPromptTemplate;

    const defaultPath = path.join(dataDir, 'default_prompt.txt');
    
    if (fs.existsSync(defaultPath)) {
      manualPromptTemplate = fs.readFileSync(defaultPath, 'utf8');
    } else {
      manualPromptTemplate = getDefaultManualPrompt();
    }

    const updateQuery = `
      UPDATE admin_settings
      SET 
        manual_prompt_template = $1,
        updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh'),
        updated_by = $2
      WHERE setting_key = 'prompt_template'
      RETURNING setting_id, updated_at
    `;
    
    const insertQuery = `
      INSERT INTO admin_settings (
        setting_key, manual_prompt_template, updated_by, created_at
      ) VALUES ('prompt_template', $1, $2, (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh'))
      RETURNING setting_id, created_at
    `;

    const checkQuery = `
      SELECT setting_id 
      FROM admin_settings 
      WHERE setting_key = 'prompt_template'
      LIMIT 1
    `;
    
    const checkResult = await pool.query(checkQuery);
    
    if (checkResult.rows.length > 0) {
      const result = await pool.query(updateQuery, [manualPromptTemplate, req.user.id]);
      
      res.json({
        success: true,
        message: '✅ Đã khôi phục manual prompt về mặc định',
        data: {
          manual_prompt_template: manualPromptTemplate,
          updated_at: formatTimestampForAPI(result.rows[0].updated_at)
        }
      });
    } else {
      const result = await pool.query(insertQuery, [manualPromptTemplate, req.user.id]);
      
      res.json({
        success: true,
        message: '✅ Đã tạo manual prompt mặc định',
        data: {
          manual_prompt_template: manualPromptTemplate,
          created_at: formatTimestampForAPI(result.rows[0].created_at)
        }
      });
    }
    
  } catch (error) {
    console.error('Error resetting manual prompt:', error);
    res.status(500).json({
      success: false,
      error: 'Lỗi khi khôi phục manual prompt'
    });
  }
});

// 9. POST /api/admin/prompt-template/reset - Reset prompt template về mặc định
app.post("/api/admin/prompt-template/reset", requireAdmin, async (req, res) => {
  try {
    let defaultPrompt;
    let defaultJsonFormat;
    
    const defaultPath = path.join(dataDir, 'default_prompt_ai.txt');
    
    if (fs.existsSync(defaultPath)) {
      const content = fs.readFileSync(defaultPath, 'utf8');
      defaultPrompt = content;
      
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      defaultJsonFormat = jsonMatch ? jsonMatch[0] : getHardcodedJsonFormat();
    } else {
      defaultPrompt = buildDefaultPromptTemplate();
      defaultJsonFormat = getHardcodedJsonFormat();
    }
    
    const updateQuery = `
      UPDATE admin_settings
      SET 
        prompt_template = $1,
        json_format_response = $2,
        updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh'),
        updated_by = $3
      WHERE setting_key = 'prompt_template'
      RETURNING setting_id, updated_at
    `;
    
    const result = await pool.query(updateQuery, [defaultPrompt, defaultJsonFormat, req.user.id]);
    
    if (result.rows.length === 0) {
      const insertQuery = `
        INSERT INTO admin_settings (
          setting_key, prompt_template, json_format_response, updated_by
        ) VALUES ('prompt_template', $1, $2, $3)
        RETURNING setting_id, created_at
      `;
      
      await pool.query(insertQuery, [defaultPrompt, defaultJsonFormat, req.user.id]);
    }
    
    res.json({
      success: true,
      message: '✅ Đã khôi phục prompt AI về mặc định',
      data: {
        prompt_template: defaultPrompt,
        json_format_response: defaultJsonFormat
      }
    });
    
  } catch (error) {
    console.error('Error resetting AI prompt:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể khôi phục prompt AI'
    });
  }
});

// 10. POST /api/admin/prompt - Cập nhật prompt settings
app.post("/api/admin/prompt", requireAdmin, async (req, res) => {
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
        success: false,
        error: 'Chưa có Prompt mẫu nào'
      });
    }

    const promptData = result.rows[0];
    res.json({
      success: true,
      data: {
        ...promptData,
        updated_at: formatTimestampForAPI(promptData.updated_at)
      }
    });

  } catch (error) {
    console.error('Error fetching prompt template:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể lấy Prompt mẫu'
    });
  }
});

// ============================================================================
// 33. CLEANUP OLD CODES (Chạy mỗi giờ)
// ============================================================================

setInterval(async () => {
  try {
    const vnNow = getVietnamDate();
    await pool.query(
      'DELETE FROM password_reset_codes WHERE expires_at < $1',
      [vnNow]
    );
    console.log('✅ Cleaned up expired reset codes');
  } catch (error) {
    console.error('❌ Error cleaning up codes:', error);
  }
}, 60 * 60 * 1000);

// ============================================================================
// HEALTH CHECK
// ============================================================================
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", time: new Date().toISOString() });
});

// ============================================================================
// 34. FRONTEND ROUTES
// ============================================================================

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

// ============================================================================
// 35. START SERVER
// ============================================================================

const PORT = parseInt(process.env.PORT || "5000", 10);
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`ℹ️  Local: http://localhost:${PORT}/`);
});

// ============================================================================
// 36. EXPORT DEFAULT APP
// ============================================================================

export default app;
