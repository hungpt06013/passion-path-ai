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
import Anthropic from '@anthropic-ai/sdk';
import multer from "multer";
import XLSX from "xlsx";
import Joi from "joi";
import nodemailer from 'nodemailer';

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
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// Verify email configuration
transporter.verify(function(error, success) {
  if (error) {
    console.error('❌ Email configuration error:', error.message);
  } else {
    console.log('✅ Email server is ready');
  }
});

// OpenAI client
const rawOpenAiKey = (process.env.OPENAI_API_KEY || "").trim();
const openAiKey = rawOpenAiKey.replace(/^['"]|['"]$/g, "");

if (!openAiKey || openAiKey.length < 20) {
  console.error("❌❌❌ OPENAI_API_KEY NOT SET OR INVALID!");
  console.error("❌ Key length:", openAiKey.length);
} else {
  console.log("✅ OPENAI key valid, length:", openAiKey.length, "last6:", openAiKey.slice(-6));
}

// Anthropic client
const rawAnthropicKey = (process.env.ANTHROPIC_API_KEY || "").trim();
const anthropicKey = rawAnthropicKey.replace(/^['"]|['"]$/g, "");

let anthropic = null;
if (anthropicKey && anthropicKey.length > 20) {
  anthropic = new Anthropic({ apiKey: anthropicKey });
  console.log("✅ Anthropic key valid, length:", anthropicKey.length, "last6:", anthropicKey.slice(-6));
} else {
  console.warn("⚠️ ANTHROPIC_API_KEY not set");
}

// ✅ KHAI BÁO CÁC BIẾN AI CONFIG TRƯỚC (di chuyển từ dòng 175 lên đây)
const AI_PROVIDER = process.env.AI_PROVIDER || 'openai';
const CLAUDE_MODEL = process.env.CLAUDE_MODEL || "claude-sonnet-4-20250514";
const FALLBACK_CLAUDE_MODEL = process.env.FALLBACK_CLAUDE_MODEL || "claude-3-5-haiku-20241022";
const PREFERRED_OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-5-mini";
const FALLBACK_OPENAI_MODEL = process.env.FALLBACK_OPENAI_MODEL || "gpt-5";

// ✅ SAU ĐÓ MỚI LOG (di chuyển từ dòng 63 xuống đây)
console.log(`🤖 AI Provider: ${AI_PROVIDER.toUpperCase()}`);
if (AI_PROVIDER === 'claude') {
  console.log(`📋 Claude Model: ${CLAUDE_MODEL}`);
  console.log(`📋 Fallback Model: ${FALLBACK_CLAUDE_MODEL}`);
} else {
  console.log(`📋 OpenAI Model: ${PREFERRED_OPENAI_MODEL}`);
  console.log(`📋 Fallback Model: ${FALLBACK_OPENAI_MODEL}`);
}

const openai = new OpenAI({ apiKey: openAiKey });

// __dirname ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// public dir
const publicDir = path.resolve(process.env.PUBLIC_DIR || path.join(__dirname, "public"));

// parsers
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// ✅ SERVE PUBLIC FOLDER TRƯỚC
if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir));
  console.log(`✅ Serving static files from: ${publicDir}`);
} else {
  console.warn(`⚠️ Static folder not found: ${publicDir}`);
}

// ✅ SAU ĐÓ MỚI SERVE DATA FOLDER
const dataDir = path.join(__dirname, 'Data');
if (fs.existsSync(dataDir)) {
  app.use('/Data', express.static(dataDir));
  console.log(`✅ Serving Data folder from: ${dataDir}`);
} else {
  console.warn(`⚠️ Data folder not found: ${dataDir}`);
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
    const client = await pool.connect();
    try {
      await client.query("SET client_encoding = 'UTF8'");
    } catch (e) {
      console.warn("⚠️ Could not set client_encoding to UTF8:", e.message);
    }
    client.release();
    console.log(`✅ PostgreSQL connected`);
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
function getCleanSecret() {
  const rawSecret = process.env.JWT_SECRET || "dev_local_secret";
  return rawSecret.replace(/^['"]|['"]$/g, "");
}
// ✅ CLEAN JWT_SECRET - Remove quotes nếu có
function makeToken(userId) {
  return jwt.sign(
    { userId }, 
    getCleanSecret(), // ✅ Dùng helper thay vì inline
    { 
      expiresIn: "2h",
      algorithm: 'HS256'
    }
  );
}
// AI config - CRITICAL: Temperature MUST be 1
const MAX_AI_DAYS = parseInt(process.env.MAX_AI_DAYS || "90", 10);
const MAX_AI_TOKENS = parseInt(process.env.MAX_AI_TOKENS || "200000", 10);
const TOKENS_PER_DAY = parseInt(process.env.TOKENS_PER_DAY || "800", 10);
//const AI_PROVIDER = process.env.AI_PROVIDER || 'openai'; // 'openai' hoặc 'claude'
//const CLAUDE_MODEL = process.env.CLAUDE_MODEL || "claude-3-5-sonnet-20241022";
//const FALLBACK_CLAUDE_MODEL = process.env.FALLBACK_CLAUDE_MODEL || "claude-3-haiku-20240307";
//const PREFERRED_OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-5-mini";
//const FALLBACK_OPENAI_MODEL = process.env.FALLBACK_OPENAI_MODEL || "gpt-5";
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
//01/01 rem tạm
/*async function callOpenAIWithFallback({ messages, desiredCompletionTokens }) {
  console.log("🔍 PREFERRED_OPENAI_MODEL:", PREFERRED_OPENAI_MODEL); // ✅ THÊM DÒNG NÀY
  const capped = Math.max(MIN_COMPLETION_TOKENS, Math.min(desiredCompletionTokens, MAX_AI_TOKENS - SAFETY_MARGIN_TOKENS));
  try {
    const params = buildOpenAIParams({ model: PREFERRED_OPENAI_MODEL, messages, maxCompletionTokens: capped });
    console.log("📤 Trying model:", params.model); // ✅ THÊM DÒNG NÀY
    return await openai.chat.completions.create(params);
  } catch (err) {
    console.error("❌ Model failed:", PREFERRED_OPENAI_MODEL, "Error:", err.message);
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
}*/

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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
        await pool.query(`
      DO $$ 
      BEGIN
        -- Thêm detailed_feedback
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns 
          WHERE table_name = 'learning_roadmaps' 
          AND column_name = 'detailed_feedback'
        ) THEN
          ALTER TABLE learning_roadmaps ADD COLUMN detailed_feedback TEXT;
        END IF;

        -- Thêm recommended_category
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns 
          WHERE table_name = 'learning_roadmaps' 
          AND column_name = 'recommended_category'
        ) THEN
          ALTER TABLE learning_roadmaps ADD COLUMN recommended_category VARCHAR(100);
        END IF;

        -- Thêm actual_learning_outcomes
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns 
          WHERE table_name = 'learning_roadmaps' 
          AND column_name = 'actual_learning_outcomes'
        ) THEN
          ALTER TABLE learning_roadmaps ADD COLUMN actual_learning_outcomes TEXT;
        END IF;

        -- Thêm improvement_suggestions
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns 
          WHERE table_name = 'learning_roadmaps' 
          AND column_name = 'improvement_suggestions'
        ) THEN
          ALTER TABLE learning_roadmaps ADD COLUMN improvement_suggestions TEXT;
        END IF;
      END $$;
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
        study_duration DECIMAL(4,2) NOT NULL CHECK (study_duration > 0),
        completion_status VARCHAR(20) DEFAULT 'NOT_STARTED' CHECK (completion_status IN ('NOT_STARTED', 'IN_PROGRESS', 'COMPLETED', 'SKIPPED')),
        study_date DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP,
        UNIQUE(roadmap_id, day_number)
      );
    `);
    
    // ✅ THÊM CỘT usage_instructions cho learning_roadmap_details
    await pool.query(`
      DO $$ 
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns 
          WHERE table_name = 'learning_roadmap_details' 
          AND column_name = 'usage_instructions'
        ) THEN
          ALTER TABLE learning_roadmap_details ADD COLUMN usage_instructions TEXT;
        END IF;
      END $$;
    `);

    // ✅ THÊM CỘT usage_instructions cho learning_roadmap_details_system
    await pool.query(`
      DO $$ 
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns 
          WHERE table_name = 'learning_roadmap_details_system' 
          AND column_name = 'usage_instructions'
        ) THEN
          ALTER TABLE learning_roadmap_details_system ADD COLUMN usage_instructions TEXT;
        END IF;
      END $$;
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

    // Insert dữ liệu mẫu nếu như bảng trống
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

// ✅ RESET SEQUENCE VỀ GIÁ TRỊ MAX HIỆN TẠI
await pool.query(`
  SELECT setval('categories_id_seq', COALESCE((SELECT MAX(id) FROM categories), 1));
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
    // Thêm vào hàm initDB() (sau phần tạo các table khác)
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_user_feedback_user ON user_feedback(user_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_user_feedback_created ON user_feedback(created_at DESC);`);
    // ✅ THÊM cột manual_prompt_template
    await pool.query(`
      DO $$ 
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns 
          WHERE table_name = 'admin_settings' 
          AND column_name = 'manual_prompt_template'
        ) THEN
          ALTER TABLE admin_settings ADD COLUMN manual_prompt_template TEXT;
        END IF;
      END $$;
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS password_reset_codes (
        id SERIAL PRIMARY KEY,
        email TEXT NOT NULL,
        code VARCHAR(6) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        used BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_reset_email ON password_reset_codes(email);
    `);
    
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_reset_code ON password_reset_codes(code);
    `);
    console.log("✅ DB initialized");
  } catch (err) {
    console.error("❌ DB init error:", err && err.message ? err.message : err);
  }
}
initDB();

// ---------------- Auth middlewares ----------------
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
    const payload = jwt.verify(token, getCleanSecret(), { // ✅ Dùng helper
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
    const payload = jwt.verify(token, getCleanSecret(), { // ✅ Dùng helper
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
// ========== HELPER FUNCTIONS ==========
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
/// ============== OPTIMIZED AI ROADMAP GENERATION ==============

// Link validation - GIỮ ĐƠN GIẢN, KHÔNG QUÁ STRICT
/*
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
// Parse multiple links from a string separated by semicolon or newline
function parseMultipleLinks(linkString) {
    if (!linkString) return [];
    
    // Split by semicolon or newline, then clean up
    const links = linkString
        .split(/[;\n]/)
        .map(link => link.trim())
        .filter(link => link && link.match(/^https?:\/\//i));
    
    return links;
}

// Format links for display (join with <br> for HTML)
function formatLinksForDisplay(linkString) {
    const links = parseMultipleLinks(linkString);
    if (links.length === 0) return 'N/A';
    
    return links.map(link => {
        const domain = new URL(link).hostname.replace(/^www\./, '');
        return `<a href="${link}" target="_blank" style="color: #007bff; display: block; margin: 3px 0;">${domain}</a>`;
    }).join('');
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
        } catch (e) { }
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
*/
// Main AI roadmap generation endpoint
// server.js (CHỈ SỬA PHẦN /api/generate-roadmap-ai ENDPOINT)
//01/01 xóa những hàm ko dùng
/*async function validateBasicUrl(url) {
  try {
    if (!url || typeof url !== 'string') return false;
    const urlObj = new URL(url);
    return urlObj.protocol === 'http:' || urlObj.protocol === 'https:';
  } catch {
    return false;
  }
}
*/
// ✅ THÊM HÀM MỚI - Đặt sau hàm validateBasicUrl (khoảng dòng 850)

/**
 * Validate URL với chiến lược fallback 404
 * Nếu URL gốc bị 404, tự động loại bỏ các path segment từ phải sang trái
 */
//01/01 xóa những hàm ko dùng
/*async function validateAndFallbackUrl(url, timeout = 5000) {
  try {
    if (!url || typeof url !== 'string') {
      return { success: false, finalUrl: null, navigationSteps: null };
    }
    
    const urlObj = new URL(url);
    if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
      return { success: false, finalUrl: null, navigationSteps: null };
    }

    // Helper function để check URL
    const checkUrl = async (testUrl) => {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);
        
        const response = await fetch(testUrl, {
          method: 'HEAD',
          redirect: 'follow',
          signal: controller.signal,
          headers: { 'User-Agent': 'Mozilla/5.0' }
        });
        
        clearTimeout(timeoutId);
        return response.ok; // true if 200-299
      } catch (e) {
        return false;
      }
    };

    // Thử URL gốc trước
    console.log(`🔍 Checking original URL: ${url}`);
    if (await checkUrl(url)) {
      console.log(`✅ Original URL OK`);
      return { success: true, finalUrl: url, navigationSteps: null };
    }

    console.log(`❌ Original URL failed, starting fallback...`);

    // Chiến lược Fallback: Loại bỏ path segment từ phải sang trái
    const originalPath = urlObj.pathname;
    const pathParts = originalPath.split('/').filter(p => p.length > 0);
    
    // Track các segment đã remove để tạo hướng dẫn
    const removedSegments = [];
    
    while (pathParts.length > 0) {
      // Remove segment cuối cùng
      const removed = pathParts.pop();
      removedSegments.unshift(removed); // Thêm vào đầu để giữ đúng thứ tự
      
      // Build fallback URL
      const fallbackPath = pathParts.length > 0 ? '/' + pathParts.join('/') + '/' : '/';
      const fallbackUrl = `${urlObj.protocol}//${urlObj.host}${fallbackPath}`;
      
      console.log(`🔄 Trying fallback: ${fallbackUrl}`);
      
      if (await checkUrl(fallbackUrl)) {
        console.log(`✅ Fallback succeeded: ${fallbackUrl}`);
        
        // Tạo hướng dẫn navigation
        const navigationSteps = generateNavigationSteps(removedSegments, urlObj.host);
        
        return { 
          success: true, 
          finalUrl: fallbackUrl, 
          navigationSteps: navigationSteps,
          wasOriginal: false
        };
      }
    }
    
    // Tất cả fallback đều fail
    console.log(`❌ All fallbacks failed for: ${url}`);
    return { success: false, finalUrl: null, navigationSteps: null };
    
  } catch (e) {
    console.error('validateAndFallbackUrl error:', e.message);
    return { success: false, finalUrl: null, navigationSteps: null };
  }
}*/

/**
 * Tạo hướng dẫn navigation từ các segment đã remove
 */
/*function generateNavigationSteps(segments, hostname) {
  if (!segments || segments.length === 0) return null;
  
  // Decode URL-encoded segments
  const decodedSegments = segments.map(seg => {
    try {
      return decodeURIComponent(seg);
    } catch {
      return seg;
    }
  });
  
  // Tạo hướng dẫn từng bước
  let steps = `📍 Hướng dẫn điều hướng trên ${hostname}:\n\n`;
  
  if (decodedSegments.length === 1) {
    steps += `➡️ Tìm và click vào mục: "${decodedSegments[0]}"`;
  } else {
    steps += `Từ trang đích, làm theo các bước:\n`;
    decodedSegments.forEach((segment, index) => {
      // Clean up segment name (remove file extensions, special chars)
      const cleanName = segment.replace(/\.(html|htm|php|aspx)$/i, '').replace(/[-_]/g, ' ');
      steps += `${index + 1}. Tìm và click vào: "${cleanName}"\n`;
    });
  }
  
  return steps.trim();
}*/
//01/01 end xóa những hàm ko dùng
// Improved fallback links by category
const QUALITY_FALLBACK_LINKS = {
  'toán học': {
    exercises: [
      "https://www.khanacademy.org/math",
      "https://brilliant.org/courses/mathematical-thinking/",
      "https://artofproblemsolving.com/alcumus",
      "https://www.mathsisfun.com/puzzles/",
      "https://nrich.maths.org/frontpage"
    ],
    materials: [
      "https://www.khanacademy.org/math",
      "https://brilliant.org/wiki/mathematics/",
      "https://www.mathsisfun.com/",
      "https://mathworld.wolfram.com/",
      "https://www.cut-the-knot.org/"
    ]
  },
  'lập trình': {
    exercises: [
      "https://leetcode.com/problemset/",
      "https://www.hackerrank.com/domains/algorithms",
      "https://codeforces.com/problemset",
      "https://www.codewars.com/kata",
      "https://exercism.org/tracks"
    ],
    materials: [
      "https://www.freecodecamp.org/learn",
      "https://developer.mozilla.org/en-US/docs/Learn",
      "https://www.w3schools.com/",
      "https://javascript.info/",
      "https://python.org/about/gettingstarted/"
    ]
  },
  'tiếng anh': {
    exercises: [
      "https://www.englishclub.com/grammar/",
      "https://www.perfect-english-grammar.com/grammar-exercises.html",
      "https://learnenglish.britishcouncil.org/skills/listening",
      "https://www.englishpage.com/",
      "https://www.usingenglish.com/quizzes/"
    ],
    materials: [
      "https://learnenglish.britishcouncil.org/",
      "https://www.bbc.co.uk/learningenglish/",
      "https://www.englishclub.com/",
      "https://www.thoughtco.com/esl-4133095",
      "https://www.englishforeveryone.org/"
    ]
  },
  'default': {
    exercises: [
      "https://www.khanacademy.org/",
      "https://www.coursera.org/",
      "https://www.edx.org/",
      "https://brilliant.org/",
      "https://www.udemy.com/"
    ],
    materials: [
      "https://www.khanacademy.org/",
      "https://www.coursera.org/",
      "https://www.youtube.com/education",
      "https://ocw.mit.edu/",
      "https://www.edx.org/"
    ]
  }
};

function getFallbackLinksByCategory(category) {
  const cat = (category || '').toLowerCase();
  
  if (cat.includes('toán')) return QUALITY_FALLBACK_LINKS['toán học'];
  if (cat.includes('lập trình') || cat.includes('program')) return QUALITY_FALLBACK_LINKS['lập trình'];
  if (cat.includes('tiếng anh') || cat.includes('english')) return QUALITY_FALLBACK_LINKS['tiếng anh'];
  
  return QUALITY_FALLBACK_LINKS['default'];
}

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

/*rem lại để test của claude
app.post("/api/generate-roadmap-ai", requireAuth, async (req, res) => {
  let historyId = null;
  
  try {
    console.log('🚀 AI REQUEST RECEIVED');
    console.log('📦 Request body keys:', Object.keys(req.body));
    console.log('👤 User ID:', req.user.id);
    
    if (!process.env.OPENAI_API_KEY) {
      return res.status(503).json({ 
        success: false, 
        error: "Tính năng AI chưa được cấu hình. Vui lòng liên hệ quản trị viên." 
      });
    }

    // ✅ Get data from 20 questions
    const {
      roadmap_name, category, sub_category, start_level, duration_days, duration_hours, expected_outcome,
      q1_roadmap_name, q2_category, q3_category_detail,
      q4_main_purpose, q4_main_purpose_other,
      q5_specific_goal, q5_current_job,
      q6_learning_duration, q7_current_level, q8_skills_text,
      q9_daily_time, q10_weekly_sessions, q11_program_days,
      q12_learning_styles, q12_learning_styles_other,
      q13_learning_combinations, q13_learning_combinations_other,
      q14_challenges, q14_challenges_other,
      q15_motivation, q15_motivation_other,
      q16_material_types, q16_material_types_other,
      q17_material_language,
      q18_assessment_types, q19_result_display,
      q20_assessment_frequency, q20_assessment_frequency_other
    } = req.body;

    // ✅ Process arrays with "Other" option
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

    // ✅ Build final data
    const finalData = {
      roadmap_name: q1_roadmap_name || roadmap_name,
      category: q2_category || category,
      category_detail: q3_category_detail || sub_category,
      main_purpose: processRadioWithOther(q4_main_purpose, q4_main_purpose_other),
      specific_goal: q5_specific_goal || expected_outcome,
      current_job: q5_current_job || 'Chưa xác định',
      learning_duration: q6_learning_duration || 'Chưa xác định',
      current_level: q7_current_level || start_level,
      skills_text: q8_skills_text || 'Chưa xác định',
      daily_time: (() => {
        const minutes = parseInt(q9_daily_time) || 0;
        if (minutes === 0) return '0m';
        const hours = Math.floor(minutes / 60);
        const remainingMinutes = minutes % 60;
        if (hours === 0) return `${minutes}m`;
        if (remainingMinutes === 0) return `${hours}h`;
        return `${hours}h ${remainingMinutes}m`;
      })(),
      weekly_sessions: q10_weekly_sessions || 'Chưa xác định',
      program_days: q11_program_days || duration_days,
      learning_styles: processArrayWithOther(q12_learning_styles, q12_learning_styles_other),
      learning_combinations: processArrayWithOther(q13_learning_combinations, q13_learning_combinations_other),
      challenges: processArrayWithOther(q14_challenges, q14_challenges_other),
      motivation: processArrayWithOther(q15_motivation, q15_motivation_other),
      material_types: processArrayWithOther(q16_material_types, q16_material_types_other),
      material_language: q17_material_language || 'Tiếng Việt',
      assessment_types: Array.isArray(q18_assessment_types) ? q18_assessment_types.join(', ') : 'Chưa xác định',
      result_display: Array.isArray(q19_result_display) ? q19_result_display.join(', ') : 'Chưa xác định',
      assessment_frequency: processRadioWithOther(q20_assessment_frequency, q20_assessment_frequency_other),
      start_level: q7_current_level || start_level,
      duration_days: q11_program_days || duration_days,
      duration_hours: duration_hours,
      expected_outcome: q5_specific_goal || expected_outcome
    };

    // ✅ Validate required fields
    if (!finalData.roadmap_name || !finalData.category || !finalData.current_level || 
        !finalData.program_days || !finalData.specific_goal) {
      return res.status(400).json({ 
        success: false, 
        error: "Thiếu thông tin bắt buộc để tạo lộ trình" 
      });
    }

    const actualDays = parseInt(finalData.program_days);
    const dailyMinutes = parseInt(finalData.daily_time) || 0;

    if (dailyMinutes < 15 || dailyMinutes > 720) {
      return res.status(400).json({ 
        success: false, 
        error: "Thời gian học mỗi ngày phải từ 15-720 phút (0.25-12 giờ)" 
      });
    }

    const hoursPerDay = dailyMinutes / 60;
    const totalHours = hoursPerDay * actualDays;

    console.log(`✅ Time: ${dailyMinutes}min = ${hoursPerDay.toFixed(2)}h/day × ${actualDays} days = ${totalHours.toFixed(2)}h total`);

    if (isNaN(actualDays) || actualDays <= 0 || actualDays > MAX_AI_DAYS) {
      return res.status(400).json({ 
        success: false, 
        error: `Số ngày phải từ 1 đến ${MAX_AI_DAYS}` 
      });
    }

    const roadmapStartDate = new Date();
    roadmapStartDate.setHours(0, 0, 0, 0);

    console.log(`Generating AI roadmap: ${finalData.roadmap_name} (${actualDays} days, ${hoursPerDay}h/day)`);

    // ✅ Build improved prompt with explicit link requirements
    const promptTemplate = await getPromptTemplate();
    let userPrompt = promptTemplate.prompt_template;
    let systemPrompt = `Bạn là chuyên gia thiết kế lộ trình học. 

**YÊU CẦU QUAN TRỌNG VỀ LINKS:**
1. Mỗi ngày học PHẢI có link học liệu CỤ THỂ, TRỰC TIẾP đến bài học/video/exercise
2. KHÔNG được dùng link chung chung như /courses/, /learn/, /topics/
3. Link phải hoạt động, không yêu cầu đăng nhập trả phí
4. Mỗi link phải khác nhau, không trùng lặp

Trả về JSON format:
${promptTemplate.json_format_response}`;

    const variableMapping = {
      'CATEGORY': finalData.category,
      'SUB_CATEGORY': finalData.category_detail,
      'ROADMAP_NAME': finalData.roadmap_name,
      'MAIN_PURPOSE': finalData.main_purpose,
      'SPECIFIC_GOAL': finalData.specific_goal,
      'CURRENT_JOB': finalData.current_job,
      'STUDY_TIME': finalData.learning_duration,
      'CURRENT_LEVEL': finalData.current_level,
      'SKILLS_TO_IMPROVE': finalData.skills_text,
      'DAILY_TIME': finalData.daily_time,
      'WEEKLY_FREQUENCY': finalData.weekly_sessions,
      'TOTAL_DURATION': finalData.program_days,
      'LEARNING_STYLE': finalData.learning_styles,
      'LEARNING_METHOD': finalData.learning_combinations,
      'DIFFICULTIES': finalData.challenges,
      'MOTIVATION': finalData.motivation,
      'MATERIAL_TYPE': finalData.material_types,
      'MATERIAL_LANGUAGE': finalData.material_language,
      'ASSESSMENT_TYPE': finalData.assessment_types,
      'RESULT_DISPLAY': finalData.result_display,
      'ASSESSMENT_FREQUENCY': finalData.assessment_frequency
    };

    Object.keys(variableMapping).forEach(key => {
      userPrompt = userPrompt.replace(new RegExp(`<${key}>`, 'g'), variableMapping[key]);
    });

    // ✅ Save history BEFORE AI call
    const historyResult = await pool.query(
      `INSERT INTO ai_query_history (user_id, prompt_content, status) 
       VALUES ($1, $2, 'PENDING') RETURNING id`,
      [req.user.id, JSON.stringify({ 
        roadmap_name: finalData.roadmap_name,
        category: finalData.category,
        duration_days: actualDays,
        timestamp: new Date().toISOString()
      })]
    );
    historyId = historyResult.rows[0].id;

    const estimatedTokensPerDay = TOKENS_PER_DAY;
    const desiredTokens = Math.min(actualDays * estimatedTokensPerDay, MAX_AI_TOKENS - SAFETY_MARGIN_TOKENS);

    let aiResponse = null;
    let attempts = 0;
    const MAX_ATTEMPTS = 2;

    while (attempts < MAX_ATTEMPTS && !aiResponse) {
      attempts++;
      try {
        console.log(`AI attempt ${attempts}/${MAX_ATTEMPTS}...`);
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
        console.error(`AI attempt ${attempts} failed:`, e.message);
        if (attempts === MAX_ATTEMPTS) throw e;
      }
    }

    if (!aiResponse) {
      throw new Error("AI không trả về kết quả sau nhiều lần thử");
    }

    // ✅ Parse JSON response
    let roadmapData = null;

    // Bước 1: Trích xuất JSON từ markdown code block
    const jsonMatch = aiResponse.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
    const jsonText = jsonMatch ? jsonMatch[1] : aiResponse;

    console.log('🔍 Raw AI response length:', aiResponse.length);
    console.log('📄 Extracted JSON text (first 500 chars):', jsonText.substring(0, 500));

    try {
      // Bước 2: Thử parse trực tiếp
      roadmapData = JSON.parse(jsonText);
      console.log('âœ… JSON parsed successfully on first attempt');
    } catch (e) {
      console.warn('⚠️ First parse failed, trying cleanup...', e.message);
      
      // Bước 3: Làm sạch và thử lại
      const cleaned = jsonText
        .replace(/[\u2018\u2019]/g, "'")
        .replace(/[\u201C\u201D]/g, '"')
        .replace(/,\s*([}\]])/g, '$1')
        .replace(/^\s*[\r\n]+/gm, '') // Xóa dòng trống
        .trim();
      
      try {
        roadmapData = JSON.parse(cleaned);
        console.log('âœ… JSON parsed after cleanup');
      } catch (e2) {
        console.error('âŒ Failed to parse JSON even after cleanup');
        console.error('Cleaned text (first 1000 chars):', cleaned.substring(0, 1000));
        console.error('Parse error:', e2.message);
        
        // Bước 4: Thử tìm JSON object đầu tiên trong response
        const jsonObjectMatch = aiResponse.match(/\{[\s\S]*\}/);
        if (jsonObjectMatch) {
          try {
            roadmapData = JSON.parse(jsonObjectMatch[0]);
            console.log('âœ… JSON parsed from extracted object');
          } catch (e3) {
            console.error('âŒ Cannot parse extracted object');
            throw new Error(`AI trả về format không hợp lệ. Chi tiết: ${e2.message}. Raw response đã được log.`);
          }
        } else {
          throw new Error(`AI trả về format không hợp lệ. Không tìm thấy JSON object. Raw response: ${aiResponse.substring(0, 500)}...`);
        }
      }
    }

    // Bước 5: Validate structure
    if (!roadmapData || typeof roadmapData !== 'object') {
      throw new Error('AI trả về không phải là object hợp lệ');
    }

    console.log('📊 Parsed roadmap keys:', Object.keys(roadmapData));
    console.log('📊 Roadmap array length:', Array.isArray(roadmapData.roadmap) ? roadmapData.roadmap.length : 'NOT AN ARRAY');

    let analysis = roadmapData.analysis || 'Không có phân tích';
    let days = Array.isArray(roadmapData.roadmap) ? roadmapData.roadmap : 
                (Array.isArray(roadmapData) ? roadmapData : []);

    if (days.length !== actualDays) {
      console.warn(`AI returned ${days.length} days instead of ${actualDays}, padding...`);
      if (days.length < actualDays) {
        const fallbackLinks = getFallbackLinksByCategory(finalData.category);
        for (let i = days.length; i < actualDays; i++) {
          days.push({
            day_number: i + 1,
            daily_goal: `Ôn tập và củng cố kiến thức ngày ${i + 1}`,
            learning_content: `Ôn lại các kiến thức đã học từ đầu khóa`,
            practice_exercises: `Làm bài tập tổng hợp`,
            learning_materials: fallbackLinks.materials[i % fallbackLinks.materials.length],
            study_guide: `Ôn tập toàn bộ nội dung, làm bài kiểm tra tổng hợp`,
            study_duration: hoursPerDay
          });
        }
      } else {
        days = days.slice(0, actualDays);
      }
    }

    // Normalize and validate links with fallback strategy
    const normalizedDays = [];
    const fallbackLinks = getFallbackLinksByCategory(finalData.category);
    const usedLinks = new Set();

    for (let i = 0; i < actualDays; i++) {
      const d = days[i] || {};
      
      // Extract material links - XỬ LÝ NHIỀU LINK
      let rawMaterialLink = String(d.learning_materials || d.materials || '').trim();
      let validatedLinks = [];
      let navigationGuides = [];
      
      // ✅ PARSE NHIỀU LINK - VALIDATE TẤT CẢ
      if (rawMaterialLink) {
        // Tách theo dấu ; hoặc xuống dòng
        const linkArray = rawMaterialLink
          .split(/[;\n]/)
          .map(link => link.trim())
          .filter(link => link && link.match(/^https?:\/\//i));
        
        // ✅ VALIDATE TẤT CẢ CÁC LINK
        for (const link of linkArray) {
          if (await validateBasicUrl(link)) {
            console.log(`\n🔗 Processing link ${validatedLinks.length + 1} for day ${i + 1}: ${link}`);
            
            const validationResult = await validateAndFallbackUrl(link, 5000);
            
            if (validationResult.success) {
              validatedLinks.push(validationResult.finalUrl);
              
              // ✅ LƯU NAVIGATION STEPS NẾU URL BỊ MODIFY
              if (validationResult.navigationSteps) {
                navigationGuides.push(validationResult.navigationSteps);
                console.log(`📍 Navigation steps added for link ${validatedLinks.length}`);
              }
            } else {
              console.log(`⚠️ Link validation failed, skipping: ${link}`);
            }
          }
        }
      }
      
      // ✅ NẾU KHÔNG CÓ LINK HỢP LỆ NÀO, DÙNG FALLBACK
      let finalMaterialLink = '';
      let navigationGuide = '';
      
      if (validatedLinks.length > 0) {
        // Join tất cả links hợp lệ bằng dấu ;
        finalMaterialLink = validatedLinks.join('; ');
        
        // Merge tất cả navigation guides
        if (navigationGuides.length > 0) {
          navigationGuide = navigationGuides.map((guide, idx) => 
            `📌 Link ${idx + 1}:\n${guide}`
          ).join('\n\n---\n\n');
        }
      } else {
        // Dùng fallback nếu không có link nào hợp lệ
        finalMaterialLink = fallbackLinks.materials[i % fallbackLinks.materials.length];
        navigationGuide = '';
        console.log(`⚠️ Using fallback link for day ${i + 1}`);
      }
      
      // Check duplicate (chỉ check link đầu tiên để tránh trùng lặp hoàn toàn)
      const firstLink = validatedLinks[0] || finalMaterialLink;
      if (usedLinks.has(firstLink)) {
        finalMaterialLink = fallbackLinks.materials[i % fallbackLinks.materials.length];
        navigationGuide = '';
      }
      
      usedLinks.add(firstLink);

      // ✅ MERGE navigation guide vào study_guide
      let finalStudyGuide = String(d.study_guide || d.usage_instructions || d.instructions || d.guide || `Hướng dẫn học tập ngày ${i + 1}`).trim();
      
      if (navigationGuide) {
        finalStudyGuide = `${finalStudyGuide}\n\n---\n\n${navigationGuide}`;
      }

      const normalized = {
        day_number: i + 1,
        daily_goal: String(d.daily_goal || d.goal || `Mục tiêu ngày ${i + 1}`).trim().substring(0, 500),
        learning_content: String(d.learning_content || d.content || `Nội dung học tập ngày ${i + 1}`).trim().substring(0, 1000),
        practice_exercises: String(d.practice_exercises || d.exercises || `Bài tập thực hành ngày ${i + 1}`).trim().substring(0, 1000),
        learning_materials: finalMaterialLink, // ✅ CÓ THỂ CÓ NHIỀU LINK, CÁCH NHAU BỞI ;
        study_guide: finalStudyGuide.substring(0, 2000),
        study_duration: parseFloat(d.study_duration || d.hours || hoursPerDay),
        completion_status: 'NOT_STARTED',
        study_date: new Date(roadmapStartDate.getTime() + (i * 86400000)).toISOString().split('T')[0]
      };

      normalizedDays.push(normalized);
    }

    console.log(`✅ AI generated ${normalizedDays.length} days successfully`);

    // ✅ Update history to SUCCESS
    if (historyId) {
      await pool.query(
        `UPDATE ai_query_history 
         SET status = 'SUCCESS', 
             response_tokens = $1,
             updated_at = CURRENT_TIMESTAMP 
         WHERE id = $2`,
        [normalizedDays.length, historyId]
      );
    }

    return res.json({
      success: true,
      message: "Tạo lộ trình AI thành công",
      analysis: analysis,
      data: normalizedDays,
      metadata: {
        total_days: normalizedDays.length,
        start_date: roadmapStartDate.toISOString().split('T')[0],
        hours_per_day: hoursPerDay,
        total_hours: totalHours,
        history_id: historyId
      }
    });

  } catch (error) {
    console.error("❌ AI GENERATION ERROR:", error.message);
    
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
*/

// =Begin 01/01===========================================

// ============================================
// FUNCTION 1: Validate URLs with retry logic
// ============================================
async function validateUrlWithRetry(url, maxRetries = 2, timeout = 5000) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);
      
      const response = await fetch(url, {
        method: 'HEAD',
        redirect: 'follow',
        signal: controller.signal,
        headers: { 'User-Agent': 'Mozilla/5.0' }
      });
      
      clearTimeout(timeoutId);
      
      // Accept 2xx and 3xx status codes
      if (response.status >= 200 && response.status < 400) {
        return { valid: true, url: url };
      }
      
      // If 404, try removing last path segment (fallback strategy)
      if (response.status === 404 && attempt === 1) {
        const urlObj = new URL(url);
        const pathParts = urlObj.pathname.split('/').filter(p => p);
        
        if (pathParts.length > 1) {
          pathParts.pop(); // Remove last segment
          const fallbackUrl = `${urlObj.origin}/${pathParts.join('/')}`;
          console.log(`âš ï¸ 404 detected, trying fallback: ${fallbackUrl}`);
          
          // Recursive call with fallback URL
          return await validateUrlWithRetry(fallbackUrl, 1, timeout);
        }
      }
      
    } catch (error) {
      if (attempt === maxRetries) {
        console.error(`âŒ URL validation failed after ${maxRetries} attempts: ${url}`);
        return { valid: false, url: url };
      }
      await new Promise(resolve => setTimeout(resolve, 1000)); // Wait 1s before retry
    }
  }
  
  return { valid: false, url: url };
}

// ============================================
// FUNCTION 2: Improved Fallback Links
// ============================================
const IMPROVED_FALLBACK_LINKS = {
  'Toán học': {
    materials: [
      "https://www.khanacademy.org/math",
      "https://brilliant.org/courses/",
      "https://www.mathsisfun.com/",
      "https://www.wolframalpha.com/examples/mathematics"
    ]
  },
  'Lập trình': {
    materials: [
      "https://www.freecodecamp.org/learn",
      "https://developer.mozilla.org/en-US/docs/Learn",
      "https://www.w3schools.com/",
      "https://javascript.info/"
    ]
  },
  'Tiếng Anh': {
    materials: [
      "https://learnenglish.britishcouncil.org/",
      "https://www.englishclub.com/",
      "https://www.bbc.co.uk/learningenglish/",
      "https://www.perfect-english-grammar.com/"
    ]
  },
  'default': {
    materials: [
      "https://www.coursera.org/",
      "https://www.edx.org/",
      "https://www.udemy.com/",
      "https://www.youtube.com/education"
    ]
  }
};

//01/01 rem tạm
/*function getImprovedFallbackLink(category, dayIndex) {
  const cat = (category || '').toLowerCase();
  let fallbackList;
  
  if (cat.includes('toÃ¡n')) fallbackList = IMPROVED_FALLBACK_LINKS['toÃ¡n há»c'].materials;
  else if (cat.includes('láº­p trÃ¬nh') || cat.includes('program')) fallbackList = IMPROVED_FALLBACK_LINKS['láº­p trÃ¬nh'].materials;
  else if (cat.includes('tiáº¿ng anh') || cat.includes('english')) fallbackList = IMPROVED_FALLBACK_LINKS['tiáº¿ng anh'].materials;
  else fallbackList = IMPROVED_FALLBACK_LINKS['default'].materials;
  
  return fallbackList[dayIndex % fallbackList.length];
}*/
// ============================================
// ENHANCED: Call OpenAI for main content (without materials)
// ============================================
async function callOpenAIForMainContent({ messages, desiredCompletionTokens, temperature = 1 }) {
  const capped = Math.max(MIN_COMPLETION_TOKENS, Math.min(desiredCompletionTokens, MAX_AI_TOKENS - SAFETY_MARGIN_TOKENS));
  
  try {
    const params = {
      model: PREFERRED_OPENAI_MODEL,
      messages,
      max_completion_tokens: capped,
      temperature: temperature
    };
    
    console.log(`📤 OpenAI call (main content): model=${params.model}, temp=${temperature}, tokens=${capped}`);
    return await openai.chat.completions.create(params);
    
  } catch (err) {
    console.error("❌ Model failed:", PREFERRED_OPENAI_MODEL, err.message);
    
    const code = err && (err.code || (err.error && err.error.code));
    const status = err && err.status;
    
    if (code === "model_not_found" || status === 404 || String(err.message).toLowerCase().includes("model")) {
      console.warn(`⚠️ Falling back to ${FALLBACK_OPENAI_MODEL}`);
      
      const fallbackParams = {
        model: FALLBACK_OPENAI_MODEL,
        messages,
        max_completion_tokens: Math.min(capped, MAX_AI_TOKENS - SAFETY_MARGIN_TOKENS),
        temperature: temperature
      };
      
      return await openai.chat.completions.create(fallbackParams);
    }
    
    throw err;
  }
}

// ============================================
// ENHANCED: Call Claude for materials and instructions (1 SEARCH FOR ALL DAYS)
// ============================================
async function callClaudeForMaterials({ days, category, temperature = 0.3 }) {
  if (!anthropic) {
    throw new Error("Claude API key not configured");
  }

  const daysInfo = days.map(d => ({
    day_number: d.day_number,
    daily_goal: d.daily_goal,
    learning_content: d.learning_content.substring(0, 200)
  }));

  const userPrompt = `Tìm learning_materials (link cụ thể) và usage_instructions cho ${days.length} ngày học về ${category}.

Danh sách ngày học:
${JSON.stringify(daysInfo, null, 2)}

**CHIẾN LƯỢC TÌM KIẾM THÔNG MINH:**
1. Tìm kiếm 1 lần với query tổng quát về "${category}"
2. Từ kết quả tìm được, phân phối links phù hợp cho từng ngày
3. Ưu tiên nguồn có nhiều bài học (playlists, courses, series)

**YÊU CẦU:**
- Mỗi ngày PHẢI có 1 link CỤ THỂ (không trùng lặp)
- Link phải miễn phí
- Từ 1 nguồn lớn (như YouTube playlist), chọn các video khác nhau cho từng ngày
- Nếu tìm thấy khóa học có nhiều bài, sử dụng các bài khác nhau cho các ngày

**Trả về JSON format:**
{
  "search_summary": "Mô tả ngắn về nguồn tìm được",
  "materials": [
    {
      "day_number": 1,
      "learning_materials": "https://...",
      "usage_instructions": "Hướng dẫn chi tiết..."
    },
    {
      "day_number": 2,
      "learning_materials": "https://...",
      "usage_instructions": "..."
    }
  ]
}`;

  const systemPrompt = `Bạn là chuyên gia tìm kiếm tài nguyên học tập trực tuyến.
**QUAN TRỌNG - FORMAT RESPONSE:**
- BẮT BUỘC trả về ĐÚNG JSON format, KHÔNG có text thêm
- KHÔNG thêm markdown code blocks
- KHÔNG thêm giải thích trước/sau JSON
- Response PHẢI bắt đầu bằng dấu { và kết thúc bằng }

**CHIẾN LƯỢC TÌM KIẾM TỐI ƯU:**
1. Sử dụng web_search CHỈ 1 LẦN với query tổng quát
2. Tìm nguồn TỐT NHẤT (playlist, course, documentation series)
3. Từ nguồn đó, phân phối links cụ thể cho từng ngày

**VÍ DỤ:**
- Tìm "Python tutorial freeCodeCamp" → Tìm được video 4h
  → Ngày 1: 0:00-0:30 (Basics)
  → Ngày 2: 0:30-1:00 (Variables)
  → Ngày 3: 1:00-1:30 (Functions)

- Tìm "JavaScript MDN tutorial" → Tìm được series bài
  → Ngày 1: Link bài 1 (Introduction)
  → Ngày 2: Link bài 2 (Data types)
  → Ngày 3: Link bài 3 (Functions)

**LƯU Ý:** 
- Mỗi link phải ĐỘC NHẤT (không trùng)
- Nếu cùng 1 video dài, thì ghi rõ timestamp khác nhau
- Nếu cùng 1 series, thì link đến các bài khác nhau

Trả về ĐÚNG JSON format như yêu cầu.`;

  try {
    // ✅ GIỚI HẠN MAX_TOKENS CHO CLAUDE
    const CLAUDE_MAX_OUTPUT = 64000;
    const CLAUDE_SAFETY_MARGIN = 2000;
    
    const estimatedTokensPerDay = 200;
    const estimatedTotal = days.length * estimatedTokensPerDay;
    
    const cappedTokens = Math.min(
      estimatedTotal,
      CLAUDE_MAX_OUTPUT - CLAUDE_SAFETY_MARGIN
    );
    
    console.log(`📊 Claude request: days=${days.length}, estimated=${estimatedTotal}, capped=${cappedTokens}`);
    
    const params = {
      model: CLAUDE_MODEL,
      max_tokens: cappedTokens, // ✅ FIX: Dùng capped value
      temperature: temperature,
      system: systemPrompt,
      messages: [
        {
          role: 'user',
          content: userPrompt
        }
      ],
      tools: [
        {
          type: "web_search_20250305",
          name: "web_search"
        }
      ],
      stream: true
    };
    
    console.log(`📤 Claude call with WEB SEARCH for ${days.length} days: model=${params.model}, max_tokens=${params.max_tokens}`);
    
    let fullText = '';
    let chunkCount = 0;

    const stream = await anthropic.messages.create(params);

    for await (const event of stream) {
      if (event.type === 'content_block_delta' && event.delta.type === 'text_delta') {
        fullText += event.delta.text;
        chunkCount++;

        if (chunkCount % 50 === 0) {
          console.log(`📄 [Claude materials] ${chunkCount} chunks, ${fullText.length} chars so far...`);
        }
      }
    }

    console.log(`✅ [Claude materials] Streaming complete: ${fullText.length} chars`);

    return {
      choices: [{
        message: {
          content: fullText
        }
      }]
    };
    
  } catch (err) {
    console.error("❌ Claude materials failed:", CLAUDE_MODEL, err.message);
    throw err;
  }
}
// ============================================
// ENHANCED: Fix broken links with OpenAI (max 3 attempts)
// ============================================
async function fixBrokenLinksWithOpenAI(failedDays, category, maxAttempts = 3) {
  console.log(`🔧 Fixing ${failedDays.length} broken links with OpenAI (max ${maxAttempts} attempts)...`);
  
  let currentFailedDays = [...failedDays];
  let attempt = 0;
  
  while (currentFailedDays.length > 0 && attempt < maxAttempts) {
    attempt++;
    console.log(`\n🔄 OpenAI Fix Attempt ${attempt}/${maxAttempts} for ${currentFailedDays.length} days...`);
    
    const daysInfo = currentFailedDays.map(d => ({
      day_number: d.day_number,
      daily_goal: d.daily_goal,
      learning_content: d.learning_content.substring(0, 200),
      old_material: d.learning_materials
    }));

    const userPrompt = `Tìm lại learning_materials và usage_instructions cho ${currentFailedDays.length} ngày học có link lỗi.

Danh sách ngày cần sửa:
${JSON.stringify(daysInfo, null, 2)}

YÊU CẦU:
1. Tìm link MỚI, KHÁC HOÀN TOÀN với link cũ
2. Link PHẢI:
   - Miễn phí, không yêu cầu đăng nhập
   - Cụ thể, trực tiếp đến nội dung
   - Hoạt động (không bị 404)

3. Trả về JSON:
{
  "materials": [
    {
      "day_number": 1,
      "learning_materials": "https://...",
      "usage_instructions": "..."
    }
  ]
}`;

    const systemPrompt = `Bạn là chuyên gia tìm tài nguyên học tập thay thế khi link gốc bị lỗi.
Tìm nguồn TỐT HƠN, ĐÁNG TIN CẬY HƠN.`;

    try {
      const completion = await callOpenAIForMainContent({
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt }
        ],
        desiredCompletionTokens: Math.min(
          currentFailedDays.length * 300,
          MAX_AI_TOKENS - SAFETY_MARGIN_TOKENS
        ),
        temperature: 1
      });

      const text = completion?.choices?.[0]?.message?.content?.trim();
      if (!text) {
        console.warn(`⚠️ Attempt ${attempt}: No response from OpenAI`);
        continue;
      }

      const jsonMatch = text.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
      const jsonText = jsonMatch ? jsonMatch[1] : text;
      
      let parsed;
      try {
        parsed = JSON.parse(jsonText);
      } catch (e) {
        const cleaned = jsonText
          .replace(/[\u2018\u2019]/g, "'")
          .replace(/[\u201C\u201D]/g, '"')
          .replace(/,\s*([}\]])/g, '$1')
          .trim();
        parsed = JSON.parse(cleaned);
      }

      if (!parsed.materials || !Array.isArray(parsed.materials)) {
        console.warn(`⚠️ Attempt ${attempt}: Invalid response format`);
        continue;
      }

      // Validate new links
      const fixedDays = [];
      const stillFailedDays = [];

      for (const material of parsed.materials) {
        const originalDay = currentFailedDays.find(d => d.day_number === material.day_number);
        if (!originalDay) continue;

        const validation = await validateUrlSmart(material.learning_materials, 2, 8000);
        
        if (validation.valid) {
          fixedDays.push({
            ...originalDay,
            learning_materials: material.learning_materials,
            study_guide: material.usage_instructions || originalDay.study_guide
          });
          console.log(`✅ Fixed day ${material.day_number}: ${material.learning_materials}`);
        } else {
          stillFailedDays.push(originalDay);
          console.log(`❌ Still failed day ${material.day_number}`);
        }
      }

      // Update current failed list
      currentFailedDays = stillFailedDays;
      
      // Return fixed days
      if (fixedDays.length > 0) {
        return { fixedDays, remainingFailedDays: currentFailedDays };
      }

    } catch (error) {
      console.error(`❌ Fix attempt ${attempt} error:`, error.message);
    }
  }

  return { fixedDays: [], remainingFailedDays: currentFailedDays };
}

// ============================================
// ENHANCED: Use Google Search fallback for remaining errors
// ============================================
function createGoogleSearchFallback(day, category) {
  const searchQuery = encodeURIComponent(`${day.daily_goal} ${category} tutorial`);
  const googleSearchUrl = `https://www.google.com/search?q=${searchQuery}`;
  
  // ✅ Tạo guide với ký tự xuống dòng thực
  let fallbackGuide = `⚠️ Tìm link không thành công.\n🔍 Để tìm tài liệu phù hợp, vui lòng:\n1. Truy cập link tìm kiếm Google.\n2. Tìm bài học/bài tập cụ thể về "${day.daily_goal}".\n\n${day.study_guide || ''}`;
  
  // ✅ Convert \n → <br> để hiển thị đúng trong HTML
  fallbackGuide = fallbackGuide.replace(/\n/g, '<br>');

  return {
    learning_materials: googleSearchUrl,
    study_guide: fallbackGuide
  };
}

// ============================================
// MAIN: Enhanced AI Roadmap Generation
// ============================================
app.post("/api/generate-roadmap-ai", requireAuth, async (req, res) => {
  let historyId = null;
  const startTime = Date.now();
  
  try {
    console.log('🚀 AI REQUEST RECEIVED');
    
    if (!process.env.OPENAI_API_KEY) {
      return res.status(503).json({ 
        success: false, 
        error: "Tính năng AI chưa được cấu hình." 
      });
    }

    // [... existing validation code ...]
    const {
      roadmap_name, category, sub_category, start_level, duration_days, duration_hours, expected_outcome,
      q1_roadmap_name, q2_category, q3_category_detail,
      q4_main_purpose, q4_main_purpose_other,
      q5_specific_goal, q5_current_job,
      q6_learning_duration, q7_current_level, q8_skills_text,
      q9_daily_time, q10_weekly_sessions, q11_program_days,
      q12_learning_styles, q12_learning_styles_other,
      q13_learning_combinations, q13_learning_combinations_other,
      q14_challenges, q14_challenges_other,
      q15_motivation, q15_motivation_other,
      q16_material_types, q16_material_types_other,
      q17_material_language,
      q18_assessment_types, q19_result_display,
      q20_assessment_frequency, q20_assessment_frequency_other
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
      main_purpose: processRadioWithOther(q4_main_purpose, q4_main_purpose_other),
      specific_goal: q5_specific_goal || expected_outcome,
      current_job: q5_current_job || 'Chưa xác định',
      learning_duration: q6_learning_duration || 'Chưa xác định',
      current_level: q7_current_level || start_level,
      skills_text: q8_skills_text || 'Chưa xác định',
      daily_time: (() => {
        const minutes = parseInt(q9_daily_time) || 0;
        if (minutes === 0) return '0m';
        const hours = Math.floor(minutes / 60);
        const remainingMinutes = minutes % 60;
        if (hours === 0) return `${minutes}m`;
        if (remainingMinutes === 0) return `${hours}h`;
        return `${hours}h ${remainingMinutes}m`;
      })(),
      weekly_sessions: q10_weekly_sessions || 'Chưa xác định',
      program_days: q11_program_days || duration_days,
      learning_styles: processArrayWithOther(q12_learning_styles, q12_learning_styles_other),
      learning_combinations: processArrayWithOther(q13_learning_combinations, q13_learning_combinations_other),
      challenges: processArrayWithOther(q14_challenges, q14_challenges_other),
      motivation: processArrayWithOther(q15_motivation, q15_motivation_other),
      material_types: processArrayWithOther(q16_material_types, q16_material_types_other),
      material_language: q17_material_language || 'Tiếng Việt',
      assessment_types: Array.isArray(q18_assessment_types) ? q18_assessment_types.join(', ') : 'Chưa xác định',
      result_display: Array.isArray(q19_result_display) ? q19_result_display.join(', ') : 'Chưa xác định',
      assessment_frequency: processRadioWithOther(q20_assessment_frequency, q20_assessment_frequency_other),
      start_level: q7_current_level || start_level,
      duration_days: q11_program_days || duration_days,
      duration_hours: duration_hours,
      expected_outcome: q5_specific_goal || expected_outcome
    };

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

    if (isNaN(actualDays) || actualDays <= 0 || actualDays > MAX_AI_DAYS) {
      return res.status(400).json({ 
        success: false, 
        error: `Số ngày phải từ 1 đến ${MAX_AI_DAYS}` 
      });
    }

    const roadmapStartDate = new Date();
    roadmapStartDate.setHours(0, 0, 0, 0);

    console.log(`Generating AI roadmap: ${finalData.roadmap_name} (${actualDays} days, ${hoursPerDay}h/day)`);

    // ============================================
    // STEP 1: OpenAI generates main content (without materials)
    // ============================================
    const promptTemplate = await getPromptTemplate();
    let userPrompt = promptTemplate.prompt_template;
    
    userPrompt += `\n\n**QUAN TRỌNG:** 
- KHÔNG cần tạo learning_materials và usage_instructions
- Chỉ tạo: day_number, daily_goal, learning_content, practice_exercises, study_duration`;

    const variableMapping = {
      'CATEGORY': finalData.category,
      'SUB_CATEGORY': finalData.category_detail,
      'ROADMAP_NAME': finalData.roadmap_name,
      'MAIN_PURPOSE': finalData.main_purpose,
      'SPECIFIC_GOAL': finalData.specific_goal,
      'CURRENT_JOB': finalData.current_job,
      'STUDY_TIME': finalData.learning_duration,
      'CURRENT_LEVEL': finalData.current_level,
      'SKILLS_TO_IMPROVE': finalData.skills_text,
      'DAILY_TIME': finalData.daily_time,
      'WEEKLY_FREQUENCY': finalData.weekly_sessions,
      'TOTAL_DURATION': finalData.program_days,
      'LEARNING_STYLE': finalData.learning_styles,
      'LEARNING_METHOD': finalData.learning_combinations,
      'DIFFICULTIES': finalData.challenges,
      'MOTIVATION': finalData.motivation,
      'MATERIAL_TYPE': finalData.material_types,
      'MATERIAL_LANGUAGE': finalData.material_language,
      'ASSESSMENT_TYPE': finalData.assessment_types,
      'RESULT_DISPLAY': finalData.result_display,
      'ASSESSMENT_FREQUENCY': finalData.assessment_frequency
    };

    Object.keys(variableMapping).forEach(key => {
      userPrompt = userPrompt.replace(new RegExp(`<${key}>`, 'g'), variableMapping[key]);
    });

    let systemPrompt = `Bạn là chuyên gia thiết kế lộ trình học.
Tạo lộ trình ${actualDays} ngày KHÔNG bao gồm learning_materials và usage_instructions.

Trả về JSON format:
{
  "analysis": "Phân tích chi tiết...",
  "roadmap": [
    {
      "day_number": 1,
      "daily_goal": "...",
      "learning_content": "...",
      "practice_exercises": "...",
      "study_duration": ${hoursPerDay}
    }
  ]
}`;

    // Save history
    const historyResult = await pool.query(
      `INSERT INTO ai_query_history (user_id, prompt_content, status) 
       VALUES ($1, $2, 'PENDING') RETURNING id`,
      [req.user.id, JSON.stringify({ 
        roadmap_name: finalData.roadmap_name,
        category: finalData.category,
        duration_days: actualDays,
        timestamp: new Date().toISOString()
      })]
    );
    historyId = historyResult.rows[0].id;

    console.log(`📞 Phase 1: OpenAI call for main content...`);
    
    const completion = await callOpenAIForMainContent({
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt }
      ],
      desiredCompletionTokens: Math.min(actualDays * TOKENS_PER_DAY, MAX_AI_TOKENS - SAFETY_MARGIN_TOKENS),
      temperature: 1
    });

    const aiResponse = completion?.choices?.[0]?.message?.content?.trim();
    if (!aiResponse) {
      throw new Error("OpenAI không trả về kết quả");
    }

    let roadmapData = parseAIResponse(aiResponse);
    let analysis = roadmapData.analysis || 'Không có phân tích';
    let days = roadmapData.roadmap || [];
    
    days = normalizeDays(days, actualDays, hoursPerDay, roadmapStartDate);
    
    console.log(`✅ Phase 1 complete: ${days.length} days generated`);

    // ============================================
    // STEP 2: Claude finds materials and instructions (1 attempt only)
    // ============================================
    console.log(`📞 Phase 2: Claude call for materials...`);
    
    let claudeMaterials = [];
    try {
      const claudeCompletion = await callClaudeForMaterials({
        days: days,
        category: finalData.category,
        temperature: 1
      });

      const claudeResponse = claudeCompletion?.choices?.[0]?.message?.content?.trim();
      if (claudeResponse) {
        const jsonMatch = claudeResponse.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
        const jsonText = jsonMatch ? jsonMatch[1] : claudeResponse;
        
        try {
          const parsed = JSON.parse(jsonText);
          claudeMaterials = parsed.materials || [];
          console.log(`✅ Claude returned ${claudeMaterials.length} materials`);
        } catch (e) {
          console.warn(`⚠️ Claude JSON parse failed:`, e.message);
        }
      }
    } catch (error) {
      console.warn(`⚠️ Claude materials failed:`, error.message);
    }

    // Merge Claude materials into days
    for (const material of claudeMaterials) {
      const day = days.find(d => d.day_number === material.day_number);
      if (day) {
        day.learning_materials = material.learning_materials;
        day.study_guide = material.usage_instructions || day.study_guide;
      }
    }

    // ============================================
    // STEP 3: Validate all links
    // ============================================
    console.log('🔍 Phase 3: Validating links...');

    const validationResults = await validateBatchLinksEnhanced(days);
    const failedDays = validationResults
      .filter(r => !r.valid)
      .map(r => days[r.index]);

    console.log(`📊 Validation: ${failedDays.length}/${days.length} failed`);

    let finalDays = [...days];

    // ============================================
    // STEP 4: Google Search fallback cho links lỗi
    // ============================================
    if (failedDays.length > 0) {
      console.log(`🔍 Phase 4: Applying Google Search fallback for ${failedDays.length} days...`);
      
      for (const failed of failedDays) {
        const idx = finalDays.findIndex(d => d.day_number === failed.day_number);
        if (idx !== -1) {
          const fallback = createGoogleSearchFallback(finalDays[idx], finalData.category);
          finalDays[idx].learning_materials = fallback.learning_materials;
          finalDays[idx].study_guide = fallback.study_guide;
          console.log(`🔗 Day ${failed.day_number}: Google Search fallback applied`);
        }
      }
    }

    // ============================================
    // Final validation and response
    // ============================================
    const finalValidation = await validateBatchLinksEnhanced(finalDays);
    const finalFailCount = finalValidation.filter(r => !r.valid).length;

    const processingTime = Date.now() - startTime;

    console.log(`\n📊 FINAL REPORT:`);
    console.log(`✅ Total days: ${finalDays.length}`);
    console.log(`✅ Valid links: ${finalDays.length - finalFailCount}`);
    console.log(`🔍 Google Search fallback: ${failedDays.length}`);
    console.log(`⏱️ Processing time: ${(processingTime/1000).toFixed(2)}s`);

    await pool.query(
      `UPDATE ai_query_history 
      SET status = 'SUCCESS', 
          response_tokens = $1,
          updated_at = CURRENT_TIMESTAMP 
      WHERE id = $2`,
      [finalDays.length, historyId]
    );

    return res.json({
      success: true,
      message: "Tạo lộ trình AI thành công",
      analysis: analysis,
      data: finalDays,
      metadata: {
        total_days: finalDays.length,
        start_date: roadmapStartDate.toISOString().split('T')[0],
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
    
  } catch (error) {
    console.error("❌ AI GENERATION ERROR:", error.message);
    
    if (historyId) {
      await pool.query(
        `UPDATE ai_query_history 
         SET status = 'FAIL', 
             error_message = $1,
             updated_at = CURRENT_TIMESTAMP 
         WHERE id = $2`,
        [error.message, historyId]
      );
    }
    
    return res.status(500).json({
      success: false,
      error: error.message || "Lỗi khi tạo lộ trình AI"
    });
  }
});

// API cho user lấy manual prompt (không cần admin)
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
      const defaultPath = path.join(__dirname, 'Data', 'default_prompt.txt');
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
      'SPECIFIC_GOAL': formData.specific_goal || '',
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
      'MATERIAL_TYPE': Array.isArray(formData.material_types) ? formData.material_types.join(', ') : formData.material_types || '',
      'MATERIAL_LANGUAGE': formData.material_language || '',
      'ASSESSMENT_TYPE': Array.isArray(formData.assessment_types) ? formData.assessment_types.join(', ') : formData.assessment_types || '',
      'RESULT_DISPLAY': Array.isArray(formData.result_display) ? formData.result_display.join(', ') : formData.result_display || '',
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
// ============================================
// ENHANCED CONFIGURATION
// ============================================
const LINK_VALIDATION_CONFIG = {
  MAX_RETRY_ATTEMPTS: 1,
  FAIL_THRESHOLD_PERCENT: 5,
  MIN_FAIL_COUNT: 1,
  VALIDATION_TIMEOUT: 8000, // Tăng lên 8s để fetch HTML
  BATCH_VALIDATION_DELAY: 200, // Tăng delay
  
  // ✅ NEW: Soft 404 detection patterns
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
    /page can’t be found/i
  ],
  
};

// ============================================
// ENHANCED: Validate URL with Content Check
// ============================================
async function validateUrlSmart(url, maxRetries = 2, timeout = 8000) {
  const isKhanAcademy = url.includes('khanacademy.org');
  
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
      
      // ✅ Check HTTP status
      if (!response.ok) {
        console.log(`❌ HTTP ${response.status}: ${url}`);
        return { valid: false, reason: `http_${response.status}`, url };
      }
      
      // ✅ Fetch HTML để check error phrases
      const html = await response.text();
      
      // 🔍 Check error phrases trong title/h1
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
      
      // ✅ Khan Academy: chỉ check 404 và error phrases, pass rồi thì OK
      if (isKhanAcademy) {
        console.log(`✅ Khan Academy - passed checks: ${url}`);
        return { valid: true, url };
      }
      
      // ✅ Check content-type (chỉ cho non-Khan Academy)
      const contentType = response.headers.get('content-type') || '';
      if (!contentType.includes('text/html')) {
        console.log(`⚠️ Non-HTML content: ${contentType}`);
        // Vẫn chấp nhận nếu là educational site
        if (!url.includes('khan') && !url.includes('brilliant') && !url.includes('coursera')) {
          return { valid: false, reason: 'non_html', url };
        }
      }
      
      // ✅ Check if có content có ý nghĩa
      const bodyMatch = html.match(/<body[^>]*>([\s\S]*)<\/body>/i);
      if (bodyMatch) {
        const bodyContent = bodyMatch[1]
          .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '') // Remove scripts
          .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')   // Remove styles
          .replace(/<[^>]+>/g, '')                           // Remove tags
          .replace(/\s+/g, ' ')                              // Normalize whitespace
          .trim();
        
        if (bodyContent.length < 100) {
          console.log(`❌ Insufficient content: ${bodyContent.length} chars`);
          return { valid: false, reason: 'empty_page', url };
        }
      }
      
      // ✅ ALL CHECKS PASSED
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
      
      // Exponential backoff
      await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
    }
  }
  
  return { valid: false, reason: 'max_retries', url };
}
// ============================================
// ENHANCED: Build Retry Prompt with Whitelist
// ============================================
// Thay thế buildEnhancedRetryPrompt
function buildEnhancedRetryPrompt(originalUserPrompt, failedDayNumbers, analysis, attemptNumber) {
  const failedDaysStr = failedDayNumbers.join(', ');
  
  return `
🔴 **LẦN THỬ ${attemptNumber}/3 - TÌM KIẾM LẠI**

Các ngày ${failedDaysStr} có links KHÔNG HỢP LỆ.

**⚠️ VẤN ĐỀ:**
- Links trước đó không thể truy cập
- Có thể do: domain không tồn tại, content bị xóa, hoặc paywall

**✅ YÊU CẦU:**
- day_number PHẢI là: ${failedDaysStr}
- PHẢI TÌM KIẾM LẠI trên web
- PHẢI tìm nguồn KHÁC HOÀN TOÀN so với lần trước

**🔍 CHIẾN LƯỢC TÌM KIẾM LẦN ${attemptNumber}:**

${attemptNumber === 1 ? `
**Lần 1 - Tìm video tutorials:**
Search queries:
- "[topic] tutorial video"
- "[topic] explained youtube"
- "[topic] course free"

Ưu tiên:
- YouTube videos từ channels lớn (>100K subs)
- Udemy/Coursera free courses
- LinkedIn Learning free trials
` : ''}

${attemptNumber === 2 ? `
**Lần 2 - Tìm written content:**
Search queries:
- "[topic] tutorial blog"
- "[topic] guide documentation"
- "[topic] examples github"

Ưu tiên:
- Documentation chính thức
- Medium articles (>500 claps)
- Dev.to tutorials
- GitHub repos với README chi tiết
` : ''}

${attemptNumber >= 3 ? `
**Lần 3 - Tìm interactive resources:**
Search queries:
- "[topic] interactive exercises"
- "[topic] practice problems"
- "[topic] coding challenges"

Ưu tiên:
- freeCodeCamp challenges
- Codecademy free exercises
- LeetCode free problems
- Interactive documentation (W3Schools, MDN)
` : ''}

**📝 CÁCH TÌM KIẾM HIỆU QUẢ:**

1. Search với query CỤ THỂ về chủ đề ngày học
2. Lọc kết quả theo:
   - Miễn phí (free, no paywall)
   - Gần đây (recent, 2023-2025)
   - Uy tín (từ org lớn, creator nổi tiếng)
3. Kiểm tra:
   - Link có thể truy cập
   - Nội dung phù hợp level
   - Có exercises/examples
4. Chọn link TỐT NHẤT và ghi rõ cách dùng

**VÍ DỤ CÁCH GHI:**
{
  "day_number": ${failedDayNumbers[0]},
  "daily_goal": "Học về [topic]",
  "learning_content": "...",
  "practice_exercises": "...",
  "learning_materials": "https://[LINK MỚI TÌM ĐƯỢC]",
  "study_guide": "
  📹 Nguồn: [Tên video/bài viết]
  👤 Tác giả: [Tên]
  ⏱️ Thời lượng: [X phút]
  
  📚 Nội dung cần học:
  - Phần 1: [Tên section] (từ [time] đến [time])
  - Phần 2: [Tên section] 
  
  ✍️ Thực hành:
  - [Exercise cụ thể]
  ",
  "study_duration": 1.0
}

---

${originalUserPrompt}

---

**JSON FORMAT BẮT BUỘC:**
{
  "analysis": "${analysis}",
  "roadmap": [
    // ⚠️ CHÍNH XÁC ${failedDayNumbers.length} ngày
    // ⚠️ day_number: ${failedDaysStr}
    {
      "day_number": ${failedDayNumbers[0]},
      "daily_goal": "...",
      "learning_content": "...",
      "practice_exercises": "...",
      "learning_materials": "URL từ WHITELIST trên",
      "study_guide": "HƯỚNG DẪN CỤ THỂ: học bài gì, phút nào, bước nào",
      "study_duration": 0.5
    }
    // ... ${failedDayNumbers.length - 1} ngày còn lại
  ]
}
`;
}

// ============================================
// ENHANCED: Validate và Fix Day Numbers
// ============================================
function validateAndFixDayNumbers(retryDays, expectedDayNumbers) {
  console.log('🔍 Validating day numbers...');
  console.log('Expected:', expectedDayNumbers);
  console.log('Received:', retryDays.map(d => d.day_number));
  
  const fixedDays = retryDays.map((day, index) => {
    const expectedDayNum = expectedDayNumbers[index];
    const actualDayNum = day.day_number;
    
    if (actualDayNum !== expectedDayNum) {
      console.warn(`⚠️ Fixing day_number: ${actualDayNum} → ${expectedDayNum}`);
      return {
        ...day,
        day_number: expectedDayNum
      };
    }
    
    return day;
  });
  
  console.log('✅ Fixed day numbers:', fixedDays.map(d => d.day_number));
  return fixedDays;
}

// ============================================
// ENHANCED: Batch Validation với Content Check
// ============================================
async function validateBatchLinksEnhanced(days) {
  const results = [];
  
  for (let i = 0; i < days.length; i++) {
    const day = days[i];
    const link = String(day.learning_materials || '').trim();
    
    if (!link) {
      results.push({ 
        index: i, 
        dayNumber: day.day_number || i + 1,
        valid: false, 
        reason: 'no_link',
        originalUrl: '',
        validatedUrl: ''
      });
      continue;
    }
    
    // Delay để tránh rate limit
    if (i > 0) {
      await new Promise(resolve => 
        setTimeout(resolve, LINK_VALIDATION_CONFIG.BATCH_VALIDATION_DELAY)
      );
    }
    
    // ✅ Enhanced validation với content check
    const validation = await validateUrlSmart(
      link, 
      2, 
      LINK_VALIDATION_CONFIG.VALIDATION_TIMEOUT
    );
    
    results.push({
      index: i,
      dayNumber: day.day_number || i + 1,
      valid: validation.valid,
      originalUrl: link,
      validatedUrl: validation.url,
      reason: validation.reason || null
    });
    
    const icon = validation.valid ? '✅' : '❌';
    const reason = validation.reason ? ` (${validation.reason})` : '';
    console.log(`📋 Day ${day.day_number || i + 1}: ${icon} ${link.substring(0, 80)}...${reason}`);
  }
  
  return results;
}

// ============================================
// HELPER: Call OpenAI with custom temperature
// ============================================
async function callOpenAIWithFallback({ messages, desiredCompletionTokens, temperature = 1 }) {
  const capped = Math.max(MIN_COMPLETION_TOKENS, Math.min(desiredCompletionTokens, MAX_AI_TOKENS - SAFETY_MARGIN_TOKENS));
  
  try {
    const params = {
      model: PREFERRED_OPENAI_MODEL,
      messages,
      max_completion_tokens: capped,
      temperature: temperature
    };
    
    console.log(`📤 OpenAI call: model=${params.model}, temp=${temperature}, tokens=${capped}`);
    return await openai.chat.completions.create(params);
    
  } catch (err) {
    console.error("❌ Model failed:", PREFERRED_OPENAI_MODEL, err.message);
    
    const code = err && (err.code || (err.error && err.error.code));
    const status = err && err.status;
    
    if (code === "model_not_found" || status === 404 || String(err.message).toLowerCase().includes("model")) {
      console.warn(`⚠️ Falling back to ${FALLBACK_OPENAI_MODEL}`);
      
      const fallbackParams = {
        model: FALLBACK_OPENAI_MODEL,
        messages,
        max_completion_tokens: Math.min(capped, MAX_AI_TOKENS - SAFETY_MARGIN_TOKENS),
        temperature: temperature
      };
      
      return await openai.chat.completions.create(fallbackParams);
    }
    
    throw err;
  }
}
// ============================================
// FUNCTION: Call Claude API with Fallback
// ============================================
async function callClaudeWithFallback({ messages, desiredCompletionTokens, temperature = 1 }) {
  if (!anthropic) {
    throw new Error("Claude API key not configured");
  }

  const capped = Math.max(MIN_COMPLETION_TOKENS, Math.min(desiredCompletionTokens, MAX_AI_TOKENS - SAFETY_MARGIN_TOKENS));
  
  try {
    const systemMessage = messages.find(m => m.role === 'system');
    const userMessages = messages.filter(m => m.role !== 'system');
    
    const params = {
      model: CLAUDE_MODEL,
      max_tokens: capped,
      temperature: temperature,
      system: systemMessage ? systemMessage.content : undefined,
      messages: userMessages.map(m => ({
        role: m.role === 'user' ? 'user' : 'assistant',
        content: m.content
      })),
      // Lưu ý: tốn nhiều chi phí token
      // ✅ THÊM WEB SEARCH TOOL
      tools: [
        {
          type: "web_search_20250305",
          name: "web_search"
        }
      ],
      stream: true
    };
    
    console.log(`📤 Claude call with WEB SEARCH: model=${params.model}, temp=${temperature}, tokens=${capped}`);
    
    let fullText = '';
    let chunkCount = 0;

    const stream = await anthropic.messages.create(params);

    for await (const event of stream) {
      if (event.type === 'content_block_delta' && event.delta.type === 'text_delta') {
        fullText += event.delta.text;
        chunkCount++;

        if (chunkCount % 50 === 0) {
          console.log(`📝 [Claude] ${chunkCount} chunks, ${fullText.length} chars so far...`);
        }
      }
    }

    console.log(`✅ [Claude] Streaming complete: ${fullText.length} chars, ${chunkCount} chunks`);

    return {
      choices: [{
        message: {
          content: fullText
        }
      }]
    };
    
  } catch (err) {
    console.error("❌ Claude model failed:", CLAUDE_MODEL, err.message);
    
    const isModelError = err.status === 404 || 
                         err.message?.toLowerCase().includes("model") ||
                         err.error?.type === "invalid_request_error" ||
                         err.error?.type === "not_found_error";
    
    if (isModelError) {
      console.warn(`⚠️ Falling back to ${FALLBACK_CLAUDE_MODEL}`);
      const fallbackMaxTokens = FALLBACK_CLAUDE_MODEL.includes('haiku') 
        ? Math.min(4096, capped)
        : Math.min(capped, MAX_AI_TOKENS - SAFETY_MARGIN_TOKENS);
      
      const systemMessage = messages.find(m => m.role === 'system');
      const userMessages = messages.filter(m => m.role !== 'system');
      
      const fallbackParams = {
        model: FALLBACK_CLAUDE_MODEL,
        max_tokens: fallbackMaxTokens,
        temperature: temperature,
        system: systemMessage ? systemMessage.content : undefined,
        messages: userMessages.map(m => ({
          role: m.role === 'user' ? 'user' : 'assistant',
          content: m.content
        })),
        // Lưu ý: tốn nhiều chi phí token        
        // ✅ THÊM WEB SEARCH CHO FALLBACK
        tools: [
          {
            type: "web_search_20250305",
            name: "web_search"
          }
        ],
        stream: true
      };
      
      let fullText = '';
      let chunkCount = 0;

      const stream = await anthropic.messages.create(fallbackParams);

      for await (const event of stream) {
        if (event.type === 'content_block_delta' && event.delta.type === 'text_delta') {
          fullText += event.delta.text;
          chunkCount++;

          if (chunkCount % 50 === 0) {
            console.log(`📝 [Claude fallback] ${chunkCount} chunks, ${fullText.length} chars so far...`);
          }
        }
      }

      console.log(`✅ [Claude fallback] Streaming complete: ${fullText.length} chars, ${chunkCount} chunks`);

      return {
        choices: [{
          message: {
            content: fullText
          }
        }]
      };
    }
    
    throw err;
  }
}

// ============================================
// FUNCTION: Universal AI Call (OpenAI or Claude)
// ============================================
async function callAIWithFallback({ messages, desiredCompletionTokens, temperature = 1 }) {
  if (AI_PROVIDER === 'claude') {
    return await callClaudeWithFallback({ messages, desiredCompletionTokens, temperature });
  } else {
    return await callOpenAIWithFallback({ messages, desiredCompletionTokens, temperature });
  }
}
// ============================================
// HELPER: Extract text from OpenAI completion
// ============================================
function extractTextFromCompletion(completion) {
  if (!completion) {
    return null;
  }
  
  // Handle completion object
  if (completion.choices && completion.choices[0]) {
    return completion.choices[0].message?.content?.trim();
  }
  
  // Already a string
  if (typeof completion === 'string') {
    return completion.trim();
  }
  
  return null;
}

// ============================================
// HELPER: Parse AI Response
// ============================================
function parseAIResponse(aiResponseText) {
  const jsonMatch = aiResponseText.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
  const jsonText = jsonMatch ? jsonMatch[1] : aiResponseText;
  
  try {
    return JSON.parse(jsonText);
  } catch (e) {
    const cleaned = jsonText
      .replace(/[\u2018\u2019]/g, "'")
      .replace(/[\u201C\u201D]/g, '"')
      .replace(/,\s*([}\]])/g, '$1')
      .replace(/^\s*[\r\n]+/gm, '')
      .trim();
    
    return JSON.parse(cleaned);
  }
}

// ============================================
// HELPER: Normalize Days
// ============================================
function normalizeDays(days, targetCount, hoursPerDay, startDate) {
  const normalized = [];
  
  for (let i = 0; i < targetCount; i++) {
    const src = days[i] || {};
    
    normalized.push({
      day_number: i + 1,
      daily_goal: String(src.daily_goal || src.goal || `Mục tiêu ngày ${i + 1}`).trim().substring(0, 500),
      learning_content: String(src.learning_content || src.content || '').trim().substring(0, 1000),
      practice_exercises: String(src.practice_exercises || src.exercises || '').trim().substring(0, 1000),
      learning_materials: String(src.learning_materials || src.materials || '').trim(),
      study_guide: String(src.study_guide || src.usage_instructions || src.instructions || '').trim().substring(0, 2000),
      study_duration: parseFloat(src.study_duration || src.hours || hoursPerDay) || hoursPerDay,
      completion_status: 'NOT_STARTED',
      study_date: new Date(startDate.getTime() + (i * 86400000)).toISOString().split('T')[0]
    });
  }
  
  return normalized;
}

// ============================================
// HELPER: Analyze Validation Results
// ============================================
function analyzeValidationResults(validationResults) {
  const failedIndices = validationResults
    .filter(r => !r.valid)
    .map(r => r.index);
  
  const failedDayNumbers = validationResults
    .filter(r => !r.valid)
    .map(r => r.dayNumber);
  
  const totalDays = validationResults.length;
  const failCount = failedIndices.length;
  const failPercent = (failCount / totalDays) * 100;
  
  const shouldRetry = failCount >= LINK_VALIDATION_CONFIG.MIN_FAIL_COUNT || 
                     failPercent >= LINK_VALIDATION_CONFIG.FAIL_THRESHOLD_PERCENT;
  
  return {
    totalDays,
    failCount,
    failPercent: Math.round(failPercent),
    failedIndices,
    failedDayNumbers,
    shouldRetry,
    validResults: validationResults.filter(r => r.valid)
  };
}

// ============================================
// HELPER: Get Improved Fallback Link
// ============================================
function getImprovedFallbackLink(category, dayIndex) {
  const fallbackList = IMPROVED_FALLBACK_LINKS[category] || IMPROVED_FALLBACK_LINKS['default'];
  return fallbackList.materials[dayIndex % fallbackList.materials.length];
}

// =end 01/01===========================================


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
    const { roadmapData, roadmap_analyst, history_id } = req.body; // ✅ THÊM history_id
    const { roadmap_name, category, sub_category, start_level, duration_days, duration_hours, expected_outcome, days } = roadmapData;
    
    if (!roadmap_name || !category || !start_level || !duration_days || !duration_hours || !expected_outcome) {
      return res.status(400).json({ success: false, error: "Thiếu thông tin bắt buộc" });
    }
    
    // ✅ INSERT vào learning_roadmaps
    const roadmapResult = await pool.query(
      `INSERT INTO learning_roadmaps (roadmap_name, category, sub_category, start_level, user_id, duration_days, duration_hours, expected_outcome, roadmap_analyst)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING roadmap_id, created_at`,
      [roadmap_name, category, sub_category || null, start_level, req.user.id, duration_days, duration_hours, expected_outcome, roadmap_analyst || null]
    );
    
    const roadmapId = roadmapResult.rows[0].roadmap_id;
    const roadmapCreatedAt = new Date(roadmapResult.rows[0].created_at);
    roadmapCreatedAt.setHours(0, 0, 0, 0);
    
    // ✅ CẬP NHẬT roadmap_id vào ai_query_history
    if (history_id) {
      console.log(`✅ Updating AI history #${history_id} with roadmap_id: ${roadmapId}`);
      await pool.query(
        `UPDATE ai_query_history 
         SET roadmap_id = $1, updated_at = CURRENT_TIMESTAMP 
         WHERE id = $2`,
        [roadmapId, history_id]
      ).catch(err => {
        console.error('❌ Failed to link AI history:', err);
      });
    }
    
    // ✅ INSERT chi tiết roadmap
    if (Array.isArray(days)) {
      for (let i = 0; i < days.length; i++) {
        const day = days[i];
        const dayNumber = parseInt(day.day_number) || (i + 1);
        
        const studyDate = new Date(roadmapCreatedAt);
        studyDate.setDate(studyDate.getDate() + (dayNumber - 1));
        const studyDateStr = studyDate.toISOString().split('T')[0];
        
        await pool.query(
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
            day.study_guide || day.usage_instructions || ""
          ]
        );
      }
    }
/*
    // ✅ INSERT vào learning_roadmaps_system (code cũ giữ nguyên)
    const roadmapSystemResult = await pool.query(
      `INSERT INTO learning_roadmaps_system (roadmap_name, category, sub_category, start_level, total_user_learning, duration_days, duration_hours, overall_rating, learning_effectiveness, roadmap_analyst)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING roadmap_id, created_at`,
      [roadmap_name, category, sub_category || null, start_level, 1, duration_days, duration_hours, 0, 0, roadmap_analyst || null]
    );
    
    const roadmapSystemId = roadmapSystemResult.rows[0].roadmap_id;
    
    // ✅ INSERT chi tiết vào learning_roadmap_details_system
    if (Array.isArray(days)) {
      for (let i = 0; i < days.length; i++) {
        const day = days[i];
        const dayNumber = parseInt(day.day_number) || (i + 1);
        
        await pool.query(
          `INSERT INTO learning_roadmap_details_system 
           (roadmap_id, day_number, daily_goal, learning_content, practice_exercises, 
            learning_materials, study_duration, usage_instructions)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [
            roadmapSystemId,
            dayNumber,
            day.daily_goal || day.goal || "",
            day.learning_content || day.content || "",
            day.practice_exercises || day.exercises || "",
            day.learning_materials || day.materials || "",
            parseFloat(day.study_duration || day.hours || 2),
            day.study_guide || day.usage_instructions || ""
          ]
        );
      }
    }
    */
    res.json({ success: true, roadmap_id: roadmapId, message: "Tạo lộ trình thành công" });
  } catch (err) {
    console.error("Error creating roadmap:", err?.message || err);
    res.status(500).json({ success: false, error: "Không thể tạo lộ trình" });
  }
});
//Tạo lộ trình mới từ danh sách lộ trình của hệ thống
app.post("/api/roadmap_from_system", requireAuth, async (req, res) => {
  let client;
  try {
    client = await pool.connect(); // ✅ SỬ DỤNG TRANSACTION
    const { roadmapDataSystem } = req.body;
    const { roadmap_name, category, sub_category, start_level, duration_days, duration_hours, roadmap_analyst } = roadmapDataSystem;
    
    if (!roadmap_name || !category || !start_level || !duration_days || !duration_hours) {
      return res.status(400).json({ success: false, error: "Thiếu thông tin bắt buộc" });
    }
    
    await client.query('BEGIN');
    
    // ✅ INSERT vào learning_roadmaps
    const roadmapResult = await client.query(
      `INSERT INTO learning_roadmaps (roadmap_name, category, sub_category, start_level, user_id, duration_days, duration_hours, roadmap_analyst)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING roadmap_id, created_at`,
      [roadmap_name, category, sub_category || null, start_level, req.user.id, duration_days, duration_hours, roadmap_analyst || null]
    );
   
    const roadmapId = roadmapResult.rows[0].roadmap_id;
    const roadmapCreatedAt = new Date(roadmapResult.rows[0].created_at);
    roadmapCreatedAt.setHours(0, 0, 0, 0);
    
    // ✅ INSERT chi tiết
    const days = roadmapDataSystem?.days || [];
    if (Array.isArray(days)) {
      for (let i = 0; i < days.length; i++) {
        const day = days[i];
        const dayNumber = parseInt(day.day_number) || (i + 1);
        
        const studyDate = new Date(roadmapCreatedAt);
        studyDate.setDate(studyDate.getDate() + (dayNumber - 1));
        const studyDateStr = studyDate.toISOString().split('T')[0];

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
    
    // ✅ TĂNG total_user_learning TRONG learning_roadmaps_system
    const updateSystemQuery = `
      UPDATE learning_roadmaps_system
      SET total_user_learning = total_user_learning + 1,
          updated_at = CURRENT_TIMESTAMP
      WHERE roadmap_name = $1 AND category = $2
      RETURNING roadmap_id, total_user_learning
    `;
    
    const systemUpdate = await client.query(updateSystemQuery, [roadmap_name, category]);
    
    if (systemUpdate.rows.length > 0) {
      console.log(`✅ Updated system roadmap #${systemUpdate.rows[0].roadmap_id}, total_user_learning: ${systemUpdate.rows[0].total_user_learning}`);
    }
    
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
// ✅ HÀM PARSE TẤT CẢ FORMAT → DECIMAL (hours)
function parseDurationToHours(value) {
  if (!value) return 0;
  
  const str = String(value).trim().toLowerCase();
  
  // Pattern 1: Số thập phân thuần (1, 2.5, 1,5)
  if (/^\d+([.,]\d+)?$/.test(str)) {
    return parseFloat(str.replace(',', '.'));
  }
  
  // Pattern 2: Chỉ có "m" (30m, 90m)
  const minutesMatch = str.match(/^(\d+)m$/);
  if (minutesMatch) {
    return parseInt(minutesMatch[1]) / 60;
  }
  
  // Pattern 3: Chỉ có "h" (1h, 2.5h, 1,5h)
  const hoursMatch = str.match(/^(\d+(?:[.,]\d+)?)h$/);
  if (hoursMatch) {
    return parseFloat(hoursMatch[1].replace(',', '.'));
  }
  
  // Pattern 4: "xh ym" hoặc "xhym" (1h 30m, 2h30m)
  const combinedMatch = str.match(/^(\d+)h\s*(\d+)m$/);
  if (combinedMatch) {
    const hours = parseInt(combinedMatch[1]);
    const minutes = parseInt(combinedMatch[2]);
    return hours + (minutes / 60);
  }
  
  return 0;
}

// ✅ HÀM VALIDATE DURATION
function isValidDuration(value) {
  const hours = parseDurationToHours(value);
  return hours >= 0.05;
}
app.post("/api/roadmaps/upload", requireAuth, upload.single('file'), async (req, res) => {
  try {
    console.log('📤 Upload request received');
    console.log('👤 User:', req.user.id);
    console.log('📄 File:', req.file ? req.file.originalname : 'NO FILE');
    
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

    console.log('📊 Rows parsed:', data.length);

    if (data.length < 2) {
      return res.status(400).json({ success: false, error: "File Excel phải có ít nhất 2 dòng (header + data)" });
    }

    const roadmapAnalyst = (data[0] && data[0][0]) ? String(data[0][0]).trim() : '';
    console.log('🔍 Roadmap Analyst:', roadmapAnalyst || '(Không có)');

    const headers = data[1].map(h => String(h).trim().toLowerCase().replace(/\s+/g, '_'));
    console.log('📋 Headers:', headers);

    const requiredColumns = [
      'day_number',
      'day_study', 
      'daily_goal', 
      'learning_content', 
      'practice_exercises', 
      'learning_materials',
      'guide_learning',
      'study_duration'
    ];
    
    const missingColumns = requiredColumns.filter((col, idx) => headers[idx] !== col);
    
    if (missingColumns.length > 0) {
      return res.status(400).json({ 
        success: false, 
        error: `Thiếu các cột bắt buộc hoặc sai thứ tự: ${missingColumns.join(', ')}. \n\nCột hiện có: ${headers.join(', ')}`,
        details: {
          required: requiredColumns,
          found: headers,
          missing: missingColumns
        }
      });
    }

    const normalizedData = [];
    for (let i = 2; i < data.length; i++) {
      const row = data[i];
      if (!row || row.length === 0 || !row[0]) continue;
      
      const normalized = {};
      headers.forEach((header, idx) => {
        normalized[header] = row[idx] || '';
      });
      normalizedData.push(normalized);
    }

    console.log('📊 Normalized data rows:', normalizedData.length);

    if (normalizedData.length === 0) {
      return res.status(400).json({ success: false, error: "File Excel không có dữ liệu chi tiết" });
    }

    // ✅ VALIDATION NÂNG CAO
    const errors = [];
    let hasInvalidDayStudy = false;
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    // ✅ HÀM XỬ LÝ day_study LINH HOẠT
    function parseDayStudy(dayStudyValue) {
      if (!dayStudyValue || dayStudyValue.toString().trim() === '') {
        return null;
      }
      
      try {
        // Xử lý Excel serial number
        if (typeof dayStudyValue === 'number') {
          const excelEpoch = new Date(1899, 11, 30);
          const date = new Date(excelEpoch.getTime() + dayStudyValue * 86400000);
          // ✅ FIX: Trả về string YYYY-MM-DD thay vì Date object
          const year = date.getFullYear();
          const month = String(date.getMonth() + 1).padStart(2, '0');
          const day = String(date.getDate()).padStart(2, '0');
          return `${year}-${month}-${day}`;
        }
        
        const dayStudyStr = dayStudyValue.toString().trim().replace(/^'/, '');
        
        // Thử parse với dấu /
        let parts = dayStudyStr.split('/');
        if (parts.length === 3) {
          let day = parseInt(parts[0], 10);
          let month = parseInt(parts[1], 10);
          let year = parseInt(parts[2], 10);
          
          // ✅ FIX NĂM 2 CHỮ SỐ: 26 → 2026
          if (year < 100) {
            year += 2000;
          }
          
          if (!isNaN(day) && !isNaN(month) && !isNaN(year)) {
            // ✅ FIX TIMEZONE: Trả về string thay vì Date object
            const monthStr = String(month).padStart(2, '0');
            const dayStr = String(day).padStart(2, '0');
            return `${year}-${monthStr}-${dayStr}`;
          }
        }
        
        // Thử parse với dấu -
        parts = dayStudyStr.split('-');
        if (parts.length === 3) {
          // Kiểm tra format yyyy-mm-dd hay dd-mm-yyyy
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
            
            // ✅ FIX NĂM 2 CHỮ SỐ
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
          const year = directParse.getFullYear();
          const month = String(directParse.getMonth() + 1).padStart(2, '0');
          const day = String(directParse.getDate()).padStart(2, '0');
          return `${year}-${month}-${day}`;
        }
        
        return null;
      } catch (e) {
        return null;
      }
    }
    
    for (let i = 0; i < normalizedData.length; i++) {
      const row = normalizedData[i];
      const rowNumber = i + 3;
      
      // ✅ 1. VALIDATE day_number
      const dayNumber = parseInt(row.day_number);
      const expectedDayNumber = i + 1;
      
      if (isNaN(dayNumber) || dayNumber !== expectedDayNumber) {
        errors.push(`Hàng ${rowNumber}: day_number không hợp lệ (mong đợi ${expectedDayNumber}, nhận được "${row.day_number}")`);
      }
      
      // ✅ 2. VALIDATE study_duration
      if (!isValidDuration(row.study_duration)) {
        errors.push(`Hàng ${rowNumber}: study_duration không hợp lệ. Định dạng: 30m, 1h, 1.5h, 1,5h, 2h 30m, 2h30m (nhận được "${row.study_duration}")`);
      }
      
      // ✅ 3. VALIDATE day_study (FIXED)
      if (row.day_study && row.day_study.trim() !== '') {
        const studyDateStr = parseDayStudy(row.day_study);
        
        if (!studyDateStr || !/^\d{4}-\d{2}-\d{2}$/.test(studyDateStr)) {
          hasInvalidDayStudy = true;
          errors.push(`Hàng ${rowNumber}: day_study không đúng định dạng (nhận được "${row.day_study}"). Hỗ trợ: d/m/yyyy, dd/mm/yyyy, d-m-yyyy, dd-mm-yyyy, yyyy-mm-dd`);
        }
      }
    }
    
    if (errors.length > 0) {
      return res.status(400).json({ 
        success: false, 
        error: `File Excel có ${errors.length} lỗi:\n${errors.join('\n')}`,
        details: errors
      });
    }

    // ✅ LẤY THÔNG TIN ROADMAP
    const { roadmap_name, category, sub_category, start_level, expected_outcome } = req.body;
    
    if (!roadmap_name || !category || !start_level || !expected_outcome) {
      return res.status(400).json({ success: false, error: "Thiếu thông tin lộ trình" });
    }

    const duration_days = normalizedData.length;
    const duration_hours = normalizedData.reduce((sum, row) => {
      const hours = parseFloat(String(row.study_duration || '0').replace(',', '.')) || 0;
      return sum + hours;
    }, 0);

    // ✅ TẠO ROADMAP
    const roadmapResult = await pool.query(
      `INSERT INTO learning_roadmaps 
       (roadmap_name, category, sub_category, start_level, user_id, duration_days, duration_hours, expected_outcome, roadmap_analyst)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) 
       RETURNING roadmap_id, created_at`,
      [roadmap_name, category, sub_category || null, start_level, req.user.id, duration_days, duration_hours, expected_outcome, roadmapAnalyst || null]
    );
    
    const roadmapId = roadmapResult.rows[0].roadmap_id;
    console.log('✅ Roadmap created with analyst, ID:', roadmapId);

    // ✅ INSERT CHI TIẾT với XỬ LÝ day_study MỚI
    for (let i = 0; i < normalizedData.length; i++) {
      const row = normalizedData[i];
      const dayNumber = parseInt(row.day_number);
      
      let studyDateStr = null;
      
      if (!hasInvalidDayStudy && row.day_study && row.day_study.trim() !== '') {
        studyDateStr = parseDayStudy(row.day_study);
        // ✅ studyDateStr đã là string "YYYY-MM-DD" rồi, không cần convert
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
          studyDateStr,  // ✅ Đã là string "YYYY-MM-DD"
          'NOT_STARTED'
        ]
      );
    }

    console.log('✅ All details inserted');

    const message = hasInvalidDayStudy 
      ? `Upload thành công lộ trình với ${normalizedData.length} ngày học. ⚠️ Cảnh báo: Phát hiện ngày học không hợp lệ, tất cả ngày học đã được set là N/A.`
      : `Upload thành công lộ trình với ${normalizedData.length} ngày học`;

    res.json({ 
      success: true, 
      roadmap_id: roadmapId, 
      message: message,
      warning: hasInvalidDayStudy ? 'Một hoặc nhiều ngày học không hợp lệ' : null
    });

  } catch (error) {
    console.error("❌ Upload error:", error);
    console.error("Stack:", error.stack);
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
        study_duration,
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
      study_duration: row.study_duration,
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
    const client = await pool.connect();
    try {
        const roadmapId = parseInt(req.params.id);
        
        // ✅ Verify ownership
        const checkQuery = `
            SELECT roadmap_id, roadmap_name, category, overall_rating 
            FROM learning_roadmaps 
            WHERE roadmap_id = $1 AND user_id = $2
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
        
        // ✅ LOGIC: Nếu rating >= 4 sao, XÓA KHỎI learning_roadmaps_system
        if (roadmap.overall_rating && roadmap.overall_rating >= 4) {
            console.log(`🗑️ Xóa roadmap "${roadmap.roadmap_name}" khỏi system (rating: ${roadmap.overall_rating})`);
            
            // Tìm roadmap_id trong bảng system dựa trên tên và category
            const systemRoadmapQuery = `
                SELECT roadmap_id 
                FROM learning_roadmaps_system 
                WHERE roadmap_name = $1 
                AND category = $2
                LIMIT 1
            `;
            const systemResult = await client.query(systemRoadmapQuery, [
                roadmap.roadmap_name,
                roadmap.category
            ]);
            
            if (systemResult.rows.length > 0) {
                const systemRoadmapId = systemResult.rows[0].roadmap_id;
                
                // Xóa chi tiết trong learning_roadmap_details_system
                await client.query(
                    'DELETE FROM learning_roadmap_details_system WHERE roadmap_id = $1',
                    [systemRoadmapId]
                );
                
                // Xóa roadmap trong learning_roadmaps_system
                await client.query(
                    'DELETE FROM learning_roadmaps_system WHERE roadmap_id = $1',
                    [systemRoadmapId]
                );
                
                console.log(`✅ Đã xóa roadmap system #${systemRoadmapId}`);
            }
        }
        
        // ✅ Xóa roadmap của user (cascade sẽ tự động xóa details)
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
        study_duration,
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
// 1️⃣ REQUEST RESET CODE
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
    
    // Kiểm tra email có tồn tại trong hệ thống
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
    
    // Tạo mã reset
    const code = generateResetCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 phút
    
    // Lưu mã vào database
    await pool.query(
      `INSERT INTO password_reset_codes (email, code, expires_at) 
       VALUES ($1, $2, $3)`,
      [normalizedEmail, code, expiresAt]
    );
    
    // Gửi email
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
      expiresIn: 600 // 10 phút tính bằng giây
    });
    
  } catch (error) {
    console.error('Error requesting reset code:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể xử lý yêu cầu'
    });
  }
});

// 2️⃣ VERIFY CODE
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
    
    // Tìm mã reset hợp lệ
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
    
    // Kiểm tra đã dùng chưa
    if (resetCode.used) {
      return res.status(400).json({
        success: false,
        error: 'Mã xác thực đã được sử dụng'
      });
    }
    
    // Kiểm tra hết hạn
    if (new Date() > new Date(resetCode.expires_at)) {
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

// 3️⃣ RESET PASSWORD
app.post("/api/password-reset/reset", async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    
    if (!email || !code || !newPassword) {
      return res.status(400).json({
        success: false,
        error: 'Thiếu thông tin bắt buộc'
      });
    }
    
    // Validate password
    if (newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        error: 'Mật khẩu phải có ít nhất 8 ký tự'
      });
    }
    
    const normalizedEmail = email.trim().toLowerCase();
    
    // Kiểm tra mã reset
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
    
    if (new Date() > new Date(resetCode.expires_at)) {
      return res.status(400).json({
        success: false,
        error: 'Mã xác thực đã hết hạn'
      });
    }
    
    // Hash mật khẩu mới
    const hashedPassword = await hashPassword(newPassword, 10);
    
    // Cập nhật mật khẩu
    await pool.query(
      'UPDATE users SET password = $1 WHERE LOWER(email) = $2',
      [hashedPassword, normalizedEmail]
    );
    
    // Đánh dấu mã đã sử dụng
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

// ========== CLEANUP OLD CODES (Chạy mỗi giờ) ==========
setInterval(async () => {
  try {
    await pool.query(
      'DELETE FROM password_reset_codes WHERE expires_at < NOW()'
    );
    console.log('✅ Cleaned up expired reset codes');
  } catch (error) {
    console.error('❌ Error cleaning up codes:', error);
  }
}, 60 * 60 * 1000); // 1 giờ

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
        h.prompt_content,  -- ✅ THÊM CỘT NÀY
        h.status, 
        h.error_message,
        h.response_tokens,
        h.roadmap_id,  -- ✅ THÊM CỘT NÀY
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
// ========== FEEDBACK ENDPOINTS ==========

// Submit feedback
app.post("/api/feedback/submit", requireAuth, async (req, res) => {
  try {
    const {
      rating_1, rating_2, rating_3, rating_4, rating_5, rating_6, rating_7, rating_8,
      question_1, question_2, question_3
    } = req.body;

    // Validate ratings
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
      data: result.rows[0]
    });

  } catch (error) {
    console.error('Error submitting feedback:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể gửi phản hồi'
    });
  }
});

// Get all feedback (admin only)
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

    res.json({
      success: true,
      data: result.rows,
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

// Get feedback statistics (admin only)
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
// Thêm endpoint DELETE /api/admin/feedback/:feedbackId vào phần ADMIN ROUTES trong server.js
// (Thêm sau phần code cho GET /api/admin/feedback/stats, khoảng dòng ~1180 hoặc cuối phần admin routes)

// Thêm endpoint DELETE vào phần ADMIN ROUTES
app.delete('/api/admin/feedback/:feedbackId', requireAdmin, async (req, res) => {
  const client = await pool.connect();
  
  try {
    const feedbackId = parseInt(req.params.feedbackId);
    
    if (isNaN(feedbackId)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid feedback ID',
        message: 'ID phản hồi không hợp lệ'
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
        error: 'Feedback not found',
        message: 'Không tìm thấy phản hồi'
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
      error: 'Database error',
      message: 'Không thể xóa phản hồi'
    });
  } finally {
    client.release();
  }
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
      const study_duration = parseFloat(src.study_duration ?? src.duration ?? src.hours ?? hoursPerDay) || hoursPerDay;

      normalized.push({
        day_number,
        daily_goal,
        learning_content,
        practice_exercises,
        learning_materials,
        study_guide,
        study_duration,
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
                    study_duration, completion_status, study_date
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
    console.log('📊 /api/roadmap - req.user:', JSON.stringify(req.user, null, 2));
    
    const userId = req.user?.id;
    
    if (!userId) {
      console.error('❌ userId is falsy:', userId);
      return res.status(401).json({ message: 'User ID missing' });
    }
    
    const userIdInt = parseInt(userId);
    
    if (isNaN(userIdInt)) {
      console.error('❌ userId cannot be parsed to int:', userId);
      return res.status(401).json({ message: 'Invalid user ID format' });
    }
    
    // ✅ QUERY MỚI: Tính toán status dựa trên completion_status của các ngày học
    const query = `
      SELECT 
        r.roadmap_id,
        r.roadmap_name,
        r.category,
        r.sub_category,
        r.start_level,
        r.duration_days,
        r.duration_hours,
        r.progress_percentage,
        r.total_studied_hours,
        r.overall_rating,
        r.roadmap_analyst,
        r.expected_outcome,
        r.created_at,
        -- ✅ Đếm số ngày đang học (IN_PROGRESS)
        COUNT(d.detail_id) FILTER (WHERE d.completion_status = 'IN_PROGRESS') as in_progress_count,
        -- ✅ Đếm số ngày hoàn thành (COMPLETED)
        COUNT(d.detail_id) FILTER (WHERE d.completion_status = 'COMPLETED') as completed_count,
        -- ✅ Tổng số ngày
        COUNT(d.detail_id) as total_days
      FROM learning_roadmaps r
      LEFT JOIN learning_roadmap_details d ON r.roadmap_id = d.roadmap_id
      WHERE r.user_id = $1::integer
      GROUP BY r.roadmap_id
      ORDER BY r.created_at DESC
    `;

    console.log('📊 Executing query with userId:', userIdInt);
    
    const result = await pool.query(query, [userIdInt]);
    
    console.log('✅ Query success, rows:', result.rows.length);

    // ✅ Xử lý status logic trong backend
    const processedRows = result.rows.map(row => {
      let computed_status = 'NOT_STARTED';
      
      // Nếu có progress > 0 hoặc có ngày IN_PROGRESS/COMPLETED
      if (row.progress_percentage > 0 || row.in_progress_count > 0 || row.completed_count > 0) {
        computed_status = 'IN_PROGRESS';
      }
      
      // Nếu progress = 100% hoặc tất cả ngày đã COMPLETED
      if (row.progress_percentage >= 100 || (row.total_days > 0 && row.completed_count === row.total_days)) {
        computed_status = 'COMPLETED';
      }
      
      return {
        roadmap_id: row.roadmap_id,
        roadmap_name: row.roadmap_name,
        category: row.category,
        sub_category: row.sub_category,
        start_level: row.start_level,
        duration_days: row.duration_days,
        duration_hours: row.duration_hours,
        status: computed_status, // ✅ Status được tính toán đúng
        progress_percentage: row.progress_percentage,
        total_studied_hours: row.total_studied_hours,
        overall_rating: row.overall_rating,
        roadmap_analyst: row.roadmap_analyst,
        expected_outcome: row.expected_outcome,
        created_at: row.created_at
      };
    });

    res.json({
      success: true,
      data: processedRows
    });

  } catch (error) {
    console.error('❌❌❌ ERROR in /api/roadmap:');
    console.error('Message:', error?.message);
    console.error('Stack:', error?.stack);
    
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
          COALESCE(SUM(study_duration) FILTER (WHERE completion_status = 'COMPLETED'), 0) as total_studied_hours
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

app.post("/api/roadmap/:id/submit-evaluation", requireAuth, async (req, res) => {
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

        // ✅ VERIFY OWNERSHIP
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

        // ✅ PARSE VÀ ĐẢM BẢO LÀ INTEGER
        const overall_rating = Math.round(parseFloat(value.overall_rating));
        const learning_effectiveness = Math.round(parseFloat(value.learning_effectiveness));
        const difficulty_suitability = Math.round(parseFloat(value.difficulty_suitability));
        const content_relevance = Math.round(parseFloat(value.content_relevance));
        const engagement_level = Math.round(parseFloat(value.engagement_level));

        // ✅ UPDATE EVALUATION IN learning_roadmaps
        const updateQuery = `
            UPDATE learning_roadmaps
            SET 
                overall_rating = $1::integer,
                learning_effectiveness = $2::integer,
                difficulty_suitability = $3::integer,
                content_relevance = $4::integer,
                engagement_level = $5::integer,
                detailed_feedback = $6,
                recommended_category = $7,
                actual_learning_outcomes = $8,
                improvement_suggestions = $9,
                would_recommend = $10,
                updated_at = CURRENT_TIMESTAMP
            WHERE roadmap_id = $11
            RETURNING *
        `;

        const result = await client.query(updateQuery, [
            overall_rating,
            learning_effectiveness,
            difficulty_suitability,
            content_relevance,
            engagement_level,
            value.detailed_feedback || null,
            value.recommended_category || null,
            value.actual_learning_outcomes || null,
            value.improvement_suggestions || null,
            value.would_recommend || false,
            roadmapId
        ]);

        const updatedRoadmap = result.rows[0];

        // ✅ LOGIC MỚI: Nếu rating >= 4 sao → ADD TO SYSTEM
        if (overall_rating >= 4) {
            console.log(`⭐ Rating >= 4, adding roadmap #${roadmapId} to system...`);

            // 1️⃣ Check xem đã tồn tại trong system chưa
            const checkSystemQuery = `
                SELECT roadmap_id 
                FROM learning_roadmaps_system 
                WHERE roadmap_name = $1 AND category = $2
                LIMIT 1
            `;
            const existingSystem = await client.query(checkSystemQuery, [
                updatedRoadmap.roadmap_name,
                updatedRoadmap.category
            ]);

            if (existingSystem.rows.length === 0) {
                // 2️⃣ INSERT vào learning_roadmaps_system
                const insertSystemQuery = `
                    INSERT INTO learning_roadmaps_system (
                        roadmap_name, category, sub_category, start_level,
                        total_user_learning, duration_days, duration_hours,
                        overall_rating, learning_effectiveness, roadmap_analyst
                    ) VALUES ($1, $2, $3, $4, 1, $5, $6, $7, $8, $9)
                    RETURNING roadmap_id
                `;

                const systemResult = await client.query(insertSystemQuery, [
                    updatedRoadmap.roadmap_name,
                    updatedRoadmap.category,
                    updatedRoadmap.sub_category,
                    updatedRoadmap.start_level,
                    updatedRoadmap.duration_days,
                    updatedRoadmap.duration_hours,
                    overall_rating,
                    learning_effectiveness,
                    updatedRoadmap.roadmap_analyst
                ]);

                const systemRoadmapId = systemResult.rows[0].roadmap_id;
                console.log(`✅ Created system roadmap #${systemRoadmapId}`);

                // 3️⃣ Copy chi tiết vào learning_roadmap_details_system
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

                await client.query(copyDetailsQuery, [systemRoadmapId, roadmapId]);
                console.log(`✅ Copied ${updatedRoadmap.duration_days} days to system`);

            } else {
                // UPDATE thay vì skip
                const updateSystemQuery = `
                    UPDATE learning_roadmaps_system
                    SET 
                        overall_rating = $1::integer,
                        learning_effectiveness = $2::integer,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE roadmap_id = $3
                `;
                await client.query(updateSystemQuery, [
                    overall_rating,
                    learning_effectiveness,
                    existingSystem.rows[0].roadmap_id
                ]);
            }
        }

        await client.query('COMMIT');

        res.json({
            success: true,
            message: 'Đánh giá đã được lưu thành công',
            data: updatedRoadmap
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
// ============ MANUAL PROMPT API ENDPOINTS ============
app.get("/api/admin/manual-prompt", requireAdmin, async (req, res) => {
  try {
    const query = `
      SELECT manual_prompt_template
      FROM admin_settings
      WHERE setting_key = 'prompt_template'
      LIMIT 1
    `;
    
    const result = await pool.query(query);
    
    let manualPromptTemplate = '';
    
    // ✅ BƯỚC 1: Lấy từ admin_settings
    if (result.rows.length > 0 && result.rows[0].manual_prompt_template) {
      manualPromptTemplate = result.rows[0].manual_prompt_template;
      console.log('✅ Lấy manual prompt từ admin_settings');
    } 
    // ✅ BƯỚC 2: Nếu không có, lấy từ Data/default_prompt.txt
    else {
      const defaultPath = path.join(__dirname, 'Data', 'default_prompt.txt');
      if (fs.existsSync(defaultPath)) {
        manualPromptTemplate = fs.readFileSync(defaultPath, 'utf8');
        console.log('✅ Lấy manual prompt từ default_prompt.txt');
      } 
      // ✅ BƯỚC 3: Cuối cùng mới dùng hardcoded
      else {
        manualPromptTemplate = getDefaultManualPrompt();
        console.log('⚠️ Sử dụng manual prompt hardcoded');
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
        updated_at = CURRENT_TIMESTAMP,
        updated_by = $2
      WHERE setting_key = 'prompt_template'
      RETURNING setting_id
    `;
    
    const result = await pool.query(query, [manualPromptContent, userId]);
    
    if (result.rows.length === 0) {
      const insertQuery = `
        INSERT INTO admin_settings (
          setting_key, manual_prompt_template, updated_by
        ) VALUES ('prompt_template', $1, $2)
        RETURNING setting_id
      `;
      await pool.query(insertQuery, [manualPromptContent, userId]);
    }
    
    res.json({
      success: true,
      message: 'Manual Prompt đã được lưu thành công',
      updatedAt: new Date()
    });
  } catch (error) {
    console.error('Error saving manual prompt:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể lưu Manual Prompt'
    });
  }
});

// ✅ ENDPOINT RESET MANUAL PROMPT (TẠO THỦ CÔNG)
app.post("/api/admin/manual-prompt/reset", requireAdmin, async (req, res) => {
  try {
    let manualPromptTemplate;

    // ✅ BƯỚC 1: Lấy từ Data/default_prompt.txt
    const defaultPath = path.join(__dirname, 'Data', 'default_prompt.txt');
    
    if (fs.existsSync(defaultPath)) {
      manualPromptTemplate = fs.readFileSync(defaultPath, 'utf8');
      console.log('✅ [Manual Reset] Lấy từ default_prompt.txt');
    }
    // ✅ BƯỚC 2: Nếu không có, dùng hardcoded
    else {
      manualPromptTemplate = getDefaultManualPrompt();
      console.log('⚠️ [Manual Reset] Sử dụng hardcoded');
    }

    // ✅ UPDATE VÀO DB
    const checkQuery = `
      SELECT setting_id 
      FROM admin_settings 
      WHERE setting_key = 'prompt_template'
      LIMIT 1
    `;
    
    const checkResult = await pool.query(checkQuery);
    
    if (checkResult.rows.length > 0) {
      // UPDATE nếu đã tồn tại
      const updateQuery = `
        UPDATE admin_settings
        SET 
          manual_prompt_template = $1,
          updated_at = CURRENT_TIMESTAMP,
          updated_by = $2
        WHERE setting_key = 'prompt_template'
        RETURNING setting_id, updated_at
      `;
      
      const result = await pool.query(updateQuery, [
        manualPromptTemplate, 
        req.user.id
      ]);
      
      res.json({
        success: true,
        message: '✅ Đã khôi phục manual prompt về mặc định',
        data: {
          manual_prompt_template: manualPromptTemplate,
          updated_at: result.rows[0].updated_at
        }
      });
    } else {
      // INSERT nếu chưa có
      const insertQuery = `
        INSERT INTO admin_settings (
          setting_key, manual_prompt_template, updated_by
        ) VALUES ('prompt_template', $1, $2)
        RETURNING setting_id, created_at
      `;
      
      const result = await pool.query(insertQuery, [
        manualPromptTemplate, 
        req.user.id
      ]);
      
      res.json({
        success: true,
        message: '✅ Đã tạo manual prompt mặc định',
        data: {
          manual_prompt_template: manualPromptTemplate,
          created_at: result.rows[0].created_at
        }
      });
    }
    
  } catch (error) {
    console.error('❌ Error resetting manual prompt:', error);
    res.status(500).json({
      success: false,
      error: 'Lỗi khi khôi phục manual prompt'
    });
  }
});

function getDefaultManualPrompt() {
  return `**THIẾT KẾ LỘ TRÌNH HỌC CÁ NHÂN HÓA: <CATEGORY> -- <SUB_CATEGORY>**

**I/ Vai trò của AI**
Bạn là một chuyên gia giáo dục <CATEGORY> -- <SUB_CATEGORY> có 15+ năm kinh nghiệm.

**II/ Thông tin từ học viên:**
- Tên lộ trình: <ROADMAP_NAME>
- Mục đích chính: <MAIN_PURPOSE>
- Mục tiêu cụ thể: <SPECIFIC_GOAL>
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
- Hiển thị kết quả: <RESULT_DISPLAY>
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
// ✅ HÀM LẤY DEFAULT JSON FORMAT
function getDefaultJsonFormat() {
  try {
    // ✅ BƯỚC 1: Lấy từ Data/default_prompt_ai.txt
    const defaultAIPath = path.join(__dirname, 'Data', 'default_prompt_ai.txt');
    
    if (fs.existsSync(defaultAIPath)) {
      const content = fs.readFileSync(defaultAIPath, 'utf8');
      
      // Tìm JSON format trong nội dung (từ dấu { đến })
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      
      if (jsonMatch) {
        console.log('✅ Lấy JSON format từ default_prompt_ai.txt');
        return jsonMatch[0];
      }
    }
    
    // ✅ BƯỚC 2: Nếu không có, lấy từ prompt_template trong DB
    console.log('⚠️ Không tìm thấy JSON trong default_prompt_ai.txt, thử lấy từ DB...');
    return null; // Sẽ xử lý async ở caller
    
  } catch (error) {
    console.error('Error reading default JSON format:', error);
    return null;
  }
}

// ✅ HÀM LẤY DEFAULT JSON FORMAT (ASYNC VERSION - CHO DB)
async function getDefaultJsonFormatAsync() {
  try {
    // ✅ BƯỚC 1: Thử lấy từ file trước
    const defaultAIPath = path.join(__dirname, 'Data', 'default_prompt_ai.txt');
    
    if (fs.existsSync(defaultAIPath)) {
      const content = fs.readFileSync(defaultAIPath, 'utf8');
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      
      if (jsonMatch) {
        console.log('✅ Lấy JSON format từ default_prompt_ai.txt');
        return jsonMatch[0];
      }
    }
    
    // ✅ BƯỚC 2: Nếu không có, lấy từ admin_settings.prompt_template
    const query = `
      SELECT json_format_response 
      FROM admin_settings 
      WHERE setting_key = 'prompt_template'
      LIMIT 1
    `;
    
    const result = await pool.query(query);
    
    if (result.rows.length > 0 && result.rows[0].json_format_response) {
      console.log('✅ Lấy JSON format từ admin_settings');
      return result.rows[0].json_format_response;
    }
    
    // ✅ BƯỚC 3: Cuối cùng dùng hardcoded
    console.log('⚠️ Sử dụng JSON format hardcoded');
    return getHardcodedJsonFormat();
    
  } catch (error) {
    console.error('Error getting default JSON format:', error);
    return getHardcodedJsonFormat();
  }
}

// ✅ HÀM HARDCODED JSON FORMAT
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

app.post("/api/admin/prompt-template/reset", requireAdmin, async (req, res) => {
  try {
    let defaultPrompt;
    let defaultJsonFormat;
    
    // ✅ BƯỚC 1: Lấy từ Data/default_prompt_ai.txt
    const defaultPath = path.join(__dirname, 'Data', 'default_prompt_ai.txt');
    
    if (fs.existsSync(defaultPath)) {
      const content = fs.readFileSync(defaultPath, 'utf8');
      defaultPrompt = content;
      
      // Trích xuất JSON format từ file
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      defaultJsonFormat = jsonMatch ? jsonMatch[0] : getHardcodedJsonFormat();
      
      console.log('✅ [AI Reset] Lấy từ default_prompt_ai.txt');
    } 
    // ✅ BƯỚC 2: Nếu không có file, dùng hardcoded
    else {
      defaultPrompt = buildDefaultPromptTemplate();
      defaultJsonFormat = getHardcodedJsonFormat();
      console.log('⚠️ [AI Reset] Sử dụng hardcoded');
    }
    
    // ✅ UPDATE VÀO DB
    const updateQuery = `
      UPDATE admin_settings
      SET 
        prompt_template = $1,
        json_format_response = $2,
        updated_at = CURRENT_TIMESTAMP,
        updated_by = $3
      WHERE setting_key = 'prompt_template'
      RETURNING setting_id, updated_at
    `;
    
    const result = await pool.query(updateQuery, [
      defaultPrompt,
      defaultJsonFormat,
      req.user.id
    ]);
    
    if (result.rows.length === 0) {
      // Nếu chưa có record thì INSERT
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
    console.error('❌ Error resetting AI prompt:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể khôi phục prompt AI',
      message: error.message
    });
  }
});

// ✅ SỬA LẠI HÀM getDefaultPromptFromFile
function getDefaultPromptFromFile() {
  try {
    const defaultPath = path.join(__dirname, 'Data', 'default_prompt_ai.txt');
    if (fs.existsSync(defaultPath)) {
      console.log('✅ Lấy prompt template từ default_prompt_ai.txt');
      return fs.readFileSync(defaultPath, 'utf8');
    }
    console.log('⚠️ Không có default_prompt_ai.txt, sử dụng hardcoded');
    return buildDefaultPromptTemplate();
  } catch (error) {
    console.error('Error reading default prompt file:', error);
    return buildDefaultPromptTemplate();
  }
}
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
                AND lr.overall_rating >= 4  /* ✅ CHỈ ĐẾM LỘ TRÌNH >= 4 SAO */
            GROUP BY c.id, c.name, c.description
            HAVING COUNT(lr.roadmap_id) > 0  /* ✅ CHỈ HIỂN THỊ CATEGORY CÓ ROADMAP */
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
// Tìm dòng này trong server.js (khoảng dòng 1180)
app.get('/api/roadmapsystem/:roadmapId', async (req, res) => {
  try {
    const { roadmapId } = req.params;
    
    // ✅ Query mới: Đếm số người đánh giá >= 4 sao
    const query = `
      SELECT 
        lrs.roadmap_id,
        lrs.roadmap_name,
        lrs.category,
        lrs.sub_category,
        lrs.start_level,
        lrs.total_user_learning,
        lrs.duration_days,
        lrs.duration_hours,
        lrs.created_at,
        lrs.updated_at,
        lrs.roadmap_analyst,
        c.id as category_id,
        -- ✅ Đếm số người đánh giá >= 4 sao tổng thể
        COUNT(DISTINCT lr.user_id) FILTER (WHERE lr.overall_rating >= 4) as high_overall_rating_count,
        -- ✅ Đếm số người đánh giá >= 4 sao hiệu quả
        COUNT(DISTINCT lr.user_id) FILTER (WHERE lr.learning_effectiveness >= 4) as high_effectiveness_count
      FROM learning_roadmaps_system lrs
      LEFT JOIN categories c ON c.name = lrs.category
      LEFT JOIN learning_roadmaps lr ON lr.roadmap_name = lrs.roadmap_name AND lr.category = lrs.category
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
        study_duration,
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
