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
const CLAUDE_MODEL = process.env.CLAUDE_MODEL || "claude-sonnet-4-20250514";
const FALLBACK_CLAUDE_MODEL = process.env.FALLBACK_CLAUDE_MODEL || "claude-3-5-haiku-20241022";
const PREFERRED_OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-5-mini";
const FALLBACK_OPENAI_MODEL = process.env.FALLBACK_OPENAI_MODEL || "gpt-5";

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
const dataDir = path.join(publicDir, 'Data');
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
      await client.query("SET time zone 'Asia/Ho_Chi_Minh'"); // Thêm dòng này để set timezone UTC+7
    } catch (e) {
      console.warn("⚠️ Could not set client_encoding or time zone:", e.message);
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
// ✅ HÀM XÁC ĐỊNH MAX DAYS THEO ROLE
function getMaxDaysForUser(userRole) {
  if (userRole === 'admin') {
    return 60;  // Admin: 15-60 ngày
  }
  return 360;   // User thường: 15-360 ngày
}
const MIN_AI_DAYS = 15; // Min chung cho cả admin và user
const MAX_AI_TOKENS = parseInt(process.env.MAX_AI_TOKENS || "200000", 10);
const TOKENS_PER_DAY = parseInt(process.env.TOKENS_PER_DAY || "800", 10);
const SAFETY_MARGIN_TOKENS = parseInt(process.env.SAFETY_MARGIN_TOKENS || "2048", 10);
const MIN_COMPLETION_TOKENS = 128;

// ============ TIMEZONE HELPER ============
const VIETNAM_TIMEZONE_OFFSET = 7 * 60 * 60 * 1000; // UTC+7 in milliseconds

// ✅ HÀM LẤY NGÀY VIỆT NAM ĐÚNG
function getVietnamDate() {
  const now = new Date();
  const utc = now.getTime() + (now.getTimezoneOffset() * 60000);
  return new Date(utc + (7 * 60 * 60 * 1000)); // UTC+7
}

// ✅ HÀM CONVERT SANG STRING YYYY-MM-DD
function toVietnamDateString(date) {
  const d = new Date(date);
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}
// ============ HELPER: Format timestamp cho API responses ============
function formatTimestampForAPI(timestamp) {
  if (!timestamp) return null;
  const rawDate = new Date(timestamp);
  const utc = rawDate.getTime() + (rawDate.getTimezoneOffset() * 60000);
  const vnDate = new Date(utc + VIETNAM_TIMEZONE_OFFSET);
  return vnDate.toISOString();
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
        created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
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
        created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh'),
        updated_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
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
        created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh'),
        updated_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh'),
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
    await pool.query(`ALTER TABLE ai_query_history ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh');`);
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
        created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
      );
    `);

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
        created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
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
        created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
      );
    `);
    
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_reset_email ON password_reset_codes(email);
    `);
    
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_reset_code ON password_reset_codes(code);
    `);
// ✅ THÊM cột is_hidden cho learning_roadmaps_system
await pool.query(`
  DO $$ 
  BEGIN
    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns 
      WHERE table_name = 'learning_roadmaps_system' 
      AND column_name = 'is_hidden'
    ) THEN
      ALTER TABLE learning_roadmaps_system ADD COLUMN is_hidden BOOLEAN DEFAULT FALSE;
    END IF;
  END $$;
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
// ============================================
// ENHANCED: Call Claude for materials and instructions (1 SEARCH FOR ALL DAYS)
// ============================================
async function callClaudeForMaterials({ days, category, temperature = 0.3 }) {
  if (!anthropic) {
    throw new Error("Claude API key not configured");
  }

  // ✅ VALIDATION: Kiểm tra days array
  if (!Array.isArray(days) || days.length === 0) {
    console.error('❌ Invalid days array:', days);
    throw new Error("Days array is invalid or empty");
  }

  // ✅ CHIA BATCH ĐỂ TRÁNH VƯỢT RATE LIMIT (30000 tokens/phút)
  const BATCH_SIZE = days.length;
  const batches = [];
  
  for (let i = 0; i < days.length; i += BATCH_SIZE) {
    const batch = days.slice(i, i + BATCH_SIZE);
    
    // ✅ VALIDATION: Kiểm tra batch có hợp lệ không
    if (batch.length > 0) {
      batches.push(batch);
    }
  }

  console.log(`📊 Processing ${days.length} days in ${batches.length} batches`);

  const allMaterials = [];

  // ✅ XỬ LÝ TỪNG BATCH
  for (let batchIndex = 0; batchIndex < batches.length; batchIndex++) {
    const batch = batches[batchIndex];
    
    // ✅ VALIDATION: Kiểm tra batch trước khi xử lý
    if (!batch || batch.length === 0) {
      console.warn(`⚠️ Batch ${batchIndex + 1} is empty, skipping...`);
      continue;
    }

    // ✅ VALIDATION: Kiểm tra từng item trong batch
    const validBatch = batch.filter(d => 
      d && 
      typeof d === 'object' && 
      d.day_number && 
      d.daily_goal && 
      d.learning_content
    );

    if (validBatch.length === 0) {
      console.warn(`⚠️ Batch ${batchIndex + 1} has no valid days, skipping...`);
      continue;
    }

    // ✅ TẠO daysInfo với error handling
    const daysInfo = validBatch.map(d => {
      try {
        return {
          day_number: d.day_number,
          daily_goal: String(d.daily_goal || '').substring(0, 100),
          learning_content: String(d.learning_content || '').substring(0, 150)
        };
      } catch (err) {
        console.error('❌ Error mapping day:', err, d);
        return null;
      }
    }).filter(Boolean); // ✅ Loại bỏ null values

    if (daysInfo.length === 0) {
      console.warn(`⚠️ Batch ${batchIndex + 1} has no valid daysInfo, skipping...`);
      continue;
    }

    const userPrompt = `Tìm tài liệu học tập MIỄN PHÍ, CHẤT LƯỢNG cho ${validBatch.length} ngày học về "${category}".

**DANH SÁCH NGÀY HỌC:**
${JSON.stringify(daysInfo, null, 2)}

**CHIẾN LƯỢC TÌM KIẾM:**

1️⃣ **Tìm kiếm thông minh:**
   - Tìm các nền tảng uy tín: YouTube (kênh giáo dục lớn), documentation chính thức, khóa học miễn phí
   - Ưu tiên: Video tutorials, interactive courses, official docs
   - Tránh: Blog cá nhân, forum posts, nội dung yêu cầu đăng ký

2️⃣ **Phân phối link:**
   - Nếu tìm được 1 playlist/course dài → Chia thành các phần khác nhau
   - Nếu tìm được documentation series → Link đến các sections khác nhau
   - MỖI NGÀY phải có link ĐỘC NHẤT (không trùng lặp)

**YÊU CẦU BẮT BUỘC:**
✅ Link phải CỤ THỂ (trực tiếp đến bài học, không phải trang chủ)
✅ Link phải MIỄN PHÍ (không paywall)
✅ Mỗi ngày phải có link KHÁC NHAU
✅ Ghi rõ timestamp nếu cùng 1 video
✅ Instructions phải CHI TIẾT: học phần nào, từ đâu đến đâu

**TRẢ VỀ JSON (KHÔNG có markdown, KHÔNG có giải thích):**
{
  "search_summary": "Mô tả ngắn nguồn tìm được (vd: YouTube playlist Python Tutorial by freeCodeCamp)",
  "materials": [
    {
      "day_number": ${daysInfo[0].day_number},
      "learning_materials": "URL CỤ THỂ",
      "usage_instructions": "📹 Xem video từ 0:00 đến 30:00 - Học về: [topic]. Tập trung vào [key points]."
    }
  ]
}`;

    const systemPrompt = `Bạn là chuyên gia tìm kiếm tài liệu học tập trực tuyến với 10+ năm kinh nghiệm.

**⚠️ QUAN TRỌNG - ĐỌC KỸ:**
- BẠN PHẢI trả về ĐÚNG format JSON như yêu cầu
- KHÔNG được thêm bất kỳ text nào ngoài JSON
- KHÔNG được thêm giải thích, lời mở đầu, hay kết luận
- Bắt đầu response bằng { và kết thúc bằng }
- KHÔNG wrap JSON trong markdown code blocks

**NHIỆM VỤ:** Tìm tài liệu HỌC TẬP CHẤT LƯỢNG, MIỄN PHÍ

**QUY TẮC VÀNG:**
1. **Ưu tiên các nền tảng uy tín:**
   - YouTube: freeCodeCamp, Traversy Media, Programming with Mosh, Academind
   - Documentation: MDN, W3Schools, Official Docs
   - Platforms: Khan Academy, Coursera (audit), edX (audit), Udacity (free tier)

2. **Tránh các nguồn không đáng tin:**
   - Blog cá nhân không rõ nguồn gốc
   - Nội dung yêu cầu payment
   - Links có quá nhiều ads
   - Forum posts (trừ Stack Overflow cho references)

3. **Link phải CỤ THỂ:**
   ❌ SAI: https://youtube.com/user/channelname
   ❌ SAI: https://website.com/courses
   ✅ ĐÚNG: https://youtube.com/watch?v=abc123
   ✅ ĐÚNG: https://website.com/courses/python/lesson-1

4. **Instructions phải CHI TIẾT:**
   ❌ SAI: "Học về Python basics"
   ✅ ĐÚNG: "📹 Xem từ 0:00 đến 25:30. Học về: Variables, Data Types, Print function. Tập trung: Syntax và cách khai báo biến."

**VÍ DỤ OUTPUT ĐÚNG:**
{
  "search_summary": "Tìm thấy playlist Khan Academy về toán lớp 3",
  "materials": [
    {
      "day_number": 1,
      "learning_materials": "https://www.khanacademy.org/math/cc-third-grade-math/intro-to-multiplication",
      "usage_instructions": "📚 Xem video 'Introduction to Multiplication'. Học về: khái niệm nhân cơ bản, ví dụ thực tế. Thực hành: 5 bài tập cuối video."
    }
  ]
}`;

    try {
      // ✅ TÍNH TOÁN TOKENS AN TOÀN
      const estimatedTokensPerDay = 250;
      const estimatedTotal = validBatch.length * estimatedTokensPerDay;
      const maxTokens = Math.min(estimatedTotal + 1000, 8000);
      
      console.log(`📊 Batch ${batchIndex + 1}/${batches.length}: days=${validBatch.length}, tokens=${maxTokens}`);
      
      const params = {
        model: CLAUDE_MODEL,
        max_tokens: maxTokens,
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
      
      console.log(`📤 Claude batch ${batchIndex + 1} with WEB SEARCH: model=${params.model}, max_tokens=${params.max_tokens}`);
      
      let fullText = '';
      let chunkCount = 0;

      const stream = await anthropic.messages.create(params);

      for await (const event of stream) {
        if (event.type === 'content_block_delta' && event.delta.type === 'text_delta') {
          fullText += event.delta.text;
          chunkCount++;

          if (chunkCount % 50 === 0) {
            console.log(`📄 [Claude batch ${batchIndex + 1}] ${chunkCount} chunks, ${fullText.length} chars...`);
          }
        }
      }

      console.log(`✅ [Claude batch ${batchIndex + 1}] Complete: ${fullText.length} chars`);

      // ✅ PARSE JSON THÔNG MINH
      let parsed;
      try {
        // Bước 1: Tìm JSON block trong markdown
        const jsonMatch = fullText.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
        const jsonText = jsonMatch ? jsonMatch[1] : fullText;
        
        parsed = JSON.parse(jsonText);
      } catch (e) {
        console.warn(`⚠️ First parse failed, trying cleanup...`);
        
        try {
          // Bước 2: Clean up và thử lại
          const cleaned = fullText
            .replace(/```(?:json)?/g, '')
            .replace(/[\u2018\u2019]/g, "'")
            .replace(/[\u201C\u201D]/g, '"')
            .replace(/,\s*([}\]])/g, '$1')
            .trim();
          
          parsed = JSON.parse(cleaned);
        } catch (e2) {
          console.warn(`⚠️ Second parse failed, trying to extract JSON object...`);
          
          try {
            // Bước 3: Tìm JSON object đầu tiên trong text
            const jsonObjectMatch = fullText.match(/\{[\s\S]*?\}(?=\s*$)/);
            
            if (!jsonObjectMatch) {
              console.error(`❌ No JSON object found in response`);
              console.error(`📄 Response preview:`, fullText.substring(0, 500));
              
              // ✅ TẠO FALLBACK DATA thay vì throw error
              parsed = {
                search_summary: "Claude không trả về JSON hợp lệ",
                materials: validBatch.map(d => ({
                  day_number: d.day_number,
                  learning_materials: "",
                  usage_instructions: "Vui lòng tự tìm tài liệu học tập phù hợp"
                }))
              };
            } else {
              parsed = JSON.parse(jsonObjectMatch[0]);
            }
          } catch (e3) {
            console.error(`❌ All parse attempts failed`);
            console.error(`📄 Full response:`, fullText);
            
            // ✅ TẠO FALLBACK DATA
            parsed = {
              search_summary: "Không thể parse response từ Claude",
              materials: validBatch.map(d => ({
                day_number: d.day_number,
                learning_materials: "",
                usage_instructions: "Vui lòng tự tìm tài liệu học tập phù hợp"
              }))
            };
          }
        }
      }

      // ✅ VALIDATION: Kiểm tra parsed object
      if (!parsed || typeof parsed !== 'object') {
        console.warn(`⚠️ Invalid parsed object`);
        parsed = { materials: [] };
      }

      if (!Array.isArray(parsed.materials)) {
        console.warn(`⚠️ materials is not an array`);
        parsed.materials = [];
      }

      if (parsed.materials && Array.isArray(parsed.materials)) {
        allMaterials.push(...parsed.materials);
        console.log(`✅ Batch ${batchIndex + 1}: Got ${parsed.materials.length} materials`);
        console.log(`🔍 Summary: ${parsed.search_summary || 'N/A'}`);
      } else {
        console.warn(`⚠️ Batch ${batchIndex + 1}: No valid materials returned`);
      }

      // ✅ DELAY GIỮA CÁC BATCH ĐỂ TRÁNH RATE LIMIT
      if (batchIndex < batches.length - 1) {
        const delaySeconds = 3;
        console.log(`⏳ Waiting ${delaySeconds}s before next batch...`);
        await new Promise(resolve => setTimeout(resolve, delaySeconds * 1000));
      }

    } catch (err) {
      console.error(`❌ Claude batch ${batchIndex + 1} failed:`, err.message);
      console.error(`Stack:`, err.stack);
      
      // ✅ KHÔNG THROW - TIẾP TỤC VỚI BATCH TIẾP THEO
      console.log(`⚠️ Skipping batch ${batchIndex + 1}, continuing...`);
      continue;
    }
  }

  console.log(`✅ Total materials collected: ${allMaterials.length}`);

  return {
    choices: [{
      message: {
        content: JSON.stringify({ materials: allMaterials })
      }
    }]
  };
}
// ============================================
// ENHANCED: Use Google Search fallback for remaining errors
// ============================================
function createGoogleSearchFallback(day, category) {
  const searchQuery = encodeURIComponent(`${day.daily_goal} ${category} tutorial`);
  const googleSearchUrl = `https://www.google.com/search?q=${searchQuery}`;
  
  // ✅ Tạo guide với ký tự xuống dòng thực
  let fallbackGuide = `${day.study_guide || ''}`;
  
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

    // ✅ LẤY ROLE CỦA USER
    const userRole = req.user?.role || 'user';
    const MAX_DAYS_FOR_USER = getMaxDaysForUser(userRole);

    // ✅ VALIDATE VỚI GIỚI HẠN RIÊNG
    if (isNaN(actualDays) || actualDays < MIN_AI_DAYS || actualDays > MAX_DAYS_FOR_USER) {
      return res.status(400).json({ 
        success: false, 
        error: `Số ngày phải từ ${MIN_AI_DAYS} đến ${MAX_DAYS_FOR_USER} (Role: ${userRole})` 
      });
    }

    const roadmapStartDate = getVietnamDate();
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
        timestamp: getVietnamDate().toISOString()
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
    //console.log('🔍 Days array before Claude:', JSON.stringify(days.slice(0, 2), null, 2));
    //console.log('🔍 Days count:', days.length);
    //console.log('🔍 First day structure:', days[0]);
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
          updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh') 
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
             updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh') 
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
      
      // ✅ KHAN ACADEMY: Chỉ cần check title "Page not found"
      if (isKhanAcademy) {
        // Nếu title là "Page not found | Khan Academy" => 404
        if (titleText.includes('Page not found')) {
          console.log(`❌ Khan Academy 404: ${url}`);
          return { valid: false, reason: 'khan_404', url };
        }
        
        // Không phải 404 => OK
        console.log(`✅ Khan Academy - valid: ${url}`);
        return { valid: true, url };
      }
      
      // ✅ NON-KHAN: Check content-type
      const contentType = response.headers.get('content-type') || '';
      if (!contentType.includes('text/html')) {
        console.log(`⚠️ Non-HTML content: ${contentType}`);
        // Vẫn chấp nhận nếu là educational site
        if (!url.includes('brilliant') && !url.includes('coursera')) {
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
      study_date: toVietnamDateString(new Date(startDate.getTime() + (i * 86400000)))
    });
  }
  
  return normalized;
}

// ========== ROADMAP CRUD ENDPOINTS ==========

app.get("/api/roadmaps", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM learning_roadmaps WHERE user_id = $1 ORDER BY created_at DESC`, 
      [req.user.id]
    );
    
    // ✅ Format timestamps
    const formatTimestamp = (timestamp) => {
      if (!timestamp) return null;
      const rawDate = new Date(timestamp);
      const utc = rawDate.getTime() + (rawDate.getTimezoneOffset() * 60000);
      const vnDate = new Date(utc + VIETNAM_TIMEZONE_OFFSET);
      return vnDate.toISOString();
    };
    
    const formattedRows = result.rows.map(row => ({
      ...row,
      created_at: formatTimestamp(row.created_at),
      updated_at: formatTimestamp(row.updated_at)
    }));
    
    res.json({ success: true, data: formattedRows });
  } catch (err) {
    console.error("Error fetching roadmaps:", err && err.message ? err.message : err);
    res.status(500).json({ success: false, error: "Không thể lấy danh sách lộ trình" });
  }
});
// Thêm endpoint này vào server.js, sau dòng app.get("/api/roadmaps", ...)

app.post("/api/roadmaps", requireAuth, async (req, res) => {
  try {
    const { roadmapData, roadmap_analyst, history_id } = req.body;
    const { roadmap_name, category, sub_category, start_level, duration_days, duration_hours, expected_outcome, days } = roadmapData;
    
    if (!roadmap_name || !category || !start_level || !duration_days || !duration_hours || !expected_outcome) {
      return res.status(400).json({ success: false, error: "Thiếu thông tin bắt buộc" });
    }
    
    // ✅ THÊM created_at VÀO INSERT
    const roadmapResult = await pool.query(
      `INSERT INTO learning_roadmaps (roadmap_name, category, sub_category, start_level, user_id, duration_days, duration_hours, expected_outcome, roadmap_analyst, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')) RETURNING roadmap_id, created_at`,
      [roadmap_name, category, sub_category || null, start_level, req.user.id, duration_days, duration_hours, expected_outcome, roadmap_analyst || null]
    );
    
    const roadmapId = roadmapResult.rows[0].roadmap_id;
    
    // ✅ PARSE created_at TỪ DB VÀ APPLY VN TIMEZONE
    const roadmapCreatedAtRaw = new Date(roadmapResult.rows[0].created_at);
    const utc = roadmapCreatedAtRaw.getTime() + (roadmapCreatedAtRaw.getTimezoneOffset() * 60000);
    const roadmapCreatedAt = new Date(utc + VIETNAM_TIMEZONE_OFFSET);
    roadmapCreatedAt.setHours(0, 0, 0, 0);
    
    // ✅ CẬP NHẬT roadmap_id vào ai_query_history
    if (history_id) {
      console.log(`✅ Updating AI history #${history_id} with roadmap_id: ${roadmapId}`);
      await pool.query(
        `UPDATE ai_query_history 
         SET roadmap_id = $1, updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh') 
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
        
        // ✅ Đảm bảo studyDate luôn theo VN timezone
        const studyDate = new Date(roadmapCreatedAt.getTime());
        studyDate.setDate(studyDate.getDate() + (dayNumber - 1));
        const studyDateStr = toVietnamDateString(studyDate);
        
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
    client = await pool.connect();
    const { roadmapDataSystem } = req.body;
    const { roadmap_name, category, sub_category, start_level, duration_days, duration_hours, roadmap_analyst } = roadmapDataSystem;
    
    if (!roadmap_name || !category || !start_level || !duration_days || !duration_hours) {
      return res.status(400).json({ success: false, error: "Thiếu thông tin bắt buộc" });
    }
    
    await client.query('BEGIN');
    
    // ✅ LẤY NGÀY VIỆT NAM HIỆN TẠI
    const vietnamToday = getVietnamDate();
    vietnamToday.setHours(0, 0, 0, 0);
    
    console.log('🇻🇳 Vietnam today:', toVietnamDateString(vietnamToday)); // Debug
    
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
        
        // ✅ TÍNH NGÀY HỌC: Ngày 1 = hôm nay, Ngày 2 = mai, ...
        const studyDate = new Date(vietnamToday);
        studyDate.setDate(studyDate.getDate() + (dayNumber - 1));
        const studyDateStr = toVietnamDateString(studyDate);
        
        console.log(`📅 Day ${dayNumber}: ${studyDateStr}`); // Debug

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
// =====================================================
// KIỂM TRA XEM NGƯỜI DÙNG ĐÃ CÓ LỘ TRÌNH NÀY CHƯA
// =====================================================
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
    
    // Bước 1: Kiểm tra xem người dùng có phải là người tạo ra lộ trình này trong hệ thống hay không.
    const creatorCheckQuery = `
      SELECT lrs.roadmap_id
      FROM learning_roadmaps_system lrs
      WHERE lrs.roadmap_name = $1 
        AND lrs.category = $2
        AND EXISTS (
          SELECT 1 
          FROM learning_roadmaps lr
          WHERE lr.roadmap_name = lrs.roadmap_name
            AND lr.category = lrs.category
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
    
    // Bước 2: Kiểm tra xem người dùng đã có lộ trình này chưa (bao gồm cả những lộ trình đã bị xóa)
    const existingQuery = `
      SELECT roadmap_id, roadmap_name
      FROM learning_roadmaps
      WHERE roadmap_name = $1 
        AND category = $2
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
    
    // Bước 3: Người dùng có thể tạo lộ trình này.
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
// ✅ HÀM PARSE TẤT CẢ FORMAT → DECIMAL (hours)
function parseDurationToHours(value) {
  if (!value) return 0;
  
  const str = String(value).trim().toLowerCase();
  
  // Pattern 1: Số thập phân thuần (1, 2.5, 1,5) → giờ
  if (/^\d+([.,]\d+)?$/.test(str)) {
    return parseFloat(str.replace(',', '.'));
  }
  
  // Pattern 2: CHỈ CÓ "m" (30m, 90m, 15m) → phút
  const minutesMatch = str.match(/^(\d+)m$/);
  if (minutesMatch) {
    return parseInt(minutesMatch[1]) / 60;
  }
  
  // Pattern 3: CHỈ CÓ "h" (1h, 2.5h, 1,5h) → giờ
  const hoursMatch = str.match(/^(\d+(?:[.,]\d+)?)h$/);
  if (hoursMatch) {
    return parseFloat(hoursMatch[1].replace(',', '.'));
  }
  
  // Pattern 4: "xh ym" hoặc "xhym" (1h 30m, 2h30m) → giờ + phút
  const combinedMatch = str.match(/^(\d+)h\s*(\d+)m$/);
  if (combinedMatch) {
    const hours = parseInt(combinedMatch[1]);
    const minutes = parseInt(combinedMatch[2]);
    return hours + (minutes / 60);
  }
  
  console.warn(`⚠️ Invalid duration format: "${value}" - returning 0`);
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
    const today = getVietnamDate();
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
          const rawDate = new Date(excelEpoch.getTime() + dayStudyValue * 86400000);
          
          // ✅ APPLY VN TIMEZONE
          const utc = rawDate.getTime() + (rawDate.getTimezoneOffset() * 60000);
          const vnDate = new Date(utc + VIETNAM_TIMEZONE_OFFSET);
          
          const year = vnDate.getFullYear();
          const month = String(vnDate.getMonth() + 1).padStart(2, '0');
          const day = String(vnDate.getDate()).padStart(2, '0');
          return `${year}-${month}-${day}`;
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
          // ✅ APPLY VN TIMEZONE
          const utc = directParse.getTime() + (directParse.getTimezoneOffset() * 60000);
          const vnDate = new Date(utc + VIETNAM_TIMEZONE_OFFSET);
          
          const year = vnDate.getFullYear();
          const month = String(vnDate.getMonth() + 1).padStart(2, '0');
          const day = String(vnDate.getDate()).padStart(2, '0');
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

    const { roadmap_name, category, sub_category, start_level } = req.body;

    if (!roadmap_name || !category || !sub_category || !start_level) {
      return res.status(400).json({ 
        success: false, 
        error: "Thiếu thông tin lộ trình (tên, danh mục, danh mục chi tiết, trình độ)" 
      });
    }

    const duration_days = normalizedData.length;

    // ✅ SỬA LẠI - DÙNG parseDurationToHours()
    const duration_hours = normalizedData.reduce((sum, row) => {
      const parsed = parseDurationToHours(row.study_duration);
      console.log(`📊 Day ${normalizedData.indexOf(row) + 1}: "${row.study_duration}" → ${parsed}h`);
      return sum + parsed;
    }, 0);

    console.log(`✅ TOTAL: ${duration_days} days × avg = ${duration_hours.toFixed(2)}h`);

    // ✅ TẠO ROADMAP
    const roadmapResult = await pool.query(
      `INSERT INTO learning_roadmaps 
       (roadmap_name, category, sub_category, start_level, user_id, duration_days, duration_hours, roadmap_analyst, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8, (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')) 
       RETURNING roadmap_id, created_at`,
      [roadmap_name, category, sub_category || null, start_level, req.user.id, duration_days, duration_hours, roadmapAnalyst || null]
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
    
    // ✅ ĐÚNG: Apply VN timezone khi format
    const formattedData = result.rows.map(row => {
      let studyDateFormatted = null;
      
      if (row.study_date) {
        // Parse và apply VN timezone
        const rawDate = new Date(row.study_date);
        const utc = rawDate.getTime() + (rawDate.getTimezoneOffset() * 60000);
        const vnDate = new Date(utc + VIETNAM_TIMEZONE_OFFSET);
        
        // Format theo kiểu Việt Nam: DD/MM/YYYY
        const day = String(vnDate.getDate()).padStart(2, '0');
        const month = String(vnDate.getMonth() + 1).padStart(2, '0');
        const year = vnDate.getFullYear();
        studyDateFormatted = `${day}/${month}/${year}`;
      }
      
      return {
        detail_id: row.detail_id,
        day_number: row.day_number,
        study_date: studyDateFormatted,
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
      };
    });
    
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
      `UPDATE learning_roadmap_details SET completion_status = $1::varchar, completed_at = CASE WHEN $1::varchar = 'COMPLETED' THEN (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh') ELSE completed_at END, updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh') WHERE detail_id = $2 RETURNING *`,
      [completion_status, detailId]
    );
    if (result.rows.length === 0) return res.status(404).json({ success: false, error: "Không tìm thấy" });
    const detail = result.rows[0];
    await pool.query(
      `UPDATE learning_roadmaps SET progress_percentage = (
         SELECT ROUND(COUNT(*) FILTER (WHERE completion_status = 'COMPLETED') * 100.0 / COUNT(*), 2)
         FROM learning_roadmap_details WHERE roadmap_id = $1
       ), updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh') WHERE roadmap_id = $1`,
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
app.get("/api/roadmaps/progress", requireAuth, async (req, res) => {
  try {
    const userId = parseInt(req.user?.id);
    if (!userId || isNaN(userId)) {
      console.error('❌ Invalid user ID:', req.user?.id);
      return res.status(401).json({ 
        success: false, 
        error: "Invalid user session"
      });
    }

    console.log('📊 Progress API called by user:', userId);
    
    // ✅ Sử dụng getVietnamDate() thay vì new Date()
    const todayVN = getVietnamDate();
    todayVN.setHours(0, 0, 0, 0);
    const todayStr = toVietnamDateString(todayVN);
    
    console.log('📅 Today (VN):', todayStr);
    
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
    
    // ✅ FORMAT study_date TRƯỚC KHI SO SÁNH
    tasks.forEach(task => {
      if (!task.study_date) {
        upcoming_tasks.push(task);
        return;
      }
      
      try {
        // ✅ APPLY VN TIMEZONE khi parse study_date
        const taskDateRaw = new Date(task.study_date);
        const utc = taskDateRaw.getTime() + (taskDateRaw.getTimezoneOffset() * 60000);
        const taskDate = new Date(utc + VIETNAM_TIMEZONE_OFFSET);
        
        if (isNaN(taskDate.getTime())) {
          console.warn('⚠️ Invalid date for task', task.detail_id);
          upcoming_tasks.push(task);
          return;
        }
        
        taskDate.setHours(0, 0, 0, 0);
        const taskDateStr = toVietnamDateString(taskDate);
        
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
    const roadmapId = parseInt(req.params.id);
    
    if (isNaN(roadmapId)) {
      return res.status(400).json({ success: false, error: "ID lộ trình không hợp lệ" });
    }
    
    const userId = parseInt(req.user?.id);
    
    if (!userId || isNaN(userId)) {
      return res.status(401).json({ success: false, error: "Phiên đăng nhập không hợp lệ" });
    }
    
    // ✅ CHECK OWNERSHIP
    const ownershipCheck = await pool.query(
      "SELECT roadmap_id, user_id FROM learning_roadmaps WHERE roadmap_id = $1::integer", 
      [roadmapId]
    );
    
    if (ownershipCheck.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Lộ trình không tồn tại" });
    }
    
    const ownerId = parseInt(ownershipCheck.rows[0].user_id);
    const userRole = req.user?.role || 'user';
    
    // ✅ CHO PHÉP ADMIN VÀO BẤT KỲ ROADMAP NÀO
    if (ownerId !== userId && userRole !== 'admin') {
      return res.status(403).json({ 
        success: false, 
        error: "Bạn không có quyền truy cập lộ trình này" 
      });
    }
    
    console.log('✅ Access granted, fetching data...');
    
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
        actual_learning_outcomes,
        improvement_suggestions,
        would_recommend,
        roadmap_analyst,
        created_at,
        updated_at
      FROM learning_roadmaps
      WHERE roadmap_id = $1::integer AND user_id = $2::integer
    `;
    
    const roadmapResult = await pool.query(roadmapQuery, [roadmapId, userId]);
    
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
    
    const detailsResult = await pool.query(detailsQuery, [roadmapId]);
    
    // ✅ Format timestamps
    const formatTimestamp = (timestamp) => {
      if (!timestamp) return null;
      const rawDate = new Date(timestamp);
      const utc = rawDate.getTime() + (rawDate.getTimezoneOffset() * 60000);
      const vnDate = new Date(utc + VIETNAM_TIMEZONE_OFFSET);
      return vnDate.toISOString();
    };
    
    const formatDate = (dateStr) => {
      if (!dateStr) return null;
      const rawDate = new Date(dateStr);
      const utc = rawDate.getTime() + (rawDate.getTimezoneOffset() * 60000);
      const vnDate = new Date(utc + VIETNAM_TIMEZONE_OFFSET);
      return toVietnamDateString(vnDate);
    };
    
    const roadmap = roadmapResult.rows[0];
    const formattedRoadmap = {
      ...roadmap,
      created_at: formatTimestamp(roadmap.created_at),
      updated_at: formatTimestamp(roadmap.updated_at)
    };
    
    const formattedDetails = detailsResult.rows.map(detail => ({
      ...detail,
      study_date: formatDate(detail.study_date),
      created_at: formatTimestamp(detail.created_at),
      updated_at: formatTimestamp(detail.updated_at),
      completed_at: formatTimestamp(detail.completed_at)
    }));
    
    res.json({ 
      success: true, 
      data: {
        roadmap: formattedRoadmap,
        details: formattedDetails
      }
    });
    
  } catch (err) {
    console.error("❌❌❌ ERROR in /api/roadmaps/:id:");
    console.error("Message:", err?.message);
    console.error("Stack:", err?.stack);
    
    res.status(500).json({ 
      success: false, 
      error: "Không thể lấy thông tin lộ trình",
      debug: process.env.NODE_ENV === 'development' ? err?.message : undefined
    });
  }
});
app.put("/api/roadmaps/:id/update-details", requireAuth, async (req, res) => {
  const client = await pool.connect();
  
  try {
    const roadmapId = parseInt(req.params.id);
    const { existingRows, newRows, deletedIds, roadmap_analyst } = req.body;
    
    // Verify ownership
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
    
    console.log(`📊 Update breakdown:`);
    console.log(`  - ${existingRows?.length || 0} existing`);
    console.log(`  - ${newRows?.length || 0} new`);
    console.log(`  - ${deletedIds?.length || 0} deleted`);
    
    // ✅ XÓA TOÀN BỘ details của roadmap này
    await client.query(
      'DELETE FROM learning_roadmap_details WHERE roadmap_id = $1',
      [roadmapId]
    );
    
    console.log(`🗑️ Deleted all details for roadmap ${roadmapId}`);
    
    // ✅ MERGE existing + new rows thành 1 mảng duy nhất
    const allRowsToInsert = [];
    
    // Thêm existing rows (đã được frontend đánh lại số thứ tự)
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
    
    // Thêm new rows
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
    
    console.log(`📊 Total rows to insert: ${allRowsToInsert.length}`);
    
    // ✅ INSERT LẠI TOÀN BỘ theo thứ tự mới
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
    
    console.log(`✅ Inserted ${allRowsToInsert.length} rows successfully`);
    
    // ✅ Recalculate total hours
    const totalDays = allRowsToInsert.length;
    const totalHours = allRowsToInsert.reduce((sum, d) => {
      return sum + d.study_duration;
    }, 0);
    
    // ✅ TÍNH LẠI PROGRESS PERCENTAGE
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
    
    console.log(`📊 Progress: ${completed_count}/${total_count} = ${progressPercentage.toFixed(2)}%`);
    
    // ✅ Update roadmap
    const updateRoadmapQuery = updatedAnalysis 
      ? `UPDATE learning_roadmaps 
         SET 
           duration_hours = $1, 
           duration_days = $2,
           progress_percentage = $3,
           roadmap_analyst = $4, 
           updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh') 
         WHERE roadmap_id = $5`
      : `UPDATE learning_roadmaps 
         SET 
           duration_hours = $1,
           duration_days = $2,
           progress_percentage = $3,
           updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh') 
         WHERE roadmap_id = $4`;
    
    const updateParams = updatedAnalysis 
      ? [totalHours, totalDays, Number(progressPercentage.toFixed(2)), updatedAnalysis, roadmapId]
      : [totalHours, totalDays, Number(progressPercentage.toFixed(2)), roadmapId];
    
    await client.query(updateRoadmapQuery, updateParams);
    
    // ✅ CHECK và UPDATE SYSTEM nếu rating >= 4
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
        const systemCheckQuery = `
          SELECT roadmap_id 
          FROM learning_roadmaps_system 
          WHERE roadmap_name = $1 AND category = $2
          LIMIT 1
        `;
        const systemCheck = await client.query(systemCheckQuery, [
          roadmap.roadmap_name,
          roadmap.category
        ]);
        
        if (systemCheck.rows.length > 0) {
          const systemRoadmapId = systemCheck.rows[0].roadmap_id;
          
          await client.query(
            'DELETE FROM learning_roadmap_details_system WHERE roadmap_id = $1',
            [systemRoadmapId]
          );
          
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
          
          if (updatedAnalysis) {
            await client.query(
              `UPDATE learning_roadmaps_system 
              SET 
                roadmap_analyst = $1,
                duration_days = $2,
                duration_hours = $3,
                updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh') 
              WHERE roadmap_id = $4`,
              [updatedAnalysis, totalDays, totalHours, systemRoadmapId]
            );
          }
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
    console.error('❌ Error saving changes:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Không thể lưu thay đổi'
    });
  } finally {
    client.release();
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
    const existing = await pool.query(
      "SELECT id FROM users WHERE username = $1 OR email = $2", 
      [normalizedUsername, normalizedEmail]
    );
    if (existing.rows.length > 0) return res.status(409).json({ message: "Tên đăng nhập hoặc email đã tồn tại!" });
    
    const hashed = await hashPassword(password, 10);
    
    // ✅ THÊM created_at VÀO INSERT
    const result = await pool.query(
      `INSERT INTO users (name, username, email, password, created_at) 
       VALUES ($1,$2,$3,$4, (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')) 
       RETURNING id, name, username, email, created_at`,
      [name.trim(), normalizedUsername, normalizedEmail, hashed]
    );
    
    const user = result.rows[0];
    const token = makeToken(user.id);
    
    // ✅ FORMAT created_at
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

// GET /api/admin/users/:id
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
    const vnNow = getVietnamDate();
    const expiresAt = new Date(vnNow.getTime() + 10 * 60 * 1000);
    
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
    
    // ✅ ĐÚNG: Parse expires_at với VN timezone
    const vnNow = getVietnamDate();
    const expiresAtRaw = new Date(resetCode.expires_at);
    
    // Chuyển về VN timezone để so sánh
    const utc = expiresAtRaw.getTime() + (expiresAtRaw.getTimezoneOffset() * 60000);
    const expiresAtVN = new Date(utc + VIETNAM_TIMEZONE_OFFSET);
    
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
    
    // ✅ ĐÚNG: Parse expires_at với VN timezone
    const vnNow = getVietnamDate();
    const expiresAtRaw = new Date(resetCode.expires_at);
    const utc = expiresAtRaw.getTime() + (expiresAtRaw.getTimezoneOffset() * 60000);
    const expiresAtVN = new Date(utc + VIETNAM_TIMEZONE_OFFSET);
    
    if (vnNow > expiresAtVN) {
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
// ========== EMAIL VERIFICATION FOR REGISTRATION ==========

// 1️⃣ REQUEST VERIFICATION CODE
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
    const expiresAt = new Date(vnNow.getTime() + 10 * 60 * 1000); // 10 phút
    
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
    
    try {
      await transporter.sendMail(mailOptions);
      
      res.json({
        success: true,
        message: 'Mã xác thực đã được gửi đến email của bạn',
        expiresIn: 600 // 10 phút
      });
    } catch (emailError) {
      console.error('❌ Send email error:', emailError);
      return res.status(500).json({
        success: false,
        error: 'Không thể gửi email. Vui lòng thử lại sau.'
      });
    }
    
  } catch (error) {
    console.error('Error requesting verification code:', error);
    res.status(500).json({
      success: false,
      error: 'Không thể xử lý yêu cầu'
    });
  }
});

// 2️⃣ VERIFY CODE FOR REGISTRATION
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
    const utc = expiresAtRaw.getTime() + (expiresAtRaw.getTimezoneOffset() * 60000);
    const expiresAtVN = new Date(utc + VIETNAM_TIMEZONE_OFFSET);
    
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
// ========== CLEANUP OLD CODES (Chạy mỗi giờ) ==========
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

// ============ CATEGORY API ENDPOINTS ============
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
    
    // ✅ Format created_at
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
// ============ SUB-CATEGORIES API ENDPOINT ============
// Thêm SAU endpoint GET /api/categories
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
      SELECT 
        id,
        name || ' - ' || description name,
        description,
        created_at
      FROM sub_categories
      WHERE category_id = $1
      ORDER BY id ASC
    `;
    
    const result = await pool.query(query, [categoryId]);
    
    // ✅ Format timestamps
    const formattedSubCategories = result.rows.map(sub => ({
      ...sub,
      created_at: formatTimestampForAPI(sub.created_at)
    }));
    
    res.json({ 
      success: true, 
      data: formattedSubCategories 
    });
    
  } catch (err) {
    console.error("Error fetching sub-categories:", err?.message || err);
    res.status(500).json({ 
      success: false, 
      error: "Không thể lấy danh mục con" 
    });
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
app.put("/api/admin/sub-categories/:id", requireAdmin, async (req, res) => {
  try {
    const { name, description } = req.body;
    const subId = parseInt(req.params.id);
    
    if (!name || !name.trim()) {
      return res.status(400).json({ success: false, error: "Tên danh mục con không được để trống" });
    }
    
    const result = await pool.query(
      `UPDATE sub_categories 
       SET name = $1, description = $2 
       WHERE id = $3 
       RETURNING *`,
      [name.trim(), description?.trim() || null, subId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Danh mục con không tồn tại" });
    }
    
    res.json({ 
      success: true, 
      data: result.rows[0], 
      message: "Cập nhật thành công" 
    });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ success: false, error: "Tên danh mục con đã tồn tại" });
    }
    console.error(err);
    res.status(500).json({ success: false, error: "Không thể cập nhật" });
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
    
    // ✅ Format query_time
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
    
    // ✅ Format created_at
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
const updateDetailStatusSchema = Joi.object({
    detailId: Joi.number().required(),
    status: Joi.string().valid('NOT_STARTED', 'IN_PROGRESS', 'COMPLETED', 'SKIPPED').required(),
    studyDate: Joi.string().allow(null, '')
});
// ============ ADMIN: SYSTEM ROADMAPS ============
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

app.get("/api/admin/roadmaps-system/:id", requireAdmin, async (req, res) => {
  try {
    const roadmapId = parseInt(req.params.id);
    
    const query = `
      SELECT * FROM learning_roadmap_details_system
      WHERE roadmap_id = $1
      ORDER BY day_number ASC
    `;
    
    const result = await pool.query(query, [roadmapId]);
    
    res.json({ success: true, data: result.rows });
  } catch (error) {
    console.error('Error fetching system roadmap details:', error);
    res.status(500).json({ success: false, error: 'Không thể tải chi tiết' });
  }
});

// ============ ADMIN: USER ROADMAPS ============
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
// ✅ API: Ẩn/hiện lộ trình hệ thống
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
// Tìm đoạn code này (khoảng dòng 1180-1230):

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
        r.learning_effectiveness,
        r.difficulty_suitability,
        r.content_relevance,
        r.engagement_level,
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

    console.log('📊 Executing query with userId:', userIdInt);
    
    const result = await pool.query(query, [userIdInt]);
    
    console.log('✅ Query success, rows:', result.rows.length);

    // ✅ HELPER: Format timestamp
    const formatTimestamp = (timestamp) => {
      if (!timestamp) return null;
      const rawDate = new Date(timestamp);
      const utc = rawDate.getTime() + (rawDate.getTimezoneOffset() * 60000);
      const vnDate = new Date(utc + VIETNAM_TIMEZONE_OFFSET);
      return vnDate.toISOString();
    };

    const processedRows = result.rows.map(row => {
      let computed_status = 'NOT_STARTED';
      
      if (row.total_days > 0 && row.skipped_count === row.total_days) {
        computed_status = 'SKIPPED';
      }
      else if (row.progress_percentage > 0 || row.in_progress_count > 0 || row.completed_count > 0) {
        computed_status = 'IN_PROGRESS';
      }
      
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
        status: computed_status,
        progress_percentage: row.progress_percentage,
        total_studied_hours: row.total_studied_hours,
        overall_rating: row.overall_rating,
        learning_effectiveness: row.learning_effectiveness,
        difficulty_suitability: row.difficulty_suitability,
        content_relevance: row.content_relevance,
        engagement_level: row.engagement_level,
        roadmap_analyst: row.roadmap_analyst,
        expected_outcome: row.expected_outcome,
        created_at: formatTimestamp(row.created_at) // ✅ ĐÚNG: Format theo VN timezone
      };
    });

    res.json({
      success: true,
      data: processedRows
    });

  } catch (error) {
    console.error('❌❌❌ ERROR in /api/roadmap:', error);
    
    res.status(500).json({
      error: 'Database query failed',
      message: 'Không thể lấy danh sách lộ trình',
      debug: process.env.NODE_ENV === 'development' ? error?.message : undefined
    });
  }
});
app.get("/api/roadmap/:id", requireAuth, async (req, res) => {
  try {
    console.log('🔍 /api/roadmap/:id - req.params.id:', req.params.id);
    console.log('👤 req.user:', JSON.stringify(req.user, null, 2));
    
    const roadmapId = parseInt(req.params.id);
    
    if (isNaN(roadmapId)) {
      console.error('❌ Invalid roadmap ID:', req.params.id);
      return res.status(400).json({
        error: 'Invalid roadmap ID',
        message: 'ID lộ trình không hợp lệ'
      });
    }
    
    const userId = parseInt(req.user?.id);
    
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

    const roadmapResult = await pool.query(roadmapQuery, [roadmapId, userId]);

    if (roadmapResult.rows.length === 0) {
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

    const detailsResult = await pool.query(detailsQuery, [roadmapId]);

    // ✅ ĐÚNG: Format timestamps theo VN timezone
    const formatTimestamp = (timestamp) => {
      if (!timestamp) return null;
      const rawDate = new Date(timestamp);
      const utc = rawDate.getTime() + (rawDate.getTimezoneOffset() * 60000);
      const vnDate = new Date(utc + VIETNAM_TIMEZONE_OFFSET);
      return vnDate.toISOString();
    };

    const formatDate = (dateStr) => {
      if (!dateStr) return null;
      const rawDate = new Date(dateStr);
      const utc = rawDate.getTime() + (rawDate.getTimezoneOffset() * 60000);
      const vnDate = new Date(utc + VIETNAM_TIMEZONE_OFFSET);
      return toVietnamDateString(vnDate);
    };

    // Format roadmap
    const roadmap = roadmapResult.rows[0];
    const formattedRoadmap = {
      ...roadmap,
      created_at: formatTimestamp(roadmap.created_at),
      updated_at: formatTimestamp(roadmap.updated_at)
    };

    // Format details
    const formattedDetails = detailsResult.rows.map(detail => ({
      ...detail,
      study_date: formatDate(detail.study_date),
      created_at: formatTimestamp(detail.created_at),
      updated_at: formatTimestamp(detail.updated_at),
      completed_at: formatTimestamp(detail.completed_at)
    }));

    res.json({
      success: true,
      data: {
        roadmap: formattedRoadmap,
        details: formattedDetails
      }
    });

  } catch (error) {
    console.error('❌❌❌ ERROR in /api/roadmap/:id:', error);
    res.status(500).json({
      error: 'Database query failed',
      message: 'Không thể lấy dữ liệu lộ trình',
      debug: process.env.NODE_ENV === 'development' ? error?.message : undefined
    });
  }
});
app.put("/api/roadmap/:id/update-status", requireAuth, async (req, res) => {
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

    const { detailId, status } = value;

    const statusStr = String(status);
    const detailIdNum = parseInt(detailId, 10);
    const roadmapIdNum = parseInt(roadmapId, 10);

    await client.query('BEGIN');

    const updateDetailQuery = `
      UPDATE learning_roadmap_details
      SET 
        completion_status = $1::varchar,
        updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh'),
        completed_at = CASE 
          WHEN $1::varchar = 'COMPLETED' THEN (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
          ELSE completed_at
        END
      WHERE detail_id = $2::int AND roadmap_id = $3::int
      RETURNING detail_id, completion_status, study_date, roadmap_id, updated_at, completed_at
    `;
    const detailResult = await client.query(updateDetailQuery, [
      statusStr,
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

    const progressQuery = `
      SELECT 
        COUNT(*) FILTER (WHERE completion_status = 'COMPLETED') as completed_count,
        COUNT(*) as total_count,
        COALESCE(SUM(study_duration) FILTER (WHERE completion_status = 'COMPLETED'), 0) as total_studied_hours
      FROM learning_roadmap_details
      WHERE roadmap_id = $1
    `;

    const progressResult = await client.query(progressQuery, [roadmapId]);

    const completed_count = Number(progressResult.rows[0].completed_count) || 0;
    const total_count = Number(progressResult.rows[0].total_count) || 0;
    const total_studied_hours = Number(progressResult.rows[0].total_studied_hours) || 0;

    const progressPercentage = total_count === 0 ? 0 : (completed_count / total_count) * 100;

    const updateProgressQuery = `
      UPDATE learning_roadmaps
      SET 
        progress_percentage = $1::numeric,
        total_studied_hours = $2::numeric,
        updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
      WHERE roadmap_id = $3::int
      RETURNING roadmap_id, progress_percentage, total_studied_hours, updated_at
    `;

    const updateValues = [
      Number(progressPercentage.toFixed(2)),
      total_studied_hours,
      roadmapId
    ];

    const roadmapResult = await client.query(updateProgressQuery, updateValues);

    await client.query('COMMIT');

    // ✅ Format timestamps
    const detail = detailResult.rows[0];
    const roadmap = roadmapResult.rows[0];

    res.json({
      success: true,
      message: 'Đã cập nhật trạng thái thành công',
      data: {
        detail: {
          ...detail,
          updated_at: formatTimestampForAPI(detail.updated_at),
          completed_at: formatTimestampForAPI(detail.completed_at)
        },
        roadmap: {
          ...roadmap,
          updated_at: formatTimestampForAPI(roadmap.updated_at)
        }
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
            SELECT roadmap_id, roadmap_name, category FROM learning_roadmaps
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

        const roadmap = verifyResult.rows[0];

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
                actual_learning_outcomes = $7,
                improvement_suggestions = $8,
                would_recommend = $9,
                updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
            WHERE roadmap_id = $10
            RETURNING *
        `;

        const result = await client.query(updateQuery, [
            overall_rating,
            learning_effectiveness,
            difficulty_suitability,
            content_relevance,
            engagement_level,
            value.detailed_feedback || null,
            value.actual_learning_outcomes || null,
            value.improvement_suggestions || null,
            value.would_recommend || false,
            roadmapId
        ]);

        const updatedRoadmap = result.rows[0];

        // ✅ BƯỚC 1: Lấy category name ĐÚNG từ bảng categories
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
            console.log(`✅ Found category name: "${categoryName}" for roadmap "${updatedRoadmap.roadmap_name}"`);
        } else {
            // Fallback: Tách lấy phần trước dấu " - "
            const parts = roadmap.category.split(' - ');
            categoryName = parts[0].trim();
            console.log(`⚠️ Using fallback category: "${categoryName}"`);
        }

        // ✅ BƯỚC 2: CHECK XEM CÓ ĐỦ ĐIỀU KIỆN HIỆN Ở HỆ THỐNG KHÔNG
        const checkSystemQuery = `
            SELECT roadmap_id 
            FROM learning_roadmaps_system 
            WHERE roadmap_name = $1 AND category = $2
            LIMIT 1
        `;
        const existingSystem = await client.query(checkSystemQuery, [
            roadmap.roadmap_name,
            categoryName  // ✅ SỬ DỤNG category name ĐÚNG
        ]);

        const systemExists = existingSystem.rows.length > 0;
        const systemRoadmapId = systemExists ? existingSystem.rows[0].roadmap_id : null;

        // ✅ BƯỚC 3: LOGIC MỚI - overall_rating >= 4 OR learning_effectiveness >= 4
        const meetsQualityCriteria = (overall_rating >= 4 || learning_effectiveness >= 4);

        console.log(`📊 Evaluation check for roadmap #${roadmapId}:`, {
            overall_rating,
            learning_effectiveness,
            meetsQualityCriteria,
            systemExists,
            categoryName
        });

        if (meetsQualityCriteria) {
            // ✅ ĐỦ ĐIỀU KIỆN: THÊM HOẶC CẬP NHẬT
            console.log(`✅ Rating >= 4, processing roadmap #${roadmapId}...`);

            if (!systemExists) {
                // ✅ BƯỚC 4: INSERT vào learning_roadmaps_system với category name ĐÚNG
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
                    categoryName,  // ✅ ĐÚNG - Chỉ lưu tên ngắn
                    updatedRoadmap.sub_category,
                    updatedRoadmap.start_level,
                    updatedRoadmap.duration_days,
                    updatedRoadmap.duration_hours,
                    overall_rating,
                    learning_effectiveness,
                    updatedRoadmap.roadmap_analyst
                ]);

                const newSystemRoadmapId = systemResult.rows[0].roadmap_id;
                console.log(`✅ Created system roadmap #${newSystemRoadmapId} with category: "${categoryName}"`);
                
                console.log(`✅ INSERTED into learning_roadmaps_system:`, {
                    roadmap_name: updatedRoadmap.roadmap_name,
                    category: categoryName,
                    overall_rating: overall_rating,
                    learning_effectiveness: learning_effectiveness
                });

                // ✅ BƯỚC 5: Copy chi tiết
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
                console.log(`✅ Copied ${updatedRoadmap.duration_days} days to system`);

            } else {
                // UPDATE rating trong system
                const updateSystemQuery = `
                    UPDATE learning_roadmaps_system
                    SET 
                        overall_rating = $1::integer,
                        learning_effectiveness = $2::integer,
                        updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh')
                    WHERE roadmap_id = $3
                `;
                await client.query(updateSystemQuery, [
                    overall_rating,
                    learning_effectiveness,
                    systemRoadmapId
                ]);
                console.log(`✅ Updated system roadmap #${systemRoadmapId} ratings`);
            }

        } else if (systemExists) {
            // ✅ KHÔNG ĐỦ ĐIỀU KIỆN VÀ ĐÃ TỒN TẠI: XÓA KHỎI SYSTEM
            console.log(`🗑️ Rating < 4, removing roadmap from system #${systemRoadmapId}...`);

            // Xóa chi tiết trước
            await client.query(
                'DELETE FROM learning_roadmap_details_system WHERE roadmap_id = $1',
                [systemRoadmapId]
            );

            // Xóa roadmap trong system
            await client.query(
                'DELETE FROM learning_roadmaps_system WHERE roadmap_id = $1',
                [systemRoadmapId]
            );

            console.log(`✅ Removed roadmap from system (rating < 4)`);
        }

        await client.query('COMMIT');

        // ✅ Format timestamps
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
        RETURNING setting_id, created_at as updated_at
      `;

      const insertResult = await pool.query(insertQuery, [
        promptContent,
        jsonFormat,
        req.user.id
      ]);
      
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
      error: 'Database error',
      message: 'Không thể lưu Prompt mẫu'
    });
  }
});
// ============ MANUAL PROMPT API ENDPOINTS ============
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

    // ✅ KHAI BÁO updateQuery VÀ insertQuery
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

    // ✅ CHECK và UPDATE/INSERT
    const checkQuery = `
      SELECT setting_id 
      FROM admin_settings 
      WHERE setting_key = 'prompt_template'
      LIMIT 1
    `;
    
    const checkResult = await pool.query(checkQuery);
    
    if (checkResult.rows.length > 0) {
      const result = await pool.query(updateQuery, [
        manualPromptTemplate, 
        req.user.id
      ]);
      
      res.json({
        success: true,
        message: '✅ Đã khôi phục manual prompt về mặc định',
        data: {
          manual_prompt_template: manualPromptTemplate,
          updated_at: formatTimestampForAPI(result.rows[0].updated_at)
        }
      });
    } else {
      const result = await pool.query(insertQuery, [
        manualPromptTemplate, 
        req.user.id
      ]);
      
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
        updated_at = (NOW() AT TIME ZONE 'Asia/Ho_Chi_Minh'),
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
        // ✅ BƯỚC 1: Đếm roadmap trong learning_roadmaps_system
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
            GROUP BY c.id, c.name, c.description
            HAVING COUNT(DISTINCT lrs.roadmap_id) > 0
            ORDER BY roadmap_count DESC
            LIMIT 6
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

/**
 * GET /api/roadmaps/category/:categoryName
 * Lấy thông tin category và tất cả lộ trình thuộc category đó (hệ thống)
 */
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

    const countQuery = `
      SELECT COUNT(*) as total
      FROM learning_roadmaps_system
      WHERE category = $1
        AND (overall_rating >= 4 OR learning_effectiveness >= 4)
    `;
    const countResult = await pool.query(countQuery, [result.rows[0].name]);
    
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


// =====================================================
// API: Lấy chi tiết 1 lộ trình system
// =====================================================
// Tìm dòng này trong server.js (khoảng dòng 1180)

app.get('/api/roadmapsystem/:roadmapId', async (req, res) => {
  try {
    const { roadmapId } = req.params;
    
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
        COUNT(DISTINCT lr.user_id) FILTER (WHERE lr.overall_rating >= 4) as high_overall_rating_count,
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
    
    // ✅ ĐÚNG: Format timestamps
    const formatTimestamp = (timestamp) => {
      if (!timestamp) return null;
      const rawDate = new Date(timestamp);
      const utc = rawDate.getTime() + (rawDate.getTimezoneOffset() * 60000);
      const vnDate = new Date(utc + VIETNAM_TIMEZONE_OFFSET);
      return vnDate.toISOString();
    };

    const roadmap = result.rows[0];
    const formattedRoadmap = {
      ...roadmap,
      created_at: formatTimestamp(roadmap.created_at),
      updated_at: formatTimestamp(roadmap.updated_at)
    };
    
    res.json({
      success: true,
      data: formattedRoadmap
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
    
    // ✅ ĐÚNG: Format timestamps và dates
    const formatTimestamp = (timestamp) => {
      if (!timestamp) return null;
      const rawDate = new Date(timestamp);
      const utc = rawDate.getTime() + (rawDate.getTimezoneOffset() * 60000);
      const vnDate = new Date(utc + VIETNAM_TIMEZONE_OFFSET);
      return vnDate.toISOString();
    };

    const formatDate = (dateStr) => {
      if (!dateStr) return null;
      const rawDate = new Date(dateStr);
      const utc = rawDate.getTime() + (rawDate.getTimezoneOffset() * 60000);
      const vnDate = new Date(utc + VIETNAM_TIMEZONE_OFFSET);
      return toVietnamDateString(vnDate);
    };

    const formattedDetails = result.rows.map(detail => ({
      ...detail,
      study_date: formatDate(detail.study_date),
      created_at: formatTimestamp(detail.created_at),
      updated_at: formatTimestamp(detail.updated_at),
      completed_at: formatTimestamp(detail.completed_at)
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

// =====================================================
// API: Lấy thông tin category cụ thể
// =====================================================
app.get('/api/categories/:categoryName', async (req, res) => {
  try {
    const categoryName  = req.params.categoryName;
    
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
// ========== START SERVER ==========

const PORT = parseInt(process.env.PORT || "5000", 10);
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`ℹ️  Local: http://localhost:${PORT}/`);
});
export default app;
