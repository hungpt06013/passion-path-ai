CREATE SCHEMA "public";
CREATE TABLE "admin_settings" (
	"setting_id" serial PRIMARY KEY,
	"setting_key" varchar(100) NOT NULL CONSTRAINT "admin_settings_setting_key_key" UNIQUE,
	"prompt_template" text,
	"json_format_response" text,
	"updated_at" timestamp DEFAULT (now() AT TIME ZONE 'Asia/Ho_Chi_Minh'::text),
	"updated_by" integer,
	"manual_prompt_template" text
);
CREATE TABLE "ai_query_history" (
	"id" serial PRIMARY KEY,
	"user_id" integer NOT NULL,
	"query_time" timestamp DEFAULT (now() AT TIME ZONE 'Asia/Ho_Chi_Minh'::text),
	"prompt_content" text NOT NULL,
	"status" varchar(20) DEFAULT 'PENDING',
	"roadmap_id" integer,
	"error_message" text,
	"response_tokens" integer,
	"created_at" timestamp DEFAULT (now() AT TIME ZONE 'Asia/Ho_Chi_Minh'::text),
	"updated_at" timestamp DEFAULT (now() AT TIME ZONE 'Asia/Ho_Chi_Minh'::text),
	CONSTRAINT "ai_query_history_status_check" CHECK (CHECK (((status)::text = ANY ((ARRAY['PENDING'::character varying, 'SUCCESS'::character varying, 'FAIL'::character varying, 'TIMEOUT'::character varying])::text[]))))
);
CREATE TABLE "categories" (
	"id" serial PRIMARY KEY,
	"name" varchar(100) NOT NULL CONSTRAINT "categories_name_key" UNIQUE,
	"description" text,
	"created_at" timestamp DEFAULT (now() AT TIME ZONE 'Asia/Ho_Chi_Minh'::text)
);
CREATE TABLE "learning_roadmap_details" (
	"detail_id" serial PRIMARY KEY,
	"roadmap_id" integer NOT NULL UNIQUE,
	"day_number" integer NOT NULL UNIQUE,
	"daily_goal" varchar(500) NOT NULL,
	"learning_content" text NOT NULL,
	"practice_exercises" text,
	"learning_materials" varchar(1000),
	"study_duration" numeric(4, 2) NOT NULL,
	"completion_status" varchar(20) DEFAULT 'NOT_STARTED',
	"study_date" date,
	"created_at" timestamp DEFAULT (now() AT TIME ZONE 'Asia/Ho_Chi_Minh'::text),
	"updated_at" timestamp DEFAULT (now() AT TIME ZONE 'Asia/Ho_Chi_Minh'::text),
	"completed_at" timestamp,
	"usage_instructions" text,
	CONSTRAINT "learning_roadmap_details_roadmap_id_day_number_key" UNIQUE("roadmap_id","day_number"),
	CONSTRAINT "learning_roadmap_details_completion_status_check" CHECK (CHECK (((completion_status)::text = ANY ((ARRAY['NOT_STARTED'::character varying, 'IN_PROGRESS'::character varying, 'COMPLETED'::character varying, 'SKIPPED'::character varying])::text[])))),
	CONSTRAINT "learning_roadmap_details_study_duration_hours_check" CHECK (CHECK ((study_duration > (0)::numeric)))
);
CREATE TABLE "learning_roadmap_details_system" (
	"detail_id" serial PRIMARY KEY,
	"roadmap_id" integer NOT NULL,
	"day_number" integer NOT NULL,
	"study_date" date,
	"daily_goal" text,
	"learning_content" text,
	"practice_exercises" text,
	"learning_materials" text,
	"usage_instructions" text,
	"study_duration" numeric(4, 2),
	"completion_status" varchar(20),
	"created_at" timestamp DEFAULT (now() AT TIME ZONE 'Asia/Ho_Chi_Minh'::text),
	"updated_at" timestamp DEFAULT (now() AT TIME ZONE 'Asia/Ho_Chi_Minh'::text),
	"completed_at" timestamp
);
CREATE TABLE "learning_roadmaps" (
	"roadmap_id" serial PRIMARY KEY,
	"roadmap_name" varchar(255) NOT NULL,
	"category" varchar(100) NOT NULL,
	"sub_category" varchar(100),
	"start_level" varchar(20),
	"user_id" integer NOT NULL,
	"duration_days" integer NOT NULL,
	"duration_hours" numeric(6, 2) NOT NULL,
	"status" varchar(20) DEFAULT 'ACTIVE',
	"expected_outcome" text,
	"progress_percentage" numeric(5, 2) DEFAULT '0.00',
	"total_studied_hours" numeric(6, 2) DEFAULT '0.00',
	"overall_rating" numeric(2, 1),
	"learning_effectiveness" integer,
	"difficulty_suitability" integer,
	"content_relevance" integer,
	"engagement_level" integer,
	"would_recommend" boolean,
	"created_at" timestamp DEFAULT (now() AT TIME ZONE 'Asia/Ho_Chi_Minh'::text),
	"updated_at" timestamp DEFAULT (now() AT TIME ZONE 'Asia/Ho_Chi_Minh'::text),
	"roadmap_analyst" text,
	"detailed_feedback" text,
	"actual_learning_outcomes" text,
	"improvement_suggestions" text,
	CONSTRAINT "learning_roadmaps_content_relevance_check" CHECK (CHECK (((content_relevance >= 1) AND (content_relevance <= 5)))),
	CONSTRAINT "learning_roadmaps_difficulty_suitability_check" CHECK (CHECK (((difficulty_suitability >= 1) AND (difficulty_suitability <= 5)))),
	CONSTRAINT "learning_roadmaps_duration_days_check" CHECK (CHECK ((duration_days > 0))),
	CONSTRAINT "learning_roadmaps_duration_hours_check" CHECK (CHECK ((duration_hours > (0)::numeric))),
	CONSTRAINT "learning_roadmaps_engagement_level_check" CHECK (CHECK (((engagement_level >= 1) AND (engagement_level <= 5)))),
	CONSTRAINT "learning_roadmaps_learning_effectiveness_check" CHECK (CHECK (((learning_effectiveness >= 1) AND (learning_effectiveness <= 5)))),
	CONSTRAINT "learning_roadmaps_overall_rating_check" CHECK (CHECK (((overall_rating >= (1)::numeric) AND (overall_rating <= (5)::numeric)))),
	CONSTRAINT "learning_roadmaps_progress_percentage_check" CHECK (CHECK (((progress_percentage >= (0)::numeric) AND (progress_percentage <= (100)::numeric)))),
	CONSTRAINT "learning_roadmaps_start_level_check" CHECK (CHECK (((start_level)::text = ANY ((ARRAY['Mới bắt đầu'::character varying, 'Cơ bản'::character varying, 'Trung bình'::character varying, 'Khá tốt'::character varying, 'Nâng cao'::character varying])::text[])))),
	CONSTRAINT "learning_roadmaps_status_check" CHECK (CHECK (((status)::text = ANY ((ARRAY['ACTIVE'::character varying, 'COMPLETED'::character varying, 'PAUSED'::character varying])::text[]))))
);
CREATE TABLE "learning_roadmaps_system" (
	"roadmap_id" serial PRIMARY KEY,
	"roadmap_name" varchar(255) NOT NULL,
	"category" varchar(100),
	"sub_category" varchar(100),
	"start_level" varchar(50),
	"total_user_learning" integer DEFAULT 0,
	"duration_days" integer,
	"duration_hours" numeric(5, 2),
	"overall_rating" integer,
	"learning_effectiveness" integer,
	"created_at" timestamp DEFAULT (now() AT TIME ZONE 'Asia/Ho_Chi_Minh'::text),
	"updated_at" timestamp DEFAULT (now() AT TIME ZONE 'Asia/Ho_Chi_Minh'::text),
	"roadmap_analyst" text,
	"is_hidden" boolean DEFAULT false,
	CONSTRAINT "learning_roadmaps_system_learning_effectiveness_check" CHECK (CHECK (((learning_effectiveness >= 0) AND (learning_effectiveness <= 100)))),
	CONSTRAINT "learning_roadmaps_system_overall_rating_check" CHECK (CHECK (((overall_rating >= 0) AND (overall_rating <= 100))))
);
CREATE TABLE "password_reset_codes" (
	"id" serial PRIMARY KEY,
	"email" text NOT NULL,
	"code" varchar(6) NOT NULL,
	"expires_at" timestamp NOT NULL,
	"used" boolean DEFAULT false,
	"created_at" timestamp DEFAULT (now() AT TIME ZONE 'Asia/Ho_Chi_Minh'::text)
);
CREATE TABLE "sub_categories" (
	"id" serial PRIMARY KEY,
	"category_id" integer NOT NULL UNIQUE,
	"name" varchar(100) NOT NULL UNIQUE,
	"description" text,
	"created_at" timestamp DEFAULT (now() AT TIME ZONE 'Asia/Ho_Chi_Minh'::text),
	CONSTRAINT "sub_categories_category_id_name_key" UNIQUE("category_id","name")
);
CREATE TABLE "user_feedback" (
	"feedback_id" serial PRIMARY KEY,
	"user_id" integer NOT NULL,
	"rating_1" integer NOT NULL,
	"rating_2" integer NOT NULL,
	"rating_3" integer NOT NULL,
	"rating_4" integer NOT NULL,
	"rating_5" integer NOT NULL,
	"rating_6" integer NOT NULL,
	"rating_7" integer NOT NULL,
	"rating_8" integer NOT NULL,
	"question_1" text,
	"question_2" text,
	"question_3" text,
	"created_at" timestamp DEFAULT (now() AT TIME ZONE 'Asia/Ho_Chi_Minh'::text),
	CONSTRAINT "user_feedback_rating_1_check" CHECK (CHECK (((rating_1 >= 1) AND (rating_1 <= 5)))),
	CONSTRAINT "user_feedback_rating_2_check" CHECK (CHECK (((rating_2 >= 1) AND (rating_2 <= 5)))),
	CONSTRAINT "user_feedback_rating_3_check" CHECK (CHECK (((rating_3 >= 1) AND (rating_3 <= 5)))),
	CONSTRAINT "user_feedback_rating_4_check" CHECK (CHECK (((rating_4 >= 1) AND (rating_4 <= 5)))),
	CONSTRAINT "user_feedback_rating_5_check" CHECK (CHECK (((rating_5 >= 1) AND (rating_5 <= 5)))),
	CONSTRAINT "user_feedback_rating_6_check" CHECK (CHECK (((rating_6 >= 1) AND (rating_6 <= 5)))),
	CONSTRAINT "user_feedback_rating_7_check" CHECK (CHECK (((rating_7 >= 1) AND (rating_7 <= 5)))),
	CONSTRAINT "user_feedback_rating_8_check" CHECK (CHECK (((rating_8 >= 1) AND (rating_8 <= 5))))
);
CREATE TABLE "users" (
	"id" serial PRIMARY KEY,
	"name" text NOT NULL,
	"username" text NOT NULL CONSTRAINT "users_username_key" UNIQUE,
	"email" text NOT NULL CONSTRAINT "users_email_key" UNIQUE,
	"password" text NOT NULL,
	"role" text DEFAULT 'user',
	"created_at" timestamp DEFAULT (now() AT TIME ZONE 'Asia/Ho_Chi_Minh'::text)
);
ALTER TABLE "admin_settings" ADD CONSTRAINT "admin_settings_updated_by_fkey" FOREIGN KEY ("updated_by") REFERENCES "users"("id") ON DELETE SET NULL;
ALTER TABLE "ai_query_history" ADD CONSTRAINT "ai_query_history_roadmap_id_fkey" FOREIGN KEY ("roadmap_id") REFERENCES "learning_roadmaps"("roadmap_id") ON DELETE SET NULL;
ALTER TABLE "ai_query_history" ADD CONSTRAINT "ai_query_history_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE;
ALTER TABLE "learning_roadmap_details" ADD CONSTRAINT "learning_roadmap_details_roadmap_id_fkey" FOREIGN KEY ("roadmap_id") REFERENCES "learning_roadmaps"("roadmap_id") ON DELETE CASCADE;
ALTER TABLE "learning_roadmap_details_system" ADD CONSTRAINT "fk_roadmap" FOREIGN KEY ("roadmap_id") REFERENCES "learning_roadmaps_system"("roadmap_id") ON DELETE CASCADE;
ALTER TABLE "learning_roadmaps" ADD CONSTRAINT "learning_roadmaps_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE;
ALTER TABLE "sub_categories" ADD CONSTRAINT "sub_categories_category_id_fkey" FOREIGN KEY ("category_id") REFERENCES "categories"("id") ON DELETE CASCADE;
ALTER TABLE "user_feedback" ADD CONSTRAINT "user_feedback_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE;
CREATE UNIQUE INDEX "admin_settings_pkey" ON "admin_settings" ("setting_id");
CREATE UNIQUE INDEX "admin_settings_setting_key_key" ON "admin_settings" ("setting_key");
CREATE INDEX "idx_admin_settings_key" ON "admin_settings" ("setting_key");
CREATE UNIQUE INDEX "ai_query_history_pkey" ON "ai_query_history" ("id");
CREATE INDEX "idx_ai_history_time" ON "ai_query_history" ("query_time");
CREATE INDEX "idx_ai_history_user" ON "ai_query_history" ("user_id");
CREATE UNIQUE INDEX "categories_name_key" ON "categories" ("name");
CREATE UNIQUE INDEX "categories_pkey" ON "categories" ("id");
CREATE INDEX "idx_roadmap_details_completion" ON "learning_roadmap_details" ("completion_status");
CREATE INDEX "idx_roadmap_details_roadmap_id" ON "learning_roadmap_details" ("roadmap_id");
CREATE INDEX "idx_roadmap_details_study_date" ON "learning_roadmap_details" ("study_date");
CREATE UNIQUE INDEX "learning_roadmap_details_pkey" ON "learning_roadmap_details" ("detail_id");
CREATE UNIQUE INDEX "learning_roadmap_details_roadmap_id_day_number_key" ON "learning_roadmap_details" ("roadmap_id","day_number");
CREATE UNIQUE INDEX "learning_roadmap_details_system_pkey" ON "learning_roadmap_details_system" ("detail_id");
CREATE INDEX "idx_roadmaps_status" ON "learning_roadmaps" ("status");
CREATE INDEX "idx_roadmaps_user_id" ON "learning_roadmaps" ("user_id");
CREATE UNIQUE INDEX "learning_roadmaps_pkey" ON "learning_roadmaps" ("roadmap_id");
CREATE UNIQUE INDEX "learning_roadmaps_system_pkey" ON "learning_roadmaps_system" ("roadmap_id");
CREATE INDEX "idx_reset_code" ON "password_reset_codes" ("code");
CREATE INDEX "idx_reset_email" ON "password_reset_codes" ("email");
CREATE UNIQUE INDEX "password_reset_codes_pkey" ON "password_reset_codes" ("id");
CREATE UNIQUE INDEX "sub_categories_category_id_name_key" ON "sub_categories" ("category_id","name");
CREATE UNIQUE INDEX "sub_categories_pkey" ON "sub_categories" ("id");
CREATE INDEX "idx_feedback_created_at" ON "user_feedback" ("created_at");
CREATE INDEX "idx_feedback_user_id" ON "user_feedback" ("user_id");
CREATE INDEX "idx_user_feedback_created" ON "user_feedback" ("created_at");
CREATE INDEX "idx_user_feedback_user" ON "user_feedback" ("user_id");
CREATE UNIQUE INDEX "user_feedback_pkey" ON "user_feedback" ("feedback_id");
CREATE UNIQUE INDEX "users_email_key" ON "users" ("email");
CREATE UNIQUE INDEX "users_pkey" ON "users" ("id");
CREATE UNIQUE INDEX "users_username_key" ON "users" ("username");
