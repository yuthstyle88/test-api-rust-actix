-- Add up migration script here
CREATE TABLE "forgot_password_tokens" (
    "id" SERIAL PRIMARY KEY,
    "user_id" UUID NOT NULL,
    "token" VARCHAR(255) NOT NULL UNIQUE,
    "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    "expired_at" TIMESTAMP,
    FOREIGN KEY ("user_id") REFERENCES users("id") ON DELETE CASCADE
);