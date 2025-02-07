-- Add up migration script here
CREATE TABLE "forgot_password_tokens" (
    "id" SERIAL PRIMARY KEY,
    "email" VARCHAR NOT NULL,
    "token" VARCHAR(255) NOT NULL UNIQUE,
    "created_at" TIMESTAMP,
    "expired_at" TIMESTAMP,
    FOREIGN KEY ("email") REFERENCES users("email") ON DELETE CASCADE
);