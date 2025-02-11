-- Add up migration script here
CREATE TABLE
  "users" (
    "id" UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    "email" VARCHAR NOT NULL UNIQUE,
    "password" VARCHAR NOT NULL,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT now (),
    "updated_at" TIMESTAMPTZ NOT NULL DEFAULT now ()
  );