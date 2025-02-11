-- Add down migration script here
ALTER TABLE "users"
DROP CONSTRAINT users_role_id_fkey;

DROP TABLE IF EXISTS "roles";