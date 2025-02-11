-- Add up migration script here
CREATE TABLE
    "roles" (
        "id" UUID PRIMARY KEY DEFAULT gen_random_uuid (),
        "name" VARCHAR(255) NOT NULL UNIQUE,
        "created_at" TIMESTAMPTZ NOT NULL DEFAULT now (),
        "updated_at" TIMESTAMPTZ NOT NULL DEFAULT now ()
    );

-- back up situation that user aldeady exist with no role
INSERT INTO "roles" (id, name) VALUES ('00000000-0000-0000-0000-000000000000', 'None')
ON CONFLICT DO NOTHING;

ALTER TABLE "users" ADD COLUMN "role_id" UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000'::UUID;
ALTER TABLE "users" ADD FOREIGN KEY ("role_id") REFERENCES "roles" ("id");