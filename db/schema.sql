-- Run as the owner (migration) role. The apps connect as app_user, which does NOT own
-- the tables, and FORCE ROW LEVEL SECURITY applies the policies even to the owner.

CREATE TABLE IF NOT EXISTS hotel_rules (
  hotel_id text PRIMARY KEY,
  name text NOT NULL,
  min_price numeric(10,2) NOT NULL,
  max_discount_pct int NOT NULL,
  auto_apply_max_pct int NOT NULL DEFAULT 0,
  max_changes_per_day int NOT NULL DEFAULT 5
);

-- Availability as last re-read from (fake) Mews by the webhook receiver.
CREATE TABLE IF NOT EXISTS availability (
  hotel_id text NOT NULL,
  room_type text NOT NULL,
  occupancy_pct int NOT NULL,
  current_price numeric(10,2) NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (hotel_id, room_type)
);

CREATE TABLE IF NOT EXISTS suggestions (
  id bigserial PRIMARY KEY,
  hotel_id text NOT NULL,
  room_type text NOT NULL,
  based_on numeric(10,2) NOT NULL,
  discount_pct int,
  new_price numeric(10,2),
  reason text,
  guardrail text NOT NULL,          -- 'ok' or why it was rejected
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE suggestions ADD COLUMN IF NOT EXISTS rejected_by text;
ALTER TABLE suggestions ADD COLUMN IF NOT EXISTS trigger text NOT NULL DEFAULT 'staff';
ALTER TABLE hotel_rules ADD COLUMN IF NOT EXISTS auto_apply_paused boolean NOT NULL DEFAULT false;
ALTER TABLE hotel_rules ADD COLUMN IF NOT EXISTS paused_reason text;

-- Work for the suggestion worker: written by the webhook receiver (availability changed),
-- by staff clicks (through the API) and by the worker's own timer.
CREATE TABLE IF NOT EXISTS suggestion_requests (
  id bigserial PRIMARY KEY,
  hotel_id text NOT NULL,
  room_type text NOT NULL,
  trigger text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  processed_at timestamptz
);

-- One row per approval: the audit log and the status the dashboard shows.
CREATE TABLE IF NOT EXISTS approvals (
  approval_id uuid PRIMARY KEY,
  hotel_id text NOT NULL,
  room_type text NOT NULL,
  based_on numeric(10,2) NOT NULL,
  new_price numeric(10,2) NOT NULL,
  suggestion_id bigint REFERENCES suggestions(id),
  approver_oid text NOT NULL,
  approver_name text NOT NULL,
  status text NOT NULL DEFAULT 'pending',   -- pending | applied | stopped | failed | expired
  detail text,
  mews_request_id text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Outbox: written in the SAME transaction as the approval; the relay publishes it.
CREATE TABLE IF NOT EXISTS outbox (
  approval_id uuid PRIMARY KEY REFERENCES approvals(approval_id),
  hotel_id text NOT NULL,
  payload jsonb NOT NULL,
  sent_at timestamptz
);

CREATE TABLE IF NOT EXISTS sessions (
  id text PRIMARY KEY,
  oid text NOT NULL,
  tid text NOT NULL,
  name text NOT NULL,
  roles text[] NOT NULL,
  hotels text[] NOT NULL,
  id_token text NOT NULL,
  expires_at timestamptz NOT NULL,
  trace text[] NOT NULL DEFAULT '{}'
);

-- Seed data goes in before FORCE ROW LEVEL SECURITY, which would also block the owner.
DO $$ BEGIN
  IF NOT (SELECT relforcerowsecurity FROM pg_class WHERE relname = 'hotel_rules') THEN
    INSERT INTO hotel_rules VALUES
      ('barcelona', 'Hotel Barcelona', 80, 30, 0, 5),
      ('madrid',    'Hotel Madrid',    90, 20, 5, 5)
    ON CONFLICT DO NOTHING;
  END IF;
END $$;

-- Row-level security: every query only sees rows of the hotel set in app.hotel_id.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['hotel_rules','availability','suggestions','approvals','outbox','suggestion_requests'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS hotel_isolation ON %I', t);
    EXECUTE format($p$CREATE POLICY hotel_isolation ON %I
      USING (hotel_id = current_setting('app.hotel_id', true))
      WITH CHECK (hotel_id = current_setting('app.hotel_id', true))$p$, t);
  END LOOP;
END $$;

-- app_user: the apps. relay_user: the outbox relay, the only role that sees every hotel's
-- outbox rows (and nothing else). Neither owns the tables.
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO app_user;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO app_user;
GRANT DELETE ON sessions TO app_user;
GRANT SELECT, UPDATE ON outbox TO relay_user;
DROP POLICY IF EXISTS relay_all ON outbox;
CREATE POLICY relay_all ON outbox TO relay_user USING (true);
