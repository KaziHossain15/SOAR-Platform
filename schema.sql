-- SOAR Platform schema
-- Run this in the Supabase SQL Editor (Dashboard → SQL → New query)

-- ---------------------------------------------------------------------------
-- keyword_rules
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.keyword_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    keyword TEXT NOT NULL,
    weight INTEGER NOT NULL CHECK (weight BETWEEN 1 AND 10),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_keyword_rules_enabled
    ON public.keyword_rules (enabled);

CREATE INDEX IF NOT EXISTS idx_keyword_rules_keyword
    ON public.keyword_rules (keyword);

-- ---------------------------------------------------------------------------
-- alerts
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.alerts (
    gmail_uid TEXT PRIMARY KEY,
    message_id TEXT,
    sender TEXT,
    subject TEXT,
    threat_score INTEGER NOT NULL DEFAULT 0,
    matched_keywords TEXT[] NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'APPROVED', 'DELETED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_status
    ON public.alerts (status);

CREATE INDEX IF NOT EXISTS idx_alerts_threat_score
    ON public.alerts (threat_score);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at
    ON public.alerts (created_at DESC);

-- ---------------------------------------------------------------------------
-- Privileges + Row Level Security
-- For a local/demo SOAR app using the anon key, allow full access.
-- Tighten these policies before any shared/production deployment.
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO anon, authenticated;

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.keyword_rules TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.alerts TO anon, authenticated;

ALTER TABLE public.keyword_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.alerts ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Allow all on keyword_rules" ON public.keyword_rules;
CREATE POLICY "Allow all on keyword_rules"
    ON public.keyword_rules
    FOR ALL
    TO anon, authenticated
    USING (true)
    WITH CHECK (true);

DROP POLICY IF EXISTS "Allow all on alerts" ON public.alerts;
CREATE POLICY "Allow all on alerts"
    ON public.alerts
    FOR ALL
    TO anon, authenticated
    USING (true)
    WITH CHECK (true);

-- ---------------------------------------------------------------------------
-- Seed detection rules (skip if keyword already exists)
-- ---------------------------------------------------------------------------
INSERT INTO public.keyword_rules (keyword, weight, enabled)
SELECT v.keyword, v.weight, TRUE
FROM (
    VALUES
        ('urgent', 2),
        ('verify', 2),
        ('invoice', 2),
        ('bank', 3),
        ('payment', 3),
        ('password', 4),
        ('account suspended', 5),
        ('wire transfer', 5),
        ('gift card', 5),
        ('crypto', 4)
) AS v(keyword, weight)
WHERE NOT EXISTS (
    SELECT 1
    FROM public.keyword_rules kr
    WHERE lower(kr.keyword) = lower(v.keyword)
);

-- Refresh PostgREST schema cache (usually automatic; run if PGRST205 persists)
NOTIFY pgrst, 'reload schema';
