-- Add VirusTotal columns to existing alerts table.
-- Run in Supabase SQL Editor if the table already exists.

ALTER TABLE public.alerts
    ADD COLUMN IF NOT EXISTS vt_score INTEGER NOT NULL DEFAULT 0;

ALTER TABLE public.alerts
    ADD COLUMN IF NOT EXISTS vt_malicious INTEGER NOT NULL DEFAULT 0;

ALTER TABLE public.alerts
    ADD COLUMN IF NOT EXISTS vt_suspicious INTEGER NOT NULL DEFAULT 0;

ALTER TABLE public.alerts
    ADD COLUMN IF NOT EXISTS vt_total INTEGER NOT NULL DEFAULT 0;

ALTER TABLE public.alerts
    ADD COLUMN IF NOT EXISTS vt_urls TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE public.alerts
    ADD COLUMN IF NOT EXISTS vt_link TEXT;
