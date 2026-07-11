-- Quick fix: grant table privileges to the anon/authenticated roles
-- Run in Supabase SQL Editor, then refresh the Streamlit app.

GRANT USAGE ON SCHEMA public TO anon, authenticated;

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.keyword_rules TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.alerts TO anon, authenticated;

-- Ensure RLS policies exist (safe to re-run)
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
