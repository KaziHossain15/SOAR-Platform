-- Lock down SOAR tables to the service role only.
-- Run in the Supabase SQL Editor on any project created with an older
-- schema.sql that granted full access to the public anon key.
--
-- After running, set SUPABASE_KEY in .env to the service_role / secret key
-- (Project Settings -> API). The app refuses to start with an anon key.

DROP POLICY IF EXISTS "Allow all on keyword_rules" ON public.keyword_rules;
DROP POLICY IF EXISTS "Allow all on alerts" ON public.alerts;

REVOKE ALL ON TABLE public.keyword_rules FROM anon, authenticated;
REVOKE ALL ON TABLE public.alerts FROM anon, authenticated;

-- RLS on with no policies: anon/authenticated are denied; service_role bypasses RLS.
ALTER TABLE public.keyword_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.alerts ENABLE ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.keyword_rules TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.alerts TO service_role;

NOTIFY pgrst, 'reload schema';
