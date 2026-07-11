-- Optional seed data for keyword_rules (run in Supabase SQL editor)
-- Tables are assumed to already exist per project requirements.

INSERT INTO keyword_rules (keyword, weight, enabled, created_at) VALUES
  ('urgent', 2, true, NOW()),
  ('verify', 2, true, NOW()),
  ('invoice', 2, true, NOW()),
  ('bank', 3, true, NOW()),
  ('payment', 3, true, NOW()),
  ('password', 4, true, NOW()),
  ('account suspended', 5, true, NOW()),
  ('wire transfer', 5, true, NOW()),
  ('gift card', 5, true, NOW()),
  ('crypto', 4, true, NOW())
;
