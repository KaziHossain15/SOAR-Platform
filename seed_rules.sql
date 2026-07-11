-- Optional seed only (tables must already exist). Prefer schema.sql for first setup.

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
