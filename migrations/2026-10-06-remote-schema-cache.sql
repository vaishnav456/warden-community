-- Remote authority adds owner_access_token_version; refresh PostgREST's mutation schema cache.
-- A stale cache rejects otherwise valid remote-session PATCHes with PGRST204.
NOTIFY pgrst, 'reload schema';
