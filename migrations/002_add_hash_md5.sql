ALTER TABLE files ADD COLUMN IF NOT EXISTS hash_md5 TEXT;

CREATE INDEX IF NOT EXISTS idx_files_hash_md5 ON files(hash_md5);
