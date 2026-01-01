CREATE TABLE IF NOT EXISTS user_quotas (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    storage_quota BIGINT NOT NULL DEFAULT 268435456,
    storage_used BIGINT NOT NULL DEFAULT 0,
    file_count_quota INTEGER NOT NULL DEFAULT 1000,
    file_count_used INTEGER NOT NULL DEFAULT 0,
    max_file_size BIGINT NOT NULL DEFAULT 268435456,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE OR REPLACE FUNCTION create_user_quota()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO user_quotas (user_id) VALUES (NEW.id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_create_user_quota
    AFTER INSERT ON users
    FOR EACH ROW
    EXECUTE FUNCTION create_user_quota();

INSERT INTO user_quotas (user_id)
SELECT id FROM users
WHERE id NOT IN (SELECT user_id FROM user_quotas);

CREATE INDEX IF NOT EXISTS idx_user_quotas_user_id ON user_quotas(user_id);
