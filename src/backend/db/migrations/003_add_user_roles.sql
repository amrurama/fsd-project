CREATE TABLE IF NOT EXISTS user_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL,
    granted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, role)
);

CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles (user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles (role);

INSERT INTO user_roles (user_id, role)
SELECT id, 'ADMIN'
FROM users
WHERE lower(username) = 'amrutha'
   OR lower(display_name) = 'amrutha'
   OR lower(email) LIKE 'amrutha@%'
ON CONFLICT (user_id, role) DO NOTHING;
