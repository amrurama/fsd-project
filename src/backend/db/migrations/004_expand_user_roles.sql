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

DELETE FROM user_roles
WHERE role IN ('ADMIN', 'EDITOR', 'READONLY')
  AND user_id IN (
    SELECT id
    FROM users
    WHERE lower(username) = 'amrutha'
       OR lower(display_name) = 'amrutha'
       OR lower(email) LIKE 'amrutha@%'
  );

INSERT INTO user_roles (user_id, role)
SELECT id, 'ADMIN'
FROM users
WHERE lower(username) = 'amrutha'
   OR lower(display_name) = 'amrutha'
   OR lower(email) LIKE 'amrutha@%'
ON CONFLICT (user_id, role) DO NOTHING;

INSERT INTO user_roles (user_id, role)
SELECT u.id, 'READONLY'
FROM users u
WHERE NOT EXISTS (
  SELECT 1
  FROM user_roles ur
  WHERE ur.user_id = u.id
    AND ur.role IN ('ADMIN', 'EDITOR', 'READONLY')
)
ON CONFLICT (user_id, role) DO NOTHING;

DELETE FROM user_roles lower_role
WHERE lower_role.role IN ('EDITOR', 'READONLY')
  AND EXISTS (
    SELECT 1
    FROM user_roles higher_role
    WHERE higher_role.user_id = lower_role.user_id
      AND higher_role.role = 'ADMIN'
  );

DELETE FROM user_roles readonly_role
WHERE readonly_role.role = 'READONLY'
  AND EXISTS (
    SELECT 1
    FROM user_roles editor_role
    WHERE editor_role.user_id = readonly_role.user_id
      AND editor_role.role = 'EDITOR'
  );
