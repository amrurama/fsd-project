const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const pool = require('./shared/db');
const { signToken, authMiddleware } = require('./shared');

const app = express();
app.use(cors());
app.use(express.json());

const VALID_STATUSES = ['TODO', 'IN_PROGRESS', 'BLOCKED', 'DONE'];
const ADMIN_ROLE = 'ADMIN';
const EDITOR_ROLE = 'EDITOR';
const READONLY_ROLE = 'READONLY';
const VALID_ROLES = [ADMIN_ROLE, EDITOR_ROLE, READONLY_ROLE];
const ROLE_PRIORITY = [ADMIN_ROLE, EDITOR_ROLE, READONLY_ROLE];

const asyncHandler = (handler) => (req, res, next) => {
  Promise.resolve(handler(req, res, next)).catch(next);
};

const httpError = (status, message) => {
  const error = new Error(message);
  error.status = status;
  return error;
};

const normalizeEmail = (email) => {
  if (!email || typeof email !== 'string') {
    return null;
  }
  const trimmed = email.trim().toLowerCase();
  return trimmed || null;
};

const normalizeUsername = (username) => String(username || '').trim();

const normalizePassword = (password) => String(password || '');

const hashPassword = (password) => bcrypt.hash(normalizePassword(password), 10);

const verifyPassword = (password, passwordHash) => (
  passwordHash ? bcrypt.compare(normalizePassword(password), passwordHash) : false
);

const normalizeStatus = (status) => {
  if (!status) {
    return null;
  }
  const normalized = String(status).trim().toUpperCase();
  if (!VALID_STATUSES.includes(normalized)) {
    throw httpError(400, `Status must be one of: ${VALID_STATUSES.join(', ')}`);
  }
  return normalized;
};

const normalizeRole = (role) => {
  const normalized = String(role || '').trim().toUpperCase();
  if (!VALID_ROLES.includes(normalized)) {
    throw httpError(400, `Role must be one of: ${VALID_ROLES.join(', ')}`);
  }
  return normalized;
};

const getPrimaryRole = (roles = []) => {
  const normalizedRoles = Array.isArray(roles) ? roles.map((item) => String(item).toUpperCase()) : [];
  return ROLE_PRIORITY.find((role) => normalizedRoles.includes(role)) || READONLY_ROLE;
};

const normalizeRoles = (roles) => [getPrimaryRole(Array.isArray(roles) ? roles.filter(Boolean) : [])];

const isAdminUser = (user) => getPrimaryRole(user?.roles) === ADMIN_ROLE;

const canWriteUser = (user) => [ADMIN_ROLE, EDITOR_ROLE].includes(getPrimaryRole(user?.roles));

const toPublicUser = (user) => user && ({
  id: user.id || user.user_id,
  username: user.username,
  display_name: user.display_name,
  email: user.email,
  created_at: user.created_at,
  roles: normalizeRoles(user.roles)
});

const getStoredUserRoles = async (client, userId) => {
  const result = await client.query(
    'SELECT role FROM user_roles WHERE user_id = $1 AND role = ANY($2::text[]) ORDER BY role',
    [userId, VALID_ROLES]
  );
  return result.rows.map((row) => row.role);
};

const getUserRoles = async (client, userId) => normalizeRoles(await getStoredUserRoles(client, userId));

const isBootstrapAdminUser = (user) => {
  const username = String(user?.username || '').trim().toLowerCase();
  const displayName = String(user?.display_name || user?.displayName || '').trim().toLowerCase();
  const email = normalizeEmail(user?.email);
  return username === 'amrutha' || displayName === 'amrutha' || Boolean(email && email.startsWith('amrutha@'));
};

const grantUserRole = async (client, userId, role, grantedBy = null) => {
  const normalizedRole = normalizeRole(role);
  const result = await client.query(
    `INSERT INTO user_roles (user_id, role, granted_by)
     VALUES ($1, $2, $3)
     ON CONFLICT (user_id, role) DO NOTHING
     RETURNING *`,
    [userId, normalizedRole, grantedBy]
  );
  return result.rows[0] || null;
};

const setUserPrimaryRole = async (client, userId, role, grantedBy = null) => {
  const normalizedRole = normalizeRole(role);
  await client.query(
    'DELETE FROM user_roles WHERE user_id = $1 AND role = ANY($2::text[])',
    [userId, VALID_ROLES]
  );
  return grantUserRole(client, userId, normalizedRole, grantedBy);
};

const ensureDefaultRole = async (client, user) => {
  if (isBootstrapAdminUser(user)) {
    return setUserPrimaryRole(client, user.id, ADMIN_ROLE, null);
  }
  const storedRoles = await getStoredUserRoles(client, user.id);
  if (storedRoles.length === 0) {
    return grantUserRole(client, user.id, READONLY_ROLE, null);
  }
  return null;
};

const getUserWithRoles = async (client, userId) => {
  const result = await client.query(
    `SELECT u.id,
            u.username,
            u.display_name,
            u.email,
            u.created_at,
            COALESCE(array_remove(array_agg(ur.role ORDER BY ur.role), NULL), '{}') AS roles
     FROM users u
     LEFT JOIN user_roles ur ON ur.user_id = u.id
     WHERE u.id = $1
     GROUP BY u.id`,
    [userId]
  );
  return result.rows[0] || null;
};

const loadCurrentUser = asyncHandler(async (req, res, next) => {
  const result = await pool.query(
    'SELECT id, username, display_name, email, created_at FROM users WHERE id = $1',
    [req.user.id]
  );
  if (result.rows.length === 0) {
    throw httpError(401, 'User no longer exists');
  }
  const user = result.rows[0];
  req.currentUser = { ...user, roles: await getUserRoles(pool, user.id) };
  next();
});

const requireAuth = [authMiddleware, loadCurrentUser];

const requireAdmin = [
  authMiddleware,
  loadCurrentUser,
  (req, res, next) => {
    if (!isAdminUser(req.currentUser)) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    return next();
  }
];

const requireEditor = [
  authMiddleware,
  loadCurrentUser,
  (req, res, next) => {
    if (!canWriteUser(req.currentUser)) {
      return res.status(403).json({ error: 'Editor or admin access required' });
    }
    return next();
  }
];

const logAudit = async (client, { entityType, entityId, userId, action, previousValue = null, newValue = null, note = null }) => {
  if (!entityType || !entityId || !action) {
    return null;
  }
  const result = await client.query(
    `INSERT INTO audit_logs
     (entity_type, entity_id, user_id, action, previous_value, new_value, note)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     RETURNING *`,
    [entityType, entityId, userId, action, previousValue, newValue, note]
  );
  return result.rows[0];
};

const notifyUser = async (client, userId, message) => {
  if (!userId || !message) {
    return null;
  }
  const result = await client.query(
    'INSERT INTO notifications (user_id, message) VALUES ($1, $2) RETURNING *',
    [userId, message]
  );
  return result.rows[0];
};

const getAssignableUsers = async (client, projectId) => {
  const ownerResult = await client.query(
    `SELECT u.id AS user_id, u.username, u.display_name, u.email, 'OWNER' AS role, NULL::uuid AS membership_id
     FROM projects p
     JOIN users u ON u.id = p.owner_id
     WHERE p.id = $1`,
    [projectId]
  );
  const membersResult = await client.query(
    `SELECT pm.id AS membership_id,
            pm.role,
            pm.member_email,
            COALESCE(u.id, pm.user_id) AS user_id,
            u.username,
            u.display_name,
            COALESCE(u.email, pm.member_email) AS email
     FROM project_members pm
     LEFT JOIN users u
       ON u.id = pm.user_id
       OR (pm.user_id IS NULL AND pm.member_email IS NOT NULL AND lower(u.email) = lower(pm.member_email))
     WHERE pm.project_id = $1
     ORDER BY pm.created_at ASC`,
    [projectId]
  );

  const seen = new Set();
  const users = [];
  const addUser = (row, fallbackRole) => {
    const email = normalizeEmail(row.email || row.member_email);
    const key = row.user_id || email;
    if (!key || seen.has(key)) {
      return;
    }
    seen.add(key);
    users.push({
      membership_id: row.membership_id || null,
      user_id: row.user_id || null,
      username: row.username || email || 'Pending invite',
      display_name: row.display_name || row.username || email || 'Pending invite',
      email,
      role: row.role || fallbackRole || 'MEMBER',
      is_pending: !row.user_id,
      is_assignable: Boolean(row.user_id)
    });
  };

  ownerResult.rows.forEach((row) => addUser(row, 'OWNER'));
  membersResult.rows.forEach((row) => addUser(row, 'MEMBER'));
  return users;
};

const getProjectCounts = async (client, projectId) => {
  const result = await client.query(
    `SELECT
       (SELECT COUNT(*)::int FROM trackers WHERE project_id = $1) AS tracker_count,
       (SELECT COUNT(*)::int
        FROM tracker_tasks tt
        JOIN trackers t ON t.id = tt.tracker_id
        WHERE t.project_id = $1) AS task_count,
       (SELECT COUNT(*)::int
        FROM tracker_tasks tt
        JOIN trackers t ON t.id = tt.tracker_id
        WHERE t.project_id = $1 AND tt.status <> 'DONE') AS open_task_count`,
    [projectId]
  );
  return result.rows[0];
};

const enrichProject = async (client, project) => {
  const members = await getAssignableUsers(client, project.id);
  const counts = await getProjectCounts(client, project.id);
  return {
    ...project,
    owner: {
      id: project.owner_id,
      username: project.owner_username,
      display_name: project.owner_display_name,
      email: project.owner_email
    },
    members,
    tracker_count: counts.tracker_count || 0,
    task_count: counts.task_count || 0,
    open_task_count: counts.open_task_count || 0
  };
};

const getProjectOrThrow = async (client, projectId, user, options = {}) => {
  const result = await client.query(
    `SELECT p.*,
            owner.username AS owner_username,
            owner.display_name AS owner_display_name,
            owner.email AS owner_email
     FROM projects p
     JOIN users owner ON owner.id = p.owner_id
     WHERE p.id = $1`,
    [projectId]
  );
  if (result.rows.length === 0) {
    throw httpError(404, 'Project not found');
  }

  const project = result.rows[0];
  const userEmail = normalizeEmail(user.email);
  const isOwner = project.owner_id === user.id;
  const userIsAdmin = isAdminUser(user);
  const membership = await client.query(
    `SELECT 1
     FROM project_members pm
     WHERE pm.project_id = $1
       AND (pm.user_id = $2 OR ($3::text IS NOT NULL AND lower(pm.member_email) = lower($3)))
     LIMIT 1`,
    [projectId, user.id, userEmail]
  );
  const hasAccess = userIsAdmin || isOwner || membership.rows.length > 0;

  if (options.ownerOnly && !isOwner && !userIsAdmin) {
    throw httpError(403, 'Only the project owner can perform this action');
  }
  if (!hasAccess) {
    throw httpError(403, 'You do not have access to this project');
  }
  return project;
};

const getTrackerContext = async (client, trackerId, user) => {
  const result = await client.query(
    `SELECT t.*, p.id AS project_id, p.name AS project_name, p.owner_id
     FROM trackers t
     JOIN projects p ON p.id = t.project_id
     WHERE t.id = $1`,
    [trackerId]
  );
  if (result.rows.length === 0) {
    throw httpError(404, 'Tracker not found');
  }
  const tracker = result.rows[0];
  const project = await getProjectOrThrow(client, tracker.project_id, user);
  return { tracker, project };
};

const getTaskContext = async (client, taskId, user) => {
  const result = await client.query(
    `SELECT tt.*, t.name AS tracker_name, t.project_id, p.name AS project_name, p.owner_id
     FROM tracker_tasks tt
     JOIN trackers t ON t.id = tt.tracker_id
     JOIN projects p ON p.id = t.project_id
     WHERE tt.id = $1`,
    [taskId]
  );
  if (result.rows.length === 0) {
    throw httpError(404, 'Task not found');
  }
  const task = result.rows[0];
  const project = await getProjectOrThrow(client, task.project_id, user);
  return { task, project };
};

const isUserAssignableToProject = async (client, projectId, userId) => {
  if (!userId) {
    return true;
  }
  const result = await client.query(
    `SELECT 1
     FROM projects p
     JOIN users u ON u.id = $2
     WHERE p.id = $1
       AND (
         p.owner_id = $2
         OR EXISTS (
           SELECT 1
           FROM project_members pm
           WHERE pm.project_id = p.id
             AND (pm.user_id = $2 OR lower(pm.member_email) = lower(u.email))
         )
       )
     LIMIT 1`,
    [projectId, userId]
  );
  return result.rows.length > 0;
};

const resolveProjectMember = async (client, member) => {
  const input = typeof member === 'string' ? { email: member } : (member || {});
  const email = normalizeEmail(input.email || input.member_email);
  const role = input.role || 'MEMBER';
  let user = null;

  if (input.userId || input.user_id) {
    const userResult = await client.query(
      'SELECT id, username, display_name, email FROM users WHERE id = $1',
      [input.userId || input.user_id]
    );
    if (userResult.rows.length === 0) {
      throw httpError(400, 'One of the selected members does not exist');
    }
    user = userResult.rows[0];
  } else if (email) {
    const userResult = await client.query(
      'SELECT id, username, display_name, email FROM users WHERE lower(email) = lower($1) LIMIT 1',
      [email]
    );
    user = userResult.rows[0] || null;
  }

  return {
    userId: user?.id || null,
    email: normalizeEmail(user?.email) || email,
    role
  };
};

const replaceProjectMembers = async (client, project, owner, members = []) => {
  await client.query('DELETE FROM project_members WHERE project_id = $1', [project.id]);
  if (!Array.isArray(members)) {
    return [];
  }

  const ownerEmail = normalizeEmail(owner.email || project.owner_email);
  const seen = new Set();
  const saved = [];

  for (const member of members) {
    const resolved = await resolveProjectMember(client, member);
    const email = normalizeEmail(resolved.email);
    const key = resolved.userId || email;
    if (!key || seen.has(key)) {
      continue;
    }
    seen.add(key);
    if (resolved.userId === owner.id || (email && ownerEmail && email === ownerEmail)) {
      continue;
    }
    const result = await client.query(
      `INSERT INTO project_members (project_id, user_id, member_email, role)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [project.id, resolved.userId, email, resolved.role || 'MEMBER']
    );
    saved.push(result.rows[0]);
  }
  return saved;
};

const taskSelect = `
  SELECT tt.*,
         t.name AS tracker_name,
         t.project_id,
         p.name AS project_name,
         assignee.username AS assigned_username,
         assignee.display_name AS assigned_display_name,
         assignee.email AS assigned_email,
         creator.username AS created_by_username,
         creator.display_name AS created_by_display_name,
         creator.email AS created_by_email
  FROM tracker_tasks tt
  JOIN trackers t ON t.id = tt.tracker_id
  JOIN projects p ON p.id = t.project_id
  LEFT JOIN users assignee ON assignee.id = tt.assigned_to
  LEFT JOIN users creator ON creator.id = tt.created_by
`;

const listTasks = async (client, whereSql, params) => {
  const result = await client.query(
    `${taskSelect}
     ${whereSql}
     ORDER BY tt.priority DESC, tt.deadline NULLS LAST, tt.created_at DESC`,
    params
  );
  return result.rows;
};

const getEnrichedTask = async (client, taskId) => {
  const result = await listTasks(client, 'WHERE tt.id = $1', [taskId]);
  return result.rows ? result.rows[0] : result[0];
};

const serializeTaskForAudit = (task) => ({
  id: task.id,
  tracker_id: task.tracker_id,
  title: task.title,
  description: task.description,
  status: task.status,
  priority: task.priority,
  deadline: task.deadline,
  effort_estimate: task.effort_estimate,
  assigned_to: task.assigned_to
});

const ensureAuditEntityAccess = async (client, entityType, entityId, user) => {
  if (!entityType || !entityId) {
    return;
  }
  if (['tracker_task', 'task'].includes(entityType)) {
    await getTaskContext(client, entityId, user);
  } else if (entityType === 'tracker') {
    await getTrackerContext(client, entityId, user);
  } else if (entityType === 'project') {
    await getProjectOrThrow(client, entityId, user);
  }
};

const ensureRoleSchema = async () => {
  await pool.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');
  await pool.query(
    `CREATE TABLE IF NOT EXISTS user_roles (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role VARCHAR(50) NOT NULL,
      granted_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, role)
    )`
  );
  await pool.query('CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles (user_id)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles (role)');
  await pool.query(
    `DELETE FROM user_roles
     WHERE role = ANY($1::text[])
       AND user_id IN (
         SELECT id
         FROM users
         WHERE lower(username) = 'amrutha'
            OR lower(display_name) = 'amrutha'
            OR lower(email) LIKE 'amrutha@%'
       )`,
    [VALID_ROLES]
  );
  await pool.query(
    `INSERT INTO user_roles (user_id, role)
     SELECT id, $1
     FROM users
     WHERE lower(username) = 'amrutha'
        OR lower(display_name) = 'amrutha'
        OR lower(email) LIKE 'amrutha@%'
     ON CONFLICT (user_id, role) DO NOTHING`,
    [ADMIN_ROLE]
  );
  await pool.query(
    `INSERT INTO user_roles (user_id, role)
     SELECT u.id, $1
     FROM users u
     WHERE NOT EXISTS (
       SELECT 1
       FROM user_roles ur
       WHERE ur.user_id = u.id
         AND ur.role = ANY($2::text[])
     )
     ON CONFLICT (user_id, role) DO NOTHING`,
    [READONLY_ROLE, VALID_ROLES]
  );
  await pool.query(
    `DELETE FROM user_roles lower_role
     WHERE lower_role.role = ANY($1::text[])
       AND EXISTS (
         SELECT 1
         FROM user_roles higher_role
         WHERE higher_role.user_id = lower_role.user_id
           AND (
             (higher_role.role = $2 AND lower_role.role <> $2)
             OR (higher_role.role = $3 AND lower_role.role = $4)
           )
       )`,
    [VALID_ROLES, ADMIN_ROLE, EDITOR_ROLE, READONLY_ROLE]
  );
};

const createUserAccount = async ({ username, password, displayName, email }) => {
  const normalizedUsername = normalizeUsername(username);
  const normalizedPassword = normalizePassword(password);
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedUsername || !normalizedPassword) {
    throw httpError(400, 'username and password required');
  }
  if (normalizedPassword.length < 6) {
    throw httpError(400, 'Password must be at least 6 characters');
  }

  const existing = await pool.query(
    `SELECT id
     FROM users
     WHERE lower(username) = lower($1)
        OR ($2::text IS NOT NULL AND lower(email) = lower($2))
     LIMIT 1`,
    [normalizedUsername, normalizedEmail]
  );
  if (existing.rows.length > 0) {
    throw httpError(409, 'A user with that username or email already exists');
  }

  const hash = await hashPassword(normalizedPassword);
  const result = await pool.query(
    `INSERT INTO users (username, password_hash, display_name, email)
     VALUES ($1, $2, $3, $4)
     RETURNING id, username, display_name, email, created_at`,
    [normalizedUsername, hash, displayName ? String(displayName).trim() || null : null, normalizedEmail]
  );
  const user = result.rows[0];
  await ensureDefaultRole(pool, user);
  return toPublicUser({ ...user, roles: await getUserRoles(pool, user.id) });
};

// Auth
app.post('/auth/signup', asyncHandler(async (req, res) => {
  const { username, password, displayName } = req.body;
  const publicUser = await createUserAccount({ username, password, displayName, email: req.body.email });
  const token = signToken({ id: publicUser.id, username: publicUser.username, email: publicUser.email });
  res.json({ token, user: publicUser });
}));

app.post('/auth/login', asyncHandler(async (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = normalizePassword(req.body.password);
  if (!username || !password) {
    throw httpError(400, 'username and password required');
  }
  let result = await pool.query(
    'SELECT * FROM users WHERE lower(username) = lower($1) OR lower(email) = lower($1) LIMIT 1',
    [username]
  );
  if (result.rows.length === 0) {
    const displayNameResult = await pool.query(
      'SELECT * FROM users WHERE lower(display_name) = lower($1) LIMIT 2',
      [username]
    );
    if (displayNameResult.rows.length === 1) {
      result = displayNameResult;
    }
  }
  if (result.rows.length === 0) {
    throw httpError(401, 'Invalid credentials');
  }
  const user = result.rows[0];
  const match = await verifyPassword(password, user.password_hash);
  if (!match) {
    throw httpError(401, 'Invalid credentials');
  }
  await ensureDefaultRole(pool, user);
  const publicUser = toPublicUser({ ...user, roles: await getUserRoles(pool, user.id) });
  const token = signToken({ id: user.id, username: user.username, email: user.email });
  res.json({ token, user: publicUser });
}));

app.get('/users/me', requireAuth, asyncHandler(async (req, res) => {
  res.json(toPublicUser(req.currentUser));
}));

app.get('/users', requireAuth, asyncHandler(async (req, res) => {
  const search = req.query.search ? `%${String(req.query.search).trim()}%` : null;
  const result = await pool.query(
    `SELECT id, username, display_name, email, created_at
     FROM users
     WHERE $1::text IS NULL
        OR username ILIKE $1
        OR display_name ILIKE $1
        OR email ILIKE $1
     ORDER BY created_at DESC
     LIMIT 50`,
    [search]
  );
  res.json(result.rows.map(toPublicUser));
}));

const updateUserPrimaryRole = async (client, { targetUserId, role, actor }) => {
  const nextRole = normalizeRole(role);
  const target = await getUserWithRoles(client, targetUserId);
  if (!target) {
    throw httpError(404, 'User not found');
  }

  const previousRole = getPrimaryRole(target.roles);
  if (targetUserId === actor.id && previousRole === ADMIN_ROLE && nextRole !== ADMIN_ROLE) {
    throw httpError(400, 'You cannot remove your own admin access');
  }

  if (previousRole === ADMIN_ROLE && nextRole !== ADMIN_ROLE) {
    const count = await client.query(
      'SELECT COUNT(*)::int AS count FROM user_roles WHERE role = $1',
      [ADMIN_ROLE]
    );
    if (count.rows[0].count <= 1) {
      throw httpError(400, 'At least one admin is required');
    }
  }

  if (previousRole !== nextRole) {
    await setUserPrimaryRole(client, targetUserId, nextRole, actor.id);
    await logAudit(client, {
      entityType: 'user',
      entityId: targetUserId,
      userId: actor.id,
      action: 'ROLE_UPDATED',
      previousValue: { role: previousRole },
      newValue: { role: nextRole },
      note: `Role changed from ${previousRole} to ${nextRole}`
    });
    await notifyUser(client, targetUserId, `${actor.username} changed your role to ${nextRole}.`);
  }

  return getUserWithRoles(client, targetUserId);
};

// Admin
app.get('/admin/users', requireAdmin, asyncHandler(async (req, res) => {
  const search = req.query.search ? `%${String(req.query.search).trim()}%` : null;
  const result = await pool.query(
    `SELECT u.id,
            u.username,
            u.display_name,
            u.email,
            u.created_at,
            COALESCE(array_remove(array_agg(ur.role ORDER BY ur.role), NULL), '{}') AS roles
     FROM users u
     LEFT JOIN user_roles ur ON ur.user_id = u.id
     WHERE $1::text IS NULL
        OR u.username ILIKE $1
        OR u.display_name ILIKE $1
        OR u.email ILIKE $1
     GROUP BY u.id
     ORDER BY bool_or(ur.role = $2) DESC, bool_or(ur.role = $3) DESC, u.created_at DESC`,
    [search, ADMIN_ROLE, EDITOR_ROLE]
  );
  res.json(result.rows.map(toPublicUser));
}));

app.post('/admin/users', requireAdmin, asyncHandler(async (req, res) => {
  const publicUser = await createUserAccount({
    username: req.body.username,
    password: req.body.password,
    displayName: req.body.displayName,
    email: req.body.email
  });
  await logAudit(pool, {
    entityType: 'user',
    entityId: publicUser.id,
    userId: req.currentUser.id,
    action: 'USER_CREATED',
    newValue: { id: publicUser.id, username: publicUser.username, email: publicUser.email },
    note: `${req.currentUser.username} created user ${publicUser.username}`
  });
  res.status(201).json(publicUser);
}));

app.put('/admin/users/:userId/role', requireAdmin, asyncHandler(async (req, res) => {
  const updated = await updateUserPrimaryRole(pool, {
    targetUserId: req.params.userId,
    role: req.body.role,
    actor: req.currentUser
  });
  res.json(toPublicUser(updated));
}));

app.put('/admin/users/:userId/password', requireAdmin, asyncHandler(async (req, res) => {
  const password = normalizePassword(req.body.password);
  if (password.length < 6) {
    throw httpError(400, 'Password must be at least 6 characters');
  }

  const target = await getUserWithRoles(pool, req.params.userId);
  if (!target) {
    throw httpError(404, 'User not found');
  }

  const hash = await hashPassword(password);
  await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.params.userId]);
  await logAudit(pool, {
    entityType: 'user',
    entityId: req.params.userId,
    userId: req.currentUser.id,
    action: 'PASSWORD_RESET',
    note: `${req.currentUser.username} reset the password for ${target.username}`
  });
  await notifyUser(pool, req.params.userId, `${req.currentUser.username} reset your password.`);

  res.json(toPublicUser(target));
}));

app.post('/admin/users/:userId/roles', requireAdmin, asyncHandler(async (req, res) => {
  const updated = await updateUserPrimaryRole(pool, {
    targetUserId: req.params.userId,
    role: req.body.role || ADMIN_ROLE,
    actor: req.currentUser
  });
  res.json(toPublicUser(updated));
}));

app.delete('/admin/users/:userId/roles/:role', requireAdmin, asyncHandler(async (req, res) => {
  normalizeRole(req.params.role);
  const updated = await updateUserPrimaryRole(pool, {
    targetUserId: req.params.userId,
    role: READONLY_ROLE,
    actor: req.currentUser
  });
  res.json(toPublicUser(updated));
}));

// Templates
app.get('/templates', requireAuth, asyncHandler(async (req, res) => {
  const result = await pool.query(
    `SELECT t.*,
            u.username AS owner_username,
            u.display_name AS owner_display_name,
            u.email AS owner_email,
            latest.id AS latest_version_id,
            latest.version AS latest_version,
            latest.schema_json AS latest_schema_json
     FROM templates t
     JOIN users u ON u.id = t.owner_id
     LEFT JOIN LATERAL (
       SELECT id, version, schema_json
       FROM template_versions tv
       WHERE tv.template_id = t.id
       ORDER BY version DESC
       LIMIT 1
     ) latest ON true
     WHERE t.owner_id = $1 OR t.visibility = 'PUBLIC'
     ORDER BY t.created_at DESC`,
    [req.currentUser.id]
  );
  res.json(result.rows);
}));

app.get('/templates/:templateId/versions', requireAuth, asyncHandler(async (req, res) => {
  const { templateId } = req.params;
  const template = await pool.query(
    'SELECT * FROM templates WHERE id = $1 AND (owner_id = $2 OR visibility = $3)',
    [templateId, req.currentUser.id, 'PUBLIC']
  );
  if (template.rows.length === 0) {
    throw httpError(404, 'Template not found');
  }
  const result = await pool.query(
    'SELECT * FROM template_versions WHERE template_id = $1 ORDER BY version DESC',
    [templateId]
  );
  res.json(result.rows);
}));

app.post('/templates', requireEditor, asyncHandler(async (req, res) => {
  const { name, description } = req.body;
  const visibility = req.body.visibility === 'PUBLIC' ? 'PUBLIC' : 'PRIVATE';
  const schemaJson = req.body.schemaJson || {};
  if (!name || !name.trim()) {
    throw httpError(400, 'Template name is required');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const template = await client.query(
      `INSERT INTO templates (owner_id, name, description, visibility)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [req.currentUser.id, name.trim(), description || null, visibility]
    );
    const version = await client.query(
      `INSERT INTO template_versions (template_id, version, schema_json)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [template.rows[0].id, 1, schemaJson]
    );
    await logAudit(client, {
      entityType: 'template',
      entityId: template.rows[0].id,
      userId: req.currentUser.id,
      action: 'CREATE',
      newValue: template.rows[0]
    });
    await client.query('COMMIT');
    res.json({ template: template.rows[0], version: version.rows[0] });
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}));

app.post('/templates/:templateId/versions', requireEditor, asyncHandler(async (req, res) => {
  const { templateId } = req.params;
  const template = await pool.query(
    'SELECT * FROM templates WHERE id = $1 AND owner_id = $2',
    [templateId, req.currentUser.id]
  );
  if (template.rows.length === 0) {
    throw httpError(404, 'Template not found');
  }
  const latest = await pool.query(
    'SELECT COALESCE(MAX(version), 0) AS version FROM template_versions WHERE template_id = $1',
    [templateId]
  );
  const nextVersion = Number(latest.rows[0].version) + 1;
  const version = await pool.query(
    `INSERT INTO template_versions (template_id, version, schema_json)
     VALUES ($1, $2, $3)
     RETURNING *`,
    [templateId, nextVersion, req.body.schemaJson || {}]
  );
  await logAudit(pool, {
    entityType: 'template',
    entityId: templateId,
    userId: req.currentUser.id,
    action: 'VERSION',
    newValue: version.rows[0]
  });
  res.json(version.rows[0]);
}));

// Projects
app.get('/projects', requireAuth, asyncHandler(async (req, res) => {
  const userEmail = normalizeEmail(req.currentUser.email);
  const result = await pool.query(
    `SELECT DISTINCT p.*,
            owner.username AS owner_username,
            owner.display_name AS owner_display_name,
            owner.email AS owner_email
     FROM projects p
     JOIN users owner ON owner.id = p.owner_id
     WHERE $3::boolean
        OR p.owner_id = $1
        OR EXISTS (
          SELECT 1
          FROM project_members pm
          WHERE pm.project_id = p.id
            AND (pm.user_id = $1 OR ($2::text IS NOT NULL AND lower(pm.member_email) = lower($2)))
        )
     ORDER BY p.created_at DESC`,
    [req.currentUser.id, userEmail, isAdminUser(req.currentUser)]
  );
  const projects = await Promise.all(result.rows.map((project) => enrichProject(pool, project)));
  res.json(projects);
}));

app.get('/member-of-projects', requireAuth, asyncHandler(async (req, res) => {
  const projects = await pool.query(
    `SELECT DISTINCT p.*,
            owner.username AS owner_username,
            owner.display_name AS owner_display_name,
            owner.email AS owner_email
     FROM projects p
     JOIN users owner ON owner.id = p.owner_id
     JOIN project_members pm ON pm.project_id = p.id
     WHERE NOT $3::boolean
       AND p.owner_id <> $1
       AND (pm.user_id = $1 OR ($2::text IS NOT NULL AND lower(pm.member_email) = lower($2)))
     ORDER BY p.created_at DESC`,
    [req.currentUser.id, normalizeEmail(req.currentUser.email), isAdminUser(req.currentUser)]
  );
  const enriched = await Promise.all(projects.rows.map((project) => enrichProject(pool, project)));
  res.json(enriched);
}));

app.get('/projects/:projectId', requireAuth, asyncHandler(async (req, res) => {
  const project = await getProjectOrThrow(pool, req.params.projectId, req.currentUser);
  res.json(await enrichProject(pool, project));
}));

app.get('/projects/:projectId/members', requireAuth, asyncHandler(async (req, res) => {
  await getProjectOrThrow(pool, req.params.projectId, req.currentUser);
  res.json(await getAssignableUsers(pool, req.params.projectId));
}));

app.post('/projects', requireEditor, asyncHandler(async (req, res) => {
  const { name, description, templateId } = req.body;
  if (!name || !name.trim()) {
    throw httpError(400, 'Project name is required');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const projectResult = await client.query(
      `INSERT INTO projects (owner_id, name, description, template_id)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [req.currentUser.id, name.trim(), description || null, templateId || null]
    );
    const project = projectResult.rows[0];
    const savedMembers = await replaceProjectMembers(client, project, req.currentUser, req.body.members || []);
    await logAudit(client, {
      entityType: 'project',
      entityId: project.id,
      userId: req.currentUser.id,
      action: 'CREATE',
      newValue: { ...project, members: savedMembers }
    });
    for (const member of savedMembers) {
      await notifyUser(client, member.user_id, `${req.currentUser.username} shared project "${project.name}" with you.`);
    }
    await client.query('COMMIT');
    res.json(await enrichProject(pool, project));
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}));

app.put('/projects/:projectId', requireEditor, asyncHandler(async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const project = await getProjectOrThrow(client, req.params.projectId, req.currentUser, { ownerOnly: true });
    const updatedResult = await client.query(
      `UPDATE projects
       SET name = COALESCE($1, name),
           description = COALESCE($2, description),
           template_id = COALESCE($3, template_id)
       WHERE id = $4
       RETURNING *`,
      [
        req.body.name ? req.body.name.trim() : null,
        Object.prototype.hasOwnProperty.call(req.body, 'description') ? req.body.description || null : null,
        req.body.templateId || null,
        req.params.projectId
      ]
    );
    let savedMembers = null;
    if (Array.isArray(req.body.members)) {
      savedMembers = await replaceProjectMembers(client, project, req.currentUser, req.body.members);
    }
    await logAudit(client, {
      entityType: 'project',
      entityId: project.id,
      userId: req.currentUser.id,
      action: 'UPDATE',
      previousValue: project,
      newValue: { ...updatedResult.rows[0], members: savedMembers }
    });
    if (savedMembers) {
      for (const member of savedMembers) {
        await notifyUser(client, member.user_id, `${req.currentUser.username} updated sharing for project "${updatedResult.rows[0].name}".`);
      }
    }
    await client.query('COMMIT');
    res.json(await enrichProject(pool, updatedResult.rows[0]));
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}));

app.delete('/projects/:projectId', requireEditor, asyncHandler(async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const project = await getProjectOrThrow(client, req.params.projectId, req.currentUser, { ownerOnly: true });
    await logAudit(client, {
      entityType: 'project',
      entityId: project.id,
      userId: req.currentUser.id,
      action: 'DELETE',
      previousValue: project
    });
    await client.query('DELETE FROM projects WHERE id = $1', [project.id]);
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}));

// Trackers and Tasks
app.get('/projects/:projectId/trackers', requireAuth, asyncHandler(async (req, res) => {
  await getProjectOrThrow(pool, req.params.projectId, req.currentUser);
  const result = await pool.query(
    `SELECT t.*,
            COUNT(tt.id)::int AS task_count,
            COUNT(tt.id) FILTER (WHERE tt.status <> 'DONE')::int AS open_task_count
     FROM trackers t
     LEFT JOIN tracker_tasks tt ON tt.tracker_id = t.id
     WHERE t.project_id = $1
     GROUP BY t.id
     ORDER BY t.created_at DESC`,
    [req.params.projectId]
  );
  res.json(result.rows);
}));

app.post('/trackers', requireEditor, asyncHandler(async (req, res) => {
  const { projectId, templateVersionId, name } = req.body;
  if (!projectId || !name || !name.trim()) {
    throw httpError(400, 'projectId and tracker name are required');
  }
  const project = await getProjectOrThrow(pool, projectId, req.currentUser);
  const result = await pool.query(
    `INSERT INTO trackers (project_id, template_version_id, name, created_by)
     VALUES ($1, $2, $3, $4)
     RETURNING *`,
    [projectId, templateVersionId || null, name.trim(), req.currentUser.id]
  );
  await logAudit(pool, {
    entityType: 'tracker',
    entityId: result.rows[0].id,
    userId: req.currentUser.id,
    action: 'CREATE',
    newValue: result.rows[0],
    note: `Tracker created for ${project.name}`
  });
  res.json(result.rows[0]);
}));

app.put('/trackers/:trackerId', requireEditor, asyncHandler(async (req, res) => {
  const { tracker } = await getTrackerContext(pool, req.params.trackerId, req.currentUser);
  if (!req.body.name || !req.body.name.trim()) {
    throw httpError(400, 'Tracker name is required');
  }
  const result = await pool.query(
    'UPDATE trackers SET name = $1 WHERE id = $2 RETURNING *',
    [req.body.name.trim(), tracker.id]
  );
  await logAudit(pool, {
    entityType: 'tracker',
    entityId: tracker.id,
    userId: req.currentUser.id,
    action: 'UPDATE',
    previousValue: tracker,
    newValue: result.rows[0]
  });
  res.json(result.rows[0]);
}));

app.delete('/trackers/:trackerId', requireEditor, asyncHandler(async (req, res) => {
  const { tracker, project } = await getTrackerContext(pool, req.params.trackerId, req.currentUser);
  if (!isAdminUser(req.currentUser) && project.owner_id !== req.currentUser.id && tracker.created_by !== req.currentUser.id) {
    throw httpError(403, 'Only the project owner or tracker creator can delete this tracker');
  }
  await logAudit(pool, {
    entityType: 'tracker',
    entityId: tracker.id,
    userId: req.currentUser.id,
    action: 'DELETE',
    previousValue: tracker
  });
  await pool.query('DELETE FROM trackers WHERE id = $1', [tracker.id]);
  res.json({ ok: true });
}));

app.get('/trackers/:trackerId/tasks', requireAuth, asyncHandler(async (req, res) => {
  await getTrackerContext(pool, req.params.trackerId, req.currentUser);
  const tasks = await listTasks(pool, 'WHERE tt.tracker_id = $1', [req.params.trackerId]);
  res.json(tasks);
}));

app.get('/tasks/report', requireAuth, asyncHandler(async (req, res) => {
  const params = [req.currentUser.id, normalizeEmail(req.currentUser.email), isAdminUser(req.currentUser)];
  const conditions = [
    `($3::boolean
      OR p.owner_id = $1
      OR tt.assigned_to = $1
      OR EXISTS (
        SELECT 1
        FROM project_members pm
        WHERE pm.project_id = p.id
          AND (pm.user_id = $1 OR ($2::text IS NOT NULL AND lower(pm.member_email) = lower($2)))
      ))`
  ];
  let nextIndex = 4;

  if (req.query.status) {
    conditions.push(`tt.status = $${nextIndex}`);
    params.push(normalizeStatus(req.query.status));
    nextIndex += 1;
  }
  if (req.query.projectId) {
    conditions.push(`p.id = $${nextIndex}`);
    params.push(req.query.projectId);
    nextIndex += 1;
  }
  if (req.query.trackerId) {
    conditions.push(`t.id = $${nextIndex}`);
    params.push(req.query.trackerId);
    nextIndex += 1;
  }
  if (req.query.assignedTo) {
    if (req.query.assignedTo === 'me') {
      conditions.push('tt.assigned_to = $1');
    } else if (req.query.assignedTo === 'unassigned') {
      conditions.push('tt.assigned_to IS NULL');
    } else {
      conditions.push(`tt.assigned_to = $${nextIndex}`);
      params.push(req.query.assignedTo);
      nextIndex += 1;
    }
  }

  const tasks = await listTasks(pool, `WHERE ${conditions.join(' AND ')}`, params);
  res.json(tasks);
}));

app.post('/tasks', requireEditor, asyncHandler(async (req, res) => {
  const { trackerId, title, description } = req.body;
  if (!trackerId || !title || !title.trim()) {
    throw httpError(400, 'trackerId and task title are required');
  }
  const { tracker, project } = await getTrackerContext(pool, trackerId, req.currentUser);
  const status = normalizeStatus(req.body.status) || 'TODO';
  const assignedTo = req.body.assignedTo || null;
  if (assignedTo && !(await isUserAssignableToProject(pool, project.id, assignedTo))) {
    throw httpError(400, 'Assigned user must be a project member');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query(
      `INSERT INTO tracker_tasks
       (tracker_id, title, description, status, priority, deadline, effort_estimate, assigned_to, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [
        trackerId,
        title.trim(),
        description || null,
        status,
        Boolean(req.body.priority),
        req.body.deadline || null,
        req.body.effortEstimate ? Number(req.body.effortEstimate) : null,
        assignedTo,
        req.currentUser.id
      ]
    );
    await logAudit(client, {
      entityType: 'tracker_task',
      entityId: result.rows[0].id,
      userId: req.currentUser.id,
      action: 'CREATE',
      newValue: result.rows[0],
      note: req.body.note || `Task created in ${tracker.name}`
    });
    if (assignedTo && assignedTo !== req.currentUser.id) {
      await notifyUser(client, assignedTo, `You were assigned "${result.rows[0].title}" in ${project.name}.`);
    }
    await client.query('COMMIT');
    res.json(await getEnrichedTask(pool, result.rows[0].id));
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}));

app.put('/tasks/:taskId', requireEditor, asyncHandler(async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { task, project } = await getTaskContext(client, req.params.taskId, req.currentUser);
    const fields = [];
    const values = [];
    const pushField = (column, value) => {
      values.push(value);
      fields.push(`${column} = $${values.length}`);
    };

    if (Object.prototype.hasOwnProperty.call(req.body, 'title')) {
      const title = String(req.body.title || '').trim();
      if (!title) {
        throw httpError(400, 'Task title is required');
      }
      pushField('title', title);
    }
    if (Object.prototype.hasOwnProperty.call(req.body, 'description')) {
      pushField('description', req.body.description || null);
    }
    if (Object.prototype.hasOwnProperty.call(req.body, 'status')) {
      pushField('status', normalizeStatus(req.body.status));
    }
    if (Object.prototype.hasOwnProperty.call(req.body, 'priority')) {
      pushField('priority', Boolean(req.body.priority));
    }
    if (Object.prototype.hasOwnProperty.call(req.body, 'deadline')) {
      pushField('deadline', req.body.deadline || null);
    }
    if (Object.prototype.hasOwnProperty.call(req.body, 'effortEstimate')) {
      pushField('effort_estimate', req.body.effortEstimate ? Number(req.body.effortEstimate) : null);
    }
    if (Object.prototype.hasOwnProperty.call(req.body, 'assignedTo')) {
      const assignedTo = req.body.assignedTo || null;
      if (assignedTo && !(await isUserAssignableToProject(client, project.id, assignedTo))) {
        throw httpError(400, 'Assigned user must be a project member');
      }
      pushField('assigned_to', assignedTo);
    }

    let updated = task;
    if (fields.length > 0) {
      values.push(req.params.taskId);
      const result = await client.query(
        `UPDATE tracker_tasks
         SET ${fields.join(', ')}
         WHERE id = $${values.length}
         RETURNING *`,
        values
      );
      updated = result.rows[0];
    }

    if (fields.length > 0 || req.body.note) {
      await client.query(
        `INSERT INTO task_update_history (task_id, user_id, note, previous_value, new_value)
         VALUES ($1, $2, $3, $4, $5)`,
        [
          req.params.taskId,
          req.currentUser.id,
          req.body.note || null,
          serializeTaskForAudit(task),
          serializeTaskForAudit(updated)
        ]
      );
      await logAudit(client, {
        entityType: 'tracker_task',
        entityId: req.params.taskId,
        userId: req.currentUser.id,
        action: 'UPDATE',
        previousValue: serializeTaskForAudit(task),
        newValue: serializeTaskForAudit(updated),
        note: req.body.note || null
      });
    }

    if (updated.assigned_to && updated.assigned_to !== task.assigned_to && updated.assigned_to !== req.currentUser.id) {
      await notifyUser(client, updated.assigned_to, `You were assigned "${updated.title}" in ${project.name}.`);
    }
    if (updated.status !== task.status && updated.created_by && updated.created_by !== req.currentUser.id) {
      await notifyUser(client, updated.created_by, `"${updated.title}" moved to ${updated.status}.`);
    }

    await client.query('COMMIT');
    res.json(await getEnrichedTask(pool, req.params.taskId));
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}));

app.delete('/tasks/:taskId', requireEditor, asyncHandler(async (req, res) => {
  const { task, project } = await getTaskContext(pool, req.params.taskId, req.currentUser);
  if (!isAdminUser(req.currentUser) && project.owner_id !== req.currentUser.id && task.created_by !== req.currentUser.id) {
    throw httpError(403, 'Only the project owner or task creator can delete this task');
  }
  await logAudit(pool, {
    entityType: 'tracker_task',
    entityId: task.id,
    userId: req.currentUser.id,
    action: 'DELETE',
    previousValue: serializeTaskForAudit(task)
  });
  await pool.query('DELETE FROM tracker_tasks WHERE id = $1', [task.id]);
  res.json({ ok: true });
}));

app.get('/tasks/:taskId/comments', requireAuth, asyncHandler(async (req, res) => {
  await getTaskContext(pool, req.params.taskId, req.currentUser);
  const result = await pool.query(
    `SELECT tc.*,
            u.username,
            u.display_name,
            u.email
     FROM task_comments tc
     JOIN users u ON u.id = tc.user_id
     WHERE tc.task_id = $1
     ORDER BY tc.created_at ASC`,
    [req.params.taskId]
  );
  res.json(result.rows);
}));

app.post('/tasks/:taskId/comments', requireEditor, asyncHandler(async (req, res) => {
  const comment = req.body.comment ? String(req.body.comment).trim() : '';
  if (!comment) {
    throw httpError(400, 'Comment is required');
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { task, project } = await getTaskContext(client, req.params.taskId, req.currentUser);
    const result = await client.query(
      `INSERT INTO task_comments (task_id, user_id, comment)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [req.params.taskId, req.currentUser.id, comment]
    );
    await logAudit(client, {
      entityType: 'tracker_task',
      entityId: req.params.taskId,
      userId: req.currentUser.id,
      action: 'COMMENT',
      note: comment
    });
    const recipients = new Set([task.created_by, task.assigned_to].filter(Boolean));
    recipients.delete(req.currentUser.id);
    for (const userId of recipients) {
      await notifyUser(client, userId, `${req.currentUser.username} commented on "${task.title}" in ${project.name}.`);
    }
    await client.query('COMMIT');
    res.json(result.rows[0]);
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}));

// Notifications
app.get('/notifications', requireAuth, asyncHandler(async (req, res) => {
  const result = await pool.query(
    'SELECT * FROM notifications WHERE user_id = $1 ORDER BY is_read ASC, created_at DESC LIMIT 50',
    [req.currentUser.id]
  );
  res.json(result.rows);
}));

app.post('/notifications', requireEditor, asyncHandler(async (req, res) => {
  const { userId, message } = req.body;
  if (!userId || !message) {
    throw httpError(400, 'userId and message are required');
  }
  const result = await pool.query(
    'INSERT INTO notifications (user_id, message) VALUES ($1, $2) RETURNING *',
    [userId, message]
  );
  res.json(result.rows[0]);
}));

app.put('/notifications/:notificationId/read', requireAuth, asyncHandler(async (req, res) => {
  const result = await pool.query(
    `UPDATE notifications
     SET is_read = true
     WHERE id = $1 AND user_id = $2
     RETURNING *`,
    [req.params.notificationId, req.currentUser.id]
  );
  if (result.rows.length === 0) {
    throw httpError(404, 'Notification not found');
  }
  res.json(result.rows[0]);
}));

app.put('/notifications/read-all', requireAuth, asyncHandler(async (req, res) => {
  await pool.query('UPDATE notifications SET is_read = true WHERE user_id = $1', [req.currentUser.id]);
  res.json({ ok: true });
}));

// Audit Logs
app.get('/audit', requireAuth, asyncHandler(async (req, res) => {
  const { entityType, entityId } = req.query;
  const params = [];
  const conditions = [];

  if (entityType && entityId) {
    await ensureAuditEntityAccess(pool, entityType, entityId, req.currentUser);
    params.push(entityType, entityId);
    conditions.push('al.entity_type = $1 AND al.entity_id = $2');
  } else {
    params.push(req.currentUser.id);
    conditions.push('al.user_id = $1');
  }

  const result = await pool.query(
    `SELECT al.*,
            u.username,
            u.display_name,
            u.email
     FROM audit_logs al
     LEFT JOIN users u ON u.id = al.user_id
     WHERE ${conditions.join(' AND ')}
     ORDER BY al.created_at DESC
     LIMIT 100`,
    params
  );
  res.json(result.rows);
}));

app.post('/audit', requireEditor, asyncHandler(async (req, res) => {
  const { entityType, entityId, action, previousValue, newValue, note } = req.body;
  if (!entityType || !entityId || !action) {
    throw httpError(400, 'entityType, entityId and action are required');
  }
  await ensureAuditEntityAccess(pool, entityType, entityId, req.currentUser);
  const result = await logAudit(pool, {
    entityType,
    entityId,
    userId: req.currentUser.id,
    action,
    previousValue,
    newValue,
    note
  });
  res.json(result);
}));

app.use((err, req, res, next) => {
  if (err.code === '23505') {
    return res.status(409).json({ error: 'A record with these details already exists' });
  }
  if (err.code === '23503') {
    return res.status(400).json({ error: 'Referenced record does not exist' });
  }
  if (err.code === '22P02') {
    return res.status(400).json({ error: 'Invalid identifier format' });
  }
  const status = err.status || 500;
  if (status >= 500) {
    console.error(err);
  }
  return res.status(status).json({ error: err.message || 'Unexpected server error' });
});

const PORT = process.env.PORT || 4000;
ensureRoleSchema()
  .then(() => {
    app.listen(PORT, () => console.log(`Unified server running on ${PORT}`));
  })
  .catch((error) => {
    console.error('Failed to initialize admin role schema', error);
    process.exit(1);
  });
