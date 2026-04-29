const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const pool = require('./shared/db');
const { signToken, authMiddleware } = require('./shared');

const app = express();
app.use(cors());
app.use(express.json());

// Auth
app.post('/auth/signup', async (req, res) => {
  const { username, password, displayName, email } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password required' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password_hash, display_name, email) VALUES ($1, $2, $3, $4) RETURNING id, username, display_name, email',
      [username, hash, displayName || null, email || null]
    );
    const user = result.rows[0];
    const token = signToken({ id: user.id, username: user.username });
    return res.json({ token, user });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to create user', details: error.message });
  }
});

app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password required' });
  }
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = signToken({ id: user.id, username: user.username });
    return res.json({ token, user: { id: user.id, username: user.username, display_name: user.display_name, email: user.email } });
  } catch (error) {
    return res.status(500).json({ error: 'Login failed', details: error.message });
  }
});

// Templates
app.get('/templates', authMiddleware, async (req, res) => {
  const { id } = req.user;
  const result = await pool.query(
    "SELECT * FROM templates WHERE owner_id = $1 OR visibility = 'PUBLIC'",
    [id]
  );
  res.json(result.rows);
});

app.post('/templates', authMiddleware, async (req, res) => {
  const { name, description, visibility, schemaJson } = req.body;
  const { id } = req.user;
  const template = await pool.query(
    'INSERT INTO templates (owner_id, name, description, visibility) VALUES ($1, $2, $3, $4) RETURNING *',
    [id, name, description || null, visibility || 'PRIVATE']
  );
  const version = await pool.query(
    'INSERT INTO template_versions (template_id, version, schema_json) VALUES ($1, $2, $3) RETURNING *',
    [template.rows[0].id, 1, schemaJson || {}]
  );
  res.json({ template: template.rows[0], version: version.rows[0] });
});

app.post('/templates/:templateId/versions', authMiddleware, async (req, res) => {
  const { templateId } = req.params;
  const { schemaJson } = req.body;
  const latest = await pool.query(
    'SELECT COALESCE(MAX(version), 0) AS version FROM template_versions WHERE template_id = $1',
    [templateId]
  );
  const nextVersion = Number(latest.rows[0].version) + 1;
  const version = await pool.query(
    'INSERT INTO template_versions (template_id, version, schema_json) VALUES ($1, $2, $3) RETURNING *',
    [templateId, nextVersion, schemaJson || {}]
  );
  res.json(version.rows[0]);
});

// Projects
app.get('/projects', authMiddleware, async (req, res) => {
  const { id } = req.user;
  const result = await pool.query(
    `SELECT DISTINCT p.* FROM projects p
     LEFT JOIN project_members pm ON pm.project_id = p.id
     WHERE p.owner_id = $1 OR pm.user_id = $1`,
    [id]
  );
  res.json(result.rows);
});

app.get('/member-of-projects', authMiddleware, async (req, res) => {
  const result = await pool.query(
      `SELECT DISTINCT p.*, users.email FROM projects p
       LEFT JOIN project_members pm ON pm.project_id = p.id
       LEFT JOIN users ON users.id = p.owner_id
       WHERE pm.member_email = $1`,
      [req.headers['login-email-id']]
  );
  res.json(result.rows);
});

app.put('/projects/:projectId', authMiddleware, async (req, res) => {
  const { projectId } = req.params;
  const { name, members } = req.body;
  const { id } = req.user;

  const projectResult = await pool.query('SELECT * FROM projects WHERE id = $1', [projectId]);
  if (projectResult.rows.length === 0) {
    return res.status(404).json({ error: 'Project not found' });
  }
  if (projectResult.rows[0].owner_id !== id) {
    return res.status(403).json({ error: 'Only the project owner can update this project.' });
  }

  const updated = await pool.query(
    'UPDATE projects SET name = COALESCE($1, name) WHERE id = $2 RETURNING *',
    [name || null, projectId]
  );

  if (Array.isArray(members)) {
    await pool.query('DELETE FROM project_members WHERE project_id = $1', [projectId]);
    for (const email of members) {
      await pool.query(
        'INSERT INTO project_members (project_id, user_id, member_email) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
        [projectId, null, email]
      );
    }
  }

  res.json(updated.rows[0]);
});

app.post('/projects', authMiddleware, async (req, res) => {
  const { name, description, templateId, members } = req.body;
  const { id } = req.user;
  const project = await pool.query(
    'INSERT INTO projects (owner_id, name, description, template_id) VALUES ($1, $2, $3, $4) RETURNING *',
    [id, name, description || null, templateId || null]
  );
  if (Array.isArray(members)) {
    for (const email of members) {
      await pool.query(
        'INSERT INTO project_members (project_id, user_id, member_email) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
        [project.rows[0].id, null, email]
      );
    }
  }
  res.json(project.rows[0]);
});

// Trackers & Tasks
app.get('/projects/:projectId/trackers', authMiddleware, async (req, res) => {
  const { projectId } = req.params;
  const result = await pool.query('SELECT * FROM trackers WHERE project_id = $1', [projectId]);
  res.json(result.rows);
});

app.post('/trackers', authMiddleware, async (req, res) => {
  const { projectId, templateVersionId, name } = req.body;
  const { id } = req.user;
  const result = await pool.query(
    'INSERT INTO trackers (project_id, template_version_id, name, created_by) VALUES ($1, $2, $3, $4) RETURNING *',
    [projectId, templateVersionId || null, name, id]
  );
  res.json(result.rows[0]);
});

app.get('/trackers/:trackerId/tasks', authMiddleware, async (req, res) => {
  const { trackerId } = req.params;
  const result = await pool.query('SELECT * FROM tracker_tasks WHERE tracker_id = $1', [trackerId]);
  res.json(result.rows);
});

app.get('/tasks/report', authMiddleware, async (req, res) => {
  const { id } = req.user;
  const result = await pool.query(
    `SELECT tt.*, p.name AS project_name
     FROM tracker_tasks tt
     JOIN trackers t ON t.id = tt.tracker_id
     JOIN projects p ON p.id = t.project_id
     LEFT JOIN project_members pm ON pm.project_id = p.id
     WHERE tt.assigned_to = $1 OR p.owner_id = $1 OR pm.user_id = $1`,
    [id]
  );
  res.json(result.rows);
});

app.put('/tasks/:taskId', authMiddleware, async (req, res) => {
  const { taskId } = req.params;
  const { status, priority, deadline, effortEstimate, note, assignedTo } = req.body;
  const { id } = req.user;

  const current = await pool.query('SELECT * FROM tracker_tasks WHERE id = $1', [taskId]);
  if (current.rows.length === 0) {
    return res.status(404).json({ error: 'Task not found' });
  }
  const task = current.rows[0];
  const updated = await pool.query(
    `UPDATE tracker_tasks
     SET status = COALESCE($1, status),
         priority = COALESCE($2, priority),
         deadline = COALESCE($3, deadline),
         effort_estimate = COALESCE($4, effort_estimate),
         assigned_to = COALESCE($5, assigned_to)
     WHERE id = $6 RETURNING *`,
    [status, priority, deadline, effortEstimate, assignedTo, taskId]
  );
  await pool.query(
    'INSERT INTO task_update_history (task_id, user_id, note, previous_value, new_value) VALUES ($1, $2, $3, $4, $5)',
    [taskId, id, note || null, task, updated.rows[0]]
  );
  res.json(updated.rows[0]);
});

app.post('/tasks', authMiddleware, async (req, res) => {
  const { trackerId, title, description, status, priority, deadline, effortEstimate, assignedTo } = req.body;
  const { id } = req.user;
  const result = await pool.query(
    `INSERT INTO tracker_tasks
     (tracker_id, title, description, status, priority, deadline, effort_estimate, assigned_to, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
    [trackerId, title, description || null, status || 'TODO', priority || false, deadline || null, effortEstimate || null, assignedTo || null, id]
  );
  res.json(result.rows[0]);
});

// Notifications
app.get('/notifications', authMiddleware, async (req, res) => {
  const { id } = req.user;
  const result = await pool.query('SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC', [id]);
  res.json(result.rows);
});

app.post('/notifications', authMiddleware, async (req, res) => {
  const { userId, message } = req.body;
  const result = await pool.query(
    'INSERT INTO notifications (user_id, message) VALUES ($1, $2) RETURNING *',
    [userId, message]
  );
  res.json(result.rows[0]);
});

// Audit Logs
app.get('/audit', authMiddleware, async (req, res) => {
  const { entityType, entityId } = req.query;
  const result = await pool.query(
    'SELECT * FROM audit_logs WHERE entity_type = $1 AND entity_id = $2 ORDER BY created_at DESC',
    [entityType, entityId]
  );
  res.json(result.rows);
});

app.post('/audit', authMiddleware, async (req, res) => {
  const { entityType, entityId, action, previousValue, newValue, note } = req.body;
  const { id } = req.user;
  const result = await pool.query(
    'INSERT INTO audit_logs (entity_type, entity_id, user_id, action, previous_value, new_value, note) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
    [entityType, entityId, id, action, previousValue || null, newValue || null, note || null]
  );
  res.json(result.rows[0]);
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Unified server running on ${PORT}`));
