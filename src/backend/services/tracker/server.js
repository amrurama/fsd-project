const express = require('express');
const cors = require('cors');
const pool = require('../../shared/db');
const { authMiddleware } = require('../../shared');

const app = express();
app.use(cors());
app.use(express.json());

app.post('/trackers', authMiddleware, async (req, res) => {
  const { projectId, templateVersionId, name } = req.body;
  const { id } = req.user;
  const result = await pool.query(
    'INSERT INTO trackers (project_id, template_version_id, name, created_by) VALUES ($1, $2, $3, $4) RETURNING *',
    [projectId, templateVersionId || null, name, id]
  );
  res.json(result.rows[0]);
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

const PORT = process.env.PORT || 4004;
app.listen(PORT, () => console.log(`Tracker service running on ${PORT}`));
