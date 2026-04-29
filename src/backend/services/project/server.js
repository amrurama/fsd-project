const express = require('express');
const cors = require('cors');
const pool = require('../../shared/db');
const { authMiddleware } = require('../../shared');
const {json} = require("express");

const app = express();
app.use(cors());
app.use(express.json());

app.get('/member-of-projects', authMiddleware, async (req, res) => {
  const result = await pool.query(
      `SELECT DISTINCT p.*, users.email FROM projects p
            LEFT JOIN project_members pm ON pm.project_id = p.id
            LEFT JOIN users ON users.id = p.owner_id
       WHERE pm.member_email = $1`,
      [req.headers['login-email-id']]
  );
  res.json(result.rows);
})

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

const PORT = process.env.PORT || 4003;
app.listen(PORT, () => console.log(`Project service running on ${PORT}`));
