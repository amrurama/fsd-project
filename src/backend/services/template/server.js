const express = require('express');
const cors = require('cors');
const pool = require('../../shared/db');
const { authMiddleware } = require('../../shared');

const app = express();
app.use(cors());
app.use(express.json());

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

const PORT = process.env.PORT || 4002;
app.listen(PORT, () => console.log(`Template service running on ${PORT}`));
