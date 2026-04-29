const express = require('express');
const cors = require('cors');
const pool = require('../../shared/db');
const { authMiddleware } = require('../../shared');

const app = express();
app.use(cors());
app.use(express.json());

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

const PORT = process.env.PORT || 4006;
app.listen(PORT, () => console.log(`Audit service running on ${PORT}`));
