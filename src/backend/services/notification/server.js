const express = require('express');
const cors = require('cors');
const pool = require('../../shared/db');
const { authMiddleware } = require('../../shared');

const app = express();
app.use(cors());
app.use(express.json());

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

const PORT = process.env.PORT || 4005;
app.listen(PORT, () => console.log(`Notification service running on ${PORT}`));
