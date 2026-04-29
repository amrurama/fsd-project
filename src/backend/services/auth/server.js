const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const pool = require('../../shared/db');
const { signToken } = require('../../shared');

const app = express();
app.use(cors());
app.use(express.json());

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

app.get('/auth/me', async (req, res) => {
  res.json({ status: 'ok' });
});

const PORT = process.env.PORT || 4001;
app.listen(PORT, () => console.log(`Auth service running on ${PORT}`));
