const path     = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const fs       = require('fs');
const crypto   = require('crypto');
const express  = require('express');
const Database = require('better-sqlite3');

// ── DB SETUP ─────────────────────────────────────────
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'tracker.db');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    token TEXT PRIMARY KEY,
    email TEXT UNIQUE,
    current_progression INTEGER DEFAULT 1,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_token TEXT NOT NULL,
    progression INTEGER NOT NULL,
    attempts INTEGER NOT NULL,
    sets_completed INTEGER NOT NULL,
    passed INTEGER DEFAULT 0,
    notes TEXT DEFAULT '',
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS prs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_token TEXT NOT NULL,
    reps INTEGER NOT NULL,
    notes TEXT DEFAULT '',
    created_at INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_token, created_at);
  CREATE INDEX IF NOT EXISTS idx_prs_user ON prs(user_token, created_at);
`);

// ── TOKEN GEN ────────────────────────────────────────
const SECRET = process.env.TOKEN_SECRET || 'dev-only-secret-change-me';

function tokenForEmail(email) {
  const norm = String(email).trim().toLowerCase();
  return crypto.createHmac('sha256', SECRET).update(norm).digest('hex').slice(0, 16);
}

// ── APP ──────────────────────────────────────────────
const app = express();
app.use(express.json());

// Static + main app
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'app.html'));
});

// First-time setup: create or fetch user by email
app.post('/api/signup', (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email))) {
      return res.status(400).json({ error: 'Valid email required' });
    }
    const norm = String(email).trim().toLowerCase();
    const token = tokenForEmail(norm);

    const existing = db.prepare('SELECT * FROM users WHERE token = ?').get(token);
    if (!existing) {
      db.prepare(`
        INSERT INTO users (token, email, current_progression, created_at)
        VALUES (?, ?, 1, ?)
      `).run(token, norm, Date.now());
    }
    res.json({ token });
  } catch (err) {
    console.error('signup:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Middleware: load user by token
function requireUser(req, res, next) {
  const token = req.query.u || req.body.u;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  const user = db.prepare('SELECT * FROM users WHERE token = ?').get(token);
  if (!user) return res.status(401).json({ error: 'Invalid token' });
  req.user = user;
  next();
}

// Get full snapshot
app.get('/api/me', requireUser, (req, res) => {
  const user = req.user;
  const sessions = db.prepare(`
    SELECT id, progression, attempts, sets_completed, passed, notes, created_at
    FROM sessions WHERE user_token = ? ORDER BY created_at DESC
  `).all(user.token);
  const prs = db.prepare(`
    SELECT id, reps, notes, created_at FROM prs WHERE user_token = ? ORDER BY created_at DESC
  `).all(user.token);

  res.json({
    email: user.email,
    currentProgression: user.current_progression,
    sessions,
    prs,
  });
});

// Log a session
app.post('/api/session', requireUser, (req, res) => {
  try {
    const { progression, attempts, sets_completed, notes = '' } = req.body || {};
    const p = parseInt(progression, 10);
    const a = parseInt(attempts, 10);
    const s = parseInt(sets_completed, 10);
    if (![1,2,3,4,5,6].includes(p)) return res.status(400).json({ error: 'Invalid progression' });
    if (!Number.isFinite(a) || a < 1 || a > 99) return res.status(400).json({ error: 'Invalid attempts' });
    if (!Number.isFinite(s) || s < 0 || s > 10) return res.status(400).json({ error: 'Invalid sets_completed' });

    // Pass condition: 10 sets in <= 12 attempts
    const passed = (s === 10 && a <= 12) ? 1 : 0;

    const info = db.prepare(`
      INSERT INTO sessions (user_token, progression, attempts, sets_completed, passed, notes, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(req.user.token, p, a, s, passed, String(notes).slice(0, 500), Date.now());

    // Auto-advance if they passed and they're on this progression
    let advanced = false;
    if (passed && p === req.user.current_progression && p < 6) {
      db.prepare('UPDATE users SET current_progression = ? WHERE token = ?')
        .run(p + 1, req.user.token);
      advanced = true;
    }
    // Mark "graduated" by leaving at 6 but flag in response
    const graduated = passed && p === 6;

    res.json({ id: info.lastInsertRowid, passed: !!passed, advanced, graduated });
  } catch (err) {
    console.error('session:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Delete a session
app.delete('/api/session/:id', requireUser, (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    db.prepare('DELETE FROM sessions WHERE id = ? AND user_token = ?').run(id, req.user.token);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Log a PR
app.post('/api/pr', requireUser, (req, res) => {
  try {
    const { reps, notes = '' } = req.body || {};
    const r = parseInt(reps, 10);
    if (!Number.isFinite(r) || r < 1 || r > 9999) return res.status(400).json({ error: 'Invalid reps' });

    const info = db.prepare(`
      INSERT INTO prs (user_token, reps, notes, created_at)
      VALUES (?, ?, ?, ?)
    `).run(req.user.token, r, String(notes).slice(0, 500), Date.now());

    // Is this a new max?
    const max = db.prepare('SELECT MAX(reps) as max FROM prs WHERE user_token = ?').get(req.user.token);
    const isNewMax = max.max === r;

    res.json({ id: info.lastInsertRowid, isNewMax });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete a PR
app.delete('/api/pr/:id', requireUser, (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    db.prepare('DELETE FROM prs WHERE id = ? AND user_token = ?').run(id, req.user.token);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Manual progression override (in case user wants to jump ahead/back)
app.post('/api/progression', requireUser, (req, res) => {
  try {
    const { value } = req.body || {};
    const v = parseInt(value, 10);
    if (![1,2,3,4,5,6].includes(v)) return res.status(400).json({ error: 'Invalid value' });
    db.prepare('UPDATE users SET current_progression = ? WHERE token = ?').run(v, req.user.token);
    res.json({ currentProgression: v });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── START ────────────────────────────────────────────
const PORT = process.env.PORT || 3459;
app.listen(PORT, () => {
  console.log(`✅  Progression Tracker → http://localhost:${PORT}`);
});
