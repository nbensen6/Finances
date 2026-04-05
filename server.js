const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-secret-change-me';
const AUTH_USER = process.env.AUTH_USER || 'admin';
const AUTH_PASS = process.env.AUTH_PASS || 'changeme';

// ---------------------------------------------------------------------------
// Database setup
// ---------------------------------------------------------------------------
const dataDir = process.env.NODE_ENV === 'production' ? '/data' : path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const db = new Database(path.join(dataDir, 'findash.db'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS kv_store (
    key   TEXT PRIMARY KEY,
    value TEXT
  )
`);

// Prepared statements
const stmtGetAll = db.prepare('SELECT key, value FROM kv_store');
const stmtGet = db.prepare('SELECT value FROM kv_store WHERE key = ?');
const stmtUpsert = db.prepare(
  'INSERT INTO kv_store (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
);
const stmtDelete = db.prepare('DELETE FROM kv_store WHERE key = ?');

// ---------------------------------------------------------------------------
// SQLite session store (survives machine restarts / Fly suspends)
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    sid     TEXT PRIMARY KEY,
    data    TEXT NOT NULL,
    expires INTEGER NOT NULL
  )
`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires)`);

const sessGet = db.prepare('SELECT data, expires FROM sessions WHERE sid = ?');
const sessSet = db.prepare(`
  INSERT INTO sessions (sid, data, expires) VALUES (?, ?, ?)
  ON CONFLICT(sid) DO UPDATE SET data = excluded.data, expires = excluded.expires
`);
const sessDel = db.prepare('DELETE FROM sessions WHERE sid = ?');
const sessClean = db.prepare('DELETE FROM sessions WHERE expires < ?');

class SQLiteStore extends session.Store {
  get(sid, cb) {
    try {
      const row = sessGet.get(sid);
      if (!row) return cb(null, null);
      if (row.expires < Date.now()) { sessDel.run(sid); return cb(null, null); }
      cb(null, JSON.parse(row.data));
    } catch (e) { cb(e); }
  }
  set(sid, sess, cb) {
    try {
      const maxAge = (sess.cookie && sess.cookie.maxAge) || 7 * 24 * 60 * 60 * 1000;
      const expires = Date.now() + maxAge;
      sessSet.run(sid, JSON.stringify(sess), expires);
      cb && cb(null);
    } catch (e) { cb && cb(e); }
  }
  destroy(sid, cb) {
    try { sessDel.run(sid); cb && cb(null); } catch (e) { cb && cb(e); }
  }
}

// Clean expired sessions every hour
setInterval(() => { try { sessClean.run(Date.now()); } catch (_) {} }, 60 * 60 * 1000);

// ---------------------------------------------------------------------------
// Automatic SQLite backups — keep last 7 daily copies
// ---------------------------------------------------------------------------
const BACKUP_DIR = path.join(dataDir, 'backups');
if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });

function createBackup() {
  try {
    const stamp = new Date().toISOString().slice(0, 10);
    const dest = path.join(BACKUP_DIR, `findash-${stamp}.db`);
    db.backup(dest).then(() => {
      console.log('Backup created:', dest);
      const files = fs.readdirSync(BACKUP_DIR)
        .filter(f => f.startsWith('findash-') && f.endsWith('.db'))
        .sort();
      while (files.length > 7) {
        const old = files.shift();
        fs.unlinkSync(path.join(BACKUP_DIR, old));
        console.log('Pruned old backup:', old);
      }
    }).catch(err => console.error('Backup failed:', err));
  } catch (err) {
    console.error('Backup error:', err);
  }
}

// Backup on startup, then every 6 hours
createBackup();
setInterval(createBackup, 6 * 60 * 60 * 1000);

// ---------------------------------------------------------------------------
// Password hash (computed once at startup)
// ---------------------------------------------------------------------------
let passwordHash;
const hashReady = bcrypt.hash(AUTH_PASS, 10).then(h => { passwordHash = h; });

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------
const app = express();

app.set('trust proxy', 1);
app.use(express.json());

app.use(
  session({
    store: new SQLiteStore(),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    },
  })
);

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------
function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) {
    return next();
  }
  return res.status(401).json({ error: 'Not authenticated' });
}

// ---------------------------------------------------------------------------
// Auth routes
// ---------------------------------------------------------------------------
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(401).json({ error: 'Missing credentials' });
    }
    if (username !== AUTH_USER) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const match = await bcrypt.compare(password, passwordHash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    req.session.authenticated = true;
    return res.json({ ok: true });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

// ---------------------------------------------------------------------------
// Data API routes (all require auth)
// ---------------------------------------------------------------------------
app.get('/api/data', requireAuth, (_req, res) => {
  try {
    const rows = stmtGetAll.all();
    const result = {};
    for (const row of rows) {
      try {
        result[row.key] = JSON.parse(row.value);
      } catch {
        result[row.key] = row.value;
      }
    }
    return res.json(result);
  } catch (err) {
    console.error('GET /api/data error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/data/:key', requireAuth, (req, res) => {
  try {
    const row = stmtGet.get(req.params.key);
    if (!row) {
      return res.json([]);
    }
    try {
      return res.json(JSON.parse(row.value));
    } catch {
      return res.json(row.value);
    }
  } catch (err) {
    console.error('GET /api/data/:key error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/data/:key', requireAuth, (req, res) => {
  try {
    const value = JSON.stringify(req.body.value);
    stmtUpsert.run(req.params.key, value);
    return res.json({ ok: true });
  } catch (err) {
    console.error('PUT /api/data/:key error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/data/:key', requireAuth, (req, res) => {
  try {
    stmtDelete.run(req.params.key);
    return res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/data/:key error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// Backup download
// ---------------------------------------------------------------------------
app.get('/api/backup', requireAuth, (_req, res) => {
  try {
    const rows = stmtGetAll.all();
    const result = {};
    for (const row of rows) {
      try { result[row.key] = JSON.parse(row.value); } catch { result[row.key] = row.value; }
    }
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:.]/g, '-');
    res.setHeader('Content-Disposition', `attachment; filename="findash-backup-${stamp}.json"`);
    res.setHeader('Content-Type', 'application/json');
    return res.json(result);
  } catch (err) {
    console.error('GET /api/backup error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// Static files & auth gate
// ---------------------------------------------------------------------------
app.get('/', (req, res) => {
  if (req.session && req.session.authenticated) {
    return res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
  return res.redirect('/login.html');
});

app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
hashReady.then(() => {
  app.listen(PORT, () => {
    console.log(`Finances dashboard running on port ${PORT}`);
  });
});
