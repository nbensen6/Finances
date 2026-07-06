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
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
const CLAUDE_MODEL = process.env.CLAUDE_MODEL || 'claude-sonnet-5';

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
// Seed monthly dashboard data from bundled statement export (monthly-seed.json).
// Merges per-month into findash_monthly_data and runs once per seed version,
// so in-app category edits aren't clobbered on later restarts.
// ---------------------------------------------------------------------------
try {
  const seedPath = path.join(__dirname, 'monthly-seed.json');
  if (fs.existsSync(seedPath)) {
    const seed = JSON.parse(fs.readFileSync(seedPath, 'utf8'));
    const verRow = stmtGet.get('findash_seed_version');
    let applied = 0;
    if (verRow) { try { applied = Number(JSON.parse(verRow.value)) || 0; } catch (_) {} }
    if (applied < seed.version) {
      // Per-year model (seed v3+): merge into findash_yearly_data, migrating
      // any legacy month-keyed data (Oct/Nov/Dec -> 2025, else 2026) first.
      let yearly = {};
      const yRow = stmtGet.get('findash_yearly_data');
      if (yRow) {
        try { yearly = JSON.parse(yRow.value) || {}; } catch (_) {}
      } else {
        const mRow = stmtGet.get('findash_monthly_data');
        if (mRow) {
          try {
            const legacy = JSON.parse(mRow.value) || {};
            for (const [m, d] of Object.entries(legacy)) {
              const y = ['October', 'November', 'December'].includes(m) ? '2025' : '2026';
              (yearly[y] = yearly[y] || {})[m] = d;
            }
          } catch (_) {}
        }
      }
      for (const [y, months] of Object.entries(seed.years || {})) {
        yearly[y] = Object.assign(yearly[y] || {}, months);
      }
      stmtUpsert.run('findash_yearly_data', JSON.stringify(yearly));
      if (Array.isArray(seed.bills)) stmtUpsert.run('findash_bills', JSON.stringify(seed.bills));
      if (Array.isArray(seed.subs)) stmtUpsert.run('findash_subs', JSON.stringify(seed.subs));
      // Jobs are seeded write-once: the tracker is actively edited in-app,
      // so later seed versions must never clobber it
      if (Array.isArray(seed.jobs) && !stmtGet.get('findash_jobs')) {
        stmtUpsert.run('findash_jobs', JSON.stringify(seed.jobs));
      }
      stmtUpsert.run('findash_seed_version', JSON.stringify(seed.version));
      const summary = Object.entries(seed.years || {}).map(([y, m]) => `${y}: ${Object.keys(m).length} months`).join('; ');
      console.log(`Statement data seeded: v${seed.version} (${summary})`
        + (seed.bills ? `, ${seed.bills.length} bills` : '') + (seed.subs ? `, ${seed.subs.length} subs` : ''));
    }
  }
} catch (err) {
  console.error('Monthly seed error:', err);
}

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
// Job Hunt AI assistant — Claude API proxy (key stays server-side)
// ---------------------------------------------------------------------------
const NICK_PROFILE = `Candidate profile (Nicholaus "Nick" Bensen, Maple Heights / Cleveland OH):
- Current: Customer Care Specialist at Busology Tech (Jan 2024-present). SQL-level data integration across ~61 school district SaaS deployments, Jira backlog and ticket/user-story writing, UAT/QA regression testing, Salesforce/HubSpot ticket workflows, PowerShell/Python install automation, sprint ceremonies, cross-functional bridge between engineering and non-technical stakeholders.
- Portfolio: busroutepro.app — full-stack school bus routing app built SOLO (~48,000 LOC): Python/FastAPI, React/TypeScript, PostgreSQL/PostGIS, Google OR-Tools, 194 REST endpoints. Built heavily with Claude Code / AI tooling. This is his strongest differentiator, along with hands-on AI-agent and LLM experience.
- Education: Cuyahoga Community College IT cert (2024). NO bachelor's degree. NO formal PM title yet.
- Job targets, in order: Product Manager / Associate PM / Technical PM / Product Analyst / Product Ops; also Implementation Specialist/Consultant, Solutions Engineer, Technical Account Manager, Customer Success Engineer tracks.
- Hard constraints: Remote (US) ONLY — skip onsite/hybrid outside Cleveland OH. Salary floor $80,000; prefers $100K+. Skip roles requiring a bachelor's degree with no equivalent-experience language, and roles requiring 4+ years of formal PM experience.
- Green flags: "no degree required", 1-3 years experience, "we encourage you to apply anyway", AI/agent products, SaaS with technical customers, logistics/routing/edtech domains.`;

async function anthropicRequest(body) {
  if (!ANTHROPIC_API_KEY) {
    const err = new Error('ANTHROPIC_API_KEY not configured on server');
    err.status = 503;
    throw err;
  }
  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify(body)
  });
  if (!resp.ok) {
    const errText = await resp.text();
    console.error('Claude API error:', resp.status, errText);
    let detail = errText;
    try { detail = JSON.parse(errText).error?.message || errText; } catch (_) {}
    const err = new Error(`Claude API ${resp.status}: ${detail}`);
    err.status = 502;
    throw err;
  }
  return resp.json();
}

// Plain text completion (for prose like cover letters)
async function callClaude(system, userText, maxTokens) {
  const data = await anthropicRequest({
    model: CLAUDE_MODEL,
    max_tokens: maxTokens || 1500,
    system: [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }],
    messages: [{ role: 'user', content: userText }]
  });
  return (data.content || []).filter(c => c.type === 'text').map(c => c.text).join('');
}

// Structured output via forced tool use — guarantees a valid object matching
// `schema`, so there is no brittle JSON-from-prose parsing (the old approach
// that produced "No JSON in AI response" when the model replied conversationally)
async function callClaudeStructured(system, userText, schema, maxTokens) {
  const data = await anthropicRequest({
    model: CLAUDE_MODEL,
    max_tokens: maxTokens || 1500,
    system: [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }],
    tools: [{ name: 'record', description: 'Record the structured result.', input_schema: schema }],
    tool_choice: { type: 'tool', name: 'record' },
    messages: [{ role: 'user', content: userText }]
  });
  const block = (data.content || []).find(c => c.type === 'tool_use');
  if (!block) throw new Error('Model did not return structured output');
  return block.input;
}

// Web-search-backed completion — lets Claude search the live web (Built In,
// startup ATS boards) and returns its final text with any postings it found
async function callClaudeWebSearch(system, userText, maxTokens) {
  const data = await anthropicRequest({
    model: CLAUDE_MODEL,
    max_tokens: maxTokens || 3000,
    system: [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }],
    tools: [{ type: 'web_search_20250305', name: 'web_search', max_uses: 6 }],
    messages: [{ role: 'user', content: userText }]
  });
  return (data.content || []).filter(c => c.type === 'text').map(c => c.text).join('\n');
}

const JOB_PARSE_SCHEMA = {
  type: 'object',
  properties: {
    company: { type: 'string' },
    position: { type: 'string' },
    location: { type: ['string', 'null'] },
    workType: { type: ['string', 'null'], enum: ['Remote', 'Hybrid', 'Onsite', null] },
    salaryMin: { type: ['number', 'null'] },
    salaryMax: { type: ['number', 'null'] },
    url: { type: ['string', 'null'] },
    source: { type: 'string', enum: ['LinkedIn', 'Indeed', 'Glassdoor', 'Company Website', 'Built In', 'Referral', 'Recruiter', 'AngelList/Wellfound', 'Handshake', 'ZipRecruiter', 'Monster', 'Dice', 'Other'] },
    alreadyApplied: { type: 'boolean', description: 'true if the text says they already applied/submitted' },
    fit: { type: 'string', enum: ['High', 'Medium', 'Low', 'Skip'] },
    fitReasons: { type: 'string', description: '2-3 sentences: what works, plain language' },
    gaps: { type: 'string', description: 'honest gaps/risks vs the posting, 1-2 sentences' },
    suggestedPriority: { type: 'string', enum: ['High', 'Medium', 'Low'] }
  },
  required: ['company', 'position', 'source', 'alreadyApplied', 'fit', 'fitReasons', 'gaps', 'suggestedPriority']
};

const JOB_PARSE_SYSTEM = `${NICK_PROFILE}

You are the AI assistant inside Nick's job application tracker. The user pastes either (a) a job posting, (b) a LinkedIn/Built In listing blurb, or (c) a note about an application they already submitted. Extract the structured fields and give a blunt fit call using the candidate profile above.

Fit rules: Skip if onsite/hybrid outside Cleveland OH, salary tops out under $80K, hard bachelor's requirement with no equivalent-experience language, or 4+ years formal PM required. High = remote, $80K+ (or unposted at a strong-fit company), 0-3 yrs, degree-optional. If information is missing, use null and judge with what's there. Be honest in "gaps" — do not oversell fit.`;

const COVER_LETTER_SYSTEM = `${NICK_PROFILE}

You write cover letters AS Nick, in his voice: direct, concrete, confident but not corporate. Rules he insists on:
- NO dashes as punctuation (no em dashes, no hyphens standing in for commas or colons). Use commas and periods instead. Hyphens inside proper product names from his resume, like OR-Tools, are allowed.
- Short: 3-4 paragraphs, under 300 words.
- Lead with the most relevant differentiator for THIS role (Bus Routing Pro for product/technical roles, UAT/SQL/client work for implementation/support roles, AI tooling for AI-product roles).
- Mention his hands-on AI experience (built production software with Claude Code and LLM APIs) where relevant.
- Never claim a PM title, a degree, or experience he does not have. Frame Busology work as PM-equivalent: owning tickets, writing user stories, UAT, bridging customers and engineering.
- Sign off as "Nicholaus J. Bensen".
Return ONLY the letter text, no preamble, no subject line.`;

app.post('/api/ai/job-parse', requireAuth, async (req, res) => {
  try {
    const { text } = req.body || {};
    if (!text || typeof text !== 'string' || !text.trim()) {
      return res.status(400).json({ error: 'Missing text' });
    }
    if (text.length > 20000) return res.status(400).json({ error: 'Text too long' });
    // Reject bare-URL pastes early — the server can't open links
    if (/^https?:\/\/\S+$/i.test(text.trim())) {
      return res.status(400).json({ error: 'That looks like just a link. Open it and paste the posting TEXT (title, description, requirements) instead.' });
    }
    const result = await callClaudeStructured(JOB_PARSE_SYSTEM, text.trim(), JOB_PARSE_SCHEMA, 2000);
    return res.json({ result });
  } catch (err) {
    console.error('job-parse error:', err);
    return res.status(err.status || 500).json({ error: err.message || 'AI request failed' });
  }
});

app.post('/api/ai/cover-letter', requireAuth, async (req, res) => {
  try {
    const { job, postingText } = req.body || {};
    if (!job || !job.company) return res.status(400).json({ error: 'Missing job details' });
    const prompt = `Write my cover letter for this application:\n` +
      `Company: ${job.company}\nPosition: ${job.position || 'unknown'}\n` +
      (job.location ? `Location: ${job.location}\n` : '') +
      (job.salaryMin || job.salaryMax ? `Posted salary: ${job.salaryMin || '?'} - ${job.salaryMax || '?'}\n` : '') +
      (job.notes ? `My notes: ${job.notes}\n` : '') +
      (postingText ? `\nFull posting:\n${String(postingText).slice(0, 12000)}` : '');
    const reply = await callClaude(COVER_LETTER_SYSTEM, prompt, 1000);
    return res.json({ letter: reply.trim() });
  } catch (err) {
    console.error('cover-letter error:', err);
    return res.status(err.status || 500).json({ error: err.message || 'AI request failed' });
  }
});

const FIND_JOBS_SCHEMA = {
  type: 'object',
  properties: {
    jobs: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          company: { type: 'string' },
          position: { type: 'string' },
          salaryMin: { type: ['number', 'null'] },
          salaryMax: { type: ['number', 'null'] },
          location: { type: ['string', 'null'] },
          url: { type: ['string', 'null'] },
          source: { type: 'string' },
          fit: { type: 'string', enum: ['High', 'Medium', 'Low'] },
          fitReasons: { type: 'string' },
          gaps: { type: 'string' },
          suggestedPriority: { type: 'string', enum: ['High', 'Medium', 'Low'] }
        },
        required: ['company', 'position', 'fit', 'fitReasons', 'suggestedPriority']
      }
    }
  },
  required: ['jobs']
};

app.post('/api/ai/find-jobs', requireAuth, async (req, res) => {
  try {
    const { exclude } = req.body || {};
    const excludeList = Array.isArray(exclude) ? exclude.slice(0, 200) : [];
    const searchSystem = `${NICK_PROFILE}\n\nYou are Nick's automated job scout. Search the live web for CURRENTLY OPEN, recently posted job listings that fit his profile and hard constraints. Prioritize Built In (builtin.com), plus Greenhouse, Lever, and Ashby boards. Cover the product track (APM/PM/Technical PM/Product Analyst/Product Ops), the technical track (Implementation, Solutions Engineer, Technical Account Manager, Customer Success Engineer), and the AI track (Applied AI PM, Forward Deployed Engineer, AI Solutions). For each promising role, note company, exact title, salary if posted, location/remote, and the listing URL. Apply the hard filters strictly: remote US only, $80k+ floor, no 4+ years formal PM requirement, degree-optional preferred. Find 6 to 10 strong matches.`;
    const excludeNote = excludeList.length
      ? `\n\nDo NOT return roles already in his tracker (skip these company+title pairs): ${excludeList.map(e => `${e.company} / ${e.position}`).join('; ')}.`
      : '';
    const searchText = `Find me fresh remote job postings that fit, posted as recently as possible. Return real listings with working URLs.${excludeNote}`;
    const found = await callClaudeWebSearch(searchSystem, searchText, 4000);

    // Structure the search findings into clean rows with fit calls
    const structured = await callClaudeStructured(
      `${NICK_PROFILE}\n\nConvert the scout's findings into structured rows. Only include roles that pass the hard filters (remote US, $80k+ or unposted-but-plausible, not 4+ yrs formal PM, degree-optional). Give an honest fit call and gaps for each. Keep the real listing URL.`,
      `Scout findings to structure:\n\n${found}`,
      FIND_JOBS_SCHEMA, 3000
    );
    return res.json({ jobs: (structured && structured.jobs) || [] });
  } catch (err) {
    console.error('find-jobs error:', err);
    return res.status(err.status || 500).json({ error: err.message || 'Job search failed' });
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
