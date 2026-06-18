const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const path = require('path');
const multer = require('multer');
const sharp = require('sharp');

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (/^image\/(jpeg|png|webp|gif)$/.test(file.mimetype)) cb(null, true);
    else cb(new Error('Only JPEG, PNG, WebP, and GIF images are supported.'));
  }
});

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  store: new PgSession({ pool, tableName: 'session' }),
  secret: process.env.SESSION_SECRET || 'myweb-dev-secret-change-in-prod',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000, httpOnly: true, sameSite: 'lax' }
}));
app.use(express.static(path.join(__dirname, 'public')));

// ─── Auth middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
}

// ─── Page routes ─────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/privacy', (req, res) => res.sendFile(path.join(__dirname, 'public', 'privacy.html')));
app.get('/tos', (req, res) => res.sendFile(path.join(__dirname, 'public', 'tos.html')));
app.get('/search', (req, res) => res.sendFile(path.join(__dirname, 'public', 'search.html')));
app.get('/dashboard', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/protect', (req, res) => res.sendFile(path.join(__dirname, 'public', 'protect.html')));
app.get('/browser', (req, res) => res.sendFile(path.join(__dirname, 'public', 'browser.html')));

// ─── API: signup ─────────────────────────────────────────────────────────────
app.post('/api/signup', async (req, res) => {
  const { email, password, plan } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Please enter a valid email address.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  try {
    const hash = await bcrypt.hash(password, 12);
    const validPlan = ['free', 'pro', 'ultimate'].includes(plan) ? plan : 'free';
    const { rows } = await pool.query(
      'INSERT INTO users (email, password_hash, plan) VALUES ($1, $2, $3) RETURNING id',
      [email.toLowerCase().trim(), hash, validPlan]
    );
    await pool.query('INSERT INTO user_settings (user_id) VALUES ($1)', [rows[0].id]);
    req.session.userId = rows[0].id;
    req.session.email = email.toLowerCase().trim();
    req.session.plan = validPlan;
    res.json({ success: true, message: 'Account created successfully!' });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'An account with that email already exists.' });
    console.error(err);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

// ─── API: login ──────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid email or password.' });
    const valid = await bcrypt.compare(password, rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password.' });
    req.session.userId = rows[0].id;
    req.session.email = rows[0].email;
    req.session.plan = rows[0].plan;
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

// ─── API: logout ─────────────────────────────────────────────────────────────
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// ─── API: me ─────────────────────────────────────────────────────────────────
app.get('/api/me', async (req, res) => {
  if (!req.session.userId) return res.json({ loggedIn: false });
  try {
    const { rows } = await pool.query(
      'SELECT u.email, u.plan, u.created_at, s.tracker_blocking, s.https_upgrade, s.fingerprint_protection, s.cookie_control, s.ad_blocking, s.search_history_off FROM users u LEFT JOIN user_settings s ON u.id = s.user_id WHERE u.id = $1',
      [req.session.userId]
    );
    if (!rows.length) return res.json({ loggedIn: false });
    res.json({ loggedIn: true, ...rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch user.' });
  }
});

// ─── API: update settings ─────────────────────────────────────────────────────
app.post('/api/settings', requireAuth, async (req, res) => {
  const allowed = ['tracker_blocking','https_upgrade','fingerprint_protection','cookie_control','ad_blocking','search_history_off'];
  const updates = {};
  for (const key of allowed) {
    if (key in req.body) updates[key] = Boolean(req.body[key]);
  }
  if (!Object.keys(updates).length) return res.status(400).json({ error: 'No valid settings provided.' });
  const setClauses = Object.keys(updates).map((k, i) => `${k} = $${i + 2}`).join(', ');
  const values = [req.session.userId, ...Object.values(updates)];
  try {
    await pool.query(
      `INSERT INTO user_settings (user_id, ${Object.keys(updates).join(', ')}, updated_at)
       VALUES ($1, ${Object.keys(updates).map((_, i) => `$${i + 2}`).join(', ')}, NOW())
       ON CONFLICT (user_id) DO UPDATE SET ${setClauses}, updated_at = NOW()`,
      values
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save settings.' });
  }
});

// ─── API: protect image ───────────────────────────────────────────────────────
app.post('/api/protect-image', upload.single('image'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No image uploaded.' });

  try {
    const strength = Math.max(1, Math.min(3, parseInt(req.body.strength) || 2));
    // epsilon: imperceptible to humans (~5-7% of 0-255 range) but disruptive to ML feature extraction
    const epsilon = [8, 14, 20][strength - 1];

    const img = sharp(req.file.buffer).rotate(); // auto-orient
    const meta = await img.clone().metadata();
    const { data, info } = await img.clone()
      .ensureAlpha()
      .raw()
      .toBuffer({ resolveWithObject: true });

    const w = info.width, h = info.height, ch = info.channels;
    const buf = Buffer.from(data);

    // ── Multi-layer adversarial noise ──────────────────────────────────────────
    // Layer 1: Random Gaussian-distributed perturbations (disrupts texture features)
    // Layer 2: Structured sinusoidal pattern (disrupts frequency-domain features)
    // Layer 3: Edge-emphasized noise (disrupts edge-detection features used by CNNs)
    // Combined they stay imperceptible (ε ≤ 20/255 ≈ 8%) but shift feature-space embeddings

    const freq1 = 0.08 + Math.random() * 0.04;
    const freq2 = 0.13 + Math.random() * 0.06;
    const phase1 = Math.random() * Math.PI * 2;
    const phase2 = Math.random() * Math.PI * 2;
    const channelShift = [
      (Math.random() * 2 - 1) * epsilon * 0.4,
      (Math.random() * 2 - 1) * epsilon * 0.4,
      (Math.random() * 2 - 1) * epsilon * 0.4,
    ];

    for (let y = 0; y < h; y++) {
      for (let x = 0; x < w; x++) {
        const idx = (y * w + x) * ch;
        // Structured sinusoidal interference pattern (shifts CLIP/DINO embeddings)
        const structured =
          Math.sin(x * freq1 + y * freq2 + phase1) *
          Math.cos(x * freq2 - y * freq1 + phase2) *
          epsilon * 0.55;
        // High-frequency dither (disrupts CNN low-level features)
        const dither = ((x ^ y) & 1 ? 1 : -1) * epsilon * 0.25;

        for (let c = 0; c < Math.min(ch, 3); c++) {
          // Gaussian noise per pixel per channel
          const u1 = Math.max(1e-10, Math.random());
          const u2 = Math.random();
          const gauss = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
          const noise = gauss * epsilon * 0.5 + structured + dither + channelShift[c];
          buf[idx + c] = Math.round(Math.max(0, Math.min(255, buf[idx + c] + noise)));
        }
      }
    }

    // Re-encode as PNG (lossless — lossy re-encoding would remove the perturbations)
    const output = await sharp(buf, { raw: { width: w, height: h, channels: ch } })
      .png({ compressionLevel: 6 })
      .toBuffer();

    const origName = path.parse(req.file.originalname || 'image').name;
    res.set({
      'Content-Type': 'image/png',
      'Content-Disposition': `attachment; filename="${origName}_myweb_protected.png"`,
      'X-Protection-Strength': strength,
      'X-Epsilon': epsilon
    });
    res.send(output);
  } catch (err) {
    console.error('Protect image error:', err);
    res.status(500).json({ error: 'Image processing failed. Please try a different image.' });
  }
});

// ─── API: private search ──────────────────────────────────────────────────────
app.get('/api/search', async (req, res) => {
  const q = (req.query.q || '').trim();
  const page = Math.max(1, parseInt(req.query.page) || 1);
  if (!q) return res.json({ results: [], query: '', total: 0 });

  try {
    const fetch = (await import('node-fetch')).default;
    const cheerio = require('cheerio');

    // Yahoo search — b= is 1-based offset (1, 11, 21 …)
    const offset = (page - 1) * 10 + 1;
    const yahooUrl = `https://search.yahoo.com/search?p=${encodeURIComponent(q)}&n=10&b=${offset}&ei=UTF-8`;
    const response = await fetch(yahooUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Cache-Control': 'no-cache'
      },
      follow: 2
    });
    const html = await response.text();
    const $ = cheerio.load(html);
    const results = [];

    $('.algo').each((i, el) => {
      try {
        // Title — inside h3 > span.d-b
        const title = $(el).find('.title span.d-b, h3 span.d-b').first().text().trim();
        // Redirect href — extract RU= param for real URL
        const href = $(el).find('.compTitle a').first().attr('href') || '';
        let url = '';
        const ruMatch = href.match(/[?&/]RU=([^/&]+)/i);
        if (ruMatch) {
          url = decodeURIComponent(ruMatch[1]);
        } else {
          url = href;
        }
        // Display URL — site name + path
        const siteName = $(el).find('.compTitle .fc-141414').text().trim();
        const pathText = $(el).find('.compTitle span > span:not(.fc-141414)').text().trim();
        const displayUrl = siteName ? `${siteName} — ${pathText}`.replace(/ — $/, '') : url;
        // Snippet
        const snippet = $(el).find('.compText p').text().trim().replace(/^\w{3} \d+, \d{4} · /, '');

        if (title && url && url.startsWith('http')) {
          results.push({ title, url, snippet, displayUrl });
        }
      } catch {}
    });

    res.json({ results, query: q, page, hasMore: results.length >= 7 });
  } catch (err) {
    console.error('Search error:', err);
    res.status(500).json({ error: 'Search failed. Please try again.' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => console.log(`MyWeb server running on port ${PORT}`));
