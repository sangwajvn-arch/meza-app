require('dotenv').config();

const express = require('express');
const path = require('path');
const fs = require('fs');
const os = require('os');
const bcrypt = require('bcrypt');
const session = require('express-session');
const QRCode = require('qrcode');
const crypto = require('crypto');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

// Rwanda is UTC+2 all year (no daylight saving). Servers usually run in UTC,
// so dates for reports must be calculated in Kigali time, not server time.
const TZ = 'Africa/Kigali';
const TZ_OFFSET = '+02:00';

if (IS_PROD && !process.env.SESSION_SECRET) {
    console.error('SESSION_SECRET is required in production. Set it in your host\'s environment variables.');
    process.exit(1);
}
if (!process.env.SESSION_SECRET) console.warn('WARNING: SESSION_SECRET is not set. Using a temporary one (fine for local testing only).');
if (IS_PROD && !process.env.APP_BASE_URL) console.warn('WARNING: APP_BASE_URL is not set. Reset-password links and QR codes will use the request address.');
if (!process.env.SUPER_ADMIN_PASSWORD) console.warn('WARNING: SUPER_ADMIN_PASSWORD is not set. Operator login (super-admin.html) is disabled.');

app.set('trust proxy', 1);
app.disable('x-powered-by');

// ================= SAFE DATABASE UPGRADES (safe to run on every start) =================

[
    "ALTER TABLE restaurants ADD COLUMN plan TEXT DEFAULT 'Free'",
    "ALTER TABLE restaurants ADD COLUMN subscription_status TEXT DEFAULT 'active'",
    "ALTER TABLE restaurants ADD COLUMN subscription_note TEXT DEFAULT ''",
    "ALTER TABLE orders ADD COLUMN payment_status TEXT DEFAULT ''",
    "ALTER TABLE staff ADD COLUMN phone TEXT DEFAULT ''"
].forEach(sql => { try { db.exec(sql); } catch (e) { /* column already exists */ } });

db.exec(`
    CREATE TABLE IF NOT EXISTS used_transaction_ids (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        restaurant_id INTEGER,
        transaction_id TEXT,
        order_id INTEGER,
        UNIQUE(restaurant_id, transaction_id)
    );
    CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY,
        data TEXT NOT NULL,
        expires INTEGER NOT NULL
    );
`);

// ================= BASIC SECURITY HEADERS =================

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    if (IS_PROD) res.setHeader('Strict-Transport-Security', 'max-age=15552000');
    next();
});

// Only the public website folder is served. Never .env, server.js or meza.db.
app.use(express.static(path.join(__dirname, 'public'), {
    setHeaders(res, filePath) {
        if (filePath.endsWith('sw.js')) res.setHeader('Cache-Control', 'no-cache');           // phones must always see a new service worker
        else if (/\.(png|ico|svg)$/i.test(filePath)) res.setHeader('Cache-Control', 'public, max-age=604800');
    }
}));
app.use(express.json({ limit: '100kb' }));

// Everything below is live data: never let a browser or the offline cache keep a copy.
// (Only the public menu and restaurant name opt back in, further down.)
app.use((req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });

// ================= SESSIONS (stored in the database, so logins survive restarts) =================

class SqliteSessionStore extends session.Store {
    get(sid, cb) {
        try {
            const row = db.prepare('SELECT data, expires FROM sessions WHERE sid = ?').get(sid);
            if (!row) return cb(null, null);
            if (row.expires < Date.now()) {
                db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid);
                return cb(null, null);
            }
            cb(null, JSON.parse(row.data));
        } catch (e) { cb(e); }
    }
    set(sid, sess, cb) {
        try {
            const expires = sess && sess.cookie && sess.cookie.expires
                ? new Date(sess.cookie.expires).getTime()
                : Date.now() + 8 * 60 * 60 * 1000;
            db.prepare(`INSERT INTO sessions (sid, data, expires) VALUES (?, ?, ?)
                        ON CONFLICT(sid) DO UPDATE SET data = excluded.data, expires = excluded.expires`)
              .run(sid, JSON.stringify(sess), expires);
            if (cb) cb(null);
        } catch (e) { if (cb) cb(e); }
    }
    touch(sid, sess, cb) {
        try {
            const expires = sess && sess.cookie && sess.cookie.expires
                ? new Date(sess.cookie.expires).getTime()
                : Date.now() + 8 * 60 * 60 * 1000;
            db.prepare('UPDATE sessions SET expires = ? WHERE sid = ?').run(expires, sid);
            if (cb) cb(null);
        } catch (e) { if (cb) cb(e); }
    }
    destroy(sid, cb) {
        try {
            db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid);
            if (cb) cb(null);
        } catch (e) { if (cb) cb(e); }
    }
}
setInterval(() => {
    try { db.prepare('DELETE FROM sessions WHERE expires < ?').run(Date.now()); } catch (e) { /* ignore */ }
}, 15 * 60 * 1000).unref();

app.use(session({
    name: 'meza.sid',
    store: new SqliteSessionStore(),
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: IS_PROD,
        maxAge: 8 * 60 * 60 * 1000
    }
}));

// ================= SMALL HELPERS =================

class HttpError extends Error {
    constructor(status, message) { super(message); this.status = status; }
}
function sendError(res, e, fallback) {
    if (e instanceof HttpError) return res.status(e.status).json({ error: e.message });
    console.error(fallback, e);
    return res.status(500).json({ error: fallback });
}

const validId = value => Number.isSafeInteger(Number(value)) && Number(value) > 0;
const validText = (value, max = 200) => typeof value === 'string' && value.trim().length > 0 && value.trim().length <= max;
const escapeHtml = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const safeParse = (text, fallback) => { try { return JSON.parse(text); } catch (e) { return fallback; } };
const hashToken = token => crypto.createHash('sha256').update(token).digest('hex');
const safeEqual = (a, b) => {
    const ha = crypto.createHash('sha256').update(String(a)).digest();
    const hb = crypto.createHash('sha256').update(String(b)).digest();
    return crypto.timingSafeEqual(ha, hb);
};
const regenerateSession = req => new Promise((resolve, reject) => req.session.regenerate(err => err ? reject(err) : resolve()));
const saveSession = req => new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));

const PLAN_LIMITS = {
    Free: 5, Starter: 15, Standard: 25, Business: 40,
    Premium: 60, Professional: 100, Enterprise: Infinity
};
const STAFF_ROLES = ['waitress', 'kitchen', 'cashier'];
const PAYMENT_METHODS = ['momo', 'airtel', 'cash', 'urubuto'];
const INACTIVE_MESSAGE = "This restaurant's subscription is currently inactive. Please contact Meza support.";

function restaurantIsActive(restaurantId) {
    const r = db.prepare('SELECT subscription_status FROM restaurants WHERE id = ?').get(restaurantId);
    return !r || r.subscription_status !== 'disabled';
}

// ----- Rate limiting (in memory; fine for one server) -----

const buckets = new Map();
setInterval(() => {
    const now = Date.now();
    for (const [key, b] of buckets) if (b.until <= now) buckets.delete(key);
}, 10 * 60 * 1000).unref();

// Counts every request. Good for public endpoints.
function makeLimiter(name, max, windowMs, message) {
    return (req, res, next) => {
        const key = name + ':' + req.ip;
        const now = Date.now();
        let b = buckets.get(key);
        if (!b || b.until <= now) { b = { count: 0, until: now + windowMs }; buckets.set(key, b); }
        b.count++;
        if (b.count > max) return res.status(429).json({ error: message || 'Too many requests. Please wait a few minutes and try again.' });
        next();
    };
}

// Counts only FAILED attempts, so honest users are never locked out by their own successful logins.
function failLimiter(name, max, windowMs) {
    const keyOf = req => name + ':' + req.ip;
    return {
        check(req, res, next) {
            const b = buckets.get(keyOf(req));
            if (b && b.until > Date.now() && b.count >= max) {
                return res.status(429).json({ error: 'Too many failed attempts. Please wait 15 minutes and try again.' });
            }
            next();
        },
        fail(req) {
            const key = keyOf(req);
            const now = Date.now();
            let b = buckets.get(key);
            if (!b || b.until <= now) { b = { count: 0, until: now + windowMs }; buckets.set(key, b); }
            b.count++;
        },
        clear(req) { buckets.delete(keyOf(req)); }
    };
}

const loginLimiter = failLimiter('login', 12, 15 * 60 * 1000);
const staffLoginLimiter = failLimiter('staff-login', 30, 15 * 60 * 1000);
const superLoginLimiter = failLimiter('super-login', 8, 15 * 60 * 1000);
const limitRegister = makeLimiter('register', 10, 60 * 60 * 1000);
const limitForgot = makeLimiter('forgot', 10, 15 * 60 * 1000);
const limitReset = makeLimiter('reset', 20, 15 * 60 * 1000);
const limitPublicWrite = makeLimiter('public-write', 120, 10 * 60 * 1000);

// ----- Who is calling? -----
// Owners sign in with email + password. Staff sign in with a PIN. Both are checked
// against the database on every request, so a deactivated staff member loses access at once.

function getActor(req) {
    const s = req.session;
    if (!s) return null;
    if (s.ownerId) {
        const owner = db.prepare('SELECT id, restaurant_id FROM owners WHERE id = ?').get(s.ownerId);
        if (!owner) return null;
        return { role: 'owner', restaurantId: owner.restaurant_id, ownerId: owner.id };
    }
    if (s.staffId) {
        const m = db.prepare('SELECT id, restaurant_id, role, full_name, active FROM staff WHERE id = ?').get(s.staffId);
        if (!m || !m.active) return null;
        return { role: m.role, restaurantId: m.restaurant_id, staffId: m.id, name: m.full_name };
    }
    return null;
}

// requireRole()                      -> owner only
// requireRole('waitress','cashier')  -> owner, plus those staff roles
function requireRole(...roles) {
    return (req, res, next) => {
        const a = getActor(req);
        if (!a || (a.role !== 'owner' && !roles.includes(a.role))) {
            return res.status(403).json({ error: 'Not authorized.' });
        }
        if (!restaurantIsActive(a.restaurantId)) return res.status(403).json({ error: INACTIVE_MESSAGE });
        req.actor = a;
        next();
    };
}

function ownRestaurant(req, res, next) {
    if (String(req.params.id) !== String(req.actor.restaurantId)) return res.status(403).json({ error: 'Not authorized.' });
    next();
}

function requireSuper(req, res, next) {
    if (!req.session || !req.session.isSuper) return res.status(403).json({ error: 'Operator login required.' });
    next();
}

function superOrOwnRestaurant(req, res, next) {
    if (req.session && req.session.isSuper) return next();
    return requireRole()(req, res, () => ownRestaurant(req, res, next));
}

// ----- Payment message checker (a helper only; a human still confirms the money arrived) -----

function analyzeSms(text, expectedTotal) {
    const clean = (text || '').replace(/,/g, '');

    const amountMatch = clean.match(/(\d+(?:\.\d+)?)\s*RWF/i);
    const amount = amountMatch ? Number(amountMatch[1]) : null;

    const idPatterns = [
        /Financial Transaction Id:\s*([A-Za-z0-9]+)/i,
        /TxId:\s*([A-Za-z0-9]+)/i,
        /Transaction Id:\s*([A-Za-z0-9]+)/i,
        /\bId:\s*([A-Za-z0-9]{6,})/i
    ];
    let transactionId = '';
    for (const pattern of idPatterns) {
        const match = clean.match(pattern);
        if (match) { transactionId = match[1]; break; }
    }

    if (!text || !text.trim()) {
        return { verified: false, amount: null, transactionId: '', reason: 'No message was pasted.' };
    }
    if (amount === null) {
        return { verified: false, amount: null, transactionId, reason: 'Could not find an amount in RWF in this message.' };
    }
    if (Math.abs(amount - expectedTotal) > 0.5) {
        return { verified: false, amount, transactionId, reason: `Message shows ${amount.toLocaleString()} RWF but the order total is ${expectedTotal.toLocaleString()} RWF.` };
    }
    if (!transactionId) {
        return { verified: false, amount, transactionId: '', reason: 'Amount matches, but no transaction ID was found in the message.' };
    }
    return { verified: true, amount, transactionId, reason: 'Amount and transaction ID look correct.' };
}

// ================= INSTALLABLE APP =================

// The page asks for /manifest.webmanifest?start=<its own address>, so an installed icon reopens that same page.
app.get('/manifest.webmanifest', (req, res) => {
    let start = typeof req.query.start === 'string' ? req.query.start : '/';
    if (start.length > 300 || !/^\/[A-Za-z0-9._~\-\/?=&%]*$/.test(start) || start.startsWith('//')) start = '/';
    const pagePath = start.split('?')[0];
    res.setHeader('Cache-Control', 'no-cache');
    res.type('application/manifest+json').send(JSON.stringify({
        id: pagePath,
        name: 'Meza',
        short_name: 'Meza',
        description: 'Restaurant ordering made simple.',
        start_url: start,
        scope: '/',
        display: 'standalone',
        orientation: 'any',
        background_color: '#FAF6EE',
        theme_color: '#1A1712',
        icons: [
            { src: '/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
            { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
            { src: '/icon-maskable-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' }
        ]
    }));
});

// ================= HEALTH CHECK (for the hosting platform) =================

app.get('/health', (req, res) => {
    try { db.prepare('SELECT 1').get(); res.json({ status: 'ok' }); }
    catch (e) { res.status(500).json({ status: 'error' }); }
});

// ================= OPERATOR (SUPER ADMIN) =================

app.post('/super-login', superLoginLimiter.check, async (req, res) => {
    const password = req.body && req.body.password;
    const expected = process.env.SUPER_ADMIN_PASSWORD;
    if (!expected || typeof password !== 'string' || !safeEqual(password, expected)) {
        superLoginLimiter.fail(req);
        return res.status(401).json({ error: 'Incorrect operator password.' });
    }
    superLoginLimiter.clear(req);
    try {
        await regenerateSession(req);
        req.session.isSuper = true;
        await saveSession(req);
        res.json({ status: 'ok' });
    } catch (e) {
        console.error('Operator login failed:', e);
        res.status(500).json({ error: 'Could not start session.' });
    }
});

app.post('/super-logout', (req, res) => {
    req.session.destroy(() => res.json({ status: 'ok' }));
});

app.get('/super/me', requireSuper, (req, res) => res.json({ status: 'ok' }));

// Open this address in your browser while signed in at /super-admin.html to download a full backup.
app.get('/super/backup', requireSuper, async (req, res) => {
    const file = path.join(os.tmpdir(), `meza-backup-${Date.now()}.db`);
    try {
        await db.backup(file);
        const name = `meza-backup-${new Date().toISOString().slice(0, 10)}.db`;
        res.download(file, name, () => fs.unlink(file, () => {}));
    } catch (e) {
        console.error('Backup failed:', e);
        fs.unlink(file, () => {});
        res.status(500).json({ error: 'Backup failed.' });
    }
});

// ================= OWNER AUTH =================

app.post('/register', limitRegister, async (req, res) => {
    const { venueName, fullName, email, password } = req.body || {};
    if (!validText(venueName, 120) || !validText(fullName, 120) ||
        typeof email !== 'string' || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
        typeof password !== 'string' || password.length < 10 || password.length > 200) {
        return res.status(400).json({ error: 'Enter a valid restaurant name, full name, email, and password of at least 10 characters.' });
    }
    try {
        const passwordHash = await bcrypt.hash(password, 12);
        const createAccount = db.transaction(() => {
            const restaurantResult = db.prepare('INSERT INTO restaurants (name) VALUES (?)').run(venueName.trim());
            const restaurantId = Number(restaurantResult.lastInsertRowid);
            const ownerResult = db.prepare('INSERT INTO owners (restaurant_id, full_name, email, password_hash) VALUES (?, ?, ?, ?)')
                .run(restaurantId, fullName.trim(), email.trim().toLowerCase(), passwordHash);
            return { restaurantId, ownerId: Number(ownerResult.lastInsertRowid) };
        });
        const account = createAccount();
        await regenerateSession(req);
        req.session.ownerId = account.ownerId;
        req.session.restaurantId = account.restaurantId;
        await saveSession(req);
        res.json({ status: 'created', restaurantId: account.restaurantId });
    } catch (error) {
        if (error && String(error.code || '').startsWith('SQLITE_CONSTRAINT')) {
            return res.status(400).json({ error: 'That email is already registered.' });
        }
        console.error('Registration failed:', error);
        res.status(500).json({ error: 'Could not create the account. Please try again.' });
    }
});

const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 12);

app.post('/login', loginLimiter.check, async (req, res) => {
    const { email, password } = req.body || {};
    if (typeof email !== 'string' || email.length > 254 || typeof password !== 'string' || password.length > 200) {
        return res.status(400).json({ error: 'Enter your email and password.' });
    }
    const owner = db.prepare('SELECT * FROM owners WHERE lower(email) = ?').get(email.trim().toLowerCase());
    // Always run a password check, even for unknown emails, so timing does not reveal which emails exist.
    const match = await bcrypt.compare(password, owner ? owner.password_hash : DUMMY_HASH);
    if (!owner || !match) {
        loginLimiter.fail(req);
        return res.status(401).json({ error: 'Incorrect email or password.' });
    }
    if (!restaurantIsActive(owner.restaurant_id)) return res.status(403).json({ error: INACTIVE_MESSAGE });
    loginLimiter.clear(req);
    try {
        await regenerateSession(req);
        req.session.ownerId = owner.id;
        req.session.restaurantId = owner.restaurant_id;
        await saveSession(req);
    } catch (e) {
        console.error('Session save error:', e);
        return res.status(500).json({ error: 'Could not save login session.' });
    }
    res.json({ status: 'logged in', restaurantId: owner.restaurant_id });
});

app.post('/logout', (req, res) => {
    req.session.destroy(() => res.json({ status: 'logged out' }));
});

app.get('/me', (req, res) => {
    const a = getActor(req);
    if (!a || a.role !== 'owner' || !restaurantIsActive(a.restaurantId)) return res.status(401).json({ error: 'Not logged in' });
    res.json({ ownerId: a.ownerId, restaurantId: a.restaurantId });
});

app.get('/admin/me', (req, res) => {
    const a = getActor(req);
    if (!a || a.role !== 'owner' || !restaurantIsActive(a.restaurantId)) return res.status(401).json({ error: 'Not logged in' });
    res.json({ restaurantId: a.restaurantId, role: 'owner' });
});

// ================= STAFF AUTH =================

app.get('/staff/me', (req, res) => {
    const a = getActor(req);
    if (!a || a.role === 'owner' || !restaurantIsActive(a.restaurantId)) return res.status(401).json({ error: 'Not logged in' });
    res.json({ role: a.role, name: a.name, restaurantId: a.restaurantId });
});

app.post('/staff-login', staffLoginLimiter.check, async (req, res) => {
    const { restaurant_id, pin } = req.body || {};
    if (!validId(restaurant_id) || typeof pin !== 'string' || !/^\d{4,8}$/.test(pin)) {
        staffLoginLimiter.fail(req);
        return res.status(401).json({ error: 'Incorrect PIN.' });
    }
    if (!restaurantIsActive(restaurant_id)) return res.status(403).json({ error: 'This restaurant is temporarily unavailable.' });
    const member = db.prepare('SELECT * FROM staff WHERE restaurant_id = ? AND pin = ? AND active = 1').get(Number(restaurant_id), pin);
    if (!member) {
        staffLoginLimiter.fail(req);
        return res.status(401).json({ error: 'Incorrect PIN.' });
    }
    staffLoginLimiter.clear(req);
    try {
        await regenerateSession(req);
        req.session.staffId = member.id;
        req.session.staffRole = member.role;
        req.session.staffRestaurantId = member.restaurant_id;
        await saveSession(req);
    } catch (e) {
        console.error('Staff session error:', e);
        return res.status(500).json({ error: 'Could not start session.' });
    }
    res.json({ role: member.role, name: member.full_name });
});

app.post('/staff-logout', (req, res) => {
    req.session.destroy(() => res.json({ status: 'logged out' }));
});

// ================= PASSWORD RESET =================

app.post('/forgot-password', limitForgot, async (req, res) => {
    const email = req.body && typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    if (!email || email.length > 254) return res.status(400).json({ error: 'Enter a valid email address.' });
    const owner = db.prepare('SELECT * FROM owners WHERE lower(email) = ?').get(email);
    if (owner) {
        // Only the most recent link works.
        db.prepare('DELETE FROM password_reset_tokens WHERE owner_id = ?').run(owner.id);
        const token = crypto.randomBytes(32).toString('hex');
        const expiresAt = Date.now() + 15 * 60 * 1000;
        // Only a fingerprint (hash) of the token is stored, so a leaked database cannot be used to reset passwords.
        db.prepare('INSERT INTO password_reset_tokens (owner_id, token, expires_at) VALUES (?, ?, ?)').run(owner.id, hashToken(token), expiresAt);
        const baseUrl = (process.env.APP_BASE_URL || (req.protocol + '://' + req.get('host'))).replace(/\/$/, '');
        const resetUrl = `${baseUrl}/reset-password.html?token=${token}`;
        try {
            if (!process.env.RESEND_API_KEY) throw new Error('RESEND_API_KEY is not set');
            const response = await fetch('https://api.resend.com/emails', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    from: process.env.EMAIL_FROM || 'Meza <no-reply@meza-app.com>',
                    to: [email],
                    subject: 'Reset your Meza password',
                    html: `
        <div style="font-family: Arial, sans-serif; background:#FAF6EE; padding:40px 20px;">
          <div style="max-width:420px; margin:0 auto; text-align:center;">
            <div style="width:48px; height:48px; background:#A8371E; border-radius:12px; margin:0 auto 16px;">
              <span style="color:#FAF6EE; font-size:24px; font-weight:800; line-height:48px;">M</span>
            </div>
            <h2 style="color:#1A1712; margin:0 0 4px;">Meza</h2>
            <p style="color:#6B6455; font-size:13px; margin:0 0 28px;">Reset your account password</p>
            <div style="background:#fff; border:1px solid #E7E0D2; border-radius:12px; padding:28px; text-align:left;">
              <p style="color:#1A1712; font-size:15px;">Hi ${escapeHtml(owner.full_name)},</p>
              <p style="color:#1A1712; font-size:15px;">We received a request to reset the password on your Meza account. Click the button below to choose a new one.</p>
              <p style="color:#6B6455; font-size:13px;">This link expires in <strong>15 minutes</strong> and can only be used once.</p>
              <div style="text-align:center; margin:24px 0;">
                <a href="${resetUrl}" style="background:#A8371E; color:#FAF6EE; text-decoration:none; padding:14px 28px; border-radius:26px; font-weight:700; display:inline-block;">Reset my password</a>
              </div>
              <p style="color:#6B6455; font-size:12px;">Or copy this link: <a href="${resetUrl}" style="color:#A8371E;">${resetUrl}</a></p>
              <p style="color:#6B6455; font-size:12px;">If you didn't request this, you can safely ignore this email.</p>
            </div>
            <p style="color:#6B6455; font-size:11px; margin-top:24px;">Meza · Restaurant ordering platform</p>
          </div>
        </div>`
                })
            });
            if (!response.ok) {
                const detail = await response.text();
                throw new Error(`Resend API error ${response.status}: ${detail}`);
            }
        } catch (error) {
            console.error('Password reset email failed:', error.message);
        }
    }
    // Always the same answer, so nobody can use this form to discover which emails are registered.
    res.json({ status: 'sent' });
});

app.post('/reset-password', limitReset, async (req, res) => {
    const { token, password } = req.body || {};
    if (typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token) || typeof password !== 'string' || password.length < 10 || password.length > 200) {
        return res.status(400).json({ error: 'Use a valid reset link and a password of at least 10 characters.' });
    }
    const record = db.prepare('SELECT * FROM password_reset_tokens WHERE token = ?').get(hashToken(token));
    if (!record || record.expires_at < Date.now()) {
        return res.status(400).json({ error: 'This reset link is invalid or has expired.' });
    }
    const passwordHash = await bcrypt.hash(password, 12);
    const reset = db.transaction(() => {
        const stillValid = db.prepare('SELECT id FROM password_reset_tokens WHERE id = ? AND token = ? AND expires_at >= ?').get(record.id, hashToken(token), Date.now());
        if (!stillValid) return false;
        db.prepare('UPDATE owners SET password_hash = ? WHERE id = ?').run(passwordHash, record.owner_id);
        db.prepare('DELETE FROM password_reset_tokens WHERE owner_id = ?').run(record.owner_id);
        return true;
    });
    if (!reset()) return res.status(400).json({ error: 'This reset link is invalid or has expired.' });
    res.json({ status: 'reset' });
});

// ================= STAFF MANAGEMENT (owner only) =================

function pinInUse(restaurantId, pin, exceptStaffId) {
    const row = db.prepare('SELECT id FROM staff WHERE restaurant_id = ? AND pin = ? AND active = 1 AND id != ?')
        .get(restaurantId, pin, exceptStaffId || 0);
    return !!row;
}

app.get('/staff', requireRole(), (req, res) => {
    res.json(db.prepare('SELECT * FROM staff WHERE restaurant_id = ?').all(req.actor.restaurantId));
});

// Phone / contact is optional. Returns the cleaned text, or null if it looks wrong.
function cleanPhone(value) {
    if (value === undefined || value === null) return '';
    if (typeof value !== 'string') return null;
    const text = value.trim();
    return /^[+\d\s().-]{0,25}$/.test(text) ? text : null;
}

app.post('/staff', requireRole(), (req, res) => {
    const { full_name, role } = req.body || {};
    const pin = String((req.body || {}).pin ?? '');
    const phone = cleanPhone((req.body || {}).phone);
    if (!validText(full_name, 120)) return res.status(400).json({ error: 'Enter the staff member\'s name.' });
    if (!STAFF_ROLES.includes(role)) return res.status(400).json({ error: 'Choose a valid role.' });
    if (!/^\d{4,8}$/.test(pin)) return res.status(400).json({ error: 'The PIN must be 4 to 8 digits.' });
    if (phone === null) return res.status(400).json({ error: 'Enter a valid phone number (digits, spaces and + only).' });
    if (pinInUse(req.actor.restaurantId, pin)) return res.status(409).json({ error: 'Another active staff member already uses that PIN. Choose a different one.' });
    db.prepare('INSERT INTO staff (restaurant_id, full_name, role, pin, phone, active) VALUES (?, ?, ?, ?, ?, 1)')
        .run(req.actor.restaurantId, full_name.trim(), role, pin, phone);
    res.json({ status: 'added' });
});

app.put('/staff/:id', requireRole(), (req, res) => {
    const staffId = Number(req.params.id);
    if (!validId(staffId)) return res.status(400).json({ error: 'Invalid staff ID.' });
    const restaurantId = req.actor.restaurantId;
    const current = db.prepare('SELECT * FROM staff WHERE id = ? AND restaurant_id = ?').get(staffId, restaurantId);
    if (!current) return res.status(404).json({ error: 'Staff member not found.' });

    const body = req.body || {};
    const full_name = body.full_name !== undefined ? body.full_name : current.full_name;
    const role = body.role !== undefined ? body.role : current.role;
    const pin = body.pin !== undefined ? String(body.pin) : current.pin;
    const phone = body.phone !== undefined ? cleanPhone(body.phone) : (current.phone || '');
    const active = body.active !== undefined ? (body.active ? 1 : 0) : current.active;

    if (!validText(full_name, 120)) return res.status(400).json({ error: 'Enter the staff member\'s name.' });
    if (!STAFF_ROLES.includes(role)) return res.status(400).json({ error: 'Choose a valid role.' });
    if (!/^\d{4,8}$/.test(pin)) return res.status(400).json({ error: 'The PIN must be 4 to 8 digits.' });
    if (phone === null) return res.status(400).json({ error: 'Enter a valid phone number (digits, spaces and + only).' });
    if (active && pinInUse(restaurantId, pin, staffId)) return res.status(409).json({ error: 'Another active staff member already uses that PIN. Choose a different one.' });

    db.prepare('UPDATE staff SET full_name = ?, role = ?, pin = ?, phone = ?, active = ? WHERE id = ? AND restaurant_id = ?')
        .run(String(full_name).trim(), role, pin, phone, active, staffId, restaurantId);
    res.json({ status: 'updated' });
});

// Deleting a worker removes their access at once (every request re-checks the database).
app.delete('/staff/:id', requireRole(), (req, res) => {
    const staffId = Number(req.params.id);
    if (!validId(staffId)) return res.status(400).json({ error: 'Invalid staff ID.' });
    const r = db.prepare('DELETE FROM staff WHERE id = ? AND restaurant_id = ?').run(staffId, req.actor.restaurantId);
    if (r.changes !== 1) return res.status(404).json({ error: 'Staff member not found.' });
    res.json({ status: 'deleted' });
});

// ================= ORDERS =================

// Customers place orders (no login). The server works out the total itself.
app.post('/orders', limitPublicWrite, (req, res) => {
    const { restaurant_id, table } = req.body || {};
    const cartItems = req.body && req.body.items;
    if (!validId(restaurant_id) || !validText(String(table ?? ''), 30) || !cartItems || typeof cartItems !== 'object' ||
        Array.isArray(cartItems) || Object.keys(cartItems).length < 1 || Object.keys(cartItems).length > 50) {
        return res.status(400).json({ error: 'Invalid order details.' });
    }
    const restaurantId = Number(restaurant_id);
    const restaurant = db.prepare('SELECT id FROM restaurants WHERE id = ?').get(restaurantId);
    if (!restaurant) return res.status(400).json({ error: 'Invalid order details.' });
    if (!restaurantIsActive(restaurantId)) return res.status(403).json({ error: 'This restaurant is temporarily unavailable.' });

    const priceStmt = db.prepare('SELECT price FROM menu_items WHERE id = ? AND restaurant_id = ?');
    let total = 0;
    for (const dishId of Object.keys(cartItems)) {
        const quantity = Number(cartItems[dishId]);
        if (!Number.isSafeInteger(quantity) || quantity < 1 || quantity > 99) {
            return res.status(400).json({ error: 'Each item quantity must be between 1 and 99.' });
        }
        const dish = priceStmt.get(dishId, restaurantId);
        if (!dish) return res.status(400).json({ error: 'One or more menu items are invalid.' });
        total += dish.price * quantity;
    }
    if (!Number.isFinite(total) || total <= 0) return res.status(400).json({ error: 'Order total is invalid.' });

    const result = db.prepare('INSERT INTO orders (restaurant_id, table_number, items, status, paid, created_at, total) VALUES (?, ?, ?, ?, 0, ?, ?)')
        .run(restaurantId, String(table).trim(), JSON.stringify(cartItems), 'awaiting_payment', Date.now(), total);
    res.json({ status: 'awaiting_payment', orderId: Number(result.lastInsertRowid) });
});

// The customer's phone checks its own order here (it cannot use GET /orders, which is staff-only).
app.get('/orders/:id/status', (req, res) => {
    const orderId = Number(req.params.id);
    if (!validId(orderId)) return res.status(400).json({ error: 'Invalid order ID.' });
    const row = db.prepare('SELECT id, status, paid FROM orders WHERE id = ?').get(orderId);
    if (!row) return res.status(404).json({ error: 'Order not found.' });
    res.json({ id: row.id, status: row.status, paid: !!row.paid });
});

// Staff screens and the owner dashboard (the most recent 500 orders, oldest first).
app.get('/orders', requireRole('waitress', 'kitchen', 'cashier'), (req, res) => {
    try {
        const rows = db.prepare(`SELECT * FROM (
                SELECT * FROM orders WHERE restaurant_id = ? ORDER BY id DESC LIMIT 500
            ) ORDER BY id ASC`).all(req.actor.restaurantId);
        const hidePaymentProof = req.actor.role === 'kitchen';
        res.json(rows.map(row => ({
            id: row.id,
            table: row.table_number,
            items: safeParse(row.items, {}),
            status: row.status,
            paid: !!row.paid,
            payment_method: row.payment_method,
            total: row.total,
            void_reason: row.void_reason,
            sms_verified: hidePaymentProof ? false : !!row.sms_verified,
            sms_text: hidePaymentProof ? '' : row.sms_text,
            sms_amount: hidePaymentProof ? 0 : row.sms_amount,
            sms_transaction_id: hidePaymentProof ? '' : row.sms_transaction_id
        })));
    } catch (error) {
        console.error('Error retrieving orders:', error);
        res.status(500).json({ error: 'Unable to retrieve orders.' });
    }
});

// Customer says "I've paid" and pastes the SMS. This is a CLAIM, not proof.
app.post('/orders/:id/claim-payment', limitPublicWrite, (req, res) => {
    const orderId = Number(req.params.id);
    const { payment_method, sms_text } = req.body || {};
    if (!validId(orderId) || typeof payment_method !== 'string' || !PAYMENT_METHODS.includes(payment_method.toLowerCase())) {
        return res.status(400).json({ error: 'Invalid payment details.' });
    }
    if (typeof sms_text !== 'string' || sms_text.length > 5000) {
        return res.status(400).json({ error: 'Please provide a valid payment message.' });
    }
    const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
    if (!order) return res.status(404).json({ error: 'Order not found.' });
    if (order.paid) return res.status(409).json({ error: 'This order is already paid.' });
    if (!['awaiting_payment', 'awaiting_confirmation'].includes(order.status)) {
        return res.status(409).json({ error: 'This order can no longer accept a payment claim.' });
    }

    const analysis = analyzeSms(sms_text, order.total);
    let storedText = sms_text;
    if (analysis.transactionId) {
        const used = db.prepare('SELECT order_id FROM used_transaction_ids WHERE restaurant_id = ? AND transaction_id = ?')
            .get(order.restaurant_id, analysis.transactionId);
        if (used && used.order_id !== order.id) {
            storedText = `[WARNING: this transaction ID was already used on order #${used.order_id}] ` + sms_text;
        }
    }
    db.prepare(`UPDATE orders SET status = 'awaiting_confirmation', payment_method = ?, sms_text = ?, sms_amount = ?,
                sms_transaction_id = ?, sms_verified = 0
                WHERE id = ? AND paid = 0 AND status IN ('awaiting_payment','awaiting_confirmation')`)
        .run(payment_method.toLowerCase(), storedText, analysis.amount || 0, analysis.transactionId || '', orderId);
    res.json({ status: 'awaiting_confirmation', verified: false, reason: 'Payment claim received. The restaurant must independently verify the transaction.' });
});

function rememberTransactionId(order) {
    if (order.sms_transaction_id) {
        db.prepare('INSERT OR IGNORE INTO used_transaction_ids (restaurant_id, transaction_id, order_id) VALUES (?, ?, ?)')
            .run(order.restaurant_id, order.sms_transaction_id, order.id);
    }
}

// Staff press this ONLY after seeing the money in the restaurant's own MoMo / Airtel account.
app.post('/orders/:id/confirm-payment', requireRole('waitress', 'cashier'), (req, res) => {
    const orderId = Number(req.params.id);
    if (!validId(orderId)) return res.status(400).json({ error: 'Invalid order ID.' });
    try {
        db.transaction(() => {
            const order = db.prepare('SELECT * FROM orders WHERE id = ? AND restaurant_id = ?').get(orderId, req.actor.restaurantId);
            if (!order) throw new HttpError(404, 'Order not found.');
            if (order.paid) throw new HttpError(409, 'This order is already marked as paid.');
            const r = db.prepare(`UPDATE orders SET paid = 1, payment_status = 'paid', status = 'pending'
                                  WHERE id = ? AND restaurant_id = ? AND paid = 0
                                  AND status IN ('awaiting_payment','awaiting_confirmation')`)
                .run(orderId, req.actor.restaurantId);
            if (r.changes !== 1) throw new HttpError(409, 'This order can no longer be confirmed.');
            rememberTransactionId(order);
        })();
        res.json({ status: 'pending' });
    } catch (e) { sendError(res, e, 'Unable to confirm the payment.'); }
});

app.post('/orders/:id/reject-payment', requireRole('waitress', 'cashier'), (req, res) => {
    const orderId = Number(req.params.id);
    if (!validId(orderId)) return res.status(400).json({ error: 'Invalid order ID.' });
    const order = db.prepare('SELECT id, paid FROM orders WHERE id = ? AND restaurant_id = ?').get(orderId, req.actor.restaurantId);
    if (!order) return res.status(404).json({ error: 'Order not found.' });
    if (order.paid) return res.status(409).json({ error: 'A paid order cannot be rejected as unpaid.' });
    const r = db.prepare(`UPDATE orders SET status = 'rejected', void_reason = 'Payment not received'
                          WHERE id = ? AND restaurant_id = ? AND paid = 0
                          AND status IN ('awaiting_payment','awaiting_confirmation')`)
        .run(orderId, req.actor.restaurantId);
    if (r.changes !== 1) return res.status(409).json({ error: 'This order can no longer be rejected.' });
    res.json({ status: 'rejected' });
});

// Waitress approves a paid order: stock is checked and deducted all-or-nothing, and the food cost is recorded.
app.post('/orders/:id/approve', requireRole('waitress'), (req, res) => {
    const orderId = Number(req.params.id);
    if (!validId(orderId)) return res.status(400).json({ error: 'Invalid order ID.' });
    const restaurantId = req.actor.restaurantId;
    try {
        db.transaction(() => {
            const order = db.prepare('SELECT * FROM orders WHERE id = ? AND restaurant_id = ?').get(orderId, restaurantId);
            if (!order) throw new HttpError(404, 'Order not found.');
            if (order.status !== 'pending') throw new HttpError(409, 'Only pending orders can be approved.');
            if (!order.paid) throw new HttpError(409, 'The order must have confirmed payment before approval.');

            const items = safeParse(order.items, null);
            if (!items || typeof items !== 'object') throw new HttpError(400, 'The order contains invalid items.');

            const recipeStmt = db.prepare('SELECT ingredient_id, quantity_required FROM recipe_items WHERE menu_item_id = ? AND restaurant_id = ?');
            const needed = {};
            for (const dishId of Object.keys(items)) {
                const quantity = Number(items[dishId]);
                if (!Number.isSafeInteger(quantity) || quantity <= 0) throw new HttpError(400, 'Invalid item quantity.');
                for (const r of recipeStmt.all(dishId, restaurantId)) {
                    needed[r.ingredient_id] = (needed[r.ingredient_id] || 0) + (r.quantity_required * quantity);
                }
            }

            const ingredientStmt = db.prepare('SELECT * FROM ingredients WHERE id = ? AND restaurant_id = ?');
            const deductStmt = db.prepare('UPDATE ingredients SET quantity_in_stock = quantity_in_stock - ? WHERE id = ? AND restaurant_id = ? AND quantity_in_stock >= ?');
            let cost = 0;
            for (const ingredientId of Object.keys(needed)) {
                const ingredient = ingredientStmt.get(ingredientId, restaurantId);
                if (!ingredient) throw new HttpError(400, 'A recipe uses an ingredient that no longer exists. Fix the recipe in the Menu screen.');
                if (ingredient.quantity_in_stock < needed[ingredientId]) {
                    throw new HttpError(400, `Not enough ${ingredient.name} in stock to approve this order.`);
                }
                cost += needed[ingredientId] * (ingredient.cost_per_unit || 0);
            }
            for (const ingredientId of Object.keys(needed)) {
                const r = deductStmt.run(needed[ingredientId], ingredientId, restaurantId, needed[ingredientId]);
                if (r.changes !== 1) throw new HttpError(409, 'Stock changed. Refresh and try again.');
            }
            const result = db.prepare("UPDATE orders SET status = 'approved', cost = ? WHERE id = ? AND restaurant_id = ? AND status = 'pending' AND paid = 1")
                .run(cost, orderId, restaurantId);
            if (result.changes !== 1) throw new HttpError(409, 'The order or stock changed. Refresh and try again.');
        })();
        res.json({ status: 'approved' });
    } catch (e) { sendError(res, e, 'Unable to approve the order.'); }
});

function statusStep(routePath, roles, fromStatus, toStatus, wrongStateMessage) {
    app.post(routePath, requireRole(...roles), (req, res) => {
        const orderId = Number(req.params.id);
        if (!validId(orderId)) return res.status(400).json({ error: 'Invalid order ID.' });
        const order = db.prepare('SELECT status FROM orders WHERE id = ? AND restaurant_id = ?').get(orderId, req.actor.restaurantId);
        if (!order) return res.status(404).json({ error: 'Order not found.' });
        if (order.status !== fromStatus) return res.status(409).json({ error: wrongStateMessage });
        const r = db.prepare('UPDATE orders SET status = ? WHERE id = ? AND restaurant_id = ? AND status = ?')
            .run(toStatus, orderId, req.actor.restaurantId, fromStatus);
        if (r.changes !== 1) return res.status(409).json({ error: 'The order status changed. Refresh and try again.' });
        res.json({ status: toStatus });
    });
}
statusStep('/orders/:id/ready', ['kitchen'], 'approved', 'ready', 'Only approved orders can be marked ready.');
statusStep('/orders/:id/done', ['waitress'], 'ready', 'done', 'Only ready orders can be marked as done.');

// "Item not available": a waitress rejects the order. A paid order is flagged in the reports as a refund due.
app.post('/orders/:id/reject', requireRole('waitress'), (req, res) => {
    const orderId = Number(req.params.id);
    if (!validId(orderId)) return res.status(400).json({ error: 'Invalid order ID.' });
    const r = db.prepare(`UPDATE orders SET status = 'rejected', void_reason = 'Item not available'
                          WHERE id = ? AND restaurant_id = ?
                          AND status IN ('awaiting_payment','awaiting_confirmation','pending')`)
        .run(orderId, req.actor.restaurantId);
    if (!r.changes) return res.status(404).json({ error: 'Order not found or cannot be rejected.' });
    res.json({ status: 'rejected' });
});

app.post('/orders/:id/void', requireRole(), (req, res) => {
    const orderId = Number(req.params.id);
    const reason = req.body && typeof req.body.reason === 'string' ? req.body.reason.trim() : '';
    if (!validId(orderId)) return res.status(400).json({ error: 'Invalid order ID.' });
    if (!reason || reason.length > 250) return res.status(400).json({ error: 'Please provide a reason of up to 250 characters.' });
    const order = db.prepare('SELECT id, status FROM orders WHERE id = ? AND restaurant_id = ?').get(orderId, req.actor.restaurantId);
    if (!order) return res.status(404).json({ error: 'Order not found.' });
    if (['done', 'void', 'rejected'].includes(order.status)) {
        return res.status(409).json({ error: 'This order cannot be cancelled in its current state.' });
    }
    const r = db.prepare("UPDATE orders SET status = 'void', void_reason = ? WHERE id = ? AND restaurant_id = ? AND status = ?")
        .run(reason, orderId, req.actor.restaurantId, order.status);
    if (r.changes !== 1) return res.status(409).json({ error: 'The order changed. Refresh and try again.' });
    res.json({ status: 'void' });
});

// Manual payment (cash at the till, or the owner confirming a mobile-money payment).
app.post('/orders/:id/pay', requireRole('cashier', 'waitress'), (req, res) => {
    const orderId = Number(req.params.id);
    const method = String((req.body || {}).payment_method || '').toLowerCase();
    if (!validId(orderId)) return res.status(400).json({ error: 'Invalid order ID.' });
    if (!PAYMENT_METHODS.includes(method)) return res.status(400).json({ error: 'Choose a valid payment method.' });
    try {
        db.transaction(() => {
            const order = db.prepare('SELECT * FROM orders WHERE id = ? AND restaurant_id = ?').get(orderId, req.actor.restaurantId);
            if (!order) throw new HttpError(404, 'Order not found.');
            if (order.paid) throw new HttpError(409, 'Order is already marked as paid.');
            if (['void', 'rejected'].includes(order.status)) throw new HttpError(409, 'A cancelled order cannot be marked as paid.');
            // An order that was still waiting for payment now goes forward to the waitress.
            const nextStatus = ['awaiting_payment', 'awaiting_confirmation'].includes(order.status) ? 'pending' : order.status;
            const r = db.prepare("UPDATE orders SET paid = 1, payment_status = 'paid', payment_method = ?, status = ? WHERE id = ? AND restaurant_id = ? AND paid = 0")
                .run(method, nextStatus, orderId, req.actor.restaurantId);
            if (r.changes !== 1) throw new HttpError(409, 'Order payment status changed. Refresh and try again.');
            if (method !== 'cash') rememberTransactionId(order);
        })();
        res.json({ status: 'paid' });
    } catch (e) { sendError(res, e, 'Unable to record the payment.'); }
});

// ================= DASHBOARD =================

app.get('/dashboard', requireRole(), (req, res) => {
    const restaurantId = req.actor.restaurantId;
    const orders = db.prepare('SELECT status, paid, total FROM orders WHERE restaurant_id = ?').all(restaurantId);
    const counts = { awaiting_payment: 0, awaiting_confirmation: 0, pending: 0, approved: 0, ready: 0, done: 0, rejected: 0, void: 0 };
    let revenue = 0;
    orders.forEach(order => {
        counts[order.status] = (counts[order.status] || 0) + 1;
        if (order.paid && order.status !== 'void' && order.status !== 'rejected') revenue += order.total || 0;
    });
    const lowStock = db.prepare('SELECT COUNT(*) AS n FROM ingredients WHERE restaurant_id = ? AND low_stock_at > 0 AND quantity_in_stock <= low_stock_at').get(restaurantId).n;
    const openOrders = counts.pending + counts.approved + counts.ready;
    res.json({ openOrders, counts, revenue, lowStock });
});

// ================= MENU =================

// Public: customers need the menu.
app.get('/menu', (req, res) => {
    const restaurantId = req.query.restaurant;
    if (typeof restaurantId !== 'string' || !validId(restaurantId)) return res.json([]);
    res.setHeader('Cache-Control', 'no-cache');      // public: the offline copy on phones is allowed
    res.json(db.prepare('SELECT * FROM menu_items WHERE restaurant_id = ?').all(Number(restaurantId)));
});

app.get('/menu/:id/recipe', requireRole(), (req, res) => {
    const menuItemId = String(req.params.id);
    if (!menuItemId.trim() || menuItemId.length > 100) return res.status(400).json({ error: 'Invalid menu item ID.' });
    const restaurantId = req.actor.restaurantId;
    try {
        const menuItem = db.prepare('SELECT id FROM menu_items WHERE id = ? AND restaurant_id = ?').get(menuItemId, restaurantId);
        if (!menuItem) return res.status(404).json({ error: 'Menu item not found.' });
        res.json(db.prepare('SELECT ingredient_id, quantity_required FROM recipe_items WHERE menu_item_id = ? AND restaurant_id = ?').all(menuItemId, restaurantId));
    } catch (error) {
        console.error('Recipe retrieval failed:', error);
        res.status(500).json({ error: 'Unable to retrieve recipe.' });
    }
});

function validateDish(body) {
    const { name, price, prep_time_minutes, recipe } = body;
    if (typeof name !== 'string' || !name.trim() || name.trim().length > 150 ||
        typeof price !== 'number' || !Number.isFinite(price) || price < 0 || price > 100000000) {
        return 'Invalid menu item details.';
    }
    if (prep_time_minutes != null && (!Number.isInteger(Number(prep_time_minutes)) || Number(prep_time_minutes) < 0 || Number(prep_time_minutes) > 1440)) {
        return 'Invalid preparation time.';
    }
    if (recipe != null && !Array.isArray(recipe)) return 'Invalid recipe.';
    return null;
}

const str = v => typeof v === 'string' ? v : '';

function checkRecipe(recipe, restaurantId) {
    const stmt = db.prepare('SELECT id FROM ingredients WHERE id = ? AND restaurant_id = ?');
    for (const item of recipe) {
        const ingredientId = Number(item && item.ingredient_id);
        const quantity = Number(item && item.quantity);
        if (!Number.isSafeInteger(ingredientId) || ingredientId <= 0 || !Number.isFinite(quantity) || quantity <= 0 || !stmt.get(ingredientId, restaurantId)) {
            throw new HttpError(400, 'The recipe contains an invalid ingredient or quantity.');
        }
    }
}

app.post('/menu', requireRole(), (req, res) => {
    const body = req.body || {};
    const restaurantId = req.actor.restaurantId;
    const id = body.id;
    if (typeof id !== 'string' || !id.trim() || id.trim().length > 100) return res.status(400).json({ error: 'Invalid menu item details.' });
    const problem = validateDish(body);
    if (problem) return res.status(400).json({ error: problem });

    try {
        db.transaction(() => {
            if (Array.isArray(body.recipe)) checkRecipe(body.recipe, restaurantId);
            db.prepare(`INSERT INTO menu_items (id, restaurant_id, name, description, price, image_url, category,
                        name_rw, description_rw, name_fr, description_fr, prep_time_minutes)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
                .run(id.trim(), restaurantId, body.name.trim(), str(body.description), body.price, str(body.image_url), str(body.category),
                    str(body.name_rw), str(body.description_rw), str(body.name_fr), str(body.description_fr), Number(body.prep_time_minutes) || 0);
            if (Array.isArray(body.recipe)) {
                const insertRecipe = db.prepare('INSERT INTO recipe_items (restaurant_id, menu_item_id, ingredient_id, quantity_required) VALUES (?, ?, ?, ?)');
                for (const item of body.recipe) insertRecipe.run(restaurantId, id.trim(), Number(item.ingredient_id), Number(item.quantity));
            }
        })();
        res.json({ status: 'added' });
    } catch (error) {
        if (error instanceof HttpError) return sendError(res, error);
        if (error.code === 'SQLITE_CONSTRAINT_PRIMARYKEY' || error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
            return res.status(409).json({ error: 'A menu item with that ID already exists.' });
        }
        sendError(res, error, 'Unable to add the menu item.');
    }
});

app.put('/menu/:id', requireRole(), (req, res) => {
    const id = String(req.params.id);
    const body = req.body || {};
    const restaurantId = req.actor.restaurantId;
    if (!id.trim() || id.length > 100) return res.status(400).json({ error: 'Invalid menu item details.' });
    const problem = validateDish(body);
    if (problem) return res.status(400).json({ error: problem });

    try {
        db.transaction(() => {
            const existing = db.prepare('SELECT id FROM menu_items WHERE id = ? AND restaurant_id = ?').get(id, restaurantId);
            if (!existing) throw new HttpError(404, 'Menu item not found.');
            if (Array.isArray(body.recipe)) checkRecipe(body.recipe, restaurantId);
            const r = db.prepare(`UPDATE menu_items SET name = ?, description = ?, price = ?, image_url = ?, category = ?,
                                  name_rw = ?, description_rw = ?, name_fr = ?, description_fr = ?, prep_time_minutes = ?
                                  WHERE id = ? AND restaurant_id = ?`)
                .run(body.name.trim(), str(body.description), body.price, str(body.image_url), str(body.category),
                    str(body.name_rw), str(body.description_rw), str(body.name_fr), str(body.description_fr),
                    Number(body.prep_time_minutes) || 0, id, restaurantId);
            if (r.changes !== 1) throw new HttpError(404, 'Menu item not found.');
            if (Array.isArray(body.recipe)) {
                db.prepare('DELETE FROM recipe_items WHERE menu_item_id = ? AND restaurant_id = ?').run(id, restaurantId);
                const insertRecipe = db.prepare('INSERT INTO recipe_items (restaurant_id, menu_item_id, ingredient_id, quantity_required) VALUES (?, ?, ?, ?)');
                for (const item of body.recipe) insertRecipe.run(restaurantId, id, Number(item.ingredient_id), Number(item.quantity));
            }
        })();
        res.json({ status: 'updated' });
    } catch (error) { sendError(res, error, 'Unable to update the menu item.'); }
});

app.delete('/menu/:id', requireRole(), (req, res) => {
    const id = String(req.params.id);
    const restaurantId = req.actor.restaurantId;
    if (!id.trim() || id.length > 100) return res.status(400).json({ error: 'Invalid menu item ID.' });
    try {
        db.transaction(() => {
            const existing = db.prepare('SELECT id FROM menu_items WHERE id = ? AND restaurant_id = ?').get(id, restaurantId);
            if (!existing) throw new HttpError(404, 'Menu item not found.');
            db.prepare('DELETE FROM recipe_items WHERE menu_item_id = ? AND restaurant_id = ?').run(id, restaurantId);
            db.prepare('DELETE FROM menu_items WHERE id = ? AND restaurant_id = ?').run(id, restaurantId);
        })();
        res.json({ status: 'deleted' });
    } catch (error) { sendError(res, error, 'Unable to delete menu item.'); }
});

// ================= INGREDIENTS =================

function readIngredient(body) {
    const name = body.name;
    const unit = body.unit;
    const quantity = Number(body.quantity_in_stock);
    const lowStockAt = Number(body.low_stock_at ?? 0);
    const costPerUnit = Number(body.cost_per_unit ?? 0);
    if (typeof name !== 'string' || !name.trim() || name.trim().length > 100 ||
        typeof unit !== 'string' || !unit.trim() || unit.trim().length > 30) {
        return { error: 'Invalid ingredient name or unit.' };
    }
    if (![quantity, lowStockAt, costPerUnit].every(n => Number.isFinite(n) && n >= 0 && n <= 1e12)) {
        return { error: 'Stock quantities and cost must be valid non-negative numbers.' };
    }
    return { name: name.trim(), unit: unit.trim(), quantity, lowStockAt, costPerUnit };
}

app.get('/ingredients', requireRole(), (req, res) => {
    try {
        res.json(db.prepare('SELECT id, name, unit, quantity_in_stock, low_stock_at, cost_per_unit FROM ingredients WHERE restaurant_id = ?').all(req.actor.restaurantId));
    } catch (error) {
        console.error('Ingredient retrieval failed:', error);
        res.status(500).json({ error: 'Unable to retrieve ingredients.' });
    }
});

app.post('/ingredients', requireRole(), (req, res) => {
    const v = readIngredient(req.body || {});
    if (v.error) return res.status(400).json({ error: v.error });
    try {
        db.prepare('INSERT INTO ingredients (restaurant_id, name, unit, quantity_in_stock, low_stock_at, cost_per_unit) VALUES (?, ?, ?, ?, ?, ?)')
            .run(req.actor.restaurantId, v.name, v.unit, v.quantity, v.lowStockAt, v.costPerUnit);
        res.status(201).json({ status: 'added' });
    } catch (error) {
        console.error('Ingredient creation failed:', error);
        res.status(500).json({ error: 'Unable to add ingredient.' });
    }
});

app.put('/ingredients/:id', requireRole(), (req, res) => {
    const ingredientId = Number(req.params.id);
    if (!validId(ingredientId)) return res.status(400).json({ error: 'Invalid ingredient ID.' });
    const v = readIngredient(req.body || {});
    if (v.error) return res.status(400).json({ error: v.error });
    try {
        const r = db.prepare('UPDATE ingredients SET name = ?, unit = ?, quantity_in_stock = ?, low_stock_at = ?, cost_per_unit = ? WHERE id = ? AND restaurant_id = ?')
            .run(v.name, v.unit, v.quantity, v.lowStockAt, v.costPerUnit, ingredientId, req.actor.restaurantId);
        if (r.changes !== 1) return res.status(404).json({ error: 'Ingredient not found.' });
        res.json({ status: 'updated' });
    } catch (error) {
        console.error('Ingredient update failed:', error);
        res.status(500).json({ error: 'Unable to update ingredient.' });
    }
});

app.delete('/ingredients/:id', requireRole(), (req, res) => {
    const ingredientId = Number(req.params.id);
    if (!validId(ingredientId)) return res.status(400).json({ error: 'Invalid ingredient ID.' });
    const restaurantId = req.actor.restaurantId;
    const inUse = db.prepare('SELECT COUNT(DISTINCT menu_item_id) AS n FROM recipe_items WHERE ingredient_id = ? AND restaurant_id = ?').get(ingredientId, restaurantId).n;
    if (inUse > 0) {
        return res.status(409).json({ error: `This ingredient is used in ${inUse} dish recipe${inUse === 1 ? '' : 's'}. Remove it from those dishes first.` });
    }
    const r = db.prepare('DELETE FROM ingredients WHERE id = ? AND restaurant_id = ?').run(ingredientId, restaurantId);
    if (r.changes !== 1) return res.status(404).json({ error: 'Ingredient not found.' });
    res.json({ status: 'deleted' });
});

// ================= EXPENSES =================

app.post('/expenses', requireRole(), (req, res) => {
    const { expense_date, category, description } = req.body || {};
    const amount = Number((req.body || {}).amount);
    if (typeof expense_date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(expense_date)) return res.status(400).json({ error: 'Enter a valid date.' });
    if (!Number.isFinite(amount) || amount < 0 || amount > 1e12) return res.status(400).json({ error: 'Enter a valid amount.' });
    if ((category != null && (typeof category !== 'string' || category.length > 100)) ||
        (description != null && (typeof description !== 'string' || description.length > 300))) {
        return res.status(400).json({ error: 'Category or description is too long.' });
    }
    db.prepare('INSERT INTO expenses (restaurant_id, expense_date, category, description, amount) VALUES (?, ?, ?, ?, ?)')
        .run(req.actor.restaurantId, expense_date, category || '', description || '', amount);
    res.json({ status: 'added' });
});

app.delete('/expenses/:id', requireRole(), (req, res) => {
    if (!validId(req.params.id)) return res.status(400).json({ error: 'Invalid expense ID.' });
    db.prepare('DELETE FROM expenses WHERE id = ? AND restaurant_id = ?').run(Number(req.params.id), req.actor.restaurantId);
    res.json({ status: 'deleted' });
});

// ================= REPORTS =================

function kigaliDateStr(ms) {
    return new Date(ms + 2 * 60 * 60 * 1000).toISOString().slice(0, 10);
}

function parseRange(query) {
    const today = kigaliDateStr(Date.now());
    const isDate = s => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s + 'T00:00:00Z'));
    const fromStr = isDate(query.from) ? query.from : today.slice(0, 8) + '01';
    const toStr = isDate(query.to) ? query.to : today;
    return {
        fromStr,
        toStr,
        fromMs: Date.parse(fromStr + 'T00:00:00' + TZ_OFFSET),
        toMs: Date.parse(toStr + 'T23:59:59.999' + TZ_OFFSET)
    };
}

function buildReport(restaurantId, range) {
    const orders = db.prepare('SELECT * FROM orders WHERE restaurant_id = ? AND created_at BETWEEN ? AND ? ORDER BY created_at DESC')
        .all(restaurantId, range.fromMs, range.toMs);
    const menu = db.prepare('SELECT id, name FROM menu_items WHERE restaurant_id = ?').all(restaurantId);
    const names = {};
    menu.forEach(m => { names[m.id] = m.name; });

    const describe = items => Object.entries(items).map(([id, qty]) => (names[id] || id) + ' x' + qty).join('; ');

    let revenue = 0, cogs = 0, orderCount = 0, waste = 0, voidedValue = 0, refundsDue = 0;
    const byMethod = {};
    const itemTotals = {};
    const sales = [];
    const voids = [];

    orders.forEach(o => {
        const items = safeParse(o.items, {});
        const total = o.total || 0;
        const cost = o.cost || 0;
        const isVoid = o.status === 'void' || o.status === 'rejected';

        if (isVoid) {
            voidedValue += total;
            waste += cost;
            const refundDue = !!o.paid;
            if (refundDue) refundsDue += total;
            voids.push({
                id: o.id, created_at: o.created_at, table: o.table_number, items: describe(items),
                status: o.status, reason: o.void_reason || '', total, cost,
                paid: !!o.paid, refund_due: refundDue
            });
        } else if (o.paid) {
            revenue += total;
            cogs += cost;
            orderCount++;
            const method = o.payment_method || 'cash';
            byMethod[method] = (byMethod[method] || 0) + total;
            for (const id in items) {
                if (!itemTotals[id]) itemTotals[id] = { name: names[id] || id, quantity: 0 };
                itemTotals[id].quantity += items[id];
            }
            sales.push({
                id: o.id, created_at: o.created_at, table: o.table_number, items: describe(items),
                payment_method: method, total, cost, profit: total - cost
            });
        }
    });

    const expenses = db.prepare('SELECT * FROM expenses WHERE restaurant_id = ? AND expense_date BETWEEN ? AND ? ORDER BY expense_date DESC')
        .all(restaurantId, range.fromStr, range.toStr);
    const expensesTotal = expenses.reduce((sum, e) => sum + e.amount, 0);

    return {
        range: { from: range.fromStr, to: range.toStr },
        revenue,
        cogs,
        grossProfit: revenue - cogs,
        waste,
        expensesTotal,
        netProfit: revenue - cogs - waste - expensesTotal,
        orderCount,
        voidedValue,
        refundsDue,
        byMethod,
        topItems: Object.values(itemTotals).sort((a, b) => b.quantity - a.quantity),
        sales,
        voids,
        expenses
    };
}

function csvEscape(value) {
    let s = String(value ?? '');
    // Stop spreadsheet programs from running text that starts like a formula (e.g. =HYPERLINK(...)).
    if (/^[=+\-@]/.test(s) && Number.isNaN(Number(s))) s = "'" + s;
    return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

function toCsv(rows) {
    // The leading \uFEFF makes Excel read the file as UTF-8 so accents display correctly.
    return '\uFEFF' + rows.map(row => row.map(csvEscape).join(',')).join('\r\n');
}

const fmtDate = ms => new Date(ms).toLocaleString('en-GB', { timeZone: TZ });

app.get('/reports', requireRole(), (req, res) => {
    try {
        res.json(buildReport(req.actor.restaurantId, parseRange(req.query)));
    } catch (error) {
        console.error('Report failed:', error);
        res.status(500).json({ error: 'Unable to build the report.' });
    }
});

app.get('/reports/export', requireRole(), (req, res) => {
    const range = parseRange(req.query);
    const r = buildReport(req.actor.restaurantId, range);
    const type = ['summary', 'sales', 'voids', 'expenses'].includes(req.query.type) ? req.query.type : 'summary';
    let rows;

    if (type === 'sales') {
        rows = [['Order', 'Date', 'Table', 'Items', 'Payment method', 'Total (RWF)', 'Food cost (RWF)', 'Profit (RWF)']];
        r.sales.forEach(s => rows.push([s.id, fmtDate(s.created_at), s.table, s.items, s.payment_method, s.total, s.cost, s.profit]));
    } else if (type === 'voids') {
        rows = [['Order', 'Date', 'Table', 'Items', 'Status', 'Reason', 'Value (RWF)', 'Food wasted (RWF)', 'Refund due']];
        r.voids.forEach(v => rows.push([v.id, fmtDate(v.created_at), v.table, v.items, v.status, v.reason, v.total, v.cost, v.refund_due ? 'Yes' : 'No']));
    } else if (type === 'expenses') {
        rows = [['Date', 'Category', 'Description', 'Amount (RWF)']];
        r.expenses.forEach(e => rows.push([e.expense_date, e.category, e.description, e.amount]));
    } else {
        rows = [
            ['Meza business report'],
            ['Period', r.range.from + ' to ' + r.range.to],
            [],
            ['Profit and loss', 'Amount (RWF)'],
            ['Revenue', r.revenue],
            ['Cost of food', r.cogs],
            ['Gross profit', r.grossProfit],
            ['Waste from voided orders', r.waste],
            ['Expenses', r.expensesTotal],
            ['Net profit / loss', r.netProfit],
            [],
            ['Paid orders', r.orderCount],
            ['Voided orders', r.voids.length],
            ['Voided value', r.voidedValue],
            ['Refunds due', r.refundsDue],
            [],
            ['Payment method', 'Sales (RWF)']
        ];
        Object.entries(r.byMethod).forEach(([method, amount]) => rows.push([method, amount]));
        rows.push([], ['Item', 'Units sold']);
        r.topItems.forEach(i => rows.push([i.name, i.quantity]));
    }

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="meza-${type}-${range.fromStr}-to-${range.toStr}.csv"`);
    res.send(toCsv(rows));
});

// ================= RESTAURANTS =================

// Operator: list every restaurant.
app.get('/restaurants', requireSuper, (req, res) => {
    res.json(db.prepare('SELECT id, name, number_of_tables, plan, subscription_status, subscription_note FROM restaurants ORDER BY id').all());
});

// One restaurant. The public (customer phone) only gets what it needs; the owner gets the full record.
app.get('/restaurants/:id', (req, res) => {
    if (!validId(req.params.id)) return res.status(404).json({ error: 'Restaurant not found.' });
    const id = Number(req.params.id);
    const a = getActor(req);
    let row;
    if (a && a.role === 'owner' && Number(a.restaurantId) === id) {
        row = db.prepare('SELECT * FROM restaurants WHERE id = ?').get(id);
    } else {
        row = db.prepare('SELECT id, name, number_of_tables, momo_number, airtel_number, urubuto_code, subscription_status FROM restaurants WHERE id = ?').get(id);
        res.setHeader('Cache-Control', 'no-cache');  // public subset only: the offline copy on phones is allowed
    }
    if (!row) return res.status(404).json({ error: 'Restaurant not found.' });
    res.json(row);
});

// Operator: create a restaurant together with its owner account.
app.post('/restaurants', requireSuper, async (req, res) => {
    const { name, fullName, email, password } = req.body || {};
    if (!validText(name, 120) || !validText(fullName, 120) || typeof email !== 'string' || email.length > 254 ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || typeof password !== 'string' || password.length < 8 || password.length > 200) {
        return res.status(400).json({ error: 'Enter the restaurant name, owner name, a valid email, and a password of at least 8 characters.' });
    }
    try {
        const passwordHash = await bcrypt.hash(password, 12);
        const created = db.transaction(() => {
            const result = db.prepare('INSERT INTO restaurants (name) VALUES (?)').run(name.trim());
            const restaurantId = Number(result.lastInsertRowid);
            db.prepare('INSERT INTO owners (restaurant_id, full_name, email, password_hash) VALUES (?, ?, ?, ?)')
                .run(restaurantId, fullName.trim(), email.trim().toLowerCase(), passwordHash);
            return restaurantId;
        })();
        res.json({ id: created, name: name.trim() });
    } catch (error) {
        if (error && String(error.code || '').startsWith('SQLITE_CONSTRAINT')) {
            return res.status(400).json({ error: 'That email is already registered.' });
        }
        console.error('Create restaurant failed:', error);
        res.status(500).json({ error: 'Could not create the restaurant.' });
    }
});

app.put('/restaurants/:id', superOrOwnRestaurant, (req, res) => {
    if (!validText(req.body && req.body.name, 120)) return res.status(400).json({ error: 'Enter a valid restaurant name.' });
    const r = db.prepare('UPDATE restaurants SET name = ? WHERE id = ?').run(req.body.name.trim(), Number(req.params.id));
    if (!r.changes) return res.status(404).json({ error: 'Restaurant not found.' });
    res.json({ status: 'updated' });
});

app.put('/restaurants/:id/tables', requireRole(), ownRestaurant, (req, res) => {
    const requested = Number((req.body || {}).number_of_tables);
    if (!Number.isInteger(requested) || requested < 0 || requested > 1000) {
        return res.status(400).json({ error: 'Enter a valid number of tables.' });
    }
    const restaurant = db.prepare('SELECT plan FROM restaurants WHERE id = ?').get(req.actor.restaurantId);
    const plan = restaurant && PLAN_LIMITS[restaurant.plan] !== undefined ? restaurant.plan : 'Free';
    const limit = PLAN_LIMITS[plan];
    if (requested > limit) {
        return res.status(400).json({ error: `Your ${plan} plan allows up to ${limit} QR codes. Upgrade your plan to add more.` });
    }
    db.prepare('UPDATE restaurants SET number_of_tables = ? WHERE id = ?').run(requested, req.actor.restaurantId);
    res.json({ status: 'updated' });
});

// NOTE: any owner can pick any plan here (billing is manual for now). To make plan changes
// operator-only, change `requireRole(), ownRestaurant` below to `requireSuper`.
app.put('/restaurants/:id/plan', requireRole(), ownRestaurant, (req, res) => {
    const plan = (req.body || {}).plan;
    if (typeof plan !== 'string' || PLAN_LIMITS[plan] === undefined) return res.status(400).json({ error: 'Choose a valid plan.' });
    db.prepare('UPDATE restaurants SET plan = ? WHERE id = ?').run(plan, req.actor.restaurantId);
    res.json({ status: 'updated', plan });
});

app.put('/restaurants/:id/payment-details', requireRole(), ownRestaurant, (req, res) => {
    const { momo_number, airtel_number, urubuto_code } = req.body || {};
    const clean = v => (typeof v === 'string' ? v.trim() : '');
    const momo = clean(momo_number), airtel = clean(airtel_number), urubuto = clean(urubuto_code);
    if ([momo, airtel, urubuto].some(v => v.length > 40)) return res.status(400).json({ error: 'Payment details are too long.' });
    db.prepare('UPDATE restaurants SET momo_number = ?, airtel_number = ?, urubuto_code = ? WHERE id = ?')
        .run(momo, airtel, urubuto, req.actor.restaurantId);
    res.json({ status: 'updated' });
});

// Operator: switch a restaurant on or off (for example when a subscription lapses).
app.put('/restaurants/:id/subscription', requireSuper, (req, res) => {
    const { status, note } = req.body || {};
    if (!['active', 'disabled'].includes(status)) return res.status(400).json({ error: 'Status must be active or disabled.' });
    if (!validId(req.params.id)) return res.status(400).json({ error: 'Invalid restaurant ID.' });
    const r = db.prepare('UPDATE restaurants SET subscription_status = ?, subscription_note = ? WHERE id = ?')
        .run(status, typeof note === 'string' ? note.slice(0, 300) : '', Number(req.params.id));
    if (!r.changes) return res.status(404).json({ error: 'Restaurant not found.' });
    res.json({ status: 'updated' });
});

// Operator only: permanently delete a restaurant and everything that belongs to it.
app.delete('/restaurants/:id', requireSuper, (req, res) => {
    if (!validId(req.params.id)) return res.status(400).json({ error: 'Invalid restaurant ID.' });
    const id = Number(req.params.id);
    db.transaction(() => {
        db.prepare('DELETE FROM password_reset_tokens WHERE owner_id IN (SELECT id FROM owners WHERE restaurant_id = ?)').run(id);
        ['menu_items', 'orders', 'owners', 'staff', 'ingredients', 'recipe_items', 'messages', 'requests', 'expenses', 'used_transaction_ids']
            .forEach(table => db.prepare(`DELETE FROM ${table} WHERE restaurant_id = ?`).run(id));
        db.prepare('DELETE FROM restaurants WHERE id = ?').run(id);
    })();
    res.json({ status: 'deleted' });
});

// ================= QR CODES =================

app.get('/qr', requireRole(), async (req, res) => {
    const table = req.query.table;
    if (typeof table !== 'string' || !validText(table, 30)) return res.status(400).json({ error: 'Invalid table.' });
    const baseUrl = (process.env.APP_BASE_URL || (req.protocol + '://' + req.get('host'))).replace(/\/$/, '');
    const url = `${baseUrl}/?restaurant=${encodeURIComponent(req.actor.restaurantId)}&table=${encodeURIComponent(table.trim())}`;
    try {
        const dataUrl = await QRCode.toDataURL(url, { margin: 1, width: 600 });
        res.json({ url, dataUrl });
    } catch (error) {
        res.status(500).json({ error: 'Could not generate QR code.' });
    }
});

// ================= MESSAGES & TABLE REQUESTS =================

// Staff send a note to a table (for example "item not available").
app.post('/messages', requireRole('waitress', 'cashier'), (req, res) => {
    const { table, text } = req.body || {};
    if (!validText(String(table ?? ''), 30) || !validText(text, 300)) return res.status(400).json({ error: 'Enter a table and a message.' });
    db.prepare('INSERT INTO messages (restaurant_id, table_number, text) VALUES (?, ?, ?)').run(req.actor.restaurantId, String(table).trim(), text.trim());
    res.json({ status: 'sent' });
});

// The customer's phone polls for notes addressed to its table, then deletes them once shown.
app.get('/messages', (req, res) => {
    const { restaurant, table } = req.query;
    if (typeof restaurant !== 'string' || !validId(restaurant) || typeof table !== 'string' || !table || table.length > 30) return res.json([]);
    res.json(db.prepare('SELECT * FROM messages WHERE restaurant_id = ? AND table_number = ?').all(Number(restaurant), table));
});

app.delete('/messages/:id', limitPublicWrite, (req, res) => {
    if (!validId(req.params.id)) return res.status(400).json({ error: 'Invalid message ID.' });
    db.prepare('DELETE FROM messages WHERE id = ?').run(Number(req.params.id));
    res.json({ status: 'deleted' });
});

// Customers press "call waiter" or "request bill".
app.post('/requests', limitPublicWrite, (req, res) => {
    const { restaurant_id, table, type } = req.body || {};
    if (!validId(restaurant_id) || !validText(String(table ?? ''), 30) || !validText(type, 40)) {
        return res.status(400).json({ error: 'Invalid request.' });
    }
    const restaurantId = Number(restaurant_id);
    if (!db.prepare('SELECT id FROM restaurants WHERE id = ?').get(restaurantId)) return res.status(400).json({ error: 'Invalid request.' });
    if (!restaurantIsActive(restaurantId)) return res.status(403).json({ error: 'This restaurant is temporarily unavailable.' });
    // Pressing the button twice should not create two rows.
    const already = db.prepare("SELECT id FROM requests WHERE restaurant_id = ? AND table_number = ? AND type = ? AND status = 'open'")
        .get(restaurantId, String(table).trim(), type.trim());
    if (!already) {
        db.prepare('INSERT INTO requests (restaurant_id, table_number, type, status) VALUES (?, ?, ?, ?)')
            .run(restaurantId, String(table).trim(), type.trim(), 'open');
    }
    res.json({ status: 'sent' });
});

app.get('/requests', requireRole('waitress', 'cashier'), (req, res) => {
    res.json(db.prepare("SELECT * FROM requests WHERE restaurant_id = ? AND status = 'open'").all(req.actor.restaurantId));
});

app.post('/requests/:id/resolve', requireRole('waitress', 'cashier'), (req, res) => {
    if (!validId(req.params.id)) return res.status(400).json({ error: 'Invalid request ID.' });
    db.prepare("UPDATE requests SET status = 'resolved' WHERE id = ? AND restaurant_id = ?").run(Number(req.params.id), req.actor.restaurantId);
    res.json({ status: 'resolved' });
});

// ================= ERRORS & START =================

app.use((err, req, res, next) => {
    console.error('Unhandled request error:', err && err.message ? err.message : err);
    if (res.headersSent) return next(err);
    res.status(500).json({ error: 'An unexpected server error occurred.' });
});

process.on('unhandledRejection', reason => console.error('Unhandled promise rejection:', reason));

app.listen(PORT, '0.0.0.0', () => {
    console.log('Server is running on port ' + PORT);
});
