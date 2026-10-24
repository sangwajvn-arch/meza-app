require('dotenv').config();


const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const QRCode = require('qrcode');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const db = require('./db');
const app = express();
app.set('trust proxy', 1);
const PORT = Number(process.env.PORT) || 3000;

// Only serve the public website folder. Never expose .env, server.js, or meza.db.
app.use(express.static(path.join(__dirname, 'public')));
// Clean URLs for all HTML pages
app.get('/:page', (req, res, next) => {
    const page = req.params.page;

    if (!/^[a-zA-Z0-9_-]+$/.test(page)) {
        return next();
    }

    const filePath = path.join(__dirname, 'public', `${page}.html`);

    res.sendFile(filePath, (err) => {
        if (err) {
            next();
        }
    });
});
app.use(express.json({ limit: '100kb' }));
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.SESSION_SECRET) console.warn('WARNING: SESSION_SECRET is not set. Set a long random value in .env before deployment.');
app.use(session({
    name: 'meza.sid',
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
        maxAge: 8 * 60 * 60 * 1000
    }
}));

// Small in-memory limiter for sensitive authentication endpoints.
const authAttempts = new Map();
function limitAuth(req, res, next) {
    const key = `${req.ip}:${req.path}`;
    const now = Date.now();
    const entry = authAttempts.get(key);
    if (entry && entry.until > now && entry.count >= 12) {
        return res.status(429).json({ error: 'Too many attempts. Please wait 15 minutes and try again.' });
    }
    if (!entry || entry.until <= now) authAttempts.set(key, { count: 1, until: now + 15 * 60 * 1000 });
    else entry.count++;
    next();
}
function validId(value) { return Number.isSafeInteger(Number(value)) && Number(value) > 0; }
function validText(value, max = 200) { return typeof value === 'string' && value.trim().length > 0 && value.trim().length <= max; }
function regenerateSession(req) { return new Promise((resolve, reject) => req.session.regenerate(err => err ? reject(err) : resolve())); }


// ⚠️ PUT YOUR REAL GMAIL ADDRESS AND APP PASSWORD HERE
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_APP_PASSWORD
    }
});
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

const PLANS = ['Free', 'Starter', 'Standard', 'Business', 'Premium', 'Professional', 'Enterprise'];

function requireOwner(req, res, restaurantId) {
    if (
        !req.session ||
        !req.session.ownerId ||
        !req.session.restaurantId ||
        restaurantId == null ||
        String(req.session.restaurantId) !== String(restaurantId)
    ) {
        res.status(403).send({ error: 'Not authorized.' });
        return false;
    }

    return true;
}

// Owners and active cashiers may access order/payment workflows only for their own restaurant.
function canManageOrders(req, restaurantId) {
    if (!req.session || restaurantId == null) return false;
    const ownerAllowed = Boolean(
        req.session.ownerId && req.session.restaurantId != null &&
        String(req.session.restaurantId) === String(restaurantId)
    );
    if (ownerAllowed) return true;
    if (!req.session.staffId || req.session.staffRestaurantId == null ||
        String(req.session.staffRestaurantId) !== String(restaurantId)) return false;
    const staff = db.prepare('SELECT id, role, active, restaurant_id FROM staff WHERE id = ?').get(req.session.staffId);
    return Boolean(staff && staff.active && staff.role === 'cashier' &&
        String(staff.restaurant_id) === String(restaurantId));
}

// ================= AUTH =================

app.post('/register', limitAuth, async (req, res) => {
    const { venueName, fullName, email, password } = req.body || {};
    if (!validText(venueName, 120) || !validText(fullName, 120) || typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || typeof password !== 'string' || password.length < 10 || password.length > 200) return res.status(400).json({ error: 'Enter a valid restaurant name, full name, email, and password of at least 10 characters.' });
    try {
        const passwordHash = await bcrypt.hash(password, 12);
        const createAccount = db.transaction(() => {
            const restaurantResult = db.prepare('INSERT INTO restaurants (name) VALUES (?)').run(venueName.trim());
            const restaurantId = Number(restaurantResult.lastInsertRowid);
            const ownerResult = db.prepare('INSERT INTO owners (restaurant_id, full_name, email, password_hash) VALUES (?, ?, ?, ?)').run(restaurantId, fullName.trim(), email.trim().toLowerCase(), passwordHash);
            return { restaurantId, ownerId: Number(ownerResult.lastInsertRowid) };
        });
        const account = createAccount();
        await regenerateSession(req);
        req.session.ownerId = account.ownerId;
        req.session.restaurantId = account.restaurantId;
        res.send({ status: 'created', restaurantId: account.restaurantId });
    } catch (error) {
        res.status(400).send({ error: 'That email is already registered.' });
    }
});

app.post('/login', limitAuth, async (req, res) => {
    const { email, password } = req.body || {};
    if (typeof email !== 'string' || typeof password !== 'string' || password.length > 200) return res.status(400).json({ error: 'Enter your email and password.' });
    const owner = db.prepare('SELECT * FROM owners WHERE email = ?').get(email.trim().toLowerCase());
    if (!owner) return res.status(401).send({ error: 'Incorrect email or password.' });
    const match = await bcrypt.compare(password, owner.password_hash);
    if (!match) return res.status(401).send({ error: 'Incorrect email or password.' });
    try { await regenerateSession(req); } catch (e) { return res.status(500).json({ error: 'Could not start session.' }); }
    req.session.ownerId = owner.id;
req.session.restaurantId = owner.restaurant_id;

req.session.save((err) => {
    if (err) {
        console.error('Session save error:', err);
        return res.status(500).json({
            error: 'Could not save login session.'
        });
    }

    res.json({
        status: 'logged in',
        restaurantId: owner.restaurant_id
    });
});
});

app.post('/logout', (req, res) => {
    req.session.destroy(() => res.send({ status: 'logged out' }));
});

app.get('/me', (req, res) => {
    if (!req.session.ownerId) return res.status(401).send({ error: 'Not logged in' });
    res.send({ ownerId: req.session.ownerId, restaurantId: req.session.restaurantId });
});
app.get('/staff/me', (req, res) => {
    if (!req.session.staffId) return res.status(401).send({ error: 'Not logged in' });
    const member = db.prepare('SELECT * FROM staff WHERE id = ?').get(req.session.staffId);
    if (!member || !member.active) return res.status(401).send({ error: 'Not logged in' });
    res.send({ role: member.role, name: member.full_name, restaurantId: req.session.staffRestaurantId });
});

app.get('/admin/me', (req, res) => {
    if (!req.session.ownerId) return res.status(401).send({ error: 'Not logged in' });
    res.send({ restaurantId: req.session.restaurantId, role: 'owner' });
});

app.post('/staff-login', limitAuth, (req, res) => {
    const { restaurant_id, pin } = req.body || {};
    if (!validId(restaurant_id) || typeof pin !== 'string' || !/^\d{4,8}$/.test(pin)) return res.status(401).json({ error: 'Incorrect PIN.' });
    if (!pin) return res.status(401).send({ error: 'Incorrect PIN.' });
    const member = db.prepare('SELECT * FROM staff WHERE restaurant_id = ? AND pin = ? AND active = 1').get(restaurant_id, pin);
    if (!member) return res.status(401).send({ error: 'Incorrect PIN.' });
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: 'Could not start session.' });
      req.session.staffId = member.id;
    req.session.staffRole = member.role;
    req.session.staffRestaurantId = restaurant_id;
      res.send({ role: member.role, name: member.full_name });
    });
});

app.post('/forgot-password', limitAuth, async (req, res) => {
    const email = req.body && typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    if (!email || email.length > 254) return res.status(400).json({ error: 'Enter a valid email address.' });
    const owner = db.prepare('SELECT * FROM owners WHERE email = ?').get(email);
    if (owner) {
        const token = crypto.randomBytes(32).toString('hex');
        const expiresAt = Date.now() + 15 * 60 * 1000;
        db.prepare('INSERT INTO password_reset_tokens (owner_id, token, expires_at) VALUES (?, ?, ?)').run(owner.id, token, expiresAt);
        const baseUrl = (process.env.APP_BASE_URL || 'http://localhost:3000').replace(/\/$/, '');
        const resetUrl = `${baseUrl}/reset-password.html?token=${token}`;
        try {
          const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
        'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        from: 'Meza <no-reply@meza-app.rw>',
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
              <p style="color:#1A1712; font-size:15px;">Hi ${owner.full_name},</p>
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

const result = await response.json();

if (!response.ok) {
    throw new Error(`Resend API error ${response.status}: ${JSON.stringify(result)}`);
}
        } catch (error) {
            console.error('Password reset email failed:', error);
        }
    }
    res.send({ status: 'sent' });
});

app.post('/reset-password', limitAuth, async (req, res) => {
    const { token, password } = req.body || {};
    if (typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token) || typeof password !== 'string' || password.length < 10 || password.length > 200) return res.status(400).json({ error: 'Use a valid reset link and a password of at least 10 characters.' });
    const record = db.prepare('SELECT * FROM password_reset_tokens WHERE token = ?').get(token);
    if (!record || record.expires_at < Date.now()) {
        return res.status(400).send({ error: 'This reset link is invalid or has expired.' });
    }
    const passwordHash = await bcrypt.hash(password, 12);
    const reset = db.transaction(() => {
        const stillValid = db.prepare('SELECT id FROM password_reset_tokens WHERE id = ? AND token = ? AND expires_at >= ?').get(record.id, token, Date.now());
        if (!stillValid) return false;
        db.prepare('UPDATE owners SET password_hash = ? WHERE id = ?').run(passwordHash, record.owner_id);
        db.prepare('DELETE FROM password_reset_tokens WHERE owner_id = ?').run(record.owner_id);
        return true;
    });
    if (!reset()) return res.status(400).json({ error: 'This reset link is invalid or has expired.' });
    res.send({ status: 'reset' });
});

// ================= STAFF =================

app.get('/staff', (req, res) => {
    const restaurantId = req.query.restaurant;
    if (!requireOwner(req, res, restaurantId)) return;
    res.json(db.prepare('SELECT * FROM staff WHERE restaurant_id = ?').all(restaurantId));
});

app.post('/staff', (req, res) => {
    const { restaurant_id, full_name, role, pin } = req.body;
    if (!requireOwner(req, res, restaurant_id)) return;
    db.prepare('INSERT INTO staff (restaurant_id, full_name, role, pin, active) VALUES (?, ?, ?, ?, 1)')
      .run(restaurant_id, full_name, role, pin);
    res.send({ status: 'added' });
});

app.put('/staff/:id', (req, res) => {
    const { restaurant_id, full_name, role, pin, active } = req.body;
    if (!requireOwner(req, res, restaurant_id)) return;
    const current = db.prepare('SELECT * FROM staff WHERE id = ?').get(req.params.id);
    if (!current) return res.status(404).send({ error: 'Staff member not found.' });
    db.prepare('UPDATE staff SET full_name = ?, role = ?, pin = ?, active = ? WHERE id = ?')
      .run(
          full_name !== undefined ? full_name : current.full_name,
          role !== undefined ? role : current.role,
          pin !== undefined ? pin : current.pin,
          active !== undefined ? (active ? 1 : 0) : current.active,
          req.params.id
      );
    res.send({ status: 'updated' });
});

// ================= ORDERS =================

app.post('/orders', (req, res) => {
    const { restaurant_id, table } = req.body || {};
    const cartItems = req.body && req.body.items;
    if (!validId(restaurant_id) || !validText(String(table ?? ''), 30) || !cartItems || typeof cartItems !== 'object' || Array.isArray(cartItems) || Object.keys(cartItems).length < 1 || Object.keys(cartItems).length > 50) return res.status(400).json({ error: 'Invalid order details.' });

    // The server works out the total itself, so it can't be tampered with from the phone.
    let total = 0;
    for (const dishId of Object.keys(cartItems)) {
        const quantity = Number(cartItems[dishId]);
        if (!Number.isSafeInteger(quantity) || quantity < 1 || quantity > 99) return res.status(400).json({ error: 'Each item quantity must be between 1 and 99.' });
        const dish = db.prepare('SELECT price FROM menu_items WHERE id = ? AND restaurant_id = ?').get(dishId, restaurant_id);
        if (!dish) return res.status(400).json({ error: 'One or more menu items are invalid.' });
        total += dish.price * quantity;
    }
    if (!Number.isFinite(total) || total <= 0) return res.status(400).json({ error: 'Order total is invalid.' });

    const result = db.prepare('INSERT INTO orders (restaurant_id, table_number, items, status, paid, created_at, total) VALUES (?, ?, ?, ?, 0, ?, ?)')
      .run(restaurant_id, table, JSON.stringify(cartItems), 'awaiting_payment', Date.now(), total);
    res.send({ status: 'awaiting_payment', orderId: result.lastInsertRowid });
});

app.get('/orders', (req, res) => {
    const restaurantId = req.query.restaurant;

    if (!canManageOrders(req, restaurantId)) {
        return res.status(403).json({ error: 'Not authorized.' });
    }

    try {
        const rows = db.prepare(
            'SELECT * FROM orders WHERE restaurant_id = ?'
        ).all(restaurantId);

        res.json(rows.map(row => ({
            id: row.id,
            table: row.table_number,
            items: JSON.parse(row.items),
            status: row.status,
            paid: !!row.paid,
            payment_method: row.payment_method,
            total: row.total,
            void_reason: row.void_reason,
            sms_verified: !!row.sms_verified,
            sms_text: row.sms_text,
            sms_amount: row.sms_amount,
            sms_transaction_id: row.sms_transaction_id
        })));
    } catch (error) {
        console.error('Error retrieving orders:', error);
        res.status(500).json({
            error: 'Unable to retrieve orders.'
        });
    }
});

app.post('/orders/:id/claim-payment', (req, res) => {
    const orderId = Number(req.params.id);
    const { payment_method, sms_text } = req.body || {};
    if (!validId(orderId) || typeof payment_method !== 'string' || !['momo', 'airtel', 'cash', 'urubuto'].includes(payment_method.toLowerCase())) return res.status(400).json({ error: 'Invalid payment details.' });
    if (typeof sms_text !== 'string' || sms_text.length > 5000) return res.status(400).json({ error: 'Please provide a valid payment message.' });
    const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
    if (!order) return res.status(404).json({ error: 'Order not found.' });
    if (order.paid) return res.status(409).json({ error: 'This order is already paid.' });
    const analysis = analyzeSms(sms_text, order.total);
    // Pasted SMS is customer-supplied and is NOT proof of payment. Owner must check the real transaction independently.
    db.prepare('UPDATE orders SET status = ?, payment_method = ?, sms_text = ?, sms_amount = ?, sms_transaction_id = ?, sms_verified = 0 WHERE id = ? AND paid = 0')
      .run('awaiting_confirmation', payment_method.toLowerCase(), sms_text, analysis.amount || 0, analysis.transactionId || '', orderId);
    res.send({ status: 'awaiting_confirmation', verified: false, reason: 'Payment claim received. The restaurant must independently verify the transaction.' });
});

app.post('/orders/:id/confirm-payment', (req, res) => {
    const orderId = Number(req.params.id);
    if (!validId(orderId)) return res.status(400).json({ error: 'Invalid order ID.' });

    const order = db.prepare('SELECT id, restaurant_id, status, paid FROM orders WHERE id = ?').get(orderId);
    if (!order) return res.status(404).json({ error: 'Order not found.' });
    if (!canManageOrders(req, order.restaurant_id)) return res.status(403).json({ error: 'Not authorized.' });
    if (order.paid) return res.status(409).json({ error: 'This order is already marked as paid.' });
    if (order.status !== 'awaiting_confirmation') {
        return res.status(409).json({ error: 'This order is not waiting for payment confirmation.' });
    }

    // Clicking this button means the cashier/owner has independently checked the real payment.
    const result = db.prepare(`
        UPDATE orders
        SET paid = 1, payment_status = 'paid', status = 'pending', sms_verified = 1
        WHERE id = ? AND restaurant_id = ? AND paid = 0 AND status = 'awaiting_confirmation'
    `).run(orderId, order.restaurant_id);
    if (result.changes !== 1) return res.status(409).json({ error: 'Order changed. Refresh and try again.' });
    return res.json({ status: 'confirmed', paid: true, orderStatus: 'pending' });
});

app.post('/orders/:id/reject-payment', (req, res) => {
    const orderId = Number(req.params.id);
    if (!validId(orderId)) return res.status(400).json({ error: 'Invalid order ID.' });
    const order = db.prepare('SELECT id, restaurant_id, status, paid FROM orders WHERE id = ?').get(orderId);
    if (!order) return res.status(404).json({ error: 'Order not found.' });
    if (!canManageOrders(req, order.restaurant_id)) return res.status(403).json({ error: 'Not authorized.' });
    if (order.paid) return res.status(409).json({ error: 'A paid order cannot be rejected as unpaid.' });
    if (order.status !== 'awaiting_confirmation') return res.status(409).json({ error: 'This order is not waiting for payment confirmation.' });

    const result = db.prepare(`
        UPDATE orders SET status = 'rejected', void_reason = 'Payment not received'
        WHERE id = ? AND restaurant_id = ? AND paid = 0 AND status = 'awaiting_confirmation'
    `).run(orderId, order.restaurant_id);
    if (result.changes !== 1) return res.status(409).json({ error: 'Order changed. Refresh and try again.' });
    return res.json({ status: 'rejected' });
});

app.post('/orders/:id/approve', (req, res) => {
    const orderId = Number(req.params.id);

    if (!Number.isSafeInteger(orderId) || orderId <= 0) {
        return res.status(400).json({
            error: 'Invalid order ID.'
        });
    }

    if (
        !req.session ||
        !req.session.ownerId ||
        !req.session.restaurantId
    ) {
        return res.status(403).json({
            error: 'Not authorized.'
        });
    }

    const order = db.prepare(
        'SELECT * FROM orders WHERE id = ? AND restaurant_id = ?'
    ).get(orderId, req.session.restaurantId);

    if (!order) {
        return res.status(404).json({
            error: 'Order not found.'
        });
    }

    if (order.status !== 'pending') {
        return res.status(409).json({
            error: 'Only pending orders can be approved.'
        });
    }

    if (!order.paid) {
        return res.status(409).json({
            error: 'The order must have verified payment before approval.'
        });
    }

    let items;

    try {
        items = JSON.parse(order.items);
    } catch (error) {
        return res.status(400).json({
            error: 'The order contains invalid items.'
        });
    }

    const needed = {};

    for (const dishId in items) {
        const quantity = Number(items[dishId]);

        if (!Number.isSafeInteger(quantity) || quantity <= 0) {
            return res.status(400).json({
                error: 'Invalid item quantity.'
            });
        }

        const recipe = db.prepare(
            'SELECT * FROM recipe_items WHERE menu_item_id = ? AND restaurant_id = ?'
        ).all(dishId, order.restaurant_id);

        for (const r of recipe) {
            needed[r.ingredient_id] =
                (needed[r.ingredient_id] || 0) +
                (r.quantity_required * quantity);
        }
    }

    let cost = 0;

    for (const ingredientId in needed) {
        const ingredient = db.prepare(
            'SELECT * FROM ingredients WHERE id = ? AND restaurant_id = ?'
        ).get(ingredientId, order.restaurant_id);

        if (
            !ingredient ||
            ingredient.quantity_in_stock < needed[ingredientId]
        ) {
            return res.status(400).json({
                error: `Not enough ${ingredient ? ingredient.name : 'an ingredient'} in stock to approve this order.`
            });
        }

        cost += needed[ingredientId] *
            (ingredient.cost_per_unit || 0);
    }

    const approveOrder = db.transaction(() => {
        for (const ingredientId in needed) {
            const result = db.prepare(
                'UPDATE ingredients SET quantity_in_stock = quantity_in_stock - ? WHERE id = ? AND restaurant_id = ? AND quantity_in_stock >= ?'
            ).run(
                needed[ingredientId],
                ingredientId,
                order.restaurant_id,
                needed[ingredientId]
            );

            if (result.changes !== 1) {
                throw new Error('STOCK_UPDATE_FAILED');
            }
        }

        const result = db.prepare(
            "UPDATE orders SET status = ?, cost = ? WHERE id = ? AND restaurant_id = ? AND status = 'pending' AND paid = 1"
        ).run(
            'approved',
            cost,
            orderId,
            order.restaurant_id
        );

        if (result.changes !== 1) {
            throw new Error('ORDER_UPDATE_FAILED');
        }
    });

    try {
        approveOrder();
        return res.json({ status: 'approved' });
    } catch (error) {
        if (
            error.message === 'STOCK_UPDATE_FAILED' ||
            error.message === 'ORDER_UPDATE_FAILED'
        ) {
            return res.status(409).json({
                error: 'The order or stock changed. Refresh and try again.'
            });
        }

        console.error('Order approval failed:', error);
        return res.status(500).json({
            error: 'Unable to approve the order.'
        });
    }
});

app.post('/orders/:id/ready', (req, res) => {
    const orderId = Number(req.params.id);

    if (!Number.isSafeInteger(orderId) || orderId <= 0) {
        return res.status(400).json({
            error: 'Invalid order ID.'
        });
    }

    if (
        !req.session ||
        !req.session.ownerId ||
        !req.session.restaurantId
    ) {
        return res.status(403).json({
            error: 'Not authorized.'
        });
    }

    const order = db.prepare(
        'SELECT id, restaurant_id, status FROM orders WHERE id = ? AND restaurant_id = ?'
    ).get(orderId, req.session.restaurantId);

    if (!order) {
        return res.status(404).json({
            error: 'Order not found.'
        });
    }

    if (order.status !== 'approved') {
        return res.status(409).json({
            error: 'Only approved orders can be marked ready.'
        });
    }

    const result = db.prepare(
        "UPDATE orders SET status = 'ready' WHERE id = ? AND restaurant_id = ? AND status = 'approved'"
    ).run(orderId, req.session.restaurantId);

    if (result.changes !== 1) {
        return res.status(409).json({
            error: 'The order status changed. Refresh and try again.'
        });
    }

    return res.json({ status: 'ready' });
});
app.post('/orders/:id/done', (req, res) => {
    const orderId = Number(req.params.id);

    if (!Number.isSafeInteger(orderId) || orderId <= 0) {
        return res.status(400).json({
            error: 'Invalid order ID.'
        });
    }

    if (
        !req.session ||
        !req.session.ownerId ||
        !req.session.restaurantId
    ) {
        return res.status(403).json({
            error: 'Not authorized.'
        });
    }

    const order = db.prepare(
        'SELECT id, restaurant_id, status FROM orders WHERE id = ? AND restaurant_id = ?'
    ).get(orderId, req.session.restaurantId);

    if (!order) {
        return res.status(404).json({
            error: 'Order not found.'
        });
    }

    if (order.status !== 'ready') {
        return res.status(409).json({
            error: 'Only ready orders can be marked as done.'
        });
    }

    const result = db.prepare(
        "UPDATE orders SET status = 'done' WHERE id = ? AND restaurant_id = ? AND status = 'ready'"
    ).run(orderId, req.session.restaurantId);

    if (result.changes !== 1) {
        return res.status(409).json({
            error: 'The order status changed. Refresh and try again.'
        });
    }

    return res.json({ status: 'done' });
});

app.post('/orders/:id/reject', (req, res) => {
    const orderId = Number(req.params.id);
    if (!validId(orderId) || !req.session.ownerId || !req.session.restaurantId) return res.status(403).json({ error: 'Not authorized.' });
    const result = db.prepare("UPDATE orders SET status = 'rejected', void_reason = 'Item not available' WHERE id = ? AND restaurant_id = ? AND status NOT IN ('done','void','rejected') AND paid = 0").run(orderId, req.session.restaurantId);
    if (!result.changes) return res.status(404).json({ error: 'Order not found or cannot be rejected.' });
    res.send({ status: 'rejected' });
});

app.post('/orders/:id/void', (req, res) => {
    const orderId = Number(req.params.id);
    const body = req.body || {};
    const reason = typeof body.reason === 'string'
        ? body.reason.trim()
        : '';

    if (!Number.isSafeInteger(orderId) || orderId <= 0) {
        return res.status(400).json({
            error: 'Invalid order ID.'
        });
    }

    if (
        !req.session ||
        !req.session.ownerId ||
        !req.session.restaurantId
    ) {
        return res.status(403).json({
            error: 'Not authorized.'
        });
    }

    if (!reason || reason.length > 250) {
        return res.status(400).json({
            error: 'Please provide a reason of up to 250 characters.'
        });
    }

    const order = db.prepare(
        'SELECT id, restaurant_id, status FROM orders WHERE id = ? AND restaurant_id = ?'
    ).get(orderId, req.session.restaurantId);

    if (!order) {
        return res.status(404).json({
            error: 'Order not found.'
        });
    }

    if (['done', 'void', 'rejected'].includes(order.status)) {
        return res.status(409).json({
            error: 'This order cannot be cancelled in its current state.'
        });
    }

    const result = db.prepare(
        `UPDATE orders
         SET status = 'void', void_reason = ?
         WHERE id = ? AND restaurant_id = ? AND status = ?`
    ).run(reason, orderId, req.session.restaurantId, order.status);

    if (result.changes !== 1) {
        return res.status(409).json({
            error: 'The order changed. Refresh and try again.'
        });
    }

    return res.json({ status: 'void' });
});

app.post('/orders/:id/pay', (req, res) => {
    const orderId = Number(req.params.id);
    const body = req.body || {};
    if (!validId(orderId)) return res.status(400).json({ error: 'Invalid order ID.' });
    const method = String(body.payment_method || '').toLowerCase();
    if (!['cash', 'momo', 'airtel', 'urubuto'].includes(method)) return res.status(400).json({ error: 'Choose a valid payment method.' });

    const order = db.prepare('SELECT id, restaurant_id, status, paid FROM orders WHERE id = ?').get(orderId);
    if (!order) return res.status(404).json({ error: 'Order not found.' });
    if (!canManageOrders(req, order.restaurant_id)) return res.status(403).json({ error: 'Not authorized.' });
    if (order.paid) return res.status(409).json({ error: 'Order is already marked as paid.' });

    const result = db.prepare("UPDATE orders SET paid = 1, payment_status = 'paid', payment_method = ?, status = CASE WHEN status = 'done' THEN status ELSE 'pending' END WHERE id = ? AND restaurant_id = ? AND paid = 0")
        .run(method, orderId, order.restaurant_id);
    if (result.changes !== 1) return res.status(409).json({ error: 'Order payment status changed. Refresh and try again.' });
    return res.json({ status: 'paid' });
});

// ================= DASHBOARD =================

app.get('/dashboard', (req, res) => {
    const restaurantId = req.query.restaurant;
    if (!requireOwner(req, res, restaurantId)) return;
    const orders = db.prepare('SELECT * FROM orders WHERE restaurant_id = ?').all(restaurantId);
    const counts = { awaiting_payment: 0, awaiting_confirmation: 0, pending: 0, approved: 0, ready: 0, done: 0, rejected: 0, void: 0 };
    let revenue = 0;

    orders.forEach(order => {
        counts[order.status] = (counts[order.status] || 0) + 1;
        if (order.paid && order.status !== 'void' && order.status !== 'rejected') revenue += order.total || 0;
    });

    const openOrders = counts.pending + counts.approved + counts.ready;
    res.send({ openOrders, counts, revenue, lowStock: 0 });
});

// ================= MENU =================

app.get('/menu', (req, res) => {
    res.json(db.prepare('SELECT * FROM menu_items WHERE restaurant_id = ?').all(req.query.restaurant));
});


app.get('/menu/:id/recipe', (req, res) => {
    if (
        !req.session ||
        !req.session.ownerId ||
        !req.session.restaurantId
    ) {
        return res.status(403).json({
            error: 'Not authorized.'
        });
    }

    const menuItemId = req.params.id.trim();
    const restaurantId = req.session.restaurantId;

    if (!menuItemId) {
        return res.status(400).json({
            error: 'Invalid menu item ID.'
        });
    }

    try {
        const menuItem = db.prepare(
            'SELECT id FROM menu_items WHERE id = ? AND restaurant_id = ?'
        ).get(menuItemId, restaurantId);

        if (!menuItem) {
            return res.status(404).json({
                error: 'Menu item not found.'
            });
        }

        const recipe = db.prepare(`
            SELECT ingredient_id, quantity_required
            FROM recipe_items
            WHERE menu_item_id = ? AND restaurant_id = ?
        `).all(menuItemId, restaurantId);

        return res.json(recipe);

    } catch (error) {
        console.error('Recipe retrieval failed:', error);

        return res.status(500).json({
            error: 'Unable to retrieve recipe.'
        });
    }
});


app.post('/menu', (req, res) => {
    const body = req.body || {};

    const {
        id,
        name,
        description,
        price,
        image_url,
        category,
        name_rw,
        description_rw,
        name_fr,
        description_fr,
        prep_time_minutes,
        recipe
    } = body;

    if (
        !req.session ||
        !req.session.ownerId ||
        !req.session.restaurantId
    ) {
        return res.status(403).json({
            error: 'Not authorized.'
        });
    }

    const restaurantId = req.session.restaurantId;

    if (
        typeof id !== 'string' ||
        !id.trim() ||
        typeof name !== 'string' ||
        !name.trim() ||
        typeof price !== 'number' ||
        !Number.isFinite(price) ||
        price < 0 ||
        price > 100000000
    ) {
        return res.status(400).json({
            error: 'Invalid menu item details.'
        });
    }

    if (
        prep_time_minutes != null &&
        (!Number.isInteger(Number(prep_time_minutes)) ||
            Number(prep_time_minutes) < 0 ||
            Number(prep_time_minutes) > 1440)
    ) {
        return res.status(400).json({
            error: 'Invalid preparation time.'
        });
    }

    if (recipe != null && !Array.isArray(recipe)) {
        return res.status(400).json({
            error: 'Invalid recipe.'
        });
    }

    const addMenuItem = db.transaction(() => {
        db.prepare(`
            INSERT INTO menu_items (
                id, restaurant_id, name, description, price,
                image_url, category, name_rw, description_rw,
                name_fr, description_fr, prep_time_minutes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
            id.trim(),
            restaurantId,
            name.trim(),
            typeof description === 'string' ? description : '',
            price,
            typeof image_url === 'string' ? image_url : '',
            typeof category === 'string' ? category : '',
            typeof name_rw === 'string' ? name_rw : '',
            typeof description_rw === 'string' ? description_rw : '',
            typeof name_fr === 'string' ? name_fr : '',
            typeof description_fr === 'string' ? description_fr : '',
            Number(prep_time_minutes) || 0
        );

        if (Array.isArray(recipe)) {
            const insertRecipe = db.prepare(`
                INSERT INTO recipe_items (
                    restaurant_id, menu_item_id,
                    ingredient_id, quantity_required
                )
                VALUES (?, ?, ?, ?)
            `);

            for (const item of recipe) {
                const ingredientId = Number(item.ingredient_id);
                const quantity = Number(item.quantity);

                if (
                    !Number.isSafeInteger(ingredientId) ||
                    ingredientId <= 0 ||
                    !Number.isFinite(quantity) ||
                    quantity <= 0
                ) {
                    throw new Error('INVALID_RECIPE');
                }

                const ingredient = db.prepare(`
                    SELECT id FROM ingredients
                    WHERE id = ? AND restaurant_id = ?
                `).get(ingredientId, restaurantId);

                if (!ingredient) {
                    throw new Error('INVALID_RECIPE');
                }

                insertRecipe.run(
                    restaurantId,
                    id.trim(),
                    ingredientId,
                    quantity
                );
            }
        }
    });

    try {
        addMenuItem();
        return res.json({ status: 'added' });
    } catch (error) {
        if (error.message === 'INVALID_RECIPE') {
            return res.status(400).json({
                error: 'The recipe contains an invalid ingredient or quantity.'
            });
        }

        if (
            error.code === 'SQLITE_CONSTRAINT_PRIMARYKEY' ||
            error.code === 'SQLITE_CONSTRAINT_UNIQUE'
        ) {
            return res.status(409).json({
                error: 'A menu item with that ID already exists.'
            });
        }

        console.error('Menu creation failed:', error);

        return res.status(500).json({
            error: 'Unable to add the menu item.'
        });
    }
});

app.delete('/menu/:id', (req, res) => {
    if (
        !req.session ||
        !req.session.ownerId ||
        !req.session.restaurantId
    ) {
        return res.status(403).json({
            error: 'Not authorized.'
        });
    }

    const menuItemId = Number(req.params.id);
    const restaurantId = req.session.restaurantId;

    if (!Number.isSafeInteger(menuItemId) || menuItemId <= 0) {
        return res.status(400).json({
            error: 'Invalid menu item ID.'
        });
    }

    try {
        const deleteMenuItem = db.transaction(() => {
            const existing = db.prepare(
                'SELECT id FROM menu_items WHERE id = ? AND restaurant_id = ?'
            ).get(menuItemId, restaurantId);

            if (!existing) {
                throw new Error('MENU_ITEM_NOT_FOUND');
            }

            db.prepare(
                'DELETE FROM recipe_items WHERE menu_item_id = ? AND restaurant_id = ?'
            ).run(menuItemId, restaurantId);

            db.prepare(
                'DELETE FROM menu_items WHERE id = ? AND restaurant_id = ?'
            ).run(menuItemId, restaurantId);
        });

        deleteMenuItem();

        return res.json({ status: 'deleted' });

    } catch (error) {
        if (error.message === 'MENU_ITEM_NOT_FOUND') {
            return res.status(404).json({
                error: 'Menu item not found.'
            });
        }

        console.error('Menu deletion failed:', error);

        return res.status(500).json({
            error: 'Unable to delete menu item.'
        });
    }
});

app.put('/menu/:id', (req, res) => {
    const id = req.params.id;
    const body = req.body || {};

    const {
        name,
        description,
        price,
        image_url,
        category,
        name_rw,
        description_rw,
        name_fr,
        description_fr,
        prep_time_minutes,
        recipe
    } = body;

    if (
        !req.session ||
        !req.session.ownerId ||
        !req.session.restaurantId
    ) {
        return res.status(403).json({
            error: 'Not authorized.'
        });
    }

    const restaurantId = req.session.restaurantId;

    if (
        typeof id !== 'string' ||
        !id.trim() ||
        typeof name !== 'string' ||
        !name.trim() ||
        typeof price !== 'number' ||
        !Number.isFinite(price) ||
        price < 0 ||
        price > 100000000
    ) {
        return res.status(400).json({
            error: 'Invalid menu item details.'
        });
    }

    if (
        prep_time_minutes != null &&
        (!Number.isInteger(Number(prep_time_minutes)) ||
            Number(prep_time_minutes) < 0 ||
            Number(prep_time_minutes) > 1440)
    ) {
        return res.status(400).json({
            error: 'Invalid preparation time.'
        });
    }

    if (recipe != null && !Array.isArray(recipe)) {
        return res.status(400).json({
            error: 'Invalid recipe.'
        });
    }

    const updateMenuItem = db.transaction(() => {
        const existing = db.prepare(
            'SELECT id FROM menu_items WHERE id = ? AND restaurant_id = ?'
        ).get(id, restaurantId);

        if (!existing) {
            throw new Error('MENU_ITEM_NOT_FOUND');
        }

        if (Array.isArray(recipe)) {
            for (const item of recipe) {
                const ingredientId = Number(item.ingredient_id);
                const quantity = Number(item.quantity);

                if (
                    !Number.isSafeInteger(ingredientId) ||
                    ingredientId <= 0 ||
                    !Number.isFinite(quantity) ||
                    quantity <= 0
                ) {
                    throw new Error('INVALID_RECIPE');
                }

                const ingredient = db.prepare(
                    'SELECT id FROM ingredients WHERE id = ? AND restaurant_id = ?'
                ).get(ingredientId, restaurantId);

                if (!ingredient) {
                    throw new Error('INVALID_RECIPE');
                }
            }
        }

        const result = db.prepare(`
            UPDATE menu_items
            SET name = ?, description = ?, price = ?, image_url = ?,
                category = ?, name_rw = ?, description_rw = ?,
                name_fr = ?, description_fr = ?, prep_time_minutes = ?
            WHERE id = ? AND restaurant_id = ?
        `).run(
            name.trim(),
            typeof description === 'string' ? description : '',
            price,
            typeof image_url === 'string' ? image_url : '',
            typeof category === 'string' ? category : '',
            typeof name_rw === 'string' ? name_rw : '',
            typeof description_rw === 'string' ? description_rw : '',
            typeof name_fr === 'string' ? name_fr : '',
            typeof description_fr === 'string' ? description_fr : '',
            Number(prep_time_minutes) || 0,
            id,
            restaurantId
        );

        if (result.changes !== 1) {
            throw new Error('MENU_ITEM_NOT_FOUND');
        }

        if (Array.isArray(recipe)) {
            db.prepare(
                'DELETE FROM recipe_items WHERE menu_item_id = ? AND restaurant_id = ?'
            ).run(id, restaurantId);

            const insertRecipe = db.prepare(`
                INSERT INTO recipe_items (
                    restaurant_id, menu_item_id,
                    ingredient_id, quantity_required
                ) VALUES (?, ?, ?, ?)
            `);

            for (const item of recipe) {
                insertRecipe.run(
                    restaurantId,
                    id,
                    Number(item.ingredient_id),
                    Number(item.quantity)
                );
            }
        }
    });

    try {
        updateMenuItem();
        return res.json({ status: 'updated' });
    } catch (error) {
        if (error.message === 'MENU_ITEM_NOT_FOUND') {
            return res.status(404).json({
                error: 'Menu item not found.'
            });
        }

        if (error.message === 'INVALID_RECIPE') {
            return res.status(400).json({
                error: 'The recipe contains an invalid ingredient or quantity.'
            });
        }

        console.error('Menu update failed:', error);

        return res.status(500).json({
            error: 'Unable to update the menu item.'
        });
    }
});

// ================= INGREDIENTS =================

app.get('/ingredients', (req, res) => {
    if (
        !req.session ||
        !req.session.ownerId ||
        !req.session.restaurantId
    ) {
        return res.status(403).json({
            error: 'Not authorized.'
        });
    }

    const restaurantId = req.session.restaurantId;

    try {
        const ingredients = db.prepare(`
            SELECT id, name, unit, quantity_in_stock, low_stock_at
            FROM ingredients
            WHERE restaurant_id = ?
        `).all(restaurantId);

        return res.json(ingredients);

    } catch (error) {
        console.error('Ingredient retrieval failed:', error);

        return res.status(500).json({
            error: 'Unable to retrieve ingredients.'
        });
    }
});

app.post('/ingredients', (req, res) => {
    if (
        !req.session ||
        !req.session.ownerId ||
        !req.session.restaurantId
    ) {
        return res.status(403).json({
            error: 'Not authorized.'
        });
    }

    const restaurantId = req.session.restaurantId;
    const body = req.body || {};

    const name = body.name;
    const unit = body.unit;
    const quantity = Number(body.quantity_in_stock);
    const lowStockAt = Number(body.low_stock_at ?? 0);
    const costPerUnit = Number(body.cost_per_unit ?? 0);

    if (
        typeof name !== 'string' ||
        !name.trim() ||
        name.trim().length > 100 ||
        typeof unit !== 'string' ||
        !unit.trim() ||
        unit.trim().length > 30
    ) {
        return res.status(400).json({
            error: 'Invalid ingredient name or unit.'
        });
    }

    if (
        !Number.isFinite(quantity) ||
        quantity < 0 ||
        !Number.isFinite(lowStockAt) ||
        lowStockAt < 0 ||
        !Number.isFinite(costPerUnit) ||
        costPerUnit < 0
    ) {
        return res.status(400).json({
            error: 'Stock quantities and cost must be valid non-negative numbers.'
        });
    }

    try {
        db.prepare(`
            INSERT INTO ingredients (
                restaurant_id,
                name,
                unit,
                quantity_in_stock,
                low_stock_at,
                cost_per_unit
            )
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(
            restaurantId,
            name.trim(),
            unit.trim(),
            quantity,
            lowStockAt,
            costPerUnit
        );

        return res.status(201).json({
            status: 'added'
        });

    } catch (error) {
        console.error('Ingredient creation failed:', error);

        return res.status(500).json({
            error: 'Unable to add ingredient.'
        });
    }
});

app.put('/ingredients/:id', (req, res) => {
    if (
        !req.session ||
        !req.session.ownerId ||
        !req.session.restaurantId
    ) {
        return res.status(403).json({
            error: 'Not authorized.'
        });
    }

    const ingredientId = Number(req.params.id);
    const restaurantId = req.session.restaurantId;
    const body = req.body || {};

    const { name, unit } = body;
    const quantity = Number(body.quantity_in_stock);
    const lowStockAt = Number(body.low_stock_at ?? 0);
    const costPerUnit = Number(body.cost_per_unit ?? 0);

    if (!Number.isSafeInteger(ingredientId) || ingredientId <= 0) {
        return res.status(400).json({
            error: 'Invalid ingredient ID.'
        });
    }

    if (
        typeof name !== 'string' ||
        !name.trim() ||
        name.trim().length > 100 ||
        typeof unit !== 'string' ||
        !unit.trim() ||
        unit.trim().length > 30
    ) {
        return res.status(400).json({
            error: 'Invalid ingredient name or unit.'
        });
    }

    if (
        !Number.isFinite(quantity) || quantity < 0 ||
        !Number.isFinite(lowStockAt) || lowStockAt < 0 ||
        !Number.isFinite(costPerUnit) || costPerUnit < 0
    ) {
        return res.status(400).json({
            error: 'Stock quantities and cost must be valid non-negative numbers.'
        });
    }

    try {
        const result = db.prepare(`
            UPDATE ingredients
            SET name = ?,
                unit = ?,
                quantity_in_stock = ?,
                low_stock_at = ?,
                cost_per_unit = ?
            WHERE id = ? AND restaurant_id = ?
        `).run(
            name.trim(),
            unit.trim(),
            quantity,
            lowStockAt,
            costPerUnit,
            ingredientId,
            restaurantId
        );

        if (result.changes !== 1) {
            return res.status(404).json({
                error: 'Ingredient not found.'
            });
        }

        return res.json({
            status: 'updated'
        });

    } catch (error) {
        console.error('Ingredient update failed:', error);

        return res.status(500).json({
            error: 'Unable to update ingredient.'
        });
    }
});

app.delete('/ingredients/:id', (req, res) => {
    db.prepare('DELETE FROM ingredients WHERE id = ?').run(req.params.id);
    res.send({ status: 'deleted' });
});

// ================= EXPENSES =================

app.post('/expenses', (req, res) => {
    const { restaurant_id, expense_date, category, description, amount } = req.body;
    if (!requireOwner(req, res, restaurant_id)) return;
    db.prepare('INSERT INTO expenses (restaurant_id, expense_date, category, description, amount) VALUES (?, ?, ?, ?, ?)')
      .run(restaurant_id, expense_date, category || '', description || '', amount);
    res.send({ status: 'added' });
});

app.delete('/expenses/:id', (req, res) => {
    const restaurantId = req.query.restaurant;
    if (!requireOwner(req, res, restaurantId)) return;
    db.prepare('DELETE FROM expenses WHERE id = ? AND restaurant_id = ?').run(req.params.id, restaurantId);
    res.send({ status: 'deleted' });
});

// ================= REPORTS =================

function dateStr(d) {
    return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
}

function parseRange(query) {
    const now = new Date();
    const fromStr = query.from || dateStr(new Date(now.getFullYear(), now.getMonth(), 1));
    const toStr = query.to || dateStr(now);
    return {
        fromStr,
        toStr,
        fromMs: new Date(fromStr + 'T00:00:00').getTime(),
        toMs: new Date(toStr + 'T23:59:59.999').getTime()
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
        const items = JSON.parse(o.items);
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
    const s = String(value ?? '');
    return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

function toCsv(rows) {
    // The leading \uFEFF makes Excel read the file as UTF-8 so accents display correctly.
    return '\uFEFF' + rows.map(row => row.map(csvEscape).join(',')).join('\r\n');
}

const fmtDate = ms => new Date(ms).toLocaleString('en-GB');

app.get('/reports', (req, res) => {
    const restaurantId = req.query.restaurant;
    if (!requireOwner(req, res, restaurantId)) return;
    res.json(buildReport(restaurantId, parseRange(req.query)));
});

app.get('/reports/export', (req, res) => {
    const restaurantId = req.query.restaurant;
    if (!requireOwner(req, res, restaurantId)) return;

    const range = parseRange(req.query);
    const r = buildReport(restaurantId, range);
    const type = req.query.type || 'summary';
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

app.get('/restaurants', (req, res) => {
    res.json(db.prepare('SELECT id, name, number_of_tables FROM restaurants').all());
});

app.get('/restaurants/:id', (req, res) => {
    res.json(db.prepare('SELECT * FROM restaurants WHERE id = ?').get(req.params.id));
});

app.post('/restaurants', async (req, res) => {
    const { name, fullName, email, password } = req.body;
    try {
        const result = db.prepare('INSERT INTO restaurants (name) VALUES (?)').run(name);
        const restaurantId = result.lastInsertRowid;
        const passwordHash = await bcrypt.hash(password, 10);
        db.prepare('INSERT INTO owners (restaurant_id, full_name, email, password_hash) VALUES (?, ?, ?, ?)')
          .run(restaurantId, fullName, email, passwordHash);
        res.send({ id: restaurantId, name });
    } catch (error) {
        res.status(400).send({ error: 'That email is already registered, or something went wrong.' });
    }
});

app.put('/restaurants/:id', (req, res) => {
    if (!requireOwner(req, res, req.params.id)) return;
    if (!validText(req.body && req.body.name, 120)) return res.status(400).json({ error: 'Enter a valid restaurant name.' });
    db.prepare('UPDATE restaurants SET name = ? WHERE id = ?').run(req.body.name.trim(), req.params.id);
    res.send({ status: 'updated' });
});

app.put('/restaurants/:id/tables', (req, res) => {
    if (!requireOwner(req, res, req.params.id)) return;
    const requested = Number(req.body.number_of_tables);
    if (!Number.isFinite(requested) || requested < 0) {
        return res.status(400).send({ error: 'Enter a valid number of tables.' });
    }
    db.prepare('UPDATE restaurants SET number_of_tables = ? WHERE id = ?').run(requested, req.params.id);
    res.send({ status: 'updated' });
});


app.put('/restaurants/:id/payment-details', (req, res) => {
    if (!requireOwner(req, res, req.params.id)) return;
    const { momo_number, airtel_number, urubuto_code } = req.body;
    db.prepare('UPDATE restaurants SET momo_number = ?, airtel_number = ?, urubuto_code = ? WHERE id = ?')
      .run(momo_number, airtel_number, urubuto_code, req.params.id);
    res.send({ status: 'updated' });
});

app.delete('/restaurants/:id', (req, res) => {
    if (!requireOwner(req, res, req.params.id)) return;
    const id = req.params.id;
    ['restaurants', 'menu_items', 'orders', 'owners', 'staff', 'ingredients', 'recipe_items', 'messages', 'requests', 'expenses'].forEach(table => {
        const column = table === 'restaurants' ? 'id' : 'restaurant_id';
        db.prepare(`DELETE FROM ${table} WHERE ${column} = ?`).run(id);
    });
    res.send({ status: 'deleted' });
});

// ================= QR CODES =================

app.get('/qr', async (req, res) => {
    const baseUrl = req.protocol + '://' + req.get('host');
    const url = `${baseUrl}/?restaurant=${req.query.restaurant}&table=${req.query.table}`;
    try {
        const dataUrl = await QRCode.toDataURL(url,{margin: 1, width: 600});
        res.send({ url, dataUrl });
    } catch (error) {
        res.status(500).send({ error: 'Could not generate QR code.' });
    }
});

// ================= MESSAGES & TABLE REQUESTS =================

app.post('/messages', (req, res) => {
    const { restaurant_id, table, text } = req.body;
    db.prepare('INSERT INTO messages (restaurant_id, table_number, text) VALUES (?, ?, ?)').run(restaurant_id, table, text);
    res.send({ status: 'sent' });
});

app.get('/messages', (req, res) => {
    res.json(db.prepare('SELECT * FROM messages WHERE restaurant_id = ? AND table_number = ?').all(req.query.restaurant, req.query.table));
});

app.delete('/messages/:id', (req, res) => {
    db.prepare('DELETE FROM messages WHERE id = ?').run(req.params.id);
    res.send({ status: 'deleted' });
});

app.post('/requests', (req, res) => {
    const { restaurant_id, table, type } = req.body;
    db.prepare('INSERT INTO requests (restaurant_id, table_number, type, status) VALUES (?, ?, ?, ?)').run(restaurant_id, table, type, 'open');
    res.send({ status: 'sent' });
});

app.get('/requests', (req, res) => {
    res.json(db.prepare("SELECT * FROM requests WHERE restaurant_id = ? AND status = 'open'").all(req.query.restaurant));
});

app.post('/requests/:id/resolve', (req, res) => {
    db.prepare("UPDATE requests SET status = 'resolved' WHERE id = ?").run(req.params.id);
    res.send({ status: 'resolved' });
});

app.use((err, req, res, next) => {
    console.error('Unhandled request error:', err && err.message ? err.message : err);
    if (res.headersSent) return next(err);
    res.status(500).json({ error: 'An unexpected server error occurred.' });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log('Server is running at http://localhost:' + PORT);
});
